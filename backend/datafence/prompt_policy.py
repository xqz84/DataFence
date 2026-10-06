"""Pure, deterministic control policy for validated sensitive-AI semantics.

No network, storage or execution occurs here. The caller must apply the returned
analysis BEFORE the sandbox operation and synchronize the final history node.
"""

import math

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from typing import Literal

from .engine import WEIGHTS
from .models import Analysis, SecurityEvent


POLICY_VERSION = "semantic-prompt-policy-v1"
KEYWORD_RULE = "SENSITIVE_PROMPT_EGRESS_INTENT"


class _Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    verdict: Literal["unsafe", "safe", "uncertain"]
    interpretation: Literal["execute", "negated", "quoted", "summary", "unknown"]
    evidence_quote: str = Field(min_length=1, max_length=2000)
    reason: str = Field(min_length=1, max_length=600)


def _level(score: float) -> str:
    return "CRITICAL" if score >= 90 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


def _updated(analysis: Analysis, *, marker: str, message: str, blocked: bool,
             actions: list[str], risk_score: float | None = None,
             dimensions: dict | None = None, remove_keyword: bool = False) -> Analysis:
    result = analysis.model_copy(deep=True)
    if risk_score is not None:
        result.risk_score = round(risk_score, 2)
        result.risk_level = _level(result.risk_score)
    if dimensions is not None:
        result.dimensions = dict(dimensions)
    result.blocked = blocked
    result.actions = list(dict.fromkeys(actions))
    result.rules = [rule for rule in result.rules if not (remove_keyword and rule == KEYWORD_RULE)]
    if marker not in result.rules:
        result.rules.append(marker)
    result.analysis_source = f"{analysis.analysis_source}+{POLICY_VERSION}"
    result.explanation = (
        f"确定性初筛记录：{analysis.explanation}\n"
        f"语义核验后的本地策略：{message} 最终风险 {result.risk_score:.2f}/100；"
        "该结果是执行前策略判定，不代表操作已经执行。"
    )
    for node in result.chain:
        if node.get("event_id") == analysis.event_id:
            node["risk_score"] = result.risk_score
            node["blocked"] = result.blocked
            node["policy_version"] = POLICY_VERSION
    return result


def _hold(analysis: Analysis, marker: str, message: str) -> Analysis:
    # A temporary refusal is NOT evidence of an attack. Do not inflate the
    # risk score or add FREEZE_SESSION solely because a model is unavailable.
    actions = [action for action in analysis.actions if action not in {"ALLOW", "WARN"}]
    return _updated(analysis, marker=marker, message=message, blocked=True,
                    actions=["BLOCK_AI_PROMPT", *actions, "PRESERVE_EVIDENCE"])


def _can_release_keyword_only(event: SecurityEvent, analysis: Analysis) -> bool:
    if not analysis.blocked or set(analysis.rules) != {KEYWORD_RULE}:
        return False
    if "BLOCK_AI_PROMPT" not in analysis.actions or not set(analysis.actions).issubset(
        {"BLOCK_AI_PROMPT", "NOTIFY_SOC", "PRESERVE_EVIDENCE"}
    ):
        return False
    if not analysis.analysis_source.startswith("rules+isolation_forest+purpose"):
        return False
    if event.channel != "internal_ai" or analysis.intent.status != "supported":
        return False
    if any(value != 100 for value in (analysis.intent.role_match, analysis.intent.purpose_match,
                                     analysis.intent.scope_match, analysis.intent.time_match, analysis.intent.trust)):
        return False
    dimensions = analysis.dimensions
    if set(dimensions) != set(WEIGHTS):
        return False
    if any(not math.isfinite(value) or not 0 <= value <= 100 for value in dimensions.values()):
        return False
    if dimensions["I"] != 0 or dimensions["P"] != 0 or dimensions["D"] != event.sensitivity:
        return False
    if dimensions["C"] != 100:
        return False
    current_nodes = [node for node in analysis.chain if node.get("event_id") == event.event_id]
    if len(current_nodes) != 1 or not analysis.chain or analysis.chain[-1].get("event_id") != event.event_id:
        return False
    for node in analysis.chain[:-1]:
        score = node.get("risk_score")
        if not isinstance(score, (int, float)) or isinstance(score, bool) or not math.isfinite(score):
            return False
        if score >= 60 or node.get("blocked") is not False:
            return False
    return True


def apply_semantic_policy(event: SecurityEvent, analysis: Analysis, semantic: dict) -> Analysis:
    """Validate semantics and return a new analysis; never execute a decision.

    Caller invokes this only when the SenseNova semantic gate is configured.
    Incomplete reviews hold this sensitive AI request without adding risk or
    freezing the session. Existing independent restrictions always survive.
    """
    if not isinstance(event, SecurityEvent) or not isinstance(analysis, Analysis):
        raise TypeError("semantic policy requires validated event and analysis contracts")
    if event.event_id != analysis.event_id:
        raise ValueError("semantic policy event and analysis do not match")
    if event.event_type != "AI_PROMPT" or event.sensitivity < 60 or not event.prompt:
        return analysis.model_copy(deep=True)
    if not isinstance(semantic, dict) or semantic.get("status") != "completed":
        return _hold(analysis, "SEMANTIC_REVIEW_UNAVAILABLE",
                     "语义核验未完成或返回不可用，暂缓本次涉敏 AI 请求；不据此认定恶意、不新增冻结。")
    try:
        # Transport metadata is not policy input. In particular, arbitrary
        # suggested_actions never authorize an operation or database write.
        decision = _Decision.model_validate({key: semantic.get(key) for key in _Decision.model_fields})
        if not decision.reason.strip() or not decision.evidence_quote.strip() or decision.evidence_quote not in event.prompt:
            raise ValueError("semantic evidence must quote the current prompt exactly")
    except (ValidationError, ValueError, TypeError):
        return _hold(analysis, "SEMANTIC_REVIEW_UNAVAILABLE",
                     "语义输出的结构或原文证据无效，暂缓本次涉敏 AI 请求；不据此提升风险或新增冻结。")
    if decision.verdict == "uncertain" or decision.interpretation == "unknown":
        return _hold(analysis, "SEMANTIC_REVIEW_UNCERTAIN",
                     "语义证据不足以完成核验，暂缓本次涉敏 AI 请求；不据此认定恶意或新增冻结。")
    if decision.verdict == "unsafe":
        if decision.interpretation != "execute":
            return _hold(analysis, "SEMANTIC_REVIEW_UNCERTAIN",
                         "语义结论与操作解释不一致，暂缓本次请求并保留原确定性约束。")
        actions = [action for action in analysis.actions if action not in {"ALLOW", "WARN"}]
        dimensions = dict(analysis.dimensions)
        dimensions["C"] = max(dimensions.get("C", 0), 100.0)
        return _updated(
            analysis, marker="SEMANTIC_PROMPT_UNSAFE",
            message=f"原文证据表明执行用途不受授权支持，由本地策略阻断当前 AI 请求。依据：{decision.reason}",
            blocked=True, actions=["BLOCK_AI_PROMPT", *actions, "NOTIFY_SOC", "PRESERVE_EVIDENCE"],
            risk_score=max(analysis.risk_score, 90.0), dimensions=dimensions,
        )
    if decision.interpretation in {"negated", "quoted", "summary"} and _can_release_keyword_only(event, analysis):
        dimensions = dict(analysis.dimensions)
        dimensions["C"] = 0.0
        risk = sum(dimensions[name] * weight for name, weight in WEIGHTS.items())
        if risk < 60:
            return _updated(
                analysis, marker="SEMANTIC_PROMPT_SAFE",
                message="原文属于否定、引用或授权汇总，且没有独立限制信号；仅撤销单独关键词引起的阻断。",
                blocked=False, actions=["WARN" if risk >= 30 else "ALLOW", "PRESERVE_EVIDENCE"],
                risk_score=risk, dimensions=dimensions, remove_keyword=True,
            )
    return _updated(
        analysis, marker="SEMANTIC_PROMPT_SAFE",
        message="语义判断为安全；现有独立约束及非单独关键词造成的策略保持不变。",
        blocked=analysis.blocked, actions=analysis.actions,
    )
