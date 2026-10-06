"""Six responsibility views over persisted evidence, not six invented AI calls.

This module has no network, storage mutation, execution, or label access. Inputs
are existing EventRecords, newest first. Counts describe only the supplied view.
"""

import math
import re
from typing import Sequence

from .knowledge import KnowledgeBase
from .models import Analysis, SecurityEvent


VERSION = "datafence-agent-evidence-v1"
_MODULES = (
    ("classification", "Data Classification Agent", "事件敏感度与确定性 D 维度", "deterministic",
     "展示事件已声明的资产类型、敏感度和 D 维度；不声称扫描过客户原始行。"),
    ("behavior", "User Behavior Agent", "本地 Isolation Forest", "local_ml",
     "展示实际计算的行为异常分及模型版本；异常分不单独证明恶意。"),
    ("intent", "Access Intent Agent", "确定性工单核验；可选语义调用单独记录", "deterministic",
     "核对角色、目的、范围和时间，保留证据不足状态；配置模型不代表本次已调用。"),
    ("flow", "Data Flow Agent", "已处理事件的对象关系", "deterministic",
     "展示真实事件的对象及父对象标识，不推演未来步骤，不连接外部接收方。"),
    ("correlation", "Threat Correlation Agent", "会话与对象关联规则", "deterministic",
     "引用已有分析中的关联事件前缀，不把模板中尚未发生的动作写成证据。"),
    ("response", "Response Agent", "本地确定性策略与已保存执行状态", "deterministic",
     "分别展示策略动作和实际记录的执行结果；模型建议不能替代执行凭据。"),
)
_STATUSES = {"completed", "unavailable", "invalid_response", "skipped", "not_configured"}


def _text(value, maximum=160) -> str | None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    if re.search(r"(?i)\bsk-[a-z0-9_-]+", value):
        return None
    return value


def _number(value) -> float | None:
    return float(value) if type(value) in {int, float} and math.isfinite(value) and value >= 0 else None


def _provider(value) -> str | None:
    return value if isinstance(value, str) and value in {"ollama", "sensenova"} else None


def _llm_summary(records: list[tuple[dict, SecurityEvent, Analysis]], configuration: dict) -> dict:
    result = dict(configured=configuration.get("enabled") is True,
                  provider=_provider(configuration.get("provider")), model=_text(configuration.get("model")),
                  configuration_status=_text(configuration.get("status"), 80) or "not_configured",
                  completed_calls=0, failed_calls=0, skipped_records=0, not_configured_records=0,
                  last_status=None, call_records=[])
    for record, event, _ in records:
        semantic = record.get("semantic_analysis")
        advisory = record.get("ai_analysis")
        sources = [("semantic", semantic)]
        # A copied semantic result is one completed operation, not another model
        # call. If the original is absent, keep the persisted record once.
        if not (isinstance(advisory, dict) and advisory.get("reused_semantic") is True and isinstance(semantic, dict)):
            sources.append(("advisory", advisory))
        for purpose, value in sources:
            if not isinstance(value, dict):
                continue
            status = value.get("status")
            if not isinstance(status, str) or status not in _STATUSES:
                continue
            if result["last_status"] is None:
                result["last_status"] = status
            if status == "completed":
                result["completed_calls"] += 1
            elif status in {"unavailable", "invalid_response"}:
                result["failed_calls"] += 1
            elif status == "skipped":
                result["skipped_records"] += 1
            else:
                result["not_configured_records"] += 1
            if len(result["call_records"]) < 16:
                result["call_records"].append(dict(
                    event_id=event.event_id, purpose=purpose, status=status,
                    provider=_provider(value.get("provider")), model=_text(value.get("model")),
                    elapsed_ms=_number(value.get("elapsed_ms")), reason_code=_text(value.get("reason_code"), 80)))
    return result


def build_agent_workbench(records: Sequence[dict], *, model_info: dict | None = None,
                          llm_info: dict | None = None) -> dict:
    """Build read-only evidence cards from validated portions of EventRecords.

    Unknown top-level metadata is never copied. Malformed detector inputs are
    rejected rather than being turned into apparently successful module work.
    """
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise TypeError("records must be a sequence of persisted event records")
    parsed, seen = [], set()
    for record in records:
        if not isinstance(record, dict):
            raise TypeError("each record must be a dictionary")
        event_data, analysis_data = record.get("event"), record.get("analysis")
        event = SecurityEvent.model_validate(event_data.model_dump() if isinstance(event_data, SecurityEvent) else event_data)
        analysis = Analysis.model_validate(analysis_data.model_dump() if isinstance(analysis_data, Analysis) else analysis_data)
        if event.event_id != analysis.event_id:
            raise ValueError("event and analysis must refer to the same event")
        if event.event_id not in seen:
            parsed.append((record, event, analysis))
            seen.add(event.event_id)
    kb = KnowledgeBase()
    modules = []
    for identifier, name, implementation, kind, description in _MODULES:
        relevant = parsed
        if identifier == "flow":
            relevant = [item for item in parsed if item[1].object_id or item[1].parent_object_id]
        findings = []
        for record, event, analysis in relevant[:3]:
            if identifier == "classification":
                values = dict(resource=event.resource, declared_sensitivity=event.sensitivity,
                              data_dimension=analysis.dimensions.get("D"), raw_rows_scanned=False)
                summary = f"事件声明敏感度 {event.sensitivity}/100；展示 D 维度，未扫描原始客户行。"
            elif identifier == "behavior":
                values = dict(anomaly_score=analysis.anomaly_score, behavior_dimension=analysis.dimensions.get("B"),
                              model_version=analysis.model_version, analysis_source=analysis.analysis_source,
                              used_in_final_score=analysis.analysis_source.startswith(("isolation_forest", "rules+isolation_forest")))
                summary = f"本地模型 {analysis.model_version} 的异常分为 {analysis.anomaly_score:g}/100。"
            elif identifier == "intent":
                intent = analysis.intent
                values = dict(status=intent.status, trust=intent.trust, role_match=intent.role_match,
                              purpose_match=intent.purpose_match, scope_match=intent.scope_match, time_match=intent.time_match)
                summary = {"supported": "工单证据支持本次业务。", "mismatch": "工单约束存在不匹配。",
                           "insufficient_evidence": "缺少可核验工单证据，不能补造授权。"}[intent.status]
            elif identifier == "flow":
                values = dict(event_type=event.event_type, object_id=event.object_id, parent_object_id=event.parent_object_id,
                              channel=event.channel, requested_records=event.record_count)
                summary = f"已观察 {event.event_type} 对象流转事件，渠道为 {event.channel}；未推演后续步骤。"
            elif identifier == "correlation":
                nodes = [node for node in analysis.chain if isinstance(node.get("event_id"), str)]
                values = dict(observed_chain_nodes=len(nodes), related_prior_nodes=max(0, len(nodes) - 1),
                              analysis_event_id=analysis.event_id, future_steps_inferred=False)
                summary = f"当前已保存分析关联 {len(nodes)} 个已处理节点，仅展示事件前缀。"
            else:
                outcome = record.get("outcome") if record.get("outcome") in {"executed", "blocked"} else None
                executed = record.get("executed_records")
                if type(executed) is not int or not 0 <= executed <= 50000:
                    executed = None
                values = dict(risk_score=analysis.risk_score, blocked=analysis.blocked,
                              policy_actions="、".join(analysis.actions), recorded_outcome=outcome,
                              executed_records=executed, uses_model_suggestions_as_authority=False)
                summary = ("执行记录：请求已阻断。" if outcome == "blocked" else
                           "执行记录：已完成沙盒操作；具体记录量以保存值为准。" if outcome == "executed" else
                           "仅有策略建议，缺少实际执行状态，不认定已完成。")
            related = kb.related(event, analysis)
            findings.append(dict(event_id=event.event_id, summary=summary, values=values,
                                 knowledge_ids=[item["id"] for item in related]))
        if identifier == "behavior" and isinstance(model_info, dict):
            version = _text(model_info.get("version"), 80)
            if version:
                implementation += "；当前注册版本 " + version
        modules.append(dict(id=identifier, name=name, implementation=implementation, execution_kind=kind,
                            status="evidence_available" if relevant else "no_observations", description=description,
                            evaluated_events=len(relevant), evidence_event_ids=[item[1].event_id for item in relevant[:8]],
                            findings=findings))
    return dict(version=VERSION, scope="provided_records_only", event_count=len(parsed),
                latest_event_id=parsed[0][1].event_id if parsed else None, knowledge=kb.status(), modules=modules,
                llm=_llm_summary(parsed, llm_info if isinstance(llm_info, dict) else {}), limitations=[
                    "六个职责视图不是六个独立 LLM，也不是六次模型调用；工作台不发起模型请求。",
                    "计数仅覆盖本次提供的事件窗口；去重复用的语义记录，不能当成全系统调用累计。",
                    "失败分析记录可能在网络请求前因预算或配置被拒绝，不等于云端 HTTP 请求次数。",
                    "敏感度来自事件契约，未扫描原始客户行；规则和模型输出都不是新的业务授权。",
                    "知识内容仅为项目沙盒政策，不是真实银行制度、法律意见或训练后的模型知识。",
                ])
