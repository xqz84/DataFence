"""Deterministic read gate; quota allocation is not a model recommendation."""

from .models import Analysis


def apply_quota_policy(analysis: Analysis, decision: dict) -> Analysis:
    result = analysis.model_copy(deep=True)
    if decision["allowed"] or analysis.blocked:
        return result
    reason = "工单累计读取额度不足" if decision["reason"] == "quota_exceeded" else "工单绑定或额度状态不允许本次读取"
    result.blocked = True
    result.risk_score = max(result.risk_score, 72)
    result.risk_level = "CRITICAL" if result.risk_score >= 90 else "HIGH"
    result.dimensions["P"] = 100.0
    result.actions = list(dict.fromkeys(["BLOCK_READ", *[a for a in result.actions if a not in {"ALLOW", "WARN"}],
                                       "NOTIFY_SOC", "PRESERVE_EVIDENCE"]))
    result.rules = list(dict.fromkeys([*result.rules, "BUSINESS_TASK_QUOTA_DENIED"]))
    result.analysis_source += "+persistent_quota_policy"
    result.explanation += f" 执行前额度核验：{reason}，已阻断；计量为获准QUERY/API请求记录数，含未确认预留。确定性策略风险下限72。"
    for node in result.chain:
        if node.get("event_id") == result.event_id:
            node.update(risk_score=result.risk_score, blocked=True)
    return result
