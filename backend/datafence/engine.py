"""Label-blind, stateful detector; response actions are recommendations only.

The fitted model is cached across engines. Session histories and business evidence
remain instance-local. Construction may load bounded local JSON model artifacts;
this module performs no network or database operations.
"""

from collections import defaultdict
from datetime import timedelta
from functools import lru_cache
import math
import os
from time import perf_counter

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from .models import Analysis, BusinessTask, Employee, IntentResult, SecurityEvent
from .model_artifacts import MODEL_ROOT, load_artifact, model_directory, read_json, sha256
from .sandbox import BANK_TZ, ROLE_RESOURCES


TRAINING_SEED = 712367
TRAINING_SAMPLES = 2400
FEATURES = ["log_records", "region_count", "hour_sin", "hour_cos", "new_device",
            "external_channel", "export_action", "log_session_reads", "api_calls_60s"]
WEIGHTS = {"D": 0.25, "B": 0.25, "I": 0.15, "P": 0.20, "C": 0.15}
_FLOW_TYPES = {"EXPORT", "COMPRESS", "UPLOAD", "AI_PROMPT"}


@lru_cache(maxsize=1)
def _trained_model() -> tuple[IsolationForest, float, float]:
    """Fit independent synthetic NORMAL activity, including approved rare workload.

    This baseline intentionally does not consume scenario generators, evaluation
    employees, task IDs, labels, session IDs or event IDs.
    """
    rng = np.random.default_rng(TRAINING_SEED)
    rows = []
    for _ in range(TRAINING_SAMPLES):
        batch = rng.random() < 0.14
        login = rng.random() < 0.12
        records = 0 if login else (int(rng.integers(300, 50001)) if batch else int(rng.integers(1, 43)))
        regions = int(rng.integers(2, 21)) if batch and not login else 1
        hour = rng.uniform(0, 24) if batch and rng.random() < 0.25 else rng.uniform(8, 18)
        session_reads = records * (rng.uniform(1, 1.3) if batch else rng.uniform(1, 3))
        rows.append([math.log1p(records), regions, math.sin(hour * math.tau / 24),
                     math.cos(hour * math.tau / 24), float(rng.random() < 0.025),
                     0.0, float(batch and rng.random() < 0.35),
                     math.log1p(session_reads), int(rng.integers(0, 4))])
    matrix = np.asarray(rows)
    model = IsolationForest(n_estimators=100, max_samples=256, contamination=0.03,
                            random_state=TRAINING_SEED, n_jobs=1)
    model.fit(matrix)
    raw = -model.score_samples(matrix)
    # Calibration percentiles are computed only from the independent training set.
    return model, float(np.quantile(raw, 0.50)), float(np.quantile(raw, 0.995))


@lru_cache(maxsize=4)
def _registered_model(name: str, artifact_mtime: int, artifact_size: int,
                      report_mtime: int, report_size: int, receipt_mtime: int, receipt_size: int,
                      expected_artifact_hash: str, expected_report_hash: str):
    directory = model_directory(name)
    model, low, high, metadata = load_artifact(directory / "model.json", FEATURES)
    report = read_json(directory / "report.json", limit=512 * 1024)
    if metadata.get("version") != name or report.get("name") != name:
        raise ValueError("registered model version does not match selection")
    gate = report.get("quality_gate")
    if not isinstance(gate, dict) or gate.get("passed") is not True or not isinstance(report.get("candidate"), dict):
        raise ValueError("registered model did not pass deployment quality gates")
    if report.get("artifact_sha256") != metadata["artifact_sha256"]:
        raise ValueError("training report does not match model artifact")
    if expected_artifact_hash and expected_artifact_hash != metadata["artifact_sha256"]:
        raise ValueError("active model artifact does not match promotion receipt")
    if expected_report_hash and expected_report_hash != sha256(report):
        raise ValueError("active model report does not match promotion receipt")
    receipt = read_json(directory / "promotion.json", limit=8192)
    expected = {"name": name, "artifact_sha256": metadata["artifact_sha256"], "report_sha256": sha256(report)}
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError("active model promotion receipt is missing or does not match")
    metadata.update(features=FEATURES, quality_gate_passed=True, holdout_metrics=report["candidate"],
                    baseline_holdout_metrics=report.get("legacy"), training_splits=report.get("splits", {}),
                    per_probe=report.get("per_probe", []), quality_gate=gate, inference_ms=report.get("inference_ms"),
                    benchmark_scope="synthetic_feature_distribution_shift; not real-bank attack accuracy",
                    registry_name=name, model_source="validated_json_artifact")
    return model, low, high, metadata


def _select_model(requested: str):
    expected_artifact_hash = expected_report_hash = ""
    if requested == "active":
        pointer = MODEL_ROOT / "active.json"
        if not pointer.exists():
            raise ValueError("active model pointer is missing")
        selection = read_json(pointer, limit=8192)
        if set(selection) != {"name", "artifact_sha256", "report_sha256"}:
            raise ValueError("invalid active model pointer")
        for field in ("artifact_sha256", "report_sha256"):
            value = selection[field]
            if (type(value) is not str or len(value) != 64
                    or any(character not in "0123456789abcdef" for character in value)):
                raise ValueError("active model pointer requires complete SHA-256 digests")
        requested = selection["name"]
        expected_artifact_hash, expected_report_hash = selection["artifact_sha256"], selection["report_sha256"]
    path = model_directory(requested) / "model.json"
    stat = path.stat()
    report = (path.parent / "report.json").stat()
    receipt = (path.parent / "promotion.json").stat()
    return _registered_model(requested, stat.st_mtime_ns, stat.st_size,
                             report.st_mtime_ns, report.st_size, receipt.st_mtime_ns, receipt.st_size,
                             expected_artifact_hash, expected_report_hash)


def _bounded(value: float) -> float:
    return round(max(0.0, min(100.0, value)), 2)


def _level(score: float) -> str:
    return "CRITICAL" if score >= 90 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


class DetectionEngine:
    def __init__(self, employees: list[Employee], tasks: list[BusinessTask], mode: str = "full", behavior_model: str | None = None):
        if mode not in {"rules", "behavior", "full"}:
            raise ValueError("mode must be rules, behavior or full")
        self.employees = {employee.id: employee for employee in employees}
        self.tasks = {task.id: task for task in tasks}
        self.mode = mode
        self._model, self._calibration_low, self._calibration_high = _trained_model()
        self._history: dict[tuple[str, str], list[dict]] = defaultdict(list)
        # Business-task totals must not depend on the bounded context window or
        # include another task's requests. These are observed requests, not an
        # execution ledger; accepted quotas remain the orchestrator's authority.
        self._task_reads: dict[tuple[str, str, str | None], int] = defaultdict(int)
        self.model_info = {
            "algorithm": "IsolationForest", "version": "iforest-v1", "training_seed": TRAINING_SEED,
            "training_samples": TRAINING_SAMPLES, "features": FEATURES,
            "training_data": "independent synthetic normal activity; includes approved batch work",
            "uses_evaluation_labels": False, "uses_evaluation_events": False,
            "sklearn_version": sklearn.__version__, "llm_enabled": False,
            "calibration": "training-only median to 99.5th percentile; capped 0..100",
            "model_source": "legacy_in_memory_fit",
        }
        requested = behavior_model if behavior_model is not None else os.environ.get("DATAFENCE_BEHAVIOR_MODEL", "active")
        if requested != "legacy":
            try:
                selected = _select_model(requested)
                if selected is not None:
                    self._model, self._calibration_low, self._calibration_high, self.model_info = selected
                    self.model_info = dict(self.model_info)
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                self.model_info.update(requested_model=requested, load_warning="模型产物或晋升凭据未通过校验，已回退已知旧版。")

    def reset(self) -> None:
        self._history.clear()
        self._task_reads.clear()

    def commit_analysis(self, event: SecurityEvent, final: Analysis) -> None:
        """Commit an orchestrator's final current-event risk without importing AI.

        Caller owns final policy authority. Only two scalar values are accepted;
        alternate histories or event metadata can never be injected by this hook.
        """
        if not isinstance(event, SecurityEvent) or not isinstance(final, Analysis):
            raise ValueError("commit requires allowlisted event and analysis contracts")
        history = self._history.get((event.employee_id, event.session_id))
        if not history or history[-1]["event"].event_id != event.event_id or final.event_id != event.event_id:
            raise ValueError("only the most recently analyzed matching event can be committed")
        if not final.chain or final.chain[-1].get("event_id") != event.event_id:
            raise ValueError("final chain must end in the current event")
        if type(final.blocked) is not bool or type(final.risk_score) not in {int, float} or not math.isfinite(final.risk_score) or not 0 <= final.risk_score <= 100:
            raise ValueError("invalid final risk or block status")
        history[-1]["node"]["risk_score"] = final.risk_score
        history[-1]["node"]["blocked"] = final.blocked
        final.chain[-1]["risk_score"] = final.risk_score
        final.chain[-1]["blocked"] = final.blocked

    def _intent(self, event: SecurityEvent, employee: Employee | None, reads: int) -> IntentResult:
        evidence: list[str] = []
        task = self.tasks.get(event.task_id or "")
        role = 100.0 if employee and (event.event_type == "LOGIN" or event.resource in ROLE_RESOURCES.get(employee.role, set())) else 0.0
        evidence.append(f"岗位与资源：{employee.role if employee else '未知员工'} / {event.resource}，匹配 {role:.0f}/100。")
        if task is None:
            evidence.append("未提供可核验业务工单；业务目的、范围与时间授权均为未知，不据此断言恶意。")
            return IntentResult(role_match=role, purpose_match=50, scope_match=50, time_match=50,
                                trust=round(role * 0.2 + 40, 2), status="insufficient_evidence", evidence=evidence)
        owner_matches = task.employee_id == event.employee_id
        purpose = 100.0 if owner_matches and event.purpose.strip() == task.purpose.strip() else 0.0
        regions_match = set(event.regions).issubset(task.regions)
        amount = max(event.record_count, reads)
        count_match = amount <= task.max_records
        channel_match = event.channel in task.approved_channels
        export_match = event.event_type not in {"EXPORT", "COMPRESS"} or task.allow_export
        scope_checks = [owner_matches, regions_match, count_match, channel_match, export_match]
        scope = 100.0 * sum(scope_checks) / len(scope_checks)
        # Partial evidence is shown, but a single explicit scope denial caps trust.
        local_time = event.timestamp.astimezone(BANK_TZ)
        time_match = task.valid_from <= event.timestamp <= task.valid_until and local_time.hour in task.allowed_hours
        time_score = 100.0 if time_match else 0.0
        trust = role * 0.2 + purpose * 0.25 + scope * 0.35 + time_score * 0.2
        if not all(scope_checks):
            trust = min(trust, 35.0 if owner_matches else 10.0)
        if purpose == 0 or time_score == 0 or role == 0:
            trust = min(trust, 25.0)
        evidence.extend([
            f"工单 {task.id}：员工绑定{'匹配' if owner_matches else '不匹配'}；目的声明与已审批目的{'一致' if purpose else '不一致'}。",
            f"区域{'在审批范围内' if regions_match else '超出审批范围'}；本工单在会话内已观察读取请求累计 {reads} 条，本次流转 {event.record_count} 条，工单上限 {task.max_records} 条。",
            f"渠道 {event.channel} {'已批准' if channel_match else '未批准'}；文件导出权限{'满足' if export_match else '不满足'}。",
            f"中国标准时间 {local_time:%H:%M}，工单有效期及允许时段{'匹配' if time_match else '不匹配'}。",
        ])
        status = "supported" if role == 100 and purpose == 100 and all(scope_checks) and time_match else "mismatch"
        return IntentResult(role_match=role, purpose_match=purpose, scope_match=scope,
                            time_match=time_score, trust=_bounded(trust), status=status, evidence=evidence)

    @staticmethod
    def _prompt_is_unsafe(event: SecurityEvent) -> bool:
        if event.event_type != "AI_PROMPT" or not event.prompt:
            return False
        prompt = event.prompt.lower()
        sensitive = any(term in prompt for term in ("电话", "身份证", "账户", "余额", "phone", "account", "identity"))
        outbound = any(term in prompt for term in ("外部", "网盘", "私人", "公开", "external", "personal", "upload"))
        return event.sensitivity >= 70 and sensitive and outbound

    def _features(self, event: SecurityEvent, employee: Employee | None, history: list[dict], reads: int) -> list[float]:
        local_time = event.timestamp.astimezone(BANK_TZ)
        hour = local_time.hour + local_time.minute / 60
        api_calls = sum(row["event"].event_type == "API" and event.timestamp - row["event"].timestamp <= timedelta(seconds=60) for row in history)
        api_calls += int(event.event_type == "API")
        return [math.log1p(event.record_count), len(event.regions), math.sin(hour * math.tau / 24),
                math.cos(hour * math.tau / 24), float(employee is None or event.device_id != employee.known_device),
                float(event.channel == "external"), float(event.event_type in {"EXPORT", "COMPRESS"}),
                math.log1p(reads), api_calls]

    def _chain(self, event: SecurityEvent, history: list[dict], current: dict) -> list[dict]:
        """Trace actual object ancestry within this employee/session's processed prefix."""
        related_objects = {value for value in (event.object_id, event.parent_object_id) if value}
        selected = []
        for row in reversed(history):
            prior: SecurityEvent = row["event"]
            if prior.event_type == "LOGIN" or (related_objects and prior.object_id in related_objects):
                selected.append(row["node"])
                if prior.parent_object_id:
                    related_objects.add(prior.parent_object_id)
            elif not related_objects and prior.resource == event.resource and prior.event_type not in _FLOW_TYPES:
                selected.append(row["node"])
        return list(reversed(selected)) + [current]

    def analyze(self, event: SecurityEvent) -> Analysis:
        if not isinstance(event, SecurityEvent):
            # Forbid accidental widening of the detector boundary to evaluation dictionaries.
            raise TypeError("analyze requires an allowlisted SecurityEvent")
        started = perf_counter()
        employee = self.employees.get(event.employee_id)
        key = (event.employee_id, event.session_id)
        history = self._history[key]
        if history and event.timestamp < history[-1]["event"].timestamp:
            raise ValueError("events in a session must have nondecreasing timestamps")
        if any(row["event"].event_id == event.event_id for row in history):
            raise ValueError("event already analyzed in this session")
        cutoff = event.timestamp - timedelta(minutes=30)
        history[:] = [row for row in history if row["event"].timestamp >= cutoff][-127:]
        # These are observed read requests. A recommendation is not proof of an
        # executed block; live orchestration decides which later events exist.
        reads = sum(row["event"].record_count for row in history if row["event"].event_type in {"QUERY", "API"})
        task_key = (*key, event.task_id)
        task_reads = self._task_reads.get(task_key, 0)
        if event.event_type in {"QUERY", "API"}:
            reads += event.record_count
            task_reads += event.record_count
        intent = self._intent(event, employee, task_reads)
        feature = self._features(event, employee, history, reads)
        raw = float(-self._model.score_samples(np.asarray([feature]))[0])
        anomaly = _bounded((raw - self._calibration_low) / (self._calibration_high - self._calibration_low) * 100)
        rules: list[str] = []
        identity = 0.0
        baseline = employee.baseline_daily_records if employee else 30
        local_hour = event.timestamp.astimezone(BANK_TZ).hour
        if employee is None or event.device_id != employee.known_device:
            rules.append("UNRECOGNIZED_DEVICE")
            identity = 75
        if not 8 <= local_hour <= 18:
            rules.append("OUTSIDE_USUAL_HOURS")
            identity = min(100, identity + 25)
        cross_region = bool(employee and any(region != employee.region for region in event.regions))
        if cross_region and event.event_type != "LOGIN":
            rules.append("CROSS_REGION_ACCESS")
        bulk = event.record_count > max(100, baseline * 4)
        if bulk:
            rules.append("LARGE_RECORD_VOLUME")
        burst = event.event_type == "API" and feature[-1] >= 5
        if burst:
            rules.append("API_FREQUENCY_SPIKE")
        exporting = event.event_type in {"EXPORT", "COMPRESS"} and event.sensitivity >= 70
        if exporting:
            rules.append("SENSITIVE_FILE_OPERATION")
        external = event.channel == "external" and event.record_count > 0 and event.sensitivity >= 70
        if external:
            rules.append("SENSITIVE_EXTERNAL_CHANNEL")
        unsafe_prompt = self._prompt_is_unsafe(event)
        if unsafe_prompt:
            rules.append("SENSITIVE_PROMPT_EGRESS_INTENT")

        behavior = max(anomaly, 80 if bulk else 0, 95 if burst else 0)
        purpose_risk = 35.0 if intent.status == "insufficient_evidence" else 100 - intent.trust
        channel = 100 if external or unsafe_prompt else 15 if event.channel == "approved_partner" else 0
        # Verified approval explains unusual workload; it cannot approve an unknown device.
        if intent.status == "supported":
            behavior *= 0.12
            if employee and event.device_id == employee.known_device:
                identity = 0
        dimensions = {"D": float(event.sensitivity), "B": _bounded(behavior), "I": identity,
                      "P": _bounded(purpose_risk), "C": float(channel)}
        rule_score = 0.0
        if event.sensitivity >= 70:
            rule_score = 20.0
        if identity:
            rule_score = max(rule_score, 35 if identity < 100 else 65)
        if cross_region:
            rule_score = max(rule_score, 42)
        if bulk:
            rule_score = max(rule_score, 70)
        if burst:
            rule_score = max(rule_score, 78)
        if exporting:
            rule_score = max(rule_score, 75 if bulk else 50)
        if external or unsafe_prompt:
            rule_score = max(rule_score, 98)

        weighted_base = sum(dimensions[dimension] * weight for dimension, weight in WEIGHTS.items())
        if self.mode == "rules":
            risk = rule_score
        elif self.mode == "behavior":
            risk = anomaly
        else:
            risk = weighted_base
            # Explicit policy overrides are disclosed; these are not learned optimal weights.
            if external or unsafe_prompt:
                risk = max(risk, 98)
            if identity == 100:
                risk = max(risk, 65)
            elif identity >= 75:
                risk = max(risk, 35)
            if intent.status == "mismatch" and event.event_type != "LOGIN" and event.sensitivity >= 70:
                risk = max(risk, 64 if event.record_count <= baseline else 72)
                rules.append("BUSINESS_TASK_CONSTRAINT_VIOLATION")
            if burst and intent.status != "supported":
                risk = max(risk, 84)
            if exporting and intent.status != "supported":
                risk = max(risk, 94 if bulk else 86)
            # A data-flow progression raises confidence only using events actually analyzed.
            prior_high = sum(row["node"]["risk_score"] >= 60 for row in history)
            if prior_high and intent.status == "mismatch" and event.event_type in _FLOW_TYPES:
                risk = min(100, risk + min(6, prior_high * 2))
        risk = _bounded(risk)
        level = _level(risk)
        actions: list[str] = []
        blocked = False
        if self.mode != "behavior":
            if external and event.event_type == "UPLOAD":
                actions.append("BLOCK_UPLOAD")
                blocked = True
            elif unsafe_prompt:
                actions.append("BLOCK_AI_PROMPT")
                blocked = True
            elif exporting and intent.status != "supported" and risk >= 60:
                actions.append("BLOCK_EXPORT")
                blocked = True
        if risk >= 90 and intent.status != "supported":
            actions.append("FREEZE_SESSION")
            blocked = True
        if risk >= 60:
            actions.extend(["NOTIFY_SOC", "PRESERVE_EVIDENCE"])
            if not blocked:
                # No reauthentication workflow exists in this local PoC. Do not
                # pretend a challenge was completed while allowing the request.
                actions.insert(0, "WARN")
        elif risk >= 30:
            actions.append("WARN")
        else:
            actions.append("ALLOW")
        node = {"event_id": event.event_id, "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat(), "risk_score": risk, "blocked": blocked,
                "object_id": event.object_id, "parent_object_id": event.parent_object_id,
                "channel": event.channel, "record_count": event.record_count}
        chain = self._chain(event, history, node)
        explanation = (
            f"{'工单证据支持本次业务' if intent.status == 'supported' else '工单约束存在不匹配' if intent.status == 'mismatch' else '业务授权证据不足'}；"
            f"独立正常基线的行为异常分为 {anomaly:.1f}/100；当前风险 {risk:.1f}/100。"
            f"已关联 {len(chain)} 个实际处理事件。"
        )
        if self.mode == "full":
            explanation += (
                f" 五维加权基础分 {weighted_base:.1f}/100；确定性策略/关联调整后的最终风险 {risk:.1f}/100；"
                "权重为 PoC 初始值。"
            )
        if rules:
            explanation += " 触发依据：" + "、".join(rules) + "。"
        explanation += " 本解释由确定性规则与工单证据生成，未调用大语言模型。"
        history.append({"event": event, "node": node})
        self._task_reads[task_key] = task_reads
        return Analysis(event_id=event.event_id, risk_score=risk, risk_level=level, dimensions=dimensions,
                        intent=intent, rules=rules if self.mode != "behavior" else [], anomaly_score=anomaly,
                        explanation=explanation, actions=actions, blocked=blocked, chain=chain,
                        analysis_source={"rules": "rules", "behavior": "isolation_forest", "full": "rules+isolation_forest+purpose"}[self.mode],
                        processing_ms=round((perf_counter() - started) * 1000, 3), model_version=self.model_info["version"])
