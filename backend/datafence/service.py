"""Control plane: schedule synthetic runs and enforce decisions before side effects."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import threading
import time
from uuid import uuid4

from .engine import DetectionEngine
from .execution import SandboxExecutor
from .sensenova import create_analyst
from .prompt_policy import apply_semantic_policy
from .quota import QuotaLedger
from .quota_policy import apply_quota_policy
from .models import BusinessTask, Employee, SimulationRequest
from .sandbox import build_bank
from .scenarios import generate_scenario
from .storage import Store, digest, dump, now

logger = logging.getLogger(__name__)


class Service:
    def __init__(self, directory: Path, customer_count: int = 50000):
        self.store = Store(directory)
        if self.store.manifest() is None:
            self.store.initialize_bank(build_bank(customer_count=customer_count))
        self.employees = [Employee.model_validate(item) for item in self.store.bank("employees")]
        self.tasks = [BusinessTask.model_validate(item) for item in self.store.bank("tasks")]
        self.customers = self.store.bank("customers")
        # Bank entities are immutable for the lifetime of this service. Count the
        # actual persisted rows once instead of scanning 300k+ entities per poll.
        self.bank_counts = self.store.bank_counts()
        self.customer_ids = [item["id"] for item in self.customers]
        self.store.recover()
        self.schedule_lock = threading.Lock()
        self.model_info = DetectionEngine(self.employees, self.tasks).model_info
        self.analyst = create_analyst(directory)
        self.quota = QuotaLedger(directory / "quota.sqlite3")

    def _model_call(self, method, event, analysis):
        try:
            result = getattr(self.analyst, method)(event, analysis)
            if not isinstance(result, dict) or result.get("status") not in {
                "not_configured", "skipped", "completed", "unavailable", "invalid_response"
            }:
                raise ValueError("Invalid model adapter result")
            return result
        except Exception as error:
            # Optional model failures must not discard a completed operation's
            # evidence. Never log exception bodies, which can contain secrets.
            logger.warning("Model adapter unavailable: %s", type(error).__name__)
            return dict(status="unavailable", reason_code="adapter_failure", summary="模型适配器不可用；保留确定性检测与执行证据。",
                        evidence_event_ids=[], suggested_actions=[], elapsed_ms=0, model=None,
                        provider="sensenova" if hasattr(self.analyst, "analyze_prompt") else "ollama", usage=None)

    def create_run(self, request: SimulationRequest) -> dict:
        run = self.prepare_run(request)
        self.store.save("runs", run)
        return run

    def prepare_run(self, request: SimulationRequest) -> dict:
        if request.employee_id not in {e.id for e in self.employees}:
            raise ValueError("员工不存在")
        if request.record_count > len(self.customer_ids):
            raise ValueError("请求记录数超过当前合成客户规模")
        run = dict(id=str(uuid4()), scenario_id=request.scenario_id, employee_id=request.employee_id,
                   status="running", created_at=now(), finished_at=None, planned_events=0,
                   processed_events=0, blocked_events=0, skipped_events=0, sink_records=0,
                   max_risk=0, error=None)
        run.update(phase="queued", current_event_type=None, phase_started_at=now())
        return run

    def execute_run(self, run_id: str, request: SimulationRequest, *, local_only: bool = False):
        run = self.store.get("runs", run_id)
        try:
            events, labels = generate_scenario(request, self.employees, self.tasks)
            # IDs are scoped to the execution, without exposing the scenario to detection.
            session_map = {event.session_id: str(uuid4()) for event in events}
            id_map = {event.event_id: str(uuid4()) for event in events}
            events = [event.model_copy(update={"event_id": id_map[event.event_id],
                                               "session_id": session_map[event.session_id]}) for event in events]
            for label in labels:
                label["event_id"] = id_map[label["event_id"]]
                label["session_id"] = session_map[label["session_id"]]
            label_dir = self.store.directory / "evaluation_labels"
            label_dir.mkdir(exist_ok=True)
            (label_dir / f"{run_id}.jsonl").write_text(
                "".join(dump(label) + "\n" for label in labels), encoding="utf-8")
            run["planned_events"] = len(events)
            self.store.save("runs", run)
            engine = DetectionEngine(self.employees, self.tasks)
            executor = SandboxExecutor(self.customers)
            frozen, denied_objects = False, set()
            advisory_calls = 0
            for index, event in enumerate(events):
                if frozen or (event.parent_object_id and event.parent_object_id in denied_objects):
                    run["skipped_events"] += 1
                    if event.object_id:
                        denied_objects.add(event.object_id)
                    self.store.save("runs", run)
                    continue
                received_at = now()
                run.update(phase="detecting", current_event_type=event.event_type, phase_started_at=received_at)
                analysis = engine.analyze(event)
                semantic_analysis = None
                if not local_only and hasattr(self.analyst, "analyze_prompt") and event.event_type == "AI_PROMPT" and event.sensitivity >= 60 and event.prompt:
                    run.update(phase="semantic_review", phase_started_at=now())
                    self.store.save("runs", run)
                    semantic_analysis = self._model_call("analyze_prompt", event, analysis)
                    analysis = apply_semantic_policy(event, analysis, semantic_analysis)
                    engine.commit_analysis(event, analysis)
                task = next((task for task in self.tasks if task.id == event.task_id), None)
                quota_decision = self.quota.reserve(event, task, blocked=analysis.blocked)
                if quota_decision["already_seen"] and quota_decision["status"] in {"confirmed", "reserved"}:
                    raise ValueError("A previously allocated event must not execute again")
                analysis = apply_quota_policy(analysis, quota_decision)
                engine.commit_analysis(event, analysis)
                detected_at = now()
                # This is the execution gate. Blocked requests never reach the sink.
                outcome = "blocked" if analysis.blocked else "executed"
                try:
                    executed = executor.execute(event, analysis.blocked)
                except Exception:
                    if quota_decision["status"] == "reserved":
                        self.quota.cancel(event.event_id, reason="executor_failed")
                    raise
                if quota_decision["status"] == "reserved":
                    quota_decision = self.quota.confirm(event.event_id)
                execution_completed_at = now()
                receipt = executed["receipt"]
                if receipt is not None:
                    run["sink_records"] += len(receipt["customer_ids"])
                if analysis.blocked and event.object_id:
                    denied_objects.add(event.object_id)
                frozen = "FREEZE_SESSION" in analysis.actions
                # Advisory text cannot authorize a write or override this decision.
                if local_only:
                    ai_analysis = dict(status="skipped", reason_code="demo_local_mode",
                                       summary="引导演示采用本地规则与行为模型，未调用语言模型。",
                                       evidence_event_ids=[], suggested_actions=[], elapsed_ms=0,
                                       provider=None, model=None, usage=None)
                elif semantic_analysis is not None:
                    ai_analysis = dict(semantic_analysis, reused_semantic=True)
                elif hasattr(self.analyst, "analyze_prompt") and analysis.risk_score >= 60 and advisory_calls >= 2:
                    ai_analysis = dict(status="skipped", reason_code="run_advisory_limit",
                                       summary="本次演练已完成两次高风险附加分析；继续执行确定性防护。",
                                       evidence_event_ids=[], suggested_actions=[], elapsed_ms=0,
                                       provider="sensenova", model=self.analyst.model, usage=None)
                else:
                    if analysis.risk_score >= 60 and hasattr(self.analyst, "analyze_prompt"):
                        run.update(phase="model_explanation", phase_started_at=now())
                        self.store.save("runs", run)
                    ai_analysis = self._model_call("analyze", event, analysis)
                    if hasattr(self.analyst, "analyze_prompt") and analysis.risk_score >= 60:
                        advisory_calls += 1
                ai_completed_at = now()
                record = dict(event=event.model_dump(mode="json"), analysis=analysis.model_dump(mode="json"),
                              run_id=run_id, outcome=outcome, received_at=received_at,
                              detected_at=detected_at, responded_at=execution_completed_at,
                              execution_completed_at=execution_completed_at, ai_completed_at=ai_completed_at,
                              executed_records=executed["record_count"],
                              ai_analysis=ai_analysis, semantic_analysis=semantic_analysis,
                              quota_decision=quota_decision,
                              response_actions=[{"action": action, "status": "simulated_completed"}
                                                for action in analysis.actions])
                self.store.append_event(record, receipt)
                run["processed_events"] += 1
                run["blocked_events"] += int(analysis.blocked)
                run["max_risk"] = max(run["max_risk"], analysis.risk_score)
                self.store.save("runs", run)
                if request.interval_ms and index < len(events) - 1 and not frozen:
                    time.sleep(request.interval_ms / 1000)
            run.update(status="completed", phase="completed", finished_at=now())
        except Exception:
            logger.exception("Synthetic run failed: %s", run_id)
            run.update(status="failed", phase="failed", finished_at=now(), error="演练执行失败，请查看本机服务日志。")
        finally:
            self.store.save("runs", run)

    def execute_evaluation(self, job_id: str, seed: int, sessions: int):
        from .evaluation import run_evaluation
        job = self.store.get("evaluations", job_id)
        try:
            directory = self.store.directory / "evaluations" / job_id
            report = run_evaluation(seed, sessions, directory)
            report["id"] = job_id
            (directory / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            job.update(status="completed", report=report, finished_at=now())
        except Exception:
            logger.exception("Evaluation failed: %s", job_id)
            job.update(status="failed", error="评测运行失败，请查看本机服务日志。", finished_at=now())
        self.store.save("evaluations", job)

    def overview(self) -> dict:
        bank_timezone = timezone(timedelta(hours=8))
        today = datetime.now(bank_timezone).date()
        events = [item for item in self.store.events(limit=1000000)
                  if datetime.fromisoformat(item["detected_at"]).astimezone(bank_timezone).date() == today]
        distribution = {name: 0 for name in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
        users, hours = {}, defaultdict(lambda: {"events": 0, "risk": 0})
        for record in events:
            event, analysis = record["event"], record["analysis"]
            distribution[analysis["risk_level"]] += 1
            employee = users.setdefault(event["employee_id"], {"employee_id": event["employee_id"],
                                                              "event_count": 0, "risk_score": 0})
            employee["event_count"] += 1
            employee["risk_score"] = max(employee["risk_score"], analysis["risk_score"])
            hour = datetime.fromisoformat(record["detected_at"]).astimezone(bank_timezone).strftime("%Y-%m-%dT%H:00")
            hours[hour]["events"] += 1
            hours[hour]["risk"] = max(hours[hour]["risk"], analysis["risk_score"])
        names = {e.id: e.name for e in self.employees}
        for employee in users.values():
            employee["name"] = names.get(employee["employee_id"], employee["employee_id"])
        return dict(total_events=len(events), abnormal_events=sum(e["analysis"]["risk_score"] >= 30 for e in events),
                    high_risk_events=sum(e["analysis"]["risk_score"] >= 60 for e in events),
                    blocked_events=sum(e["outcome"] == "blocked" for e in events),
                    sensitive_records=sum(e["event"]["record_count"] for e in events if e["event"]["sensitivity"] >= 60),
                    active_runs=sum(r["status"] == "running" for r in self.store.list("runs", 1000)),
                    risk_distribution=distribution, recent_events=events[:12],
                    top_users=sorted(users.values(), key=lambda x: x["risk_score"], reverse=True)[:5],
                    trend=[dict(hour=key, **hours[key]) for key in sorted(hours)[-24:]],
                    bank=dict(self.bank_counts), synthetic=True)

    def employee_detail(self, employee_id: str) -> dict | None:
        employee = next((item for item in self.employees if item.id == employee_id), None)
        if employee is None:
            return None
        events = self.store.events(employee_id=employee_id, limit=500)
        bank_timezone = timezone(timedelta(hours=8))
        today = datetime.now(bank_timezone).date()
        start = datetime.combine(today, datetime.min.time(), tzinfo=bank_timezone)
        activity = self.store.employee_activity(employee_id, start, start + timedelta(days=1))
        return dict(employee=employee.model_dump(mode="json"),
                    tasks=[task.model_dump(mode="json") for task in self.tasks if task.employee_id == employee_id],
                    lifetime_quotas=[self.quota.summary(task, employee_id) for task in self.tasks
                                     if task.employee_id == employee_id and task.quota_scope == "task_lifetime"],
                    events=events,
                    baseline=dict(daily_records=employee.baseline_daily_records, daily_queries=employee.baseline_daily_queries),
                    current=activity,
                    latest_intent=events[0]["analysis"]["intent"] if events else None)
