"""Persistent demo orchestration and append-only human findings, not authority grants."""

import json
from uuid import UUID, uuid4
from typing import Literal

from pydantic import Field, field_validator

from .models import Contract, SimulationRequest, SecurityEvent, Analysis
from .knowledge import build_knowledge_context
from .storage import digest, dump, now


class ReviewRequest(Contract):
    request_id: UUID
    expected_revision: int = Field(ge=0)
    disposition: Literal["confirmed_risk", "false_positive", "needs_investigation"]
    note: str = Field(min_length=1, max_length=1000)

    @field_validator("note")
    @classmethod
    def meaningful_note(cls, value):
        if not value.strip():
            raise ValueError("研判说明不能为空")
        return value.strip()


class DemoRequest(Contract):
    request_id: UUID
    employee_id: str = Field(default="E0038", min_length=1, max_length=40)


class DemoConfirmRequest(Contract):
    review_revision: int = Field(ge=1)


class WorkflowError(ValueError):
    pass


class WorkflowStore:
    def __init__(self, store):
        self.store = store
        with store.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS demos (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS case_reviews (event_id TEXT, revision INTEGER,
                    payload TEXT NOT NULL, PRIMARY KEY(event_id, revision));
                CREATE TABLE IF NOT EXISTS workflow_requests (key TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL, resource_id TEXT NOT NULL);
            """)
            for row in db.execute("SELECT id,payload FROM demos").fetchall():
                demo = json.loads(row[1])
                if demo["status"] == "running":
                    demo.update(status="interrupted", finished_at=now(), error="服务重启中断演示；已完成证据保留，未自动重跑。")
                    for step in demo["steps"]:
                        if step["status"] in {"queued", "running"}:
                            step["status"] = "interrupted"
                    db.execute("UPDATE demos SET payload=? WHERE id=?", (dump(demo), row[0]))

    @staticmethod
    def _prior(db, key, fingerprint):
        row = db.execute("SELECT fingerprint,resource_id FROM workflow_requests WHERE key=?", (key,)).fetchone()
        if row and row[0] != fingerprint:
            raise WorkflowError("同一请求编号对应不同内容，请刷新并重新提交")
        return row[1] if row else None

    @staticmethod
    def _review(db, event_id):
        history = [json.loads(row[0]) for row in db.execute(
            "SELECT payload FROM case_reviews WHERE event_id=? ORDER BY revision", (event_id,))]
        return dict(event_id=event_id, revision=len(history), current=history[-1] if history else None, history=history)

    def review(self, event_id):
        with self.store.connect() as db:
            return self._review(db, event_id)

    def append_review(self, record, request: ReviewRequest, actor, *, authorize=None):
        event_id = record["event"]["event_id"]
        fingerprint = digest(dict(event_id=event_id, **request.model_dump(mode="json")))
        key = "review:" + actor + ":" + str(request.request_id)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if authorize:
                authorize()
            prior = self._prior(db, key, fingerprint)
            result = self._review(db, event_id)
            if prior:
                return result
            if result["revision"] != request.expected_revision:
                raise WorkflowError("事件研判已更新，请刷新后核对新结论")
            item = dict(event_id=event_id, revision=result["revision"] + 1,
                        disposition=request.disposition, note=request.note, actor=actor, created_at=now(),
                        event_evidence_hash=record["evidence_hash"],
                        reference_knowledge=build_knowledge_context(SecurityEvent.model_validate(record["event"]),
                                                                   Analysis.model_validate(record["analysis"])),
                        previous_hash=result["current"]["hash"] if result["current"] else "0" * 64)
            item["hash"] = digest(item)
            if authorize:
                authorize()
            db.execute("INSERT INTO case_reviews VALUES(?,?,?)", (event_id, item["revision"], dump(item)))
            db.execute("INSERT INTO workflow_requests VALUES(?,?,?)", (key, fingerprint, event_id))
            return self._review(db, event_id)

    def verify_reviews(self):
        count, previous, revisions = 0, {}, {}
        try:
            with self.store.connect() as db:
                for row in db.execute("SELECT event_id,revision,payload FROM case_reviews ORDER BY event_id,revision"):
                    item = json.loads(row[2])
                    stored_hash = item.pop("hash")
                    event_id = row[0]
                    event = db.execute("SELECT payload FROM events WHERE id=?", (event_id,)).fetchone()
                    if (not event or item["event_id"] != event_id or item["revision"] != row[1]
                            or row[1] != revisions.get(event_id, 0) + 1
                            or item["previous_hash"] != previous.get(event_id, "0" * 64)
                            or digest(item) != stored_hash
                            or json.loads(event[0])["evidence_hash"] != item["event_evidence_hash"]):
                        return dict(valid=False, checked_reviews=count)
                    previous[event_id], revisions[event_id] = stored_hash, row[1]
                    count += 1
        except (ValueError, KeyError, TypeError):
            return dict(valid=False, checked_reviews=count)
        return dict(valid=True, checked_reviews=count)

    def demos(self):
        with self.store.connect() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT payload FROM demos ORDER BY rowid DESC LIMIT 30")]

    def demo(self, demo_id):
        with self.store.connect() as db:
            row = db.execute("SELECT payload FROM demos WHERE id=?", (demo_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def save_demo(self, demo):
        with self.store.connect() as db:
            db.execute("UPDATE demos SET payload=? WHERE id=?", (dump(demo), demo["id"]))

    def create_demo(self, service, request: DemoRequest, actor, *, authorize=None):
        fingerprint = digest(request.model_dump(mode="json"))
        key = "demo:" + actor + ":" + str(request.request_id)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if authorize:
                authorize()
            prior = self._prior(db, key, fingerprint)
            if prior:
                row = db.execute("SELECT payload FROM demos WHERE id=?", (prior,)).fetchone()
                return json.loads(row[0]), False
            if db.execute("SELECT 1 FROM runs WHERE json_extract(payload,'$.status')='running' LIMIT 1").fetchone():
                raise WorkflowError("请等待当前演练结束后启动完整演示")
            size = min(2000, len(service.customer_ids))
            steps = []
            for scenario, title in (("normal", "正常业务放行"), ("approved_batch", "已审批批量交付"), ("combined", "异常访问提前阻断")):
                payload = SimulationRequest(scenario_id=scenario, employee_id=request.employee_id,
                                            record_count=min(10, size) if scenario == "normal" else size,
                                            seed=42, interval_ms=0)
                run = service.prepare_run(payload)
                db.execute("INSERT INTO runs VALUES(?,?)", (run["id"], dump(run)))
                steps.append(dict(id=scenario, title=title, status="queued", run_id=run["id"],
                                  passed=None, summary="等待执行", blocked_events=0, processed_events=0,
                                  skipped_events=0, sink_records=0, request=payload.model_dump(mode="json")))
            demo = dict(id=str(uuid4()), status="running", created_at=now(), finished_at=None, actor=actor,
                        employee_id=request.employee_id, mode="local", steps=steps, selected_event_id=None,
                        checks=[], audit=None, review_revision=None, error=None)
            if authorize:
                authorize()
            db.execute("INSERT INTO demos VALUES(?,?)", (demo["id"], dump(demo)))
            db.execute("INSERT INTO workflow_requests VALUES(?,?,?)", (key, fingerprint, demo["id"]))
            return demo, True

    def confirm(self, demo_id, revision, actor, *, authorize=None):
        audit = self.store.verify()
        review_audit = self.verify_reviews()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if authorize:
                authorize()
            row = db.execute("SELECT payload FROM demos WHERE id=?", (demo_id,)).fetchone()
            if not row:
                raise WorkflowError("演示不存在")
            demo = json.loads(row[0])
            review = self._review(db, demo["selected_event_id"])
            if (not audit["valid"] or not review_audit["valid"] or review["revision"] != revision
                    or not review["current"] or review["current"]["disposition"] == "needs_investigation"):
                raise WorkflowError("请先完成最新版本的人工研判，并确保原始证据与研判记录校验通过")
            if demo["status"] == "completed" and demo["review_revision"] == revision:
                return demo
            if demo["status"] != "awaiting_review" or not demo["checks"] or not all(c["passed"] for c in demo["checks"]):
                raise WorkflowError("演示尚未通过自动验证，不能确认完成")
            demo.update(status="completed", finished_at=now(), review_revision=revision,
                        confirmed_by=actor, audit=audit, review_audit=review_audit)
            if authorize:
                authorize()
            db.execute("UPDATE demos SET payload=? WHERE id=?", (dump(demo), demo_id))
            return demo


def execute_demo(service, workflows, demo_id):
    demo = workflows.demo(demo_id)
    if not demo or demo["status"] != "running":
        return
    try:
        for step in demo["steps"]:
            step.update(status="running", summary="正在执行真实沙盒请求")
            workflows.save_demo(demo)
            request = SimulationRequest.model_validate(step["request"])
            service.execute_run(step["run_id"], request, local_only=True)
            run = service.store.get("runs", step["run_id"])
            records = service.store.events(run_id=run["id"], limit=500)
            receipts = service.store.sink_receipts(run["id"])
            step.update({key: run[key] for key in ("blocked_events", "processed_events", "skipped_events", "sink_records")})
            complete = run["status"] == "completed" and run["processed_events"] + run["skipped_events"] == run["planned_events"]
            if step["id"] == "normal":
                passed = complete and run["blocked_events"] == 0 and any(
                    r["event"]["event_type"] == "QUERY" and r["executed_records"] > 0 for r in records)
            elif step["id"] == "approved_batch":
                passed = complete and run["blocked_events"] == 0 and run["sink_records"] == request.record_count and bool(receipts) and all(
                    r["channel"] == "approved_partner" for r in receipts)
            else:
                passed = complete and run["blocked_events"] > 0 and run["sink_records"] == 0 and not receipts
                if records:
                    demo["selected_event_id"] = max(records, key=lambda r: r["analysis"]["risk_score"])["event"]["event_id"]
            step.update(status="completed" if complete else "failed", passed=passed,
                        summary=f"已检测 {run['processed_events']} 步，阻断 {run['blocked_events']} 步，依赖跳过 {run['skipped_events']} 步；查询实际返回 {sum(r['executed_records'] for r in records if r['event']['event_type'] in {'QUERY', 'API'})} 条，接收端收到 {run['sink_records']} 条")
            demo["checks"].append(dict(id=step["id"], title=step["title"], passed=passed, detail=step["summary"]))
            workflows.save_demo(demo)
            if not passed:
                for pending in demo["steps"]:
                    if pending["status"] == "queued":
                        pending.update(status="interrupted", summary="前序步骤未通过，后续未执行")
                        pending_run = service.store.get("runs", pending["run_id"])
                        pending_run.update(status="interrupted", phase="interrupted", finished_at=now(),
                                           error="完整演示的前序步骤未通过，未执行此步骤。")
                        service.store.save("runs", pending_run)
                break
        demo["audit"] = service.store.verify()
        demo["checks"].append(dict(id="evidence", title="原始证据与接收回执一致", passed=demo["audit"]["valid"],
                                   detail=f"已校验 {demo['audit']['checked_events']} 条留存事件"))
        if all(c["passed"] for c in demo["checks"]) and demo["selected_event_id"]:
            demo["status"] = "awaiting_review"
        else:
            demo.update(status="failed", finished_at=now(), error="实际执行未通过全部演示验证，请查看各步骤证据。")
    except Exception:
        demo.update(status="failed", finished_at=now(), error="演示执行失败；已完成记录保留，请检查本机服务日志。")
        for step in demo["steps"]:
            if step["status"] in {"queued", "running"}:
                step.update(status="interrupted", summary="执行中断，未补造结果")
                run = service.store.get("runs", step["run_id"])
                if run and run["status"] == "running":
                    run.update(status="interrupted", finished_at=now(), error=demo["error"])
                    service.store.save("runs", run)
    finally:
        workflows.save_demo(demo)
