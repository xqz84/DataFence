"""Actual, authenticated synthetic-row delivery behind deterministic policy gates.

No external destinations, caller-provided SQL, sensitivity, identity or model text.
Gateway quotas are explicitly lifetime-wide and independent from scenario demos.
"""

from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import threading
from typing import Callable, Literal
from uuid import UUID, uuid5, NAMESPACE_URL

from pydantic import Field

from .engine import DetectionEngine
from .models import Contract, SecurityEvent, Analysis
from .quota import QuotaLedger
from .quota_policy import apply_quota_policy
from .sandbox import BANK_TZ
from .storage import digest, dump, now


class AccessRequest(Contract):
    request_id: UUID
    task_id: str = Field(min_length=1, max_length=40)
    operation: Literal["query", "export"] = "query"
    record_count: int = Field(ge=1, le=5000)
    regions: list[str] = Field(min_length=1, max_length=32)


class GatewayError(ValueError):
    pass


class AccessGateway:
    def __init__(self, directory: Path, employees, tasks, customers):
        self.path = directory / "gateway.sqlite3"
        self.lock = threading.Lock()
        self.employees = employees
        # Explicitly stronger accounting for this data-delivery interface.
        self.tasks = [task.model_copy(update={"quota_scope": "task_lifetime"}) for task in tasks]
        self.customers = {row["id"]: row for row in customers}
        if any(row.get("synthetic") is not True or not row["id"].startswith("SYN-") for row in customers):
            raise ValueError("Gateway only accepts synthetic bank rows")
        self.quota = QuotaLedger(directory / "gateway-quota.sqlite3")
        with self.connect() as db:
            db.executescript("""PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS deliveries(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL, request_id TEXT NOT NULL, task_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(actor,request_id));
                CREATE INDEX IF NOT EXISTS delivery_task ON deliveries(actor,task_id,seq);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _actor_id(actor):
        value = actor.get("id") or actor.get("username")
        if not isinstance(value, str) or not value:
            raise GatewayError("insufficient_role")
        return value

    def _visible_tasks(self, actor):
        if actor is None:
            return self.tasks
        if actor.get("enabled") is False or actor.get("role") not in {"admin", "analyst", "viewer", "business"}:
            raise GatewayError("insufficient_role")
        if actor["role"] != "business":
            return self.tasks
        self._actor_id(actor)
        binding = actor.get("employee_id")
        if not binding or not any(employee.id == binding for employee in self.employees):
            raise GatewayError("employee_binding_required")
        return [task for task in self.tasks if task.employee_id == binding]

    def available_tasks(self, actor=None):
        return [dict(task.model_dump(mode="json"), quota=self.quota.summary(task, task.employee_id))
                for task in self._visible_tasks(actor)]

    def _history_scope(self, actor):
        visible = self._visible_tasks(actor)
        if actor is None or actor["role"] != "business":
            return "1=1", []
        if not visible:
            return "0=1", []
        # Filter before loading payloads/limiting results: two accounts bound to
        # the same employee still cannot inspect one another's operations.
        placeholders = ",".join("?" for _ in visible)
        return f"actor=? AND task_id IN ({placeholders})", [self._actor_id(actor), *(task.id for task in visible)]

    @staticmethod
    def _metadata(record):
        return {key: value for key, value in record.items()
                if key not in {"customer_ids", "events", "rows", "csv"}}

    def recent(self, actor=None):
        scope, parameters = self._history_scope(actor)
        with self.connect() as db:
            rows = [json.loads(row[0]) for row in db.execute(
                f"SELECT payload FROM deliveries WHERE {scope} ORDER BY seq DESC LIMIT 100", parameters)]
        return [self._metadata(row) for row in rows]

    def operation(self, request_id, actor):
        """Read an existing decision without replaying delivery or consuming quota."""
        scope, parameters = self._history_scope(actor)
        with self.connect() as db:
            rows = db.execute(f"SELECT payload FROM deliveries WHERE request_id=? AND ({scope}) ORDER BY seq DESC LIMIT 2",
                              [str(request_id), *parameters]).fetchall()
        if len(rows) > 1:
            # Request IDs are unique per actor. Never pick a different actor's
            # decision silently if a privileged lookup encounters a collision.
            raise GatewayError("ambiguous_request_id")
        return self._metadata(json.loads(rows[0][0])) if rows else None

    def _authorize_task(self, actor, task):
        if actor.get("enabled") is False or actor.get("role") not in {"admin", "analyst", "business"}:
            raise GatewayError("insufficient_role")
        self._actor_id(actor)
        if actor["role"] == "business":
            if not actor.get("employee_id"):
                raise GatewayError("employee_binding_required")
            if actor["employee_id"] != task.employee_id:
                raise GatewayError("employee_scope_denied")

    @staticmethod
    def _verify_evidence(db):
        prior, count = "0" * 64, 0
        try:
            for row in db.execute("SELECT payload FROM deliveries ORDER BY seq"):
                record = json.loads(row[0])
                expected = record.pop("evidence_hash")
                if record.get("previous_hash") != prior or digest(record) != expected:
                    return dict(valid=False, checked_operations=count)
                prior, count = expected, count + 1
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            # Missing fields/invalid JSON are failed evidence, not a successful
            # empty audit and not an unhandled exception from the verify route.
            return dict(valid=False, checked_operations=count)
        return dict(valid=True, checked_operations=count)

    def verify(self):
        with self.connect() as db:
            return self._verify_evidence(db)

    @staticmethod
    def _grant_allows(request, task, timestamp):
        return (task.valid_from <= timestamp <= task.valid_until
                and timestamp.astimezone(BANK_TZ).hour in task.allowed_hours
                and set(request.regions) <= set(task.regions)
                and (request.operation != "export" or task.allow_export))

    def execute(self, request: AccessRequest, actor: dict, at: datetime | None = None,
                *, authorize: Callable[[], dict | None] | None = None):
        if actor.get("role") not in {"admin", "analyst", "business"}:
            raise GatewayError("insufficient_role")
        actor_id = self._actor_id(actor)
        task = next((t for t in self.tasks if t.id == request.task_id), None)
        if task is None:
            raise GatewayError("unknown_task")
        self._authorize_task(actor, task)

        def authorize_current():
            if authorize is not None:
                current = authorize()
                # Legacy internal callers may use a raising-only callback. HTTP
                # supplies the current principal so rebinding/demotion cannot
                # retain the old actor's employee grant while waiting for locks.
                if current is not None:
                    if not isinstance(current, dict) or self._actor_id(current) != actor_id:
                        raise GatewayError("insufficient_role")
                    self._authorize_task(current, task)
        employee = next(e for e in self.employees if e.id == task.employee_id)
        fingerprint = digest(request.model_dump(mode="json"))
        session_id = hashlib.sha256(f"gateway:{actor_id}:{task.id}".encode()).hexdigest()
        event_id = str(uuid5(NAMESPACE_URL, f"gateway:{actor_id}:{request.request_id}"))
        with self.lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if authorize is not None:
                # API supplies a live session check, not a captured actor dict.
                # Revocation during queue/SQLite-lock waiting takes effect here.
                authorize_current()
            # Queue/database-lock wait is not an authorization lease. The
            # optional clock override is solely for deterministic offline tests.
            timestamp = at or datetime.now(timezone.utc)
            grant_ok = self._grant_allows(request, task, timestamp)
            # Every delivery depends on persisted history, not only a replay.
            # Check before interpreting that history or reserving new capacity.
            if not self._verify_evidence(db)["valid"]:
                raise GatewayError("invalid_evidence")
            prior = db.execute("SELECT fingerprint,payload FROM deliveries WHERE actor=? AND request_id=?",
                               (actor_id, str(request.request_id))).fetchone()
            history = db.execute("SELECT payload FROM deliveries WHERE actor=? AND task_id=? ORDER BY seq",
                                 (actor_id, task.id)).fetchall()
            try:
                saved_history = [json.loads(row[0]) for row in history]
                frozen = any("FREEZE_SESSION" in saved["analysis"]["actions"]
                             for record in saved_history for saved in record["events"])
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
                raise GatewayError("invalid_evidence") from None
            if prior:
                if prior[0] != fingerprint:
                    raise GatewayError("idempotency_conflict")
                # A replay delivers data again, so current authorization must
                # still pass after the evidence check shared with new requests.
                result = json.loads(prior[1])
                if result["allowed"] and not grant_ok:
                    raise GatewayError("grant_expired_or_changed")
                if result["allowed"] and frozen:
                    raise GatewayError("session_frozen")
                if authorize is not None:
                    authorize_current()
                if result["allowed"] and not self._grant_allows(request, task, at or datetime.now(timezone.utc)):
                    raise GatewayError("grant_expired_or_changed")
                return self._delivery(result, replayed=True)
            if len(history) >= 500:
                raise GatewayError("task_operation_limit")
            engine = DetectionEngine(self.employees, self.tasks)
            for record in saved_history:
                for saved in record["events"]:
                    event = SecurityEvent.model_validate(saved["event"])
                    engine.analyze(event)
                    final = Analysis.model_validate(saved["analysis"])
                    engine.commit_analysis(event, final)
                    frozen = frozen or "FREEZE_SESSION" in final.actions
            read = SecurityEvent(event_id=event_id, session_id=session_id, employee_id=employee.id,
                                 timestamp=timestamp, event_type="QUERY", task_id=task.id, purpose=task.purpose,
                                 resource="customers", record_count=request.record_count, regions=request.regions,
                                 device_id=employee.known_device, sensitivity=85, channel="internal", object_id=event_id)
            read_analysis = engine.analyze(read)
            events = [(read, read_analysis)]
            if request.operation == "export":
                export = read.model_copy(update={"event_id": str(uuid5(NAMESPACE_URL, event_id + ":export")),
                                                 "event_type": "EXPORT", "parent_object_id": event_id,
                                                 "object_id": str(uuid5(NAMESPACE_URL, event_id + ":csv"))})
                events.append((export, engine.analyze(export)))
            # History replay/model work can also cross the grant's deadline.
            if authorize is not None:
                authorize_current()
            grant_ok = grant_ok and self._grant_allows(request, task, at or datetime.now(timezone.utc))
            blocked = not grant_ok or frozen or any(analysis.blocked for _,analysis in events)
            try:
                quota = self.quota.reserve(read, task, blocked=blocked)
            except ValueError as error:
                # The stable request ID can already own quota when a crash or
                # receipt write failure prevented its delivery record. A later
                # HTTP retry has a new timestamp, hence a different quota
                # fingerprint. Translate only this ledger's exact conflict;
                # unrelated validation/storage failures must remain visible.
                if type(error) is ValueError and str(error) == "event_id was already used for a different quota request":
                    raise GatewayError("unresolved_reservation") from None
                raise
            # A gate-level refusal is not a quota denial. Preserve that reason
            # explicitly instead of interpreting not_applicable as exhausted.
            final = (apply_quota_policy(events[-1][1], quota) if quota["applicable"]
                     else events[-1][1].model_copy(deep=True))
            blocked = blocked or not quota["allowed"] or final.blocked
            if quota["already_seen"]:
                # Missing delivery receipt + existing reservation is an unresolved
                # crash window. Never repeat/implicitly refund such an operation.
                raise GatewayError("unresolved_reservation")
            if not grant_ok or frozen:
                final = final.model_copy(deep=True)
                final.blocked = True
                final.risk_score = max(final.risk_score, 72)
                final.risk_level = "CRITICAL" if final.risk_score >= 90 else "HIGH"
                final.dimensions["P"] = 100.0
                reasons = []
                if not grant_ok:
                    final.rules.append("GATEWAY_GRANT_DENIED")
                    reasons.append("工单有效期、时间、范围或导出权限不满足")
                if frozen:
                    final.rules.append("GATEWAY_SESSION_FROZEN")
                    reasons.append("该操作员的工单会话已有持久化冻结决定")
                final.rules = list(dict.fromkeys(final.rules))
                final.actions = list(dict.fromkeys([
                    "BLOCK_EXPORT" if request.operation == "export" else "BLOCK_READ",
                    *[action for action in final.actions if action not in {"ALLOW", "WARN"}],
                    *( ["FREEZE_SESSION"] if frozen else []), "PRESERVE_EVIDENCE"]))
                final.analysis_source += "+gateway_policy"
                final.explanation += (f" 受控数据入口拒绝：{'；'.join(reasons)}。"
                                      f"确定性入口策略风险下限72；最终风险{final.risk_score:.2f}/100，未交付数据。")
                for node in final.chain:
                    if node.get("event_id") == final.event_id:
                        node.update(risk_score=final.risk_score, blocked=True)
            events[-1] = (events[-1][0], final)
            if quota["status"] == "reserved":
                # Conservative accounting survives any later audit-write error.
                quota = self.quota.confirm(read.event_id)
            # Linearize this delivery's authorization immediately before its
            # audit decision. A rejection rolls back this delivery transaction;
            # any already confirmed quota stays unresolved/conservative. Never
            # persist an allowed delivery and then change it to a 401/403 after
            # commit. Later revocation cannot recall an approved in-flight reply.
            if authorize is not None:
                authorize_current()
            if not blocked and not self._grant_allows(request, task, at or datetime.now(timezone.utc)):
                raise GatewayError("grant_expired_or_changed")
            ids = [] if blocked else [key for key,row in self.customers.items() if row["region"] in set(request.regions)][:request.record_count]
            last = db.execute("SELECT payload FROM deliveries ORDER BY seq DESC LIMIT 1").fetchone()
            result = dict(request_id=str(request.request_id), actor=actor["username"], task_id=task.id,
                          employee_id=task.employee_id,
                          operation=request.operation, allowed=not blocked, delivered_records=len(ids),
                          requested_records=request.record_count, customer_ids=ids, synthetic=True,
                          created_at=now(), analysis=final.model_dump(mode="json"), quota=quota,
                          events=[dict(event=e.model_dump(mode="json"),analysis=a.model_dump(mode="json")) for e,a in events],
                          previous_hash=json.loads(last[0])["evidence_hash"] if last else "0" * 64,
                          cloud_called=False, policy_version="synthetic-access-gateway-v1")
            result["evidence_hash"] = digest(result)
            db.execute("INSERT INTO deliveries(actor,request_id,task_id,fingerprint,payload) VALUES(?,?,?,?,?)",
                       (actor_id,str(request.request_id),task.id,fingerprint,dump(result)))
        return self._delivery(result, replayed=False)

    def _delivery(self, record, replayed):
        result = {k:v for k,v in record.items() if k not in {"customer_ids", "events"}}
        result["replayed"] = replayed
        result["rows"] = [self.customers[key] for key in record["customer_ids"]] if record["allowed"] else []
        if record["allowed"] and record["operation"] == "export":
            stream = io.StringIO(newline="")
            writer = csv.DictWriter(stream,fieldnames=["id","name","contact","identity_ref","region","employee_id","synthetic"])
            writer.writeheader()
            for row in result["rows"]:
                writer.writerow({k: ("'" + v if isinstance(v,str) and v.startswith(("=","+","-","@","\t","\r")) else v)
                                 for k,v in row.items()})
            result["csv"] = stream.getvalue()
        return result
