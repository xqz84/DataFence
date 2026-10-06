"""Durable quotas for accepted synthetic QUERY/API request records.

Reserved and confirmed records both consume capacity. Reservations survive a
crash conservatively; only explicit cancellation can release an unconfirmed one.
No unique-customer or actually-returned-record interpretation is implied.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

from .models import BusinessTask, SecurityEvent


METRIC = "accepted_request_records"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(event: SecurityEvent, task: BusinessTask) -> str:
    payload = {"event": event.model_dump(mode="json"), "task_id": task.id,
               "task_employee_id": task.employee_id, "quota_scope": task.quota_scope,
               "max_records": task.max_records}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class QuotaLedger:
    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS quota_reservations (
                    event_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    employee_id TEXT NOT NULL,
                    scope TEXT NOT NULL CHECK(scope IN ('session','task_lifetime')),
                    bucket_session TEXT NOT NULL,
                    source_session_id TEXT NOT NULL,
                    requested_records INTEGER NOT NULL CHECK(requested_records >= 0),
                    limit_snapshot INTEGER NOT NULL CHECK(limit_snapshot >= 0),
                    state TEXT NOT NULL CHECK(state IN ('reserved','confirmed','cancelled','rejected')),
                    fingerprint TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS quota_usage ON quota_reservations
                    (task_id,employee_id,scope,bucket_session,state);
            """)

    @contextmanager
    def _transaction(self):
        with self._lock:
            db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            db.row_factory = sqlite3.Row
            try:
                # The capacity check and reservation insert share one writer lock.
                # This also serializes independent Ledger instances/processes.
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            finally:
                db.close()

    @staticmethod
    def _usage(db, task_id, employee_id, scope, bucket_session) -> tuple[int, int]:
        rows = db.execute("""SELECT state,COALESCE(SUM(requested_records),0)
                             FROM quota_reservations
                             WHERE task_id=? AND employee_id=? AND scope=? AND bucket_session=?
                               AND state IN ('reserved','confirmed') GROUP BY state""",
                          (task_id, employee_id, scope, bucket_session)).fetchall()
        counts = {row[0]: row[1] for row in rows}
        return counts.get("reserved", 0), counts.get("confirmed", 0)

    def _decision(self, db, row, *, already_seen=False) -> dict:
        reserved, confirmed = self._usage(db, row["task_id"], row["employee_id"], row["scope"], row["bucket_session"])
        used = reserved + confirmed
        return {"allowed": row["state"] in {"reserved", "confirmed"}, "applicable": True,
                "status": row["state"], "reservation_id": row["event_id"], "already_seen": already_seen,
                "event_id": row["event_id"], "task_id": row["task_id"], "employee_id": row["employee_id"],
                "scope": row["scope"], "metric": METRIC, "requested_records": row["requested_records"],
                "limit": row["limit_snapshot"], "reserved_records": reserved, "confirmed_records": confirmed,
                "used_records": used, "remaining_records": max(0, row["limit_snapshot"] - used),
                "reason": row["reason"]}

    @staticmethod
    def _skip(event: SecurityEvent, reason: str, allowed: bool = True) -> dict:
        return {"allowed": allowed, "applicable": False, "status": "not_applicable", "reservation_id": None,
                "already_seen": False, "event_id": event.event_id, "task_id": event.task_id,
                "employee_id": event.employee_id, "scope": None, "metric": METRIC,
                "requested_records": event.record_count, "limit": None, "reserved_records": None,
                "confirmed_records": None, "used_records": None, "remaining_records": None, "reason": reason}

    def reserve(self, event: SecurityEvent, task: BusinessTask | None, blocked: bool = False) -> dict:
        """Pre-execution capacity reservation; caller must honor allowed=False.

        A previously confirmed event is a duplicate, not permission to execute the
        operation twice. The caller must inspect already_seen/status accordingly.
        """
        if not isinstance(event, SecurityEvent) or type(blocked) is not bool:
            raise ValueError("quota reservation requires a validated event and block flag")
        if event.event_type not in {"QUERY", "API"}:
            return self._skip(event, "non_read_operation", allowed=not blocked)
        if task is None:
            return self._skip(event, "no_verified_business_task", allowed=not blocked)
        if not isinstance(task, BusinessTask) or task.id != event.task_id or task.employee_id != event.employee_id:
            return self._skip(event, "business_task_binding_mismatch", allowed=False)
        if type(task.max_records) is not int or task.max_records < 0:
            raise ValueError("quota limit must be a nonnegative integer")
        fingerprint = _fingerprint(event, task)
        bucket = event.session_id if task.quota_scope == "session" else ""
        with self._transaction() as db:
            previous = db.execute("SELECT * FROM quota_reservations WHERE event_id=?", (event.event_id,)).fetchone()
            if previous is not None:
                if previous["fingerprint"] != fingerprint:
                    raise ValueError("event_id was already used for a different quota request")
                if blocked:
                    if previous["state"] == "confirmed":
                        raise ValueError("a confirmed accepted event cannot retroactively become blocked")
                    if previous["state"] == "reserved":
                        db.execute("UPDATE quota_reservations SET state='cancelled',reason='policy_blocked',updated_at=? WHERE event_id=?",
                                   (_now(), event.event_id))
                        previous = db.execute("SELECT * FROM quota_reservations WHERE event_id=?", (event.event_id,)).fetchone()
                return self._decision(db, previous, already_seen=True)
            if blocked:
                return self._skip(event, "policy_blocked", allowed=False)
            reserved, confirmed = self._usage(db, task.id, event.employee_id, task.quota_scope, bucket)
            allowed = reserved + confirmed + event.record_count <= task.max_records
            state, reason = ("reserved", "capacity_reserved") if allowed else ("rejected", "quota_exceeded")
            timestamp = _now()
            db.execute("""INSERT INTO quota_reservations
                          (event_id,task_id,employee_id,scope,bucket_session,source_session_id,requested_records,
                           limit_snapshot,state,fingerprint,reason,created_at,updated_at)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (event.event_id, task.id, event.employee_id, task.quota_scope, bucket, event.session_id,
                        event.record_count, task.max_records, state, fingerprint, reason, timestamp, timestamp))
            row = db.execute("SELECT * FROM quota_reservations WHERE event_id=?", (event.event_id,)).fetchone()
            return self._decision(db, row)

    def confirm(self, event_id: str) -> dict:
        """Confirm a successfully accepted read; repeated confirmation is a no-op."""
        with self._transaction() as db:
            row = db.execute("SELECT * FROM quota_reservations WHERE event_id=?", (event_id,)).fetchone()
            if row is None:
                raise ValueError("quota reservation does not exist")
            previous_state = row["state"]
            if previous_state not in {"reserved", "confirmed"}:
                raise ValueError("only a reserved or confirmed event can be confirmed")
            if previous_state == "reserved":
                db.execute("UPDATE quota_reservations SET state='confirmed',reason='accepted_request',updated_at=? WHERE event_id=?",
                           (_now(), event_id))
                row = db.execute("SELECT * FROM quota_reservations WHERE event_id=?", (event_id,)).fetchone()
            return self._decision(db, row, already_seen=previous_state == "confirmed")

    def cancel(self, event_id: str, reason: str = "execution_failed") -> dict:
        """Release only an unconfirmed reservation; confirmed consumption is final."""
        if not isinstance(reason, str) or not reason or len(reason) > 200:
            raise ValueError("cancellation requires a short reason")
        with self._transaction() as db:
            row = db.execute("SELECT * FROM quota_reservations WHERE event_id=?", (event_id,)).fetchone()
            if row is None:
                raise ValueError("quota reservation does not exist")
            previous_state = row["state"]
            if previous_state == "confirmed":
                raise ValueError("confirmed accepted records cannot be cancelled")
            if previous_state == "reserved":
                db.execute("UPDATE quota_reservations SET state='cancelled',reason=?,updated_at=? WHERE event_id=?",
                           (reason, _now(), event_id))
                row = db.execute("SELECT * FROM quota_reservations WHERE event_id=?", (event_id,)).fetchone()
            return self._decision(db, row, already_seen=previous_state != "reserved")

    def summary(self, task: BusinessTask, employee_id: str, session_id: str = "") -> dict:
        if not isinstance(task, BusinessTask) or employee_id != task.employee_id:
            raise ValueError("quota summary requires the task's assigned employee")
        if task.quota_scope == "session" and not session_id:
            raise ValueError("session-scoped quota requires a session identifier")
        bucket = session_id if task.quota_scope == "session" else ""
        with self._transaction() as db:
            reserved, confirmed = self._usage(db, task.id, employee_id, task.quota_scope, bucket)
        return {"task_id": task.id, "employee_id": employee_id, "scope": task.quota_scope, "metric": METRIC,
                "limit": task.max_records, "reserved_records": reserved, "confirmed_records": confirmed,
                "used_records": reserved + confirmed, "remaining_records": max(0, task.max_records - reserved - confirmed)}


def demo(database: Path) -> dict:
    """Standalone synthetic task; does not change the application's task bank."""
    from uuid import uuid4
    from .sandbox import BANK_TZ

    task_id = "QUOTA-DEMO-" + uuid4().hex
    task = BusinessTask(id=task_id, employee_id="E0038", purpose="跨会话额度验证",
                        regions=["合成区域01"], max_records=12, quota_scope="task_lifetime",
                        valid_from=datetime(2026, 1, 1, tzinfo=BANK_TZ), valid_until=datetime(2026, 12, 31, tzinfo=BANK_TZ),
                        allowed_hours=list(range(24)))
    ledger = QuotaLedger(database)
    results = []
    for index in range(2):
        event = SecurityEvent(event_id=uuid4().hex, session_id=uuid4().hex, employee_id=task.employee_id,
                              timestamp=datetime(2026, 9, 19, 10, index, tzinfo=BANK_TZ), event_type="QUERY",
                              task_id=task.id, purpose=task.purpose, record_count=8, regions=task.regions)
        result = ledger.reserve(event, task)
        if result["allowed"]:
            result = ledger.confirm(event.event_id)
        results.append(result)
    return {"synthetic": True, "task": task.model_dump(mode="json"), "decisions": results,
            "summary": ledger.summary(task, task.employee_id)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo-database", type=Path, required=True)
    arguments = parser.parse_args()
    # ASCII JSON remains lossless under Windows terminals with a legacy code page.
    print(json.dumps(demo(arguments.demo_database), ensure_ascii=True, indent=2))
