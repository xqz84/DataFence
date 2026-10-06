"""Local SQLite persistence. Detector code never receives this storage object."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import threading


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(dump(value).encode("utf-8")).hexdigest()


class Store:
    def __init__(self, directory: Path):
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "datafence.sqlite3"
        self.lock = threading.RLock()
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS bank (kind TEXT, id TEXT, payload TEXT NOT NULL,
                    PRIMARY KEY(kind,id));
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT UNIQUE NOT NULL, run_id TEXT NOT NULL, employee_id TEXT NOT NULL,
                    payload TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_run ON events(run_id,seq);
                CREATE INDEX IF NOT EXISTS events_employee ON events(employee_id,seq);
                CREATE TABLE IF NOT EXISTS sinks (event_id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
                    payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS evaluations (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS idempotency (key TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL, resource_id TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=30)
            db.row_factory = sqlite3.Row
            try:
                with db:
                    yield db
            finally:
                db.close()

    def initialize_bank(self, bank: dict) -> None:
        with self.connect() as db:
            if db.execute("SELECT 1 FROM meta WHERE key='manifest'").fetchone():
                return
            for kind in ("employees", "tasks", "customers", "accounts", "transactions", "loans"):
                rows = []
                for index, item in enumerate(bank[kind]):
                    payload = item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                    rows.append((kind, str(payload.get("id", index)), dump(payload)))
                db.executemany("INSERT INTO bank(kind,id,payload) VALUES(?,?,?)", rows)
            db.execute("INSERT INTO meta(key,payload) VALUES('manifest',?)", (dump(bank["manifest"]),))

    def bank(self, kind: str) -> list[dict]:
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT payload FROM bank WHERE kind=? ORDER BY id", (kind,))]

    def bank_counts(self) -> dict:
        with self.connect() as db:
            return {row[0]: row[1] for row in db.execute("SELECT kind,COUNT(*) FROM bank GROUP BY kind")}

    def employee_activity(self, employee_id: str, start: datetime, end: datetime) -> dict:
        """Count the complete period, independently of the displayed event page.

        Project only the needed fields and iterate the cursor: full event chains
        and all matching payloads must not be materialized in Python memory.
        Python compares aware timestamps to preserve subsecond/timezone boundaries.
        """
        result = dict(records=0, queries=0, regions=0, exports=0)
        regions = set()
        with self.connect() as db:
            rows = db.execute("""SELECT json_extract(payload, '$.detected_at'),
                json_extract(payload, '$.event.event_type'),
                json_extract(payload, '$.event.record_count'),
                json_extract(payload, '$.event.regions')
                FROM events WHERE employee_id=?""", (employee_id,))
            for detected_at, event_type, count, event_regions in rows:
                if not start <= datetime.fromisoformat(detected_at) < end:
                    continue
                if event_type in {"QUERY", "API"}:
                    result["records"] += count
                    result["queries"] += 1
                result["exports"] += event_type == "EXPORT"
                regions.update(json.loads(event_regions))
        result["regions"] = len(regions)
        return result

    def manifest(self) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT payload FROM meta WHERE key='manifest'").fetchone()
            return json.loads(row[0]) if row else None

    def save(self, table: str, payload: dict) -> None:
        if table not in {"runs", "evaluations"}:
            raise ValueError("unknown store")
        with self.connect() as db:
            db.execute(f"INSERT INTO {table}(id,payload) VALUES(?,?) "
                       "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                       (payload["id"], dump(payload)))

    def get(self, table: str, resource_id: str) -> dict | None:
        if table not in {"runs", "evaluations"}:
            raise ValueError("unknown store")
        with self.connect() as db:
            row = db.execute(f"SELECT payload FROM {table} WHERE id=?", (resource_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def list(self, table: str, limit: int = 30) -> list[dict]:
        if table not in {"runs", "evaluations"}:
            raise ValueError("unknown store")
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute(
                f"SELECT payload FROM {table} ORDER BY rowid DESC LIMIT ?", (limit,))]

    def recover(self) -> None:
        for table in ("runs", "evaluations"):
            for resource in self.list(table, 100000):
                if resource["status"] == "running":
                    resource.update(status="interrupted", error="服务重启；上次未完成的作业已停止。")
                    self.save(table, resource)

    def idempotent(self, key: str, fingerprint: str) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT fingerprint,resource_id FROM idempotency WHERE key=?", (key,)).fetchone()
            if row and row[0] != fingerprint:
                raise ValueError("同一幂等键对应不同请求")
            return row[1] if row else None

    def remember(self, key: str, fingerprint: str, resource_id: str):
        with self.connect() as db:
            db.execute("INSERT INTO idempotency VALUES(?,?,?)", (key, fingerprint, resource_id))

    def append_event(self, record: dict, receipt: dict | None = None) -> dict:
        with self.connect() as db:
            existing = db.execute("SELECT payload FROM events WHERE id=?", (record["event"]["event_id"],)).fetchone()
            if existing:
                return json.loads(existing[0])
            record["receipt_hash"] = digest(receipt) if receipt is not None else None
            if receipt is not None:
                db.execute("INSERT INTO sinks VALUES(?,?,?)",
                           (record["event"]["event_id"], record["run_id"], dump(receipt)))
            record.setdefault("responded_at", now())
            record["persisted_at"] = now()
            prior = db.execute("SELECT payload FROM events WHERE run_id=? ORDER BY seq DESC LIMIT 1",
                               (record["run_id"],)).fetchone()
            record["previous_hash"] = json.loads(prior[0])["evidence_hash"] if prior else "0" * 64
            record["evidence_hash"] = digest(record)
            db.execute("INSERT INTO events(id,run_id,employee_id,payload) VALUES(?,?,?,?)",
                       (record["event"]["event_id"], record["run_id"], record["event"]["employee_id"], dump(record)))
        return record

    def events(self, run_id: str | None = None, employee_id: str | None = None,
               limit: int = 100, offset: int = 0) -> list[dict]:
        clauses, args = [], []
        if run_id:
            clauses.append("run_id=?")
            args.append(run_id)
        if employee_id:
            clauses.append("employee_id=?")
            args.append(employee_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT payload FROM events" + where + " ORDER BY seq DESC LIMIT ? OFFSET ?",
                (*args, limit, offset))]

    def event(self, event_id: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT payload FROM events WHERE id=?", (event_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def sink_receipts(self, run_id: str) -> list[dict]:
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT payload FROM sinks WHERE run_id=?", (run_id,))]

    def verify(self) -> dict:
        previous, count = {}, 0
        with self.connect() as db:
            for row in db.execute("SELECT payload FROM events ORDER BY seq"):
                item = json.loads(row[0])
                expected = item.pop("evidence_hash")
                if item["previous_hash"] != previous.get(item["run_id"], "0" * 64) or digest(item) != expected:
                    return {"valid": False, "checked_events": count, "broken_event": item["event"]["event_id"]}
                receipt = db.execute("SELECT payload FROM sinks WHERE event_id=?", (item["event"]["event_id"],)).fetchone()
                receipt_hash = digest(json.loads(receipt[0])) if receipt else None
                if receipt_hash != item.get("receipt_hash"):
                    return {"valid": False, "checked_events": count, "broken_event": item["event"]["event_id"]}
                previous[item["run_id"]] = expected
                count += 1
        return {"valid": True, "checked_events": count, "broken_event": None}
