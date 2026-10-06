"""Bounded synthetic log observation. No execution, quota changes or cloud calls."""

import csv
from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import threading
from typing import Literal
from uuid import uuid4

from pydantic import Field, ValidationError

from .engine import DetectionEngine
from .models import Contract, SecurityEvent
from .storage import dump, now

MAX_ROWS = 2000
MAX_BYTES = 1024 * 1024


class ImportRequest(Contract):
    source_name: str = Field(min_length=1, max_length=100, pattern=r"^[\w .\-\u4e00-\u9fff]+$")
    format: Literal["jsonl", "csv"] = "jsonl"
    content: str = Field(min_length=1, max_length=MAX_BYTES)


def _pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON含重复字段")
        result[key] = value
    return result


def parse_events(request: ImportRequest) -> list[SecurityEvent]:
    if len(request.content.encode("utf-8")) > MAX_BYTES:
        raise ValueError("导入内容超过1 MiB")
    text = request.content.lstrip("\ufeff")
    if request.format == "jsonl":
        lines = text.splitlines()
        if len(lines) > MAX_ROWS:
            raise ValueError("每批最多2000行")
        rows = []
        for index, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line, object_pairs_hook=_pairs_unique))
            except (ValueError, RecursionError):
                raise ValueError(f"第{index}行JSON格式无效") from None
    else:
        try:
            reader = csv.DictReader(io.StringIO(text), strict=True)
            fields = reader.fieldnames or []
        except csv.Error:
            raise ValueError("CSV表头格式无效") from None
        if not fields or len(fields) != len(set(fields)) or len(fields) > 24:
            raise ValueError("CSV表头缺失、重复或过多")
        rows = []
        try:
            for index, row in enumerate(reader, 1):
                if index > MAX_ROWS:
                    raise ValueError("每批最多2000行")
                if None in row or any(v is None for v in row.values()):
                    raise ValueError(f"第{index}条CSV列数不一致")
                for key in ("regions",):
                    if key in row:
                        row[key] = json.loads(row[key])
                for key in ("object_id", "parent_object_id", "prompt", "task_id"):
                    if row.get(key) == "":
                        row[key] = None
                if row.get("synthetic") != "true":
                    raise ValueError("每行必须声明synthetic=true，本入口仅接受合成安全日志")
                row["synthetic"] = True
                rows.append(row)
        except (csv.Error, json.JSONDecodeError, RecursionError):
            raise ValueError("CSV内容无效") from None
    if not rows:
        raise ValueError("导入内容没有事件")
    events, ids, clocks = [], set(), {}
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("synthetic") is not True:
            raise ValueError(f"第{index}条必须显式声明synthetic=true")
        try:
            event = SecurityEvent.model_validate(row)
        except ValidationError as exc:
            # Validation input may contain a prompt: never echo input or values.
            fields = sorted({str(e["loc"][0]) for e in exc.errors(include_input=False) if e["loc"]})
            allowed = SecurityEvent.model_fields
            safe_fields = [field if field in allowed else "额外字段" for field in fields]
            raise ValueError(f"第{index}条字段校验失败：{','.join(safe_fields[:8])}") from None
        if event.event_id in ids:
            raise ValueError(f"第{index}条事件ID重复")
        key = (event.employee_id, event.session_id)
        if key in clocks and event.timestamp < clocks[key]:
            raise ValueError(f"第{index}条会话时间倒序")
        ids.add(event.event_id)
        clocks[key] = event.timestamp
        events.append(event)
    return events


class ImportStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS imports(id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS observations(batch_id TEXT, position INTEGER, payload TEXT NOT NULL,
                    PRIMARY KEY(batch_id,position));
                CREATE TABLE IF NOT EXISTS seen_events(source TEXT,event_id TEXT, PRIMARY KEY(source,event_id));
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            with db:
                yield db
        finally:
            db.close()

    def list(self):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT payload FROM imports ORDER BY rowid DESC LIMIT 100")]

    def detail(self, batch_id: str, limit: int = 100, offset: int = 0):
        with self.connect() as db:
            row = db.execute("SELECT payload FROM imports WHERE id=?", (batch_id,)).fetchone()
            if not row:
                return None
            result = json.loads(row[0])
            result["observations"] = [json.loads(x[0]) for x in db.execute(
                "SELECT payload FROM observations WHERE batch_id=? ORDER BY position LIMIT ? OFFSET ?",
                (batch_id, min(200, max(1, limit)), max(0, offset)))]
            return result

    def ingest(self, request: ImportRequest, employees, tasks, actor: str):
        events = parse_events(request)
        known_employees = {item.id for item in employees}
        known_tasks = {item.id: item.employee_id for item in tasks}
        for event in events:
            if event.employee_id not in known_employees:
                raise ValueError("存在未登记员工，必须先映射到当前合成员工目录")
            if event.task_id and known_tasks.get(event.task_id) != event.employee_id:
                raise ValueError("工单不存在或不属于该员工")
        fingerprint = hashlib.sha256(dump([request.source_name, [e.model_dump(mode="json") for e in events]]).encode()).hexdigest()
        source_hash = hashlib.sha256(request.content.encode("utf-8")).hexdigest()
        with self.lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT payload FROM imports WHERE fingerprint=?", (fingerprint,)).fetchone()
            if prior:
                return dict(json.loads(prior[0]), replayed=True)
            # Reject the whole batch before inference if prior source IDs collide.
            for event in events:
                if db.execute("SELECT 1 FROM seen_events WHERE source=? AND event_id=?", (request.source_name,event.event_id)).fetchone():
                    raise ValueError("该来源已有相同事件ID，禁止修改后重复导入")
            engine = DetectionEngine(employees, tasks)
            records = []
            for event in events:
                analysis = engine.analyze(event)
                records.append(dict(event=event.model_dump(mode="json"), analysis=analysis.model_dump(mode="json"),
                                    mode="observe", actions_executed=False, cloud_called=False))
            result = dict(id=str(uuid4()), source_name=request.source_name, status="completed", mode="observe",
                          row_count=len(records), alert_count=sum(r["analysis"]["risk_score"] >= 30 for r in records),
                          high_risk_count=sum(r["analysis"]["risk_score"] >= 60 for r in records),
                          executed_actions=0, created_at=now(), actor=actor, source_sha256=source_hash,
                          fingerprint=fingerprint, model_version=engine.model_info["version"], replayed=False,
                          limitations=["合成日志独立批次分析，不跨批次累积会话历史。",
                                       "仅观察与建议，不执行阻断、不扣额度、不发往云模型。",
                                       "没有攻击标签，不能计算准确率或真实外泄阻断率。"])
            db.execute("INSERT INTO imports VALUES(?,?,?)", (result["id"], fingerprint, dump(result)))
            db.executemany("INSERT INTO observations VALUES(?,?,?)", [(result["id"],i,dump(r)) for i,r in enumerate(records)])
            db.executemany("INSERT INTO seen_events VALUES(?,?)", [(request.source_name,e.event_id) for e in events])
        return result
