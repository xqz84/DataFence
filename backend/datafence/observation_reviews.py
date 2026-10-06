"""Human findings bound to immutable source evidence, without control authority."""

import json
import sqlite3

from .knowledge import build_knowledge_context
from .models import Analysis, SecurityEvent
from .storage import digest, dump, now
from .workflows import WorkflowError, WorkflowStore


class ObservationReviews:
    def __init__(self, store):
        self.store = store
        with store.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS security_reviews (
                key TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL,
                PRIMARY KEY(key,revision))""")

    @staticmethod
    def _get(db, key):
        history = [json.loads(r[0]) for r in db.execute(
            "SELECT payload FROM security_reviews WHERE key=? ORDER BY revision", (key,))]
        return dict(event_id=key, revision=len(history), current=history[-1] if history else None, history=history)

    def get(self, key):
        with self.store.connect() as db:
            return self._get(db, key)

    def verify(self, queue):
        count = 0
        try:
            with self.store.connect() as db:
                keys = [row[0] for row in db.execute("SELECT DISTINCT key FROM security_reviews ORDER BY key")]
                for key in keys:
                    current = queue.detail(key)
                    if current is None:
                        return dict(valid=False, checked_reviews=count)
                    queue.assert_evidence(key, current["evidence_hash"])
                    rows = db.execute("SELECT revision,payload FROM security_reviews WHERE key=? ORDER BY revision", (key,)).fetchall()
                    history = [json.loads(row[1]) for row in rows]
                    if (any(row[0] != index for index, row in enumerate(rows, 1))
                            or not self._valid(history, current["evidence_hash"], key)):
                        return dict(valid=False, checked_reviews=count)
                    count += len(rows)
        except (ValueError, KeyError, TypeError, sqlite3.DatabaseError, WorkflowError):
            return dict(valid=False, checked_reviews=count)
        return dict(valid=True, checked_reviews=count)

    @staticmethod
    def _valid(history, evidence_hash, key):
        previous = "0" * 64
        for revision, entry in enumerate(history, 1):
            item = dict(entry)
            stored_hash = item.pop("hash", None)
            if (item.get("event_id") != key or item.get("revision") != revision or item.get("previous_hash") != previous
                    or item.get("event_evidence_hash") != evidence_hash or digest(item) != stored_hash):
                return False
            previous = stored_hash
        return True

    def append(self, key, observation, request, actor, *, authorize=None):
        fingerprint = digest(dict(observation_key=key, **request.model_dump(mode="json")))
        request_key = "observation_review:" + actor + ":" + str(request.request_id)
        source_hash = observation.get("evidence_hash")
        if not isinstance(source_hash, str) or len(source_hash) != 64:
            raise WorkflowError("此记录缺少可绑定的原始证据摘要")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if authorize:
                authorize()
            prior = WorkflowStore._prior(db, request_key, fingerprint)
            result = self._get(db, key)
            if not self._valid(result["history"], source_hash, key):
                raise WorkflowError("原始依据或研判历史摘要不一致，不能追加结论")
            if prior:
                return result
            if result["revision"] != request.expected_revision:
                raise WorkflowError("研判已更新，请重新核对最新结论")
            item = dict(event_id=key, revision=result["revision"] + 1, disposition=request.disposition,
                        note=request.note, actor=actor, created_at=now(), event_evidence_hash=source_hash,
                        source=observation["source"],
                        reference_knowledge=build_knowledge_context(SecurityEvent.model_validate(observation["event"]),
                                                                   Analysis.model_validate(observation["analysis"])),
                        previous_hash=result["current"]["hash"] if result["current"] else "0" * 64)
            item["hash"] = digest(item)
            if authorize:
                authorize()
            db.execute("INSERT INTO security_reviews VALUES(?,?,?)", (key, item["revision"], dump(item)))
            db.execute("INSERT INTO workflow_requests VALUES(?,?,?)", (request_key, fingerprint, key))
            return self._get(db, key)
