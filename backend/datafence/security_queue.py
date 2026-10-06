"""Read-only, source-labelled security inbox over complete persisted histories.

Gateway deliveries are actual synthetic-row control decisions. Scenario records
are sandbox simulations. Imported observations never executed control actions.
The inbox projects those sources without copying or changing their evidence.
"""

from contextlib import contextmanager
import json
import sqlite3

from .storage import digest
from .workflows import WorkflowError


SOURCES = {"gateway": "业务访问", "simulation": "沙盒演练", "import": "日志观察"}
STATUSES = {"all", "pending", "investigating", "resolved"}
DECISIONS = {"all", "allowed", "blocked", "observed"}


class SecurityQueue:
    def __init__(self, store, gateway, imports):
        self.store = store
        self.gateway = gateway
        self.imports = imports

    @contextmanager
    def connect(self):
        # URI mode=ro also prevents accidentally creating a missing source DB.
        db = sqlite3.connect(self.store.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            db.execute("ATTACH DATABASE ? AS gateway", (self.gateway.path.resolve().as_uri() + "?mode=ro",))
            db.execute("ATTACH DATABASE ? AS imported", (self.imports.path.resolve().as_uri() + "?mode=ro",))
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            yield db
        finally:
            db.close()

    @staticmethod
    def _review_sql(db):
        tables = {row[0] for row in db.execute("SELECT name FROM main.sqlite_master WHERE type='table'")}
        reviews = []
        if "case_reviews" in tables:
            reviews.append("""SELECT 'simulation:' || event_id AS item_key, revision, payload
                FROM main.case_reviews c WHERE revision = (
                    SELECT MAX(revision) FROM main.case_reviews latest WHERE latest.event_id = c.event_id)""")
        if "security_reviews" in tables:
            reviews.append("""SELECT key AS item_key, revision, payload
                FROM main.security_reviews c WHERE revision = (
                    SELECT MAX(revision) FROM main.security_reviews latest WHERE latest.key = c.key)""")
        return " UNION ALL ".join(reviews) if reviews else "SELECT NULL AS item_key, 0 AS revision, NULL AS payload WHERE 0"

    @classmethod
    def _cte(cls, db):
        # User strings are parameters; this SQL uses only fixed table names.
        return """WITH source_rows AS (
            SELECT 'simulation:' || e.id AS item_key, 'simulation' AS source,
                e.id AS source_id, e.payload AS payload,
                json_extract(e.payload,'$.event') AS event,
                json_extract(e.payload,'$.analysis') AS analysis,
                NULL AS request_id, NULL AS actor,
                json_extract(e.payload,'$.event.timestamp') AS occurred_at,
                COALESCE(json_extract(e.payload,'$.received_at'), json_extract(e.payload,'$.detected_at'),
                    json_extract(e.payload,'$.persisted_at'), json_extract(e.payload,'$.event.timestamp')) AS observed_at,
                CASE WHEN json_extract(e.payload,'$.outcome')='blocked' THEN 'blocked' ELSE 'allowed' END AS decision,
                COALESCE(json_extract(e.payload,'$.executed_records'),0) AS delivered_records,
                json_extract(e.payload,'$.evidence_hash') AS evidence_hash,
                e.run_id AS run_id, NULL AS batch_id, NULL AS source_name
            FROM main.events e
            UNION ALL
            SELECT 'gateway:' || d.seq, 'gateway', CAST(d.seq AS TEXT), d.payload,
                json_extract(d.payload,'$.events[#-1].event'), json_extract(d.payload,'$.analysis'),
                d.request_id, json_extract(d.payload,'$.actor'),
                json_extract(d.payload,'$.events[#-1].event.timestamp'), json_extract(d.payload,'$.created_at'),
                CASE WHEN json_extract(d.payload,'$.allowed')=1 THEN 'allowed' ELSE 'blocked' END,
                COALESCE(json_extract(d.payload,'$.delivered_records'),0),
                json_extract(d.payload,'$.evidence_hash'), NULL, NULL, NULL
            FROM gateway.deliveries d
            UNION ALL
            SELECT 'import:' || o.batch_id || ':' || o.position, 'import', o.batch_id || ':' || o.position, o.payload,
                json_extract(o.payload,'$.event'), json_extract(o.payload,'$.analysis'), NULL,
                json_extract(b.payload,'$.actor'), json_extract(o.payload,'$.event.timestamp'),
                json_extract(b.payload,'$.created_at'), 'observed', 0, NULL, NULL, o.batch_id,
                json_extract(b.payload,'$.source_name')
            FROM imported.observations o JOIN imported.imports b ON b.id=o.batch_id
        ), reviews AS (""" + cls._review_sql(db) + """), items AS (
            SELECT s.*, json_extract(s.event,'$.event_id') AS event_id,
                json_extract(s.event,'$.employee_id') AS employee_id,
                COALESCE(json_extract(emp.payload,'$.name'),json_extract(s.event,'$.employee_id')) AS employee_name,
                json_extract(s.event,'$.task_id') AS task_id,
                json_extract(s.event,'$.event_type') AS operation,
                COALESCE(json_extract(s.event,'$.record_count'),0) AS requested_records,
                COALESCE(json_extract(s.analysis,'$.risk_score'),0) AS risk_score,
                json_extract(s.analysis,'$.risk_level') AS risk_level,
                json_extract(s.analysis,'$.explanation') AS summary,
                COALESCE(r.revision,0) AS review_revision,
                CASE WHEN r.item_key IS NULL THEN 'pending'
                    WHEN json_extract(r.payload,'$.status') IN ('pending','investigating','resolved')
                        THEN json_extract(r.payload,'$.status')
                    WHEN json_extract(r.payload,'$.disposition')='needs_investigation' THEN 'investigating'
                    ELSE 'resolved' END AS status
            FROM source_rows s LEFT JOIN reviews r ON r.item_key=s.item_key
            LEFT JOIN main.bank emp ON emp.kind='employees' AND emp.id=json_extract(s.event,'$.employee_id')
        ) """

    @staticmethod
    def _item(row):
        keys = ("source", "source_id", "event_id", "request_id", "employee_id", "employee_name", "actor", "task_id",
                "operation", "occurred_at", "observed_at", "risk_score", "risk_level", "decision", "requested_records",
                "delivered_records", "status", "review_revision", "evidence_hash", "summary", "run_id", "batch_id", "source_name")
        item = {key: row[key] for key in keys}
        item.update(key=row["item_key"], source_label=SOURCES[row["source"]],
                    control_mode={"gateway": "enforced", "simulation": "simulated", "import": "observe"}[row["source"]],
                    recommended_blocked=bool(json.loads(row["analysis"])["blocked"]),
                    requires_review=row["decision"] == "blocked" or row["risk_score"] >= 30)
        return item

    def list(self, *, source="all", status="all", decision="all", risk="all", q="", limit=25, offset=0,
             min_risk=0, attention_only=False):
        if source not in {"all", *SOURCES} or status not in STATUSES or decision not in DECISIONS or risk not in {"all", "high"}:
            raise ValueError("未知队列筛选条件")
        if not isinstance(limit, int) or not 1 <= limit <= 200 or not isinstance(offset, int) or offset < 0:
            raise ValueError("分页参数无效")
        if not isinstance(q, str) or len(q) > 200 or not isinstance(min_risk, (int, float)) or not 0 <= min_risk <= 100:
            raise ValueError("搜索或风险筛选无效")
        clauses, args = [], []
        for field, value in (("source", source), ("status", status), ("decision", decision)):
            if value != "all":
                clauses.append(field + "=?")
                args.append(value)
        clauses.append("risk_score >= ?")
        args.append(max(min_risk, 60 if risk == "high" else 0))
        if attention_only:
            clauses.append("(decision='blocked' OR risk_score>=30)")
        if q.strip():
            # instr treats %, _, quotes and slashes literally, unlike LIKE.
            clauses.append("""instr(lower(COALESCE(item_key,'') || ' ' || COALESCE(event_id,'') || ' ' ||
                COALESCE(request_id,'') || ' ' || COALESCE(employee_id,'') || ' ' || COALESCE(employee_name,'') || ' ' ||
                COALESCE(actor,'') || ' ' || COALESCE(task_id,'') || ' ' || COALESCE(source_name,'') || ' ' ||
                COALESCE(summary,'') || ' ' || COALESCE(json_extract(event,'$.purpose'),'')), lower(?))>0""")
            args.append(q.strip())
        with self.connect() as db:
            cte = self._cte(db) + ", filtered AS (SELECT * FROM items WHERE " + " AND ".join(clauses) + ") "
            counts = dict(db.execute(cte + """SELECT COUNT(*) AS all_count,
                COALESCE(SUM(status='pending'),0) AS pending,
                COALESCE(SUM(status='investigating'),0) AS investigating,
                COALESCE(SUM(status='resolved'),0) AS resolved,
                COALESCE(SUM(decision='blocked'),0) AS blocked,
                COALESCE(SUM(decision='observed'),0) AS observed,
                COALESCE(SUM(risk_score>=60),0) AS high_risk
                FROM filtered""", args).fetchone())
            rows = db.execute(cte + "SELECT * FROM filtered ORDER BY julianday(observed_at) DESC,item_key DESC LIMIT ? OFFSET ?",
                              (*args, limit, offset)).fetchall()
        counts["all"] = counts.pop("all_count")
        return dict(items=[self._item(row) for row in rows], total=counts["all"], limit=limit, offset=offset, counts=counts)

    def detail(self, key):
        if not isinstance(key, str) or len(key) > 200:
            return None
        with self.connect() as db:
            row = db.execute(self._cte(db) + "SELECT * FROM items WHERE item_key=?", (key,)).fetchone()
            if row is None:
                return None
            batch = None
            if row["source"] == "import":
                batch = json.loads(db.execute("SELECT payload FROM imported.imports WHERE id=?", (row["batch_id"],)).fetchone()[0])
        result = self._item(row)
        payload = json.loads(row["payload"])
        event, analysis = json.loads(row["event"]), json.loads(row["analysis"])
        if row["source"] == "simulation":
            record = payload
            evidence = dict(kind="simulation_event_chain", hash=row["evidence_hash"], previous_hash=payload.get("previous_hash"))
        elif row["source"] == "gateway":
            # Never expose customer IDs, actual rows or downloadable CSV via an
            # investigation read. The original evidence remains in its source.
            record = dict(event=event, analysis=analysis, evidence_hash=row["evidence_hash"],
                          outcome="executed" if payload["allowed"] else "blocked",
                          executed_records=payload["delivered_records"], detected_at=payload["created_at"],
                          ai_analysis={"status": "skipped", "provider": "local", "reason": "gateway_deterministic_policy"},
                          quota_decision=payload["quota"])
            evidence = dict(kind="gateway_delivery_chain", hash=row["evidence_hash"], previous_hash=payload["previous_hash"],
                            request_id=payload["request_id"], policy_version=payload["policy_version"])
        else:
            derived_hash = digest(payload)
            record = dict(event=event, analysis=analysis, evidence_hash=derived_hash, outcome="observed",
                          executed_records=0, detected_at=row["observed_at"], actions_executed=False,
                          ai_analysis={"status": "skipped", "provider": "local", "reason": "import_observation_only"})
            evidence = dict(kind="observation_digest", hash=derived_hash, batch_id=batch["id"],
                            source_sha256=batch["source_sha256"], fingerprint=batch["fingerprint"],
                            actions_executed=False)
        events = payload["events"] if row["source"] == "gateway" else [dict(event=event, analysis=analysis)]
        result.update(record=record, event=event, analysis=analysis, events=events, evidence=evidence,
                      evidence_hash=evidence["hash"])
        return result

    def assert_evidence(self, key, expected_hash):
        """Recheck the persisted source before accepting a human finding.

        Imported logs have a content digest, not an execution audit chain.
        Their digest binds a review to this snapshot without claiming that an
        external log source or a control action has been authenticated.
        """
        try:
            current = self.detail(key)
            valid = current is not None and current["evidence_hash"] == expected_hash
            if valid and current["source"] == "gateway":
                valid = self.gateway.verify()["valid"]
            elif valid and current["source"] == "simulation":
                valid = self.store.verify()["valid"]
            if valid:
                return
        except (ValueError, KeyError, TypeError, sqlite3.DatabaseError):
            pass
        raise WorkflowError("原始证据已变化或校验失败，请重新核对记录")
