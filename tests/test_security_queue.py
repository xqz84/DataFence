"""Cross-source queue acceptance: real delivery controls, observation and history."""

from datetime import datetime, timedelta
import json
import sqlite3
from uuid import uuid4

import pytest

from datafence.engine import DetectionEngine
from datafence.gateway import AccessGateway, AccessRequest
from datafence.ingestion import ImportRequest, ImportStore
from datafence.models import SimulationRequest
from datafence.sandbox import BANK_TZ, build_bank, REGIONS
from datafence.scenarios import generate_scenario
from datafence.security_queue import SecurityQueue
from datafence.storage import Store, digest, dump
from datafence.workflows import WorkflowStore, ReviewRequest


AT = datetime(2026, 9, 19, 10, 0, tzinfo=BANK_TZ)
ACTOR = dict(id="queue-operator-1", username="业务甲", role="analyst")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAFENCE_BEHAVIOR_MODEL", "legacy")
    bank = build_bank(customer_count=100)
    store = Store(tmp_path)
    store.initialize_bank(bank)
    gate = AccessGateway(tmp_path, bank["employees"], bank["tasks"], bank["customers"])
    imports = ImportStore(tmp_path / "imports.sqlite3")
    return bank, store, gate, imports, SecurityQueue(store, gate, imports)


def grant(bank, export=False):
    return next(task for task in bank["tasks"] if task.employee_id == "E0038" and task.allow_export == export)


def deliver(gate, task, *, actor=ACTOR, request_id=None, **changes):
    values = dict(request_id=request_id or uuid4(), task_id=task.id, operation="query",
                  record_count=2, regions=[task.regions[0]])
    values.update(changes)
    return gate.execute(AccessRequest(**values), actor, at=AT)


def simulation(bank, store, *, purpose=None, timestamp=None, risk=None):
    events, _ = generate_scenario(SimulationRequest(scenario_id="normal", record_count=5, seed=123),
                                  bank["employees"], bank["tasks"])
    event = events[-1].model_copy(update={"event_id": str(uuid4())})
    if purpose:
        event = event.model_copy(update={"purpose": purpose})
    analysis = DetectionEngine(bank["employees"], bank["tasks"]).analyze(event)
    if risk is not None:
        analysis = analysis.model_copy(update={"risk_score": risk, "risk_level": "HIGH" if risk >= 60 else "LOW"})
    return store.append_event(dict(event=event.model_dump(mode="json"), analysis=analysis.model_dump(mode="json"),
                                   run_id="queue-simulation", outcome="blocked" if analysis.blocked else "executed",
                                   received_at=timestamp or AT.isoformat(), executed_records=0 if analysis.blocked else 5))


def observation(bank, imports, scenario="combined", source="离线观察"):
    events, _ = generate_scenario(SimulationRequest(scenario_id=scenario, record_count=100, seed=67),
                                  bank["employees"], bank["tasks"])
    request = ImportRequest(source_name=source, content="\n".join(dump(e.model_dump(mode="json")) for e in events))
    return imports.ingest(request, bank["employees"], bank["tasks"], "import-operator")


def test_empty_queue_and_unknown_detail(env):
    *_, queue = env
    assert queue.list()["items"] == []
    assert queue.list()["counts"] == dict(all=0, pending=0, investigating=0, resolved=0, blocked=0, observed=0, high_risk=0)
    assert queue.detail("gateway:999") is None
    assert queue.detail("' OR 1=1 --") is None


def test_real_query_and_denied_export_reach_security_queue_without_customer_rows(env):
    bank, store, gate, imports, queue = env
    task = grant(bank)
    allowed = deliver(gate, task)
    denied = deliver(gate, task, operation="export")
    page = queue.list(source="gateway")
    assert page["total"] == 2 and page["counts"]["blocked"] == 1
    safe = next(item for item in page["items"] if item["decision"] == "allowed")
    blocked = next(item for item in page["items"] if item["decision"] == "blocked")
    assert safe["delivered_records"] == allowed["delivered_records"] == len(allowed["rows"]) == 2
    assert blocked["delivered_records"] == denied["delivered_records"] == 0
    assert blocked["operation"] == "EXPORT" and blocked["control_mode"] == "enforced"
    assert blocked["employee_id"] == task.employee_id
    detail = queue.detail(blocked["key"])
    assert detail["record"]["evidence_hash"] == denied["evidence_hash"]
    assert len(detail["events"]) == 2 and detail["event"]["event_type"] == "EXPORT"
    assert detail["analysis"]["blocked"]
    serialized = dump(dict(page=page, detail=detail))
    assert "customer_ids" not in serialized and '"rows"' not in serialized and '"csv"' not in serialized
    assert "SYN-C-" not in serialized and "ground_truth" not in serialized and "attack_type" not in serialized
    assert gate.verify() == dict(valid=True, checked_operations=2)
    assert store.verify()["checked_events"] == 0


def test_gateway_ids_do_not_collide_for_same_request_uuid_across_actors(env):
    bank, _, gate, _, queue = env
    request_id = uuid4()
    deliver(gate, grant(bank), request_id=request_id)
    deliver(gate, grant(bank), request_id=request_id, actor=dict(ACTOR, id="queue-operator-2", username="业务乙"))
    items = queue.list(source="gateway")["items"]
    assert len(items) == 2 and len({item["key"] for item in items}) == 2
    assert len({item["request_id"] for item in items}) == 1
    assert queue.list(q="业务乙")["total"] == 1


def test_import_recommendation_is_observation_not_executed_block(env):
    bank, store, gate, imports, queue = env
    batch = observation(bank, imports)
    page = queue.list(source="import", risk="high")
    assert page["total"] > 0 and page["counts"]["blocked"] == 0
    assert page["counts"]["observed"] == page["total"]
    item = next(item for item in page["items"] if item["recommended_blocked"])
    assert item["decision"] == "observed" and item["control_mode"] == "observe"
    assert item["delivered_records"] == 0 and item["evidence_hash"] is None
    detail = queue.detail(item["key"])
    assert detail["evidence"]["kind"] == "observation_digest"
    assert detail["evidence"]["source_sha256"] == batch["source_sha256"]
    assert detail["record"]["outcome"] == "observed" and not detail["record"]["actions_executed"]
    original = imports.detail(batch["id"], limit=200)["observations"][int(item["source_id"].rsplit(":", 1)[-1])]
    assert detail["record"]["evidence_hash"] == digest(original)
    assert queue.list(decision="blocked")["total"] == 0
    assert store.verify()["checked_events"] == 0 and gate.verify()["checked_operations"] == 0


def test_complete_history_sql_filter_pagination_and_totals_not_recent_100(env):
    bank, store, _, _, queue = env
    oldest = simulation(bank, store, purpose="只存在最早记录的检索词", timestamp=AT.isoformat(), risk=80)
    # Reuse independent persisted records to isolate query correctness from
    # detector thresholds, not to claim detection-quality validation.
    with store.connect() as db:
        for index in range(130):
            item = json.loads(dump(oldest))
            item["event"].update(event_id=f"history-{index:04d}", purpose="普通检索")
            item["analysis"].update(event_id=item["event"]["event_id"], risk_score=20, risk_level="LOW", explanation="正常访问")
            item["received_at"] = (AT + timedelta(seconds=index + 1)).isoformat()
            db.execute("INSERT INTO events(id,run_id,employee_id,payload) VALUES(?,?,?,?)",
                       (item["event"]["event_id"], item["run_id"], item["event"]["employee_id"], dump(item)))
    assert queue.list()["total"] == 131
    found = queue.list(q="只存在最早记录的检索词")
    assert found["total"] == 1 and found["items"][0]["event_id"] == oldest["event"]["event_id"]
    assert queue.list(risk="high")["total"] == 1
    pages = [queue.list(limit=25, offset=offset) for offset in range(0, 150, 25)]
    keys = [item["key"] for page in pages for item in page["items"]]
    assert len(keys) == len(set(keys)) == 131
    assert all(page["total"] == 131 and page["counts"]["all"] == 131 for page in pages)
    assert queue.list(offset=1000)["items"] == []


def test_search_is_literal_and_across_all_sources(env):
    bank, store, gate, imports, queue = env
    simulation(bank, store, purpose="含100%_标记的用途")
    deliver(gate, grant(bank))
    observation(bank, imports)
    assert queue.list(q="%_")["total"] == 1
    assert queue.list(q="' OR 1=1 --")["total"] == 0
    assert queue.list(q="离线观察")["total"] > 0
    assert queue.list(q="E0038")["total"] == queue.list()["total"]


def test_legacy_and_new_case_reviews_filter_using_latest_revision(env):
    bank, store, gate, _, queue = env
    workflows = WorkflowStore(store)
    event = simulation(bank, store)
    first = ReviewRequest(request_id=uuid4(), expected_revision=0, disposition="needs_investigation", note="核对业务审批")
    workflows.append_review(event, first, "analyst")
    deliver(gate, grant(bank))
    gateway_key = queue.list(source="gateway")["items"][0]["key"]
    with store.connect() as db:
        db.execute("CREATE TABLE security_reviews(key TEXT,revision INTEGER,payload TEXT NOT NULL,PRIMARY KEY(key,revision))")
        db.execute("INSERT INTO security_reviews VALUES(?,?,?)", (gateway_key, 1, dump(dict(disposition="needs_investigation"))))
        db.execute("INSERT INTO security_reviews VALUES(?,?,?)", (gateway_key, 2, dump(dict(disposition="false_positive"))))
    assert queue.list(status="investigating")["total"] == 1
    resolved = queue.list(status="resolved")
    assert resolved["total"] == 1 and resolved["items"][0]["review_revision"] == 2
    assert queue.list(status="pending")["total"] == 0
    current = workflows.review(event["event"]["event_id"])
    final = first.model_copy(update={"request_id": uuid4(), "expected_revision": current["revision"], "disposition": "confirmed_risk"})
    workflows.append_review(event, final, "analyst")
    assert queue.list(status="resolved")["total"] == 2
    assert workflows.verify_reviews()["valid"]


def test_mixed_sources_timezones_sort_by_instant_and_empty_employee_directory(env):
    bank, store, _, _, queue = env
    later = simulation(bank, store, timestamp="2026-09-19T10:00:00+00:00")
    earlier = simulation(bank, store, timestamp="2026-09-19T15:00:00+08:00")
    with store.connect() as db:
        db.execute("DELETE FROM bank WHERE kind='employees'")
    items = queue.list()["items"]
    assert [item["event_id"] for item in items] == [later["event"]["event_id"], earlier["event"]["event_id"]]
    assert all(item["employee_name"] == item["employee_id"] for item in items)


def test_reads_cannot_write_or_change_evidence_and_persisted_keys_survive_restart(env):
    bank, store, gate, imports, queue = env
    record = simulation(bank, store)
    deliver(gate, grant(bank))
    observation(bank, imports)
    before = (store.verify(), gate.verify(), store.event(record["event"]["event_id"]))
    original = queue.list()
    for item in original["items"]:
        assert queue.detail(item["key"])
    with queue.connect() as db:
        for sql in ("DELETE FROM main.events", "DELETE FROM gateway.deliveries", "DELETE FROM imported.observations"):
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                db.execute(sql)
    reopened = SecurityQueue(Store(store.directory), gate, ImportStore(imports.path))
    assert reopened.list() == original
    assert (store.verify(), gate.verify(), store.event(record["event"]["event_id"])) == before


@pytest.mark.parametrize("options", [{"source": "wrong"}, {"status": "closed"}, {"decision": "executed"},
                                     {"risk": "dangerous"}, {"limit": 201}, {"limit": 0}, {"offset": -1},
                                     {"q": "x" * 201}, {"min_risk": float("nan")}])
def test_invalid_filters_rejected(env, options):
    *_, queue = env
    with pytest.raises(ValueError):
        queue.list(**options)
