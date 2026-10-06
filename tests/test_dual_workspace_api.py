"""Independent acceptance of business isolation and the persisted security inbox.

Only isolated TestClient runtimes; fixed synthetic clock; no cloud calls.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import threading
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from datafence.api import create_app
from datafence.models import SimulationRequest
from datafence.sandbox import BANK_TZ
from datafence.scenarios import generate_scenario
from datafence.storage import digest, dump


PASSWORD = "isolated acceptance password 2026"
AT = datetime(2026, 9, 19, 10, tzinfo=BANK_TZ)


class FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return AT.astimezone(tz) if tz else AT.replace(tzinfo=None)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAFENCE_NETWORK_MODE", "local")
    monkeypatch.setenv("DATAFENCE_AUTH_MODE", "required")
    monkeypatch.setenv("DATAFENCE_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("DATAFENCE_BEHAVIOR_MODEL", "legacy")
    for name in ("DATAFENCE_LLM_MODEL", "DATAFENCE_ALLOWED_HOSTS", "DATAFENCE_ALLOWED_ORIGINS", "DATAFENCE_SERVER_PORT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("datafence.gateway.datetime", FixedClock)
    with TestClient(create_app(tmp_path, customer_count=400), base_url="http://127.0.0.1",
                    client=("127.0.0.1", 51111)) as current:
        response = current.post("/api/auth/bootstrap", json=dict(username="administrator", password=PASSWORD))
        assert response.status_code == 200, response.text
        current.headers["X-DataFence-Token"] = response.json()["token"]
        yield current


def login(client, name):
    response = client.post("/api/auth/login", json=dict(username=name, password=PASSWORD))
    assert response.status_code == 200, response.text
    client.headers["X-DataFence-Token"] = response.json()["token"]
    return response.json()


def create(client, name="business.one", *, role="business", employee="E0038"):
    payload = dict(username=name, password=PASSWORD, role=role)
    if employee:
        payload["employee_id"] = employee
    response = client.post("/api/auth/users", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def task(client, employee="E0038", export=False):
    return next(item for item in client.app.state.gateway.tasks
                if item.employee_id == employee and item.allow_export == export)


def deliver(client, *, employee="E0038", export=False, operation="query", **changes):
    grant = task(client, employee, export)
    payload = dict(request_id=str(uuid4()), task_id=grant.id, operation=operation,
                   record_count=2, regions=[grant.regions[0]])
    payload.update(changes)
    response = client.post("/api/access/execute", json=payload)
    assert response.status_code in (200, 403), response.text
    return payload, response


def imported(client):
    service = client.app.state.service
    events, _ = generate_scenario(SimulationRequest(scenario_id="combined", record_count=100, interval_ms=0),
                                  service.employees, service.tasks)
    response = client.post("/api/imports", json=dict(source_name="独立观察验收", format="jsonl",
        content="\n".join(dump(event.model_dump(mode="json")) for event in events)))
    assert response.status_code == 201, response.text
    return response.json()


def simulation(client):
    response = client.post("/api/runs", json=dict(scenario_id="normal", employee_id="E0038",
                                                record_count=2, interval_ms=0))
    assert response.status_code == 202, response.text
    return response.json()


def review(client, key, *, revision=0, disposition="needs_investigation", **changes):
    payload = dict(request_id=str(uuid4()), expected_revision=revision,
                   disposition=disposition, note="独立核对工单和实际交付记录")
    payload.update(changes)
    return payload, client.post(f"/api/observations/{key}/review", json=payload)


def source_rows(client):
    store = client.app.state.service.store
    with store.connect() as db:
        events = db.execute("SELECT id,payload FROM events ORDER BY id").fetchall()
    with client.app.state.gateway.connect() as db:
        delivery = db.execute("SELECT seq,payload FROM deliveries ORDER BY seq").fetchall()
    with client.app.state.imports.connect() as db:
        observations = db.execute("SELECT batch_id,position,payload FROM observations ORDER BY batch_id,position").fetchall()
    return [tuple(row) for row in events], delivery, observations


def test_business_binding_required_and_only_admin_may_configure(client):
    response = client.post("/api/auth/users", json=dict(username="missing.binding", password=PASSWORD, role="business"))
    assert response.status_code == 422
    response = client.post("/api/auth/users", json=dict(username="bad.binding", password=PASSWORD,
                                                       role="business", employee_id="E9999"))
    assert response.status_code == 422
    create(client)
    create(client, "security.analyst", role="analyst", employee=None)
    login(client, "security.analyst")
    assert client.post("/api/auth/users/business.one", json=dict(employee_id="E0001")).status_code == 403
    login(client, "business.one")
    assert client.get("/api/session").json()["user"]["employee_id"] == "E0038"
    assert client.post("/api/auth/users/business.one", json=dict(employee_id="E0001")).status_code == 403
    grants = client.get("/api/access/tasks").json()
    assert len(grants) == 2 and {grant["employee_id"] for grant in grants} == {"E0038"}
    _, response = deliver(client, employee="E0001")
    assert response.status_code == 403 and "employee_scope_denied" in response.text
    assert client.app.state.gateway.recent() == []


def test_business_denied_every_registered_security_route_and_encoded_variants(client):
    create(client)
    login(client, "business.one")
    denied = []
    permitted = {"/api/session", "/api/access/tasks", "/api/access/operations", "/api/access/operations/{request_id}",
                 "/api/access/execute", "/api/auth/logout", "/api/auth/status", "/api/auth/login",
                 "/api/auth/bootstrap", "/api/health/live"}
    for route in client.app.routes:
        if not route.path.startswith("/api") or route.path in permitted:
            continue
        path = route.path
        for parameter in ("employee_id", "event_id", "run_id", "job_id", "batch_id", "document_id", "demo_id", "username", "key"):
            path = path.replace("{" + parameter + "}", "existing-resource")
        for method in route.methods & {"GET", "POST"}:
            response = client.request(method, path, **({"json": {}} if method == "POST" else {}))
            assert response.status_code == 403, (method, path, response.status_code, response.text)
            denied.append((method, path))
    assert len(denied) >= 30
    for path in ("/api/%6fbservations", "/%61pi/observations", "/api/access/%76erify",
                 "/api/access/tasks%2F..%2F..%2Foverview", "/api/%61uth/users", "/api/observations%2Fgateway:1"):
        assert client.get(path).status_code == 403, path


def test_business_history_and_request_metadata_are_own_actor_only_even_same_employee(client):
    create(client)
    create(client, "business.two")
    create(client, "business.three", employee="E0001")
    shared_id = str(uuid4())
    login(client, "business.one")
    first, response = deliver(client, request_id=shared_id)
    assert response.status_code == 200 and len(response.json()["rows"]) == 2
    unique, _ = deliver(client)
    login(client, "business.two")
    second, response = deliver(client, request_id=shared_id)
    assert response.status_code == 200
    mine = client.get("/api/access/operations").json()
    assert len(mine) == 1 and mine[0]["actor"] == "business.two"
    metadata = client.get(f"/api/access/operations/{shared_id}")
    assert metadata.status_code == 200 and metadata.json()["actor"] == "business.two"
    assert client.get(f"/api/access/operations/{unique['request_id']}").status_code == 404
    for excluded in ("customer_ids", '"rows"', '"csv"', '"events"', "SYN-C-"):
        assert excluded not in metadata.text
    login(client, "business.three")
    assert client.get("/api/access/operations").json() == []
    assert client.get(f"/api/access/operations/{shared_id}").status_code == 404
    login(client, "administrator")
    assert client.get(f"/api/access/operations/{shared_id}").status_code == 409
    assert client.get("/api/observations?source=gateway").json()["total"] == 3


def test_rebinding_invalidates_existing_session_and_cannot_reveal_old_employee_history(client):
    create(client)
    login(client, "business.one")
    old_payload, _ = deliver(client)
    old_cookie = client.cookies.get("df_session")
    old_token = client.headers["X-DataFence-Token"]
    login(client, "administrator")
    changed = client.post("/api/auth/users/business.one", json=dict(employee_id="E0001"))
    assert changed.status_code == 200 and changed.json()["employee_id"] == "E0001"
    client.cookies.clear()
    client.cookies.set("df_session", old_cookie)
    client.headers["X-DataFence-Token"] = old_token
    assert client.get("/api/session").status_code == 401
    assert client.post("/api/access/execute", json=old_payload).status_code == 401
    login(client, "business.one")
    assert {item["employee_id"] for item in client.get("/api/access/tasks").json()} == {"E0001"}
    assert client.get("/api/access/operations").json() == []
    assert client.get(f"/api/access/operations/{old_payload['request_id']}").status_code == 404


@pytest.mark.parametrize("source", ["gateway", "simulation", "import"])
def test_all_sources_can_be_investigated_without_mutating_original_evidence(client, source):
    if source == "gateway":
        _, response = deliver(client, export=True, operation="export")
        assert response.status_code == 200 and response.json()["delivered_records"] == 2
        assert len(response.json()["csv"].splitlines()) == 3
    elif source == "simulation":
        simulation(client)
    else:
        imported(client)
    page = client.get(f"/api/observations?source={source}").json()
    assert page["total"] >= 1 and page["counts"]["pending"] == page["total"]
    key = page["items"][0]["key"]
    detail = client.get(f"/api/observations/{key}").json()
    assert detail["review"]["revision"] == 0 and detail["related_knowledge"]
    if source == "import":
        assert detail["decision"] == "observed" and not detail["record"]["actions_executed"]
        assert page["counts"]["blocked"] == 0 and detail["delivered_records"] == 0
    baseline = source_rows(client)
    payload, saved = review(client, key)
    assert saved.status_code == 200, saved.text
    assert saved.json()["revision"] == 1
    assert client.post(f"/api/observations/{key}/review", json=payload).json()["revision"] == 1
    progress = client.get(f"/api/observations?source={source}&status=investigating").json()
    assert progress["total"] == 1 and progress["items"][0]["key"] == key
    _, resolved = review(client, key, revision=1, disposition="false_positive")
    assert resolved.status_code == 200 and resolved.json()["revision"] == 2
    current = client.get(f"/api/observations/{key}").json()
    assert current["status"] == "resolved" and current["review"]["current"]["actor"] == "administrator"
    assert current["review"]["current"]["event_evidence_hash"] == detail["record"]["evidence_hash"]
    assert current["record"] == detail["record"] and source_rows(client) == baseline
    assert client.app.state.service.store.verify()["valid"] and client.app.state.gateway.verify()["valid"]


def test_gateway_denial_is_actual_zero_delivery_and_viewer_cannot_review(client):
    _, result = deliver(client, operation="export")
    assert result.status_code == 403 and result.json()["rows"] == []
    page = client.get("/api/observations?decision=blocked").json()
    assert page["total"] == 1 and page["items"][0]["delivered_records"] == 0
    key = page["items"][0]["key"]
    create(client, "readonly", role="viewer", employee=None)
    login(client, "readonly")
    assert client.get(f"/api/observations/{key}").status_code == 200
    _, response = review(client, key)
    assert response.status_code == 403
    assert client.get(f"/api/observations/{key}/review").json()["revision"] == 0


def test_concurrent_review_has_one_winner_and_replays_do_not_duplicate(client):
    deliver(client)
    key = client.get("/api/observations").json()["items"][0]["key"]
    before = source_rows(client)
    barrier = threading.Barrier(2)
    def submit(index):
        barrier.wait(timeout=5)
        return review(client, key, note=f"独立并发核对 {index}")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, range(2)))
    assert sorted(response.status_code for _, response in results) == [200, 409]
    winner = next(payload for payload, response in results if response.status_code == 200)
    repeated = client.post(f"/api/observations/{key}/review", json=winner)
    assert repeated.status_code == 200 and repeated.json()["revision"] == 1
    changed = client.post(f"/api/observations/{key}/review", json=dict(winner, note="不同内容不能复用编号"))
    assert changed.status_code == 409
    assert source_rows(client) == before


@pytest.mark.parametrize("source", ["gateway", "simulation"])
def test_damaged_original_evidence_cannot_receive_new_conclusion(client, source):
    if source == "gateway":
        deliver(client)
    else:
        simulation(client)
    item = client.get(f"/api/observations?source={source}").json()["items"][0]
    key = item["key"]
    store = client.app.state.gateway if source == "gateway" else client.app.state.service.store
    with store.connect() as db:
        table, key_column = ("deliveries", "seq") if source == "gateway" else ("events", "id")
        payload = json.loads(db.execute(f"SELECT payload FROM {table} WHERE {key_column}=?", (item["source_id"],)).fetchone()[0])
        payload["analysis"]["explanation"] = "被篡改但原摘要保持不变"
        db.execute(f"UPDATE {table} SET payload=? WHERE {key_column}=?", (dump(payload), item["source_id"]))
    assert not store.verify()["valid"]
    _, response = review(client, key)
    assert response.status_code == 409, response.text
    assert client.get(f"/api/observations/{key}/review").json()["revision"] == 0


def test_import_queue_sql_pagination_reaches_all_rows_and_literal_filter(client):
    service = client.app.state.service
    originals, _ = generate_scenario(SimulationRequest(scenario_id="normal", record_count=2), service.employees, service.tasks)
    event = originals[-1]
    events = [event.model_copy(update={"event_id": str(uuid4()), "purpose": "最早专用检索100%_" if index == 0 else "日常核对"})
              for index in range(121)]
    response = client.post("/api/imports", json=dict(source_name="分页验收", content="\n".join(dump(e.model_dump(mode="json")) for e in events)))
    assert response.status_code == 201, response.text
    pages = [client.get(f"/api/observations?source=import&limit=25&offset={offset}").json() for offset in range(0, 150, 25)]
    keys = [item["key"] for page in pages for item in page["items"]]
    assert len(keys) == len(set(keys)) == 121
    assert all(page["total"] == page["counts"]["all"] == 121 for page in pages)
    found = client.get("/api/observations", params=dict(q="100%_", source="import")).json()
    assert found["total"] == 1 and found["items"][0]["event_id"] == events[0].event_id
    assert client.get("/api/observations", params=dict(q="' OR 1=1 --")).json()["total"] == 0
    assert client.get("/api/observations?source=import&decision=blocked").json()["total"] == 0


@pytest.mark.parametrize("source", ["gateway", "simulation", "import"])
def test_damaged_review_history_cannot_be_extended(client, source):
    {"gateway": lambda: deliver(client), "simulation": lambda: simulation(client), "import": lambda: imported(client)}[source]()
    item = client.get(f"/api/observations?source={source}").json()["items"][0]
    key = item["key"]
    _, initial = review(client, key)
    assert initial.status_code == 200, initial.text
    with client.app.state.service.store.connect() as db:
        table, column, identity = ("case_reviews", "event_id", item["event_id"]) if source == "simulation" else ("security_reviews", "key", key)
        record = json.loads(db.execute(f"SELECT payload FROM {table} WHERE {column}=?", (identity,)).fetchone()[0])
        record["note"] = "损坏历史研判，旧摘要保留"
        db.execute(f"UPDATE {table} SET payload=? WHERE {column}=?", (dump(record), identity))
    _, response = review(client, key, revision=1)
    assert response.status_code == 409, response.text
    with client.app.state.service.store.connect() as db:
        assert db.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (identity,)).fetchone()[0] == 1


def test_legacy_event_review_cannot_bypass_source_integrity_check(client):
    simulation(client)
    item = client.get("/api/observations?source=simulation").json()["items"][0]
    with client.app.state.service.store.connect() as db:
        record = json.loads(db.execute("SELECT payload FROM events WHERE id=?", (item["event_id"],)).fetchone()[0])
        record["analysis"]["explanation"] = "已损坏源证据"
        db.execute("UPDATE events SET payload=? WHERE id=?", (dump(record), item["event_id"]))
    payload = dict(request_id=str(uuid4()), expected_revision=0, disposition="false_positive", note="旧页面不能绕过证据检查")
    response = client.post(f"/api/events/{item['event_id']}/review", json=payload)
    assert response.status_code == 409, response.text


def test_revoke_analyst_during_review_transaction_rejects_final_write(client, monkeypatch):
    from datafence.observation_reviews import ObservationReviews

    deliver(client)
    key = client.get("/api/observations?source=gateway").json()["items"][0]["key"]
    create(client, "temporary.analyst", role="analyst", employee=None)
    login(client, "temporary.analyst")
    entered, release = threading.Event(), threading.Event()
    original = ObservationReviews._get
    def pause(db, selected):
        value = original(db, selected)
        if selected == key:
            entered.set()
            assert release.wait(timeout=8)
        return value
    monkeypatch.setattr(ObservationReviews, "_get", staticmethod(pause))
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(review, client, key)
        try:
            assert entered.wait(timeout=8)
            client.app.state.auth.set_enabled("temporary.analyst", False)
        finally:
            release.set()
        _, response = pending.result(timeout=8)
    assert response.status_code == 401, response.text
    with client.app.state.service.store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM security_reviews WHERE key=?", (key,)).fetchone()[0] == 0


@pytest.mark.parametrize("source", ["gateway", "import"])
def test_source_modified_during_review_is_rechecked_before_final_write(client, monkeypatch, source):
    from datafence.observation_reviews import ObservationReviews

    (deliver(client) if source == "gateway" else imported(client))
    item = client.get(f"/api/observations?source={source}").json()["items"][0]
    key = item["key"]
    entered, release = threading.Event(), threading.Event()
    original = ObservationReviews._get
    def pause(db, selected):
        value = original(db, selected)
        if selected == key:
            entered.set()
            assert release.wait(timeout=8)
        return value
    monkeypatch.setattr(ObservationReviews, "_get", staticmethod(pause))
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(review, client, key)
        try:
            assert entered.wait(timeout=8)
            owner = client.app.state.gateway if source == "gateway" else client.app.state.imports
            with owner.connect() as db:
                if source == "gateway":
                    record = json.loads(db.execute("SELECT payload FROM deliveries WHERE seq=?", (item["source_id"],)).fetchone()[0])
                    record["analysis"]["explanation"] = "研判期间原证据变化"
                    db.execute("UPDATE deliveries SET payload=? WHERE seq=?", (dump(record), item["source_id"]))
                else:
                    batch, position = item["source_id"].rsplit(":", 1)
                    record = json.loads(db.execute("SELECT payload FROM observations WHERE batch_id=? AND position=?", (batch, int(position))).fetchone()[0])
                    record["analysis"]["explanation"] = "研判期间观察内容变化"
                    db.execute("UPDATE observations SET payload=? WHERE batch_id=? AND position=?", (dump(record), batch, int(position)))
        finally:
            release.set()
        _, response = pending.result(timeout=8)
    assert response.status_code == 409, response.text
    with client.app.state.service.store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM security_reviews WHERE key=?", (key,)).fetchone()[0] == 0


def test_review_payload_bound_to_key_even_when_payload_hash_recomputed(client):
    deliver(client)
    key = client.get("/api/observations?source=gateway").json()["items"][0]["key"]
    _, response = review(client, key)
    assert response.status_code == 200
    with client.app.state.service.store.connect() as db:
        record = json.loads(db.execute("SELECT payload FROM security_reviews WHERE key=?", (key,)).fetchone()[0])
        record["event_id"] = "gateway:9999"
        record.pop("hash")
        record["hash"] = digest(record)
        db.execute("UPDATE security_reviews SET payload=? WHERE key=?", (dump(record), key))
    assert client.get("/api/reviews/verify").json()["valid"] is False
    _, response = review(client, key, revision=1)
    assert response.status_code == 409


@pytest.mark.parametrize("source", ["gateway", "simulation", "import"])
def test_source_changes_after_review_are_visible_in_review_verification(client, source):
    {"gateway": lambda: deliver(client), "simulation": lambda: simulation(client), "import": lambda: imported(client)}[source]()
    item = client.get(f"/api/observations?source={source}").json()["items"][0]
    key = item["key"]
    _, response = review(client, key)
    assert response.status_code == 200
    assert client.get("/api/reviews/verify").json() == {"valid": True, "checked_reviews": 1}
    owner = {"gateway": client.app.state.gateway, "simulation": client.app.state.service.store,
             "import": client.app.state.imports}[source]
    with owner.connect() as db:
        if source == "import":
            batch, position = item["source_id"].rsplit(":", 1)
            record = json.loads(db.execute("SELECT payload FROM observations WHERE batch_id=? AND position=?", (batch, int(position))).fetchone()[0])
            record["analysis"]["explanation"] = "研判后观察内容变化"
            db.execute("UPDATE observations SET payload=? WHERE batch_id=? AND position=?", (dump(record), batch, int(position)))
        else:
            table, column = ("deliveries", "seq") if source == "gateway" else ("events", "id")
            record = json.loads(db.execute(f"SELECT payload FROM {table} WHERE {column}=?", (item["source_id"],)).fetchone()[0])
            record["analysis"]["explanation"] = "研判后源记录变化，原摘要保留"
            db.execute(f"UPDATE {table} SET payload=? WHERE {column}=?", (dump(record), item["source_id"]))
    assert client.get("/api/reviews/verify").json()["valid"] is False
    _, response = review(client, key, revision=1)
    assert response.status_code == 409
