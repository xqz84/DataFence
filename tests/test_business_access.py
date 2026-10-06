"""Business-account binding and actual scoped delivery; isolated SQLite only."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import sqlite3
from uuid import uuid4

import pytest

from datafence.auth import AuthError, AuthStore
from datafence.gateway import AccessGateway, AccessRequest, GatewayError
from datafence.sandbox import BANK_TZ, build_bank


PASSWORD = "business-access-test-passphrase"
AT = datetime(2026, 9, 19, 10, tzinfo=BANK_TZ)
ADMIN = {"id": "admin-one", "username": "administrator", "role": "admin", "enabled": True}
BUSINESS = {"id": "business-one", "username": "business.one", "role": "business",
            "enabled": True, "employee_id": "E0038"}


@pytest.fixture
def auth(tmp_path):
    store = AuthStore(tmp_path / "auth.sqlite3")
    store.create_user("administrator", PASSWORD, "admin")
    return store


@pytest.fixture
def gateway(tmp_path):
    bank = build_bank(customer_count=400)
    return AccessGateway(tmp_path, bank["employees"], bank["tasks"], bank["customers"])


def grant(gateway, employee="E0038", export=False):
    return next(task for task in gateway.tasks if task.employee_id == employee and task.allow_export == export)


def command(task, **changes):
    return AccessRequest(**dict(dict(request_id=uuid4(), task_id=task.id, record_count=2,
                                     regions=[task.regions[0]], operation="query"), **changes))


def test_legacy_auth_migration_preserves_password_session_and_foreign_keys(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    seeded = AuthStore(path)
    original = seeded.create_user("administrator", PASSWORD, "admin")
    session = seeded.login("administrator", PASSWORD, "127.0.0.1")
    # Reconstruct the exact pre-binding table constraint/columns, leaving its
    # real scrypt password and authenticated session in place for migration.
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA foreign_keys=OFF")
        db.execute("""CREATE TABLE legacy_users (
            id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
            enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), auth_version INTEGER NOT NULL,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
        db.execute("""INSERT INTO legacy_users
            SELECT id,username,password_hash,role,enabled,auth_version,created_at,updated_at FROM auth_users""")
        db.execute("DROP TABLE auth_users")
        db.execute("ALTER TABLE legacy_users RENAME TO auth_users")
    # Concurrent startup must serialize migration rather than lose identities.
    with ThreadPoolExecutor(max_workers=2) as pool:
        migrated = list(pool.map(lambda _: AuthStore(path), range(2)))
    current = migrated[0].authenticate(session["token"])
    assert current["user"] == original
    assert migrated[1].login("administrator", PASSWORD, "127.0.0.1")["user"]["id"] == original["id"]
    business = migrated[0].create_user("business.one", PASSWORD, "business", employee_id="E0038")
    assert business["employee_id"] == "E0038"
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert db.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 2


@pytest.mark.parametrize("binding", [None, "E0000", "E0101", "E0038 ", "e0038", 38, "E００３８"])
def test_business_account_rejects_missing_or_invalid_binding(auth, binding):
    with pytest.raises(AuthError, match="employee_binding_required|invalid_employee_id"):
        auth.create_user("business.one", PASSWORD, "business", employee_id=binding)
    assert len(auth.list_users()) == 1


def test_employee_change_revokes_sessions_and_role_change_requires_binding(auth):
    auth.create_user("business.one", PASSWORD, "viewer")
    with pytest.raises(AuthError, match="employee_binding_required"):
        auth.set_role("business.one", "business")
    auth.set_employee_id("business.one", "E0038")
    auth.set_role("business.one", "business")
    session = auth.login("business.one", PASSWORD, "127.0.0.1")
    assert session["user"]["employee_id"] == "E0038"
    auth.set_employee_id("business.one", "E0038")
    assert auth.authenticate(session["token"])
    with pytest.raises(AuthError, match="employee_binding_required"):
        auth.set_employee_id("business.one", None)
    assert auth.authenticate(session["token"])
    auth.set_employee_id("business.one", "E0039")
    assert auth.authenticate(session["token"]) is None
    updated = auth.set_role("business.one", "viewer")
    assert updated["employee_id"] == "E0039"
    auth.set_employee_id("business.one", None)
    assert auth.list_users()[1]["employee_id"] is None


def test_business_tasks_and_delivery_are_bound_to_employee(gateway):
    tasks = gateway.available_tasks(BUSINESS)
    assert tasks and {task["employee_id"] for task in tasks} == {"E0038"}
    own = grant(gateway)
    delivered = gateway.execute(command(own), BUSINESS, at=AT)
    assert delivered["allowed"] and len(delivered["rows"]) == 2
    assert delivered["employee_id"] == "E0038"
    with pytest.raises(GatewayError, match="employee_scope_denied"):
        gateway.execute(command(grant(gateway, "E0039")), BUSINESS, at=AT)
    assert gateway.verify() == {"valid": True, "checked_operations": 1}
    assert gateway.quota.summary(grant(gateway, "E0039"), "E0039")["used_records"] == 0


def test_business_history_is_actor_and_current_binding_scoped_without_redelivery(gateway):
    own = grant(gateway, export=True)
    mine = gateway.execute(command(own, operation="export"), BUSINESS, at=AT)
    second_actor = dict(BUSINESS, id="business-two", username="business.two")
    theirs = gateway.execute(command(own), second_actor, at=AT)
    before = gateway.quota.summary(own, own.employee_id)
    assert [row["request_id"] for row in gateway.recent(BUSINESS)] == [mine["request_id"]]
    assert [row["request_id"] for row in gateway.recent(second_actor)] == [theirs["request_id"]]
    assert gateway.operation(theirs["request_id"], BUSINESS) is None
    assert gateway.operation(mine["request_id"], second_actor) is None
    detail = gateway.operation(mine["request_id"], BUSINESS)
    assert detail["evidence_hash"] == mine["evidence_hash"]
    assert not {"rows", "csv", "customer_ids", "events", "replayed"} & detail.keys()
    assert gateway.quota.summary(own, own.employee_id) == before
    rebound = dict(BUSINESS, employee_id="E0039")
    assert gateway.recent(rebound) == [] and gateway.operation(mine["request_id"], rebound) is None
    assert len(gateway.recent(ADMIN)) == 2
    assert gateway.operation(theirs["request_id"], ADMIN)["request_id"] == theirs["request_id"]


@pytest.mark.parametrize("checkpoint", [1, 2, 3])
def test_live_employee_rebinding_at_every_authorization_checkpoint_prevents_delivery(gateway, checkpoint):
    calls = 0
    task = grant(gateway)

    def authorize():
        nonlocal calls
        calls += 1
        return dict(BUSINESS, employee_id="E0039" if calls >= checkpoint else "E0038")

    with pytest.raises(GatewayError, match="employee_scope_denied"):
        gateway.execute(command(task), BUSINESS, at=AT, authorize=authorize)
    assert gateway.recent() == []
    # A last-moment denial keeps already confirmed capacity conservative;
    # critically, it never records an allowed decision or returns rows.
    assert gateway.quota.summary(task, task.employee_id)["used_records"] == (2 if checkpoint == 3 else 0)


def test_replay_revalidates_current_employee_and_does_not_expose_previous_rows(gateway):
    task = grant(gateway)
    request = command(task)
    gateway.execute(request, BUSINESS, at=AT)
    calls = 0

    def authorize():
        nonlocal calls
        calls += 1
        return BUSINESS if calls == 1 else dict(BUSINESS, employee_id="E0039")

    with pytest.raises(GatewayError, match="employee_scope_denied"):
        gateway.execute(request, BUSINESS, at=AT, authorize=authorize)
    assert gateway.verify()["checked_operations"] == 1
    assert gateway.quota.summary(task, task.employee_id)["used_records"] == 2


@pytest.mark.parametrize("current", [dict(BUSINESS, role="viewer"), dict(BUSINESS, enabled=False),
                                     dict(BUSINESS, id="another-principal")])
def test_binding_does_not_authorize_disabled_demoted_or_swapped_principal(gateway, current):
    with pytest.raises(GatewayError, match="insufficient_role"):
        gateway.execute(command(grant(gateway)), BUSINESS, at=AT, authorize=lambda: current)
    assert gateway.recent() == []


def test_history_request_id_collision_never_picks_another_actors_decision(gateway):
    task = grant(gateway)
    request = command(task)
    own = gateway.execute(request, BUSINESS, at=AT)
    second = dict(BUSINESS, id="business-two", username="business.two")
    gateway.execute(request, second, at=AT)
    assert gateway.operation(request.request_id, BUSINESS)["evidence_hash"] == own["evidence_hash"]
    with pytest.raises(GatewayError, match="ambiguous_request_id"):
        gateway.operation(request.request_id, ADMIN)


def test_http_business_workspace_executes_real_rows_but_rejects_security_and_other_employees(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from datafence.api import create_app

    monkeypatch.setenv("DATAFENCE_NETWORK_MODE", "local")
    monkeypatch.setenv("DATAFENCE_AUTH_MODE", "required")
    monkeypatch.setenv("DATAFENCE_BEHAVIOR_MODEL", "legacy")
    monkeypatch.setenv("DATAFENCE_LLM_PROVIDER", "ollama")
    for name in ("DATAFENCE_LLM_MODEL", "DATAFENCE_SERVER_PORT", "DATAFENCE_ALLOWED_HOSTS", "DATAFENCE_ALLOWED_ORIGINS"):
        monkeypatch.delenv(name, raising=False)

    class FixedGatewayClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return AT.astimezone(tz) if tz else AT.replace(tzinfo=None)

    monkeypatch.setattr("datafence.gateway.datetime", FixedGatewayClock)
    with TestClient(create_app(tmp_path, customer_count=400), base_url="http://127.0.0.1",
                    client=("127.0.0.1", 50321)) as client:
        bootstrap = client.post("/api/auth/bootstrap", json={"username": "administrator", "password": PASSWORD})
        assert bootstrap.status_code == 200
        client.headers["X-DataFence-Token"] = bootstrap.json()["token"]
        for username, employee in (("business.one", "E0038"), ("business.two", "E0039")):
            response = client.post("/api/auth/users", json={"username": username, "password": PASSWORD,
                                                            "role": "business", "employee_id": employee})
            assert response.status_code == 201 and response.json()["employee_id"] == employee
        login = client.post("/api/auth/login", json={"username": "business.one", "password": PASSWORD})
        assert login.status_code == 200
        client.headers["X-DataFence-Token"] = login.json()["token"]
        tasks = client.get("/api/access/tasks")
        assert tasks.status_code == 200 and {task["employee_id"] for task in tasks.json()} == {"E0038"}
        own = grant(client.app.state.gateway)
        requested = command(own)
        delivery = client.post("/api/access/execute", json=requested.model_dump(mode="json"))
        assert delivery.status_code == 200 and len(delivery.json()["rows"]) == 2
        for path in ("/api/health", "/api/employees", "/api/scenarios", "/api/events", "/api/security/queue",
                     "/api/auth/users", "/api/access/verify"):
            assert client.get(path).status_code == 403, path
        assert client.post("/api/runs", json={"scenario_id": "normal", "record_count": 2}).status_code == 403
        stolen = command(grant(client.app.state.gateway, "E0039"))
        assert client.post("/api/access/execute", json=stolen.model_dump(mode="json")).status_code == 403
        detail = client.get(f"/api/access/operations/{requested.request_id}")
        assert detail.status_code == 200 and not {"rows", "csv", "customer_ids", "events"} & detail.json().keys()
        second = client.post("/api/auth/login", json={"username": "business.two", "password": PASSWORD})
        assert second.status_code == 200
        client.headers["X-DataFence-Token"] = second.json()["token"]
        assert client.get("/api/access/operations").json() == []
        assert client.get(f"/api/access/operations/{requested.request_id}").status_code == 404
        client.app.state.auth.set_employee_id("business.two", "E0040")
        assert client.get("/api/access/tasks").status_code == 401
