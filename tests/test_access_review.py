"""Independent review regressions: temporary data, in-process HTTP, no network."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import json
import threading
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from datafence.api import create_app
from datafence.gateway import AccessGateway, AccessRequest, GatewayError
from datafence.sandbox import BANK_TZ, build_bank


AT = datetime(2026, 9, 19, 10, 0, tzinfo=BANK_TZ)
ACTOR = {"id": "review-operator", "username": "review.operator", "role": "analyst", "enabled": True}
PASSWORD = "isolated review account passphrase"


@pytest.fixture(autouse=True)
def isolated_offline(monkeypatch, tmp_path):
    monkeypatch.setenv("DATAFENCE_NETWORK_MODE", "local")
    monkeypatch.setenv("DATAFENCE_AUTH_MODE", "required")
    monkeypatch.setenv("DATAFENCE_BEHAVIOR_MODEL", "legacy")
    monkeypatch.setenv("DATAFENCE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DATAFENCE_LLM_PROVIDER", "ollama")
    monkeypatch.delenv("DATAFENCE_LLM_MODEL", raising=False)
    monkeypatch.delenv("DATAFENCE_SERVER_PORT", raising=False)


def setup_gateway(tmp_path, *, expires=None):
    bank = build_bank(customer_count=100)
    grant = next(task for task in bank["tasks"] if task.employee_id == "E0038" and task.allow_export)
    if expires is not None:
        grant = grant.model_copy(update={"valid_until": expires})
    gate = AccessGateway(tmp_path, bank["employees"], [grant], bank["customers"])
    return gate, grant


def command(grant):
    return AccessRequest(request_id=uuid4(), task_id=grant.id, record_count=2, regions=[grant.regions[0]])


@pytest.mark.parametrize("damage", ["modified_count", "missing_hash", "array", "invalid_json"])
def test_new_request_fails_closed_when_prior_evidence_is_corrupt(tmp_path, damage):
    gate, grant = setup_gateway(tmp_path)
    first = gate.execute(command(grant), ACTOR, at=AT)
    assert first["allowed"]
    with gate.connect() as db:
        saved = json.loads(db.execute("SELECT payload FROM deliveries").fetchone()[0])
        if damage == "modified_count": saved["delivered_records"] = 999
        elif damage == "missing_hash": del saved["evidence_hash"]
        payload = "[]" if damage == "array" else "not JSON" if damage == "invalid_json" else json.dumps(saved)
        db.execute("UPDATE deliveries SET payload=?", (payload,))
    assert gate.verify()["valid"] is False
    with pytest.raises(GatewayError, match="^invalid_evidence$"):
        gate.execute(command(grant), ACTOR, at=AT + timedelta(seconds=1))
    with gate.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 1
    assert gate.quota.summary(gate.tasks[0], grant.employee_id)["used_records"] == 2


def test_queued_request_rechecks_grant_clock_after_waiting_for_gateway(tmp_path, monkeypatch):
    gate, grant = setup_gateway(tmp_path, expires=AT + timedelta(seconds=1))
    clock = [AT]
    entered = threading.Event()
    class ReviewClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0].astimezone(tz) if tz else clock[0].replace(tzinfo=None)
    class ObservedLock:
        def __enter__(self):
            entered.set()
            gate_lock.acquire()
        def __exit__(self, *_):
            gate_lock.release()
    monkeypatch.setattr("datafence.gateway.datetime", ReviewClock)
    gate_lock = threading.Lock()
    gate.lock = ObservedLock()
    gate_lock.acquire()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(gate.execute, command(grant), ACTOR)
        assert entered.wait(timeout=5)
        clock[0] = AT + timedelta(seconds=2)
        gate_lock.release()
        result = pending.result(timeout=10)
    assert result["allowed"] is False
    assert result["rows"] == [] and result["delivered_records"] == 0
    assert gate.quota.summary(gate.tasks[0], grant.employee_id)["used_records"] == 0


@pytest.mark.parametrize("revoke", ["disable", "demote", "password", "logout"])
def test_revocation_during_request_body_prevents_gateway_delivery(tmp_path, revoke):
    async def run():
        app = create_app(tmp_path, customer_count=100)
        async with app.router.lifespan_context(app):
            auth = app.state.auth
            auth.create_user("review.admin", PASSWORD, "admin")
            auth.create_user("review.operator", PASSWORD, "analyst")
            grant = next(t for t in app.state.gateway.tasks if t.employee_id == "E0038" and t.allow_export)
            transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 45678))
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
                logged_in = await client.post("/api/auth/login", json={"username": "review.operator", "password": PASSWORD})
                assert logged_in.status_code == 200
                token = client.cookies.get("df_session")
                body = command(grant).model_dump_json().encode()
                async def slow_body():
                    yield body[:1]
                    if revoke == "disable": auth.set_enabled("review.operator", False)
                    elif revoke == "demote": auth.set_role("review.operator", "viewer")
                    elif revoke == "password": auth.set_password("review.operator", PASSWORD + " changed")
                    else: auth.logout(token)
                    assert auth.authenticate(token) is None
                    yield body[1:]
                response = await client.post("/api/access/execute", content=slow_body(), headers={
                    "Content-Type": "application/json", "X-DataFence-Token": logged_in.json()["token"]})
                assert response.status_code == 401
                assert "rows" not in response.json() and "csv" not in response.json()
                assert app.state.gateway.recent() == []
                assert app.state.gateway.quota.summary(grant, grant.employee_id)["used_records"] == 0
    asyncio.run(run())


@pytest.mark.parametrize("revoke", ["disable", "demote", "password", "logout"])
def test_revocation_while_waiting_for_gateway_lock_prevents_delivery(tmp_path, revoke):
    async def run():
        app = create_app(tmp_path, customer_count=100)
        async with app.router.lifespan_context(app):
            auth, gate = app.state.auth, app.state.gateway
            auth.create_user("review.admin", PASSWORD, "admin")
            auth.create_user("review.operator", PASSWORD, "analyst")
            grant = next(t for t in gate.tasks if t.employee_id == "E0038" and t.allow_export)
            entered, unlock = threading.Event(), threading.Event()
            class DelayedLock:
                def __enter__(self):
                    entered.set()
                    assert unlock.wait(timeout=5)
                def __exit__(self, *_):
                    pass
            gate.lock = DelayedLock()
            transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 45678))
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
                logged_in = await client.post("/api/auth/login", json={"username": "review.operator", "password": PASSWORD})
                token = client.cookies.get("df_session")
                pending = asyncio.create_task(client.post("/api/access/execute", json=command(grant).model_dump(mode="json"),
                    headers={"X-DataFence-Token": logged_in.json()["token"]}))
                try:
                    assert await asyncio.to_thread(entered.wait, 5)
                    if revoke == "disable": auth.set_enabled("review.operator", False)
                    elif revoke == "demote": auth.set_role("review.operator", "viewer")
                    elif revoke == "password": auth.set_password("review.operator", PASSWORD + " changed")
                    else: auth.logout(token)
                finally:
                    unlock.set()
                response = await pending
                assert response.status_code == 401
                assert "rows" not in response.json() and "csv" not in response.json()
                assert gate.recent() == []
                assert gate.quota.summary(grant, grant.employee_id)["used_records"] == 0
    asyncio.run(run())


def test_sse_stops_new_updates_after_session_revocation(tmp_path, monkeypatch):
    async def run():
        app = create_app(tmp_path, customer_count=100)
        async with app.router.lifespan_context(app):
            auth, store = app.state.auth, app.state.service.store
            auth.create_user("review.admin", PASSWORD, "admin")
            auth.create_user("review.observer", PASSWORD, "viewer")
            run_id = str(uuid4())
            store.save("runs", {"id": run_id, "status": "running", "note": "before-revocation"})
            sleeps = []
            async def revoke_before_next_update(seconds):
                sleeps.append(seconds)
                auth.set_enabled("review.observer", False)
                store.save("runs", {"id": run_id, "status": "completed", "note": "after-revocation-private-update"})
            monkeypatch.setattr("datafence.api.asyncio", SimpleNamespace(to_thread=asyncio.to_thread, sleep=revoke_before_next_update))
            transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 45678))
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
                logged_in = await client.post("/api/auth/login", json={"username": "review.observer", "password": PASSWORD})
                assert logged_in.status_code == 200
                response = await client.get(f"/api/runs/{run_id}/stream")
                assert response.status_code == 200 and sleeps == [0.5]
                assert "before-revocation" in response.text
                assert "after-revocation-private-update" not in response.text
                assert response.text.count("event: update") == 1
    asyncio.run(run())


def test_expiry_during_detection_does_not_charge_or_deliver(tmp_path, monkeypatch):
    from datafence.engine import DetectionEngine
    gate, grant = setup_gateway(tmp_path, expires=AT + timedelta(seconds=1))
    clock = [AT]
    class ReviewClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0].astimezone(tz) if tz else clock[0].replace(tzinfo=None)
    original = DetectionEngine.analyze
    def crossing_deadline(engine, event):
        result = original(engine, event)
        clock[0] = AT + timedelta(seconds=2)
        return result
    monkeypatch.setattr("datafence.gateway.datetime", ReviewClock)
    monkeypatch.setattr(DetectionEngine, "analyze", crossing_deadline)
    result = gate.execute(command(grant), ACTOR)
    assert not result["allowed"] and result["rows"] == []
    assert "GATEWAY_GRANT_DENIED" in result["analysis"]["rules"]
    assert gate.quota.summary(gate.tasks[0], grant.employee_id)["used_records"] == 0


def test_expiry_during_quota_confirmation_never_returns_rows(tmp_path, monkeypatch):
    gate, grant = setup_gateway(tmp_path, expires=AT + timedelta(seconds=1))
    clock = [AT]
    class ReviewClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0].astimezone(tz) if tz else clock[0].replace(tzinfo=None)
    original = gate.quota.confirm
    def crossing_deadline(event_id):
        result = original(event_id)
        clock[0] = AT + timedelta(seconds=2)
        return result
    monkeypatch.setattr("datafence.gateway.datetime", ReviewClock)
    monkeypatch.setattr(gate.quota, "confirm", crossing_deadline)
    with pytest.raises(GatewayError, match="^grant_expired_or_changed$"):
        gate.execute(command(grant), ACTOR)
    # An already confirmed reservation is conservative, not silently refunded.
    assert gate.quota.summary(gate.tasks[0], grant.employee_id)["confirmed_records"] == 2
    assert gate.recent() == []  # No false allowed/delivered receipt for this refusal.
    assert gate.verify() == {"valid": True, "checked_operations": 0}


def test_revocation_during_quota_confirmation_never_returns_rows(tmp_path, monkeypatch):
    async def run():
        app = create_app(tmp_path, customer_count=100)
        async with app.router.lifespan_context(app):
            auth, gate = app.state.auth, app.state.gateway
            auth.create_user("review.admin", PASSWORD, "admin")
            auth.create_user("review.operator", PASSWORD, "analyst")
            grant = next(t for t in gate.tasks if t.employee_id == "E0038" and t.allow_export)
            original = gate.quota.confirm
            def revoke_after_confirm(event_id):
                result = original(event_id)
                auth.set_enabled("review.operator", False)
                return result
            monkeypatch.setattr(gate.quota, "confirm", revoke_after_confirm)
            transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 45678))
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
                logged_in = await client.post("/api/auth/login", json={"username": "review.operator", "password": PASSWORD})
                response = await client.post("/api/access/execute", json=command(grant).model_dump(mode="json"),
                    headers={"X-DataFence-Token": logged_in.json()["token"]})
                assert response.status_code == 401
                assert "rows" not in response.json() and "csv" not in response.json()
                assert gate.quota.summary(grant, grant.employee_id)["confirmed_records"] == 2
                assert gate.recent() == []
                assert gate.verify() == {"valid": True, "checked_operations": 0}
    asyncio.run(run())
