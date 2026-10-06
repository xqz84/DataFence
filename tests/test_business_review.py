"""Independent business boundary review: real sessions and storage fault cases."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import sqlite3
import threading
from uuid import uuid4

import pytest

from datafence.auth import AuthError, AuthStore
from datafence.gateway import AccessGateway, AccessRequest, GatewayError
from datafence.sandbox import BANK_TZ, build_bank


PASSWORD = "review-business-isolated-passphrase"
AT = datetime(2026, 9, 19, 10, tzinfo=BANK_TZ)


@pytest.fixture
def environment(tmp_path):
    auth = AuthStore(tmp_path / "auth.sqlite3")
    auth.create_user("review.admin", PASSWORD, "admin")
    auth.create_user("review.business", PASSWORD, "business", employee_id="E0038")
    session = auth.login("review.business", PASSWORD, "127.0.0.1")
    bank = build_bank(customer_count=400)
    gateway = AccessGateway(tmp_path, bank["employees"], bank["tasks"], bank["customers"])
    task = next(task for task in gateway.tasks if task.employee_id == "E0038" and task.allow_export)
    return auth, session, gateway, task


def request(task, **changes):
    return AccessRequest(**dict(dict(request_id=uuid4(), task_id=task.id, record_count=2,
                                     operation="query", regions=[task.regions[0]]), **changes))


def change_account(auth, change):
    if change == "disable":
        auth.set_enabled("review.business", False)
    elif change == "demote":
        auth.set_role("review.business", "viewer")
    else:
        auth.set_employee_id("review.business", "E0039")


def authorizer(auth, session):
    def check():
        current = auth.authenticate(session["token"])
        if current is None:
            raise GatewayError("session_revoked")
        return current["user"]
    return check


@pytest.mark.parametrize("change", ["disable", "demote", "rebind"])
def test_real_business_session_changed_while_queued_never_delivers(environment, change):
    auth, session, gate, task = environment
    waiting, release = threading.Event(), threading.Event()

    class QueuedLock:
        def __enter__(self):
            waiting.set()
            assert release.wait(timeout=5)

        def __exit__(self, *_):
            pass

    gate.lock = QueuedLock()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(gate.execute, request(task), session["user"], AT,
                              authorize=authorizer(auth, session))
        try:
            assert waiting.wait(timeout=5)
            change_account(auth, change)
        finally:
            release.set()
        with pytest.raises(GatewayError, match="session_revoked"):
            pending.result(timeout=5)
    assert gate.recent() == []
    assert gate.quota.summary(task, task.employee_id)["used_records"] == 0
    assert gate.verify() == {"valid": True, "checked_operations": 0}


@pytest.mark.parametrize("change", ["disable", "demote", "rebind"])
def test_late_business_revocation_keeps_quota_conservative_without_delivery(environment, monkeypatch, change):
    auth, session, gate, task = environment
    original_confirm = gate.quota.confirm

    def confirm_then_change(event_id):
        result = original_confirm(event_id)
        change_account(auth, change)
        return result

    monkeypatch.setattr(gate.quota, "confirm", confirm_then_change)
    with pytest.raises(GatewayError, match="session_revoked"):
        gate.execute(request(task), session["user"], AT, authorize=authorizer(auth, session))
    assert gate.recent() == []
    quota = gate.quota.summary(task, task.employee_id)
    assert quota["used_records"] == quota["confirmed_records"] == 2
    assert quota["reserved_records"] == 0
    assert gate.verify() == {"valid": True, "checked_operations": 0}


def test_legacy_migration_failure_preserves_schema_users_and_sessions(tmp_path):
    path = tmp_path / "old.sqlite3"
    seeded = AuthStore(path)
    seeded.create_user("review.admin", PASSWORD, "admin")
    seeded.login("review.admin", PASSWORD, "127.0.0.1")
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA foreign_keys=OFF")
        db.execute("""CREATE TABLE old_users (
            id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
            enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), auth_version INTEGER NOT NULL,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
        db.execute("""INSERT INTO old_users SELECT id,username,password_hash,role,enabled,
                      auth_version,created_at,updated_at FROM auth_users""")
        db.execute("DROP TABLE auth_users")
        db.execute("ALTER TABLE old_users RENAME TO auth_users")
        # Fault already present in the old DB: force the migration's final FK
        # verification to fail after table replacement but before commit.
        db.execute("UPDATE auth_sessions SET user_id='missing-principal'")
        before_users = db.execute("SELECT * FROM auth_users").fetchall()
        before_sessions = db.execute("SELECT * FROM auth_sessions").fetchall()
        before_schema = db.execute("SELECT sql FROM sqlite_master WHERE name='auth_users'").fetchone()[0]
    with pytest.raises(AuthError, match="auth_unavailable"):
        AuthStore(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM auth_users").fetchall() == before_users
        assert db.execute("SELECT * FROM auth_sessions").fetchall() == before_sessions
        assert db.execute("SELECT sql FROM sqlite_master WHERE name='auth_users'").fetchone()[0] == before_schema
        assert db.execute("SELECT name FROM sqlite_master WHERE name='auth_users_employee_migration'").fetchone() is None


def test_grant_refusal_is_not_reported_as_quota_exhaustion(environment):
    _, session, gate, task = environment
    expired = task.model_copy(update={"valid_until": AT - timedelta(seconds=1)})
    gate.tasks = [expired]
    result = gate.execute(request(expired), session["user"], AT)
    assert not result["allowed"] and result["rows"] == []
    assert result["quota"]["status"] == "not_applicable"
    assert result["quota"]["reason"] == "policy_blocked"
    assert "QUOTA_EXCEEDED" not in result["analysis"]["rules"]
    assert "GATEWAY_GRANT_DENIED" in result["analysis"]["rules"]
    assert gate.available_tasks(session["user"])[0]["quota"]["used_records"] == 0


def test_small_delivery_does_not_misrepresent_requested_quota_or_history(environment):
    _, session, gate, task = environment
    command = request(task, record_count=100, operation="export")
    result = gate.execute(command, session["user"], AT)
    assert result["allowed"] and result["delivered_records"] == len(result["rows"]) == 20
    assert result["requested_records"] == result["quota"]["used_records"] == 100
    history = gate.operation(command.request_id, session["user"])
    assert history["delivered_records"] == 20 and history["requested_records"] == 100
    assert not {"rows", "csv", "customer_ids", "events"}.intersection(history)
    assert gate.quota.summary(task, task.employee_id)["used_records"] == 100
