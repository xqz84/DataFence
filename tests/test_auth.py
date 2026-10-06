"""Real scrypt and SQLite lifecycle tests; credentials are synthetic fixtures."""

from concurrent.futures import ThreadPoolExecutor
import importlib.util
from pathlib import Path
import sqlite3
import threading

import pytest

import datafence.auth as auth
from datafence.auth import AuthError, AuthStore


PASSWORD = "synthetic test passphrase 2026"
NEW_PASSWORD = "another synthetic passphrase 2026"
IP = "127.0.0.1"


@pytest.fixture
def store(tmp_path):
    result = AuthStore(tmp_path / "auth.sqlite3")
    result.create_user("administrator", PASSWORD, "admin")
    return result


def error_code(action, expected):
    with pytest.raises(AuthError) as error:
        action()
    assert error.value.code == expected
    assert str(error.value) == expected
    return error.value


def test_no_defaults_and_first_user_requires_admin(tmp_path):
    store = AuthStore(tmp_path / "auth.sqlite3")
    assert not store.initialized() and store.list_users() == []
    error_code(lambda: store.create_user("observer", PASSWORD), "first_user_must_be_admin")
    assert not store.initialized()
    user = store.create_user(" Administrator ", PASSWORD, "admin")
    assert store.initialized() and user["username"] == "administrator"
    assert set(user) == {"id", "username", "role", "enabled", "created_at", "updated_at", "employee_id"}
    error_code(lambda: store.create_user("ADMINISTRATOR", PASSWORD, "admin"), "username_taken")


def test_scrypt_uses_distinct_salts_and_never_persists_raw_password_or_tokens(store):
    store.create_user("observer", PASSWORD, "viewer")
    session = store.login("administrator", PASSWORD, IP)
    with sqlite3.connect(store.path) as db:
        hashes = [row[0] for row in db.execute("SELECT password_hash FROM auth_users")]
        persisted = "\n".join(db.iterdump())
    assert hashes[0] != hashes[1]
    assert all(value.startswith("scrypt$1$32768$8$3$") for value in hashes)
    assert PASSWORD not in persisted and session["token"] not in persisted and session["csrf_token"] not in persisted
    assert auth._digest(session["token"]) in persisted
    assert all("password_hash" not in row for row in store.list_users())


@pytest.mark.parametrize("password", ["", "x" * 14, "x" * 129, None, "\ud800" * 15])
def test_password_bounds_are_rejected_without_creating_accounts(store, password):
    error_code(lambda: store.create_user("newperson", password), "invalid_password")
    assert len(store.list_users()) == 1


def test_unicode_and_spaces_are_preserved(store):
    password = "  合成环境中的独立测试长口令密码🔒  "
    store.create_user("unicode.user", password)
    assert store.login("unicode.user", password, IP)["user"]["role"] == "viewer"
    error_code(lambda: store.login("unicode.user", password.strip(), IP), "invalid_credentials")


@pytest.mark.parametrize("username", ["ab", "../administrator", "name@example.com", "a" * 65, "用户姓名", None])
def test_username_bounds(store, username):
    error_code(lambda: store.create_user(username, PASSWORD), "invalid_input")


def test_unknown_wrong_disabled_and_malformed_users_share_login_error(store):
    store.create_user("disabled.user", PASSWORD)
    store.set_enabled("disabled.user", False)
    for username, password in [("not.created", PASSWORD), ("administrator", NEW_PASSWORD),
                               ("disabled.user", PASSWORD), ("??", PASSWORD), ("administrator", "short")]:
        error_code(lambda: store.login(username, password, IP), "invalid_credentials")


def test_fixed_expiry_and_csrf_survive_restart_without_sliding(tmp_path):
    clock = [2000000000]
    store = AuthStore(tmp_path / "auth.sqlite3", session_ttl_seconds=60, clock=lambda: clock[0])
    store.create_user("administrator", PASSWORD, "admin")
    login = store.login("administrator", PASSWORD, IP)
    clock[0] += 59
    restored = AuthStore(store.path, session_ttl_seconds=3600, clock=lambda: clock[0])
    current = restored.authenticate(login["token"])
    assert current["expires_unix"] == login["expires_unix"]
    assert current["csrf_token"] == login["csrf_token"] and "token" not in current
    assert restored.verify_csrf(login["token"], login["csrf_token"])
    clock[0] += 1
    assert restored.authenticate(login["token"]) is None
    assert not restored.verify_csrf(login["token"], login["csrf_token"])


def test_session_csrf_isolation_and_idempotent_logout(store):
    first = store.login("administrator", PASSWORD, IP)
    second = store.login("administrator", PASSWORD, IP)
    assert first["token"] != second["token"]
    assert not store.verify_csrf(first["token"], second["csrf_token"])
    assert not store.verify_csrf(first["token"], first["token"])
    assert store.authenticate(first["csrf_token"]) is None
    store.logout(first["token"])
    store.logout(first["token"])
    assert store.authenticate(first["token"]) is None
    assert store.authenticate(second["token"]) is not None
    for invalid in (None, "", "bad", "a" * 100000, "😀" * 43):
        assert store.authenticate(invalid) is None
        assert not store.verify_csrf(invalid, None)
        store.logout(invalid)


@pytest.mark.parametrize("change", ["disable", "password", "role"])
def test_account_changes_revoke_all_sessions(store, change):
    store.create_user("analyst01", PASSWORD, "analyst")
    sessions = [store.login("analyst01", PASSWORD, IP) for _ in range(2)]
    if change == "disable":
        store.set_enabled("analyst01", False)
        store.set_enabled("analyst01", True)
    elif change == "password":
        store.set_password("analyst01", NEW_PASSWORD)
    else:
        store.set_role("analyst01", "viewer")
    assert all(store.authenticate(item["token"]) is None for item in sessions)
    password = NEW_PASSWORD if change == "password" else PASSWORD
    assert store.login("analyst01", password, IP)["user"]["enabled"]


def test_last_admin_protection_and_disabled_admin_does_not_count(store):
    error_code(lambda: store.set_enabled("administrator", False), "last_admin_required")
    error_code(lambda: store.set_role("administrator", "viewer"), "last_admin_required")
    store.create_user("second.admin", PASSWORD, "admin")
    store.set_enabled("second.admin", False)
    error_code(lambda: store.set_enabled("administrator", False), "last_admin_required")


@pytest.mark.parametrize("operation", ["disable", "demote"])
def test_concurrent_admin_changes_preserve_one_enabled_admin(store, operation):
    store.create_user("second.admin", PASSWORD, "admin")
    stores = [AuthStore(store.path), AuthStore(store.path)]
    gate = threading.Barrier(2)
    def change(index):
        gate.wait(timeout=2)
        try:
            username = ("administrator", "second.admin")[index]
            if operation == "disable":
                stores[index].set_enabled(username, False)
            else:
                stores[index].set_role(username, "viewer")
            return "changed"
        except AuthError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(change, range(2)))
    assert sorted(results) == ["changed", "last_admin_required"]
    assert sum(user["role"] == "admin" and user["enabled"] for user in store.list_users()) == 1


def test_login_rate_reservations_are_atomic_across_concurrent_connections_and_restart(store):
    stores = [AuthStore(store.path) for _ in range(10)]
    gate = threading.Barrier(10)
    def attempt(index):
        gate.wait(timeout=2)
        try:
            stores[index].login("ADMINISTRATOR", NEW_PASSWORD, f"127.0.0.{index + 1}")
            return "unexpected"
        except AuthError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(attempt, range(10)))
    assert results.count("invalid_credentials") == 5
    assert results.count("rate_limited") == 5
    restored = AuthStore(store.path)
    result = error_code(lambda: restored.login("administrator", PASSWORD, "127.1.2.3"), "rate_limited")
    assert 1 <= result.retry_after <= 300
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT COUNT(*) FROM auth_login_attempts").fetchone()[0] == 5


def test_ip_quota_stops_username_rotation_and_normalizes_ipv4_mapped_addresses(store, monkeypatch):
    # Actual scrypt is covered above; this test isolates 30 transactional IP slots.
    monkeypatch.setattr(auth, "_verify_password", lambda *args: False)
    for index in range(30):
        error_code(lambda: store.login(f"missing{index}", PASSWORD, IP), "invalid_credentials")
    error_code(lambda: store.login("different.user", PASSWORD, "::ffff:127.0.0.1"), "rate_limited")
    error_code(lambda: store.login("different.user", PASSWORD, "127.0.0.2"), "invalid_credentials")


def test_failed_attempt_window_expires_but_is_not_reset_by_success(tmp_path):
    clock = [2000000000]
    store = AuthStore(tmp_path / "auth.sqlite3", clock=lambda: clock[0])
    store.create_user("administrator", PASSWORD, "admin")
    for _ in range(3):
        error_code(lambda: store.login("administrator", NEW_PASSWORD, IP), "invalid_credentials")
    assert store.login("administrator", PASSWORD, IP)["user"]["role"] == "admin"
    for _ in range(2):
        error_code(lambda: store.login("administrator", NEW_PASSWORD, IP), "invalid_credentials")
    error_code(lambda: store.login("administrator", PASSWORD, IP), "rate_limited")
    clock[0] += 300
    assert store.login("administrator", PASSWORD, IP)["user"]["role"] == "admin"


@pytest.mark.parametrize("change", ["disable", "password", "role"])
def test_account_change_during_password_check_cannot_mint_a_stale_session(store, monkeypatch, change):
    store.create_user("analyst01", PASSWORD, "analyst")
    checking, release = threading.Event(), threading.Event()
    def pause_verification(*args):
        checking.set()
        assert release.wait(timeout=3)
        return True
    monkeypatch.setattr(auth, "_verify_password", pause_verification)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(store.login, "analyst01", PASSWORD, IP)
        assert checking.wait(timeout=2)
        if change == "disable":
            store.set_enabled("analyst01", False)
        elif change == "password":
            store.set_password("analyst01", NEW_PASSWORD)
        else:
            store.set_role("analyst01", "viewer")
        release.set()
        error_code(future.result, "invalid_credentials")
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0


def test_corrupt_password_parameters_cannot_allocate_attacker_selected_memory(store, monkeypatch):
    calls = []
    def derive(password, **kwargs):
        calls.append(kwargs)
        return bytes(64)
    monkeypatch.setattr(auth.hashlib, "scrypt", derive)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE auth_users SET password_hash=?", ("scrypt$1$1073741824$999$999$" + "0" * 32 + "$" + "0" * 128,))
    error_code(lambda: store.login("administrator", PASSWORD, IP), "invalid_credentials")
    assert calls[0]["n"] == 32768 and calls[0]["r"] == 8 and calls[0]["p"] == 3
    assert calls[0]["maxmem"] == 64 * 1024 * 1024


def test_cli_never_takes_password_in_argv_and_refuses_noninteractive_echo(tmp_path, monkeypatch, capsys):
    path = Path(__file__).resolve().parents[1] / "scripts" / "manage_users.py"
    spec = importlib.util.spec_from_file_location("manage_users_for_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.sys.stdin, "isatty", lambda: False)
    db_path = tmp_path / "never-created.sqlite3"
    assert module.main(["--database", str(db_path), "create", "admin", "--role", "admin"]) == 2
    assert not db_path.exists()
    assert "interactive_terminal_required" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        module.main(["create", "admin", "--password", PASSWORD])
    assert PASSWORD not in capsys.readouterr().err


def test_cli_interactive_create_and_password_change_return_only_public_user(tmp_path, monkeypatch, capsys):
    path = Path(__file__).resolve().parents[1] / "scripts" / "manage_users.py"
    spec = importlib.util.spec_from_file_location("manage_users_interactive_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.sys.stdin, "isatty", lambda: True)
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr(module.getpass, "getpass", lambda _: next(answers))
    db_path = tmp_path / "auth.sqlite3"
    assert module.main(["--database", str(db_path), "create", "admin", "--role", "admin"]) == 0
    output = capsys.readouterr().out
    assert PASSWORD not in output and "password_hash" not in output and '"role": "admin"' in output
    assert AuthStore(db_path).login("admin", PASSWORD, IP)["user"]["role"] == "admin"


def test_bootstrap_condition_is_atomic_across_independent_stores(tmp_path):
    path = tmp_path / "auth.sqlite3"
    stores = [AuthStore(path), AuthStore(path)]
    barrier = threading.Barrier(2)
    def bootstrap(index):
        barrier.wait(timeout=2)
        try:
            stores[index].create_user(f"first.admin{index}", PASSWORD, "admin", require_uninitialized=True)
            return "created"
        except AuthError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(bootstrap, range(2)))
    assert sorted(results) == ["already_initialized", "created"]
    assert len(stores[0].list_users()) == 1


def test_cli_refuses_runtime_owned_by_service_or_maintenance(tmp_path, capsys):
    from datafence.runtime_lock import RuntimeLock
    path = Path(__file__).resolve().parents[1] / "scripts" / "manage_users.py"
    spec = importlib.util.spec_from_file_location("manage_users_lock_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with RuntimeLock(tmp_path):
        assert module.main(["--database", str(tmp_path / "auth.sqlite3"), "list"]) == 3
    assert "stop the service" in capsys.readouterr().err
    assert not (tmp_path / "auth.sqlite3").exists()
