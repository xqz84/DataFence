"""Authenticated HTTP boundary tests; isolated runtime and no model network."""

from fastapi.testclient import TestClient
import pytest

from datafence.api import create_app
from datafence.auth import AuthStore


PASSWORD = "synthetic API passphrase 2026"
WRONG_PASSWORD = "incorrect API passphrase 2026"


@pytest.fixture(autouse=True)
def local_offline_environment(monkeypatch):
    monkeypatch.setenv("DATAFENCE_NETWORK_MODE", "local")
    monkeypatch.setenv("DATAFENCE_AUTH_MODE", "required")
    monkeypatch.setenv("DATAFENCE_LLM_PROVIDER", "ollama")
    monkeypatch.delenv("DATAFENCE_LLM_MODEL", raising=False)
    monkeypatch.delenv("DATAFENCE_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("DATAFENCE_ALLOWED_ORIGINS", raising=False)


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path, customer_count=100), base_url="http://127.0.0.1",
                    client=("127.0.0.1", 50123)) as client:
        yield client


def bootstrap(client):
    response = client.post("/api/auth/bootstrap", json={"username": "administrator", "password": PASSWORD})
    assert response.status_code == 200, response.text
    client.headers["X-DataFence-Token"] = response.json()["token"]
    return response


def login(client, username="administrator", password=PASSWORD):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    if response.status_code == 200:
        client.headers["X-DataFence-Token"] = response.json()["token"]
    return response


@pytest.mark.parametrize("path", ["/api/overview", "/api/health", "/api/session", "/api/events",
                                  "/api/employees", "/api/runs", "/api/evaluations", "/api/openapi.json"])
def test_required_auth_denies_anonymous_business_reads_even_on_loopback(client, path):
    assert client.get(path).status_code == 401
    assert client.get("/api/health/live").status_code == 200
    status = client.get("/api/auth/status").json()
    assert status["authentication_required"] is True and status["initialized"] is False


def test_bootstrap_cookie_and_csrf_are_distinct_and_one_time(client):
    response = bootstrap(client)
    body = response.json()
    cookie = response.headers["set-cookie"]
    assert "httponly" in cookie.lower() and "samesite=strict" in cookie.lower() and "path=/" in cookie.lower()
    raw_session = client.cookies.get("df_session")
    assert raw_session and raw_session != body["token"] and raw_session not in response.text
    assert PASSWORD not in response.text and "password_hash" not in response.text
    assert body["user"]["role"] == "admin"
    current = client.get("/api/session").json()
    assert current["token"] == body["token"] and current["user"]["username"] == "administrator"
    assert client.get("/api/auth/status").json()["initialized"] is True
    assert client.post("/api/auth/bootstrap", json={"username": "other.admin", "password": PASSWORD}).status_code == 409
    assert len(client.app.state.auth.list_users()) == 1


def test_short_bootstrap_password_does_not_initialize(client):
    response = client.post("/api/auth/bootstrap", json={"username": "administrator", "password": "too short"})
    assert response.status_code == 422
    assert not client.app.state.auth.initialized()


def test_authenticated_write_requires_current_session_csrf(client):
    bootstrap(client)
    payload = {"scenario_id": "normal", "record_count": 2, "interval_ms": 0}
    assert client.post("/api/runs", json=payload, headers={"X-DataFence-Token": ""}).status_code == 403
    assert client.post("/api/runs", json=payload, headers={"X-DataFence-Token": "forged"}).status_code == 403
    old_csrf = client.headers["X-DataFence-Token"]
    assert login(client).status_code == 200
    assert old_csrf != client.headers["X-DataFence-Token"]
    assert client.post("/api/runs", json=payload, headers={"X-DataFence-Token": old_csrf}).status_code == 403
    assert client.post("/api/runs", json=payload).status_code == 202


def test_bad_and_unknown_password_errors_are_uniform_and_limit_persists(client):
    bootstrap(client)
    known = login(client, password=WRONG_PASSWORD)
    unknown = login(client, username="unknown.user", password=WRONG_PASSWORD)
    assert known.status_code == unknown.status_code == 401 and known.json() == unknown.json()
    for _ in range(4):
        assert login(client, password=WRONG_PASSWORD).status_code == 401
    limited = login(client)
    assert limited.status_code == 429 and int(limited.headers["retry-after"]) > 0
    assert WRONG_PASSWORD not in limited.text


def test_viewer_can_read_and_logout_but_cannot_run_writes(client):
    bootstrap(client)
    client.app.state.auth.create_user("observer01", PASSWORD, "viewer")
    assert login(client, "observer01").status_code == 200
    assert client.get("/api/overview").status_code == 200
    assert client.post("/api/runs", json={"scenario_id": "normal", "record_count": 2}).status_code == 403
    assert client.post("/api/evaluations", json={"sessions": 20}).status_code == 403
    assert client.post("/api/auth/logout", json={}).status_code == 200
    assert client.get("/api/session").status_code == 401


def test_logout_revokes_server_session_even_if_old_cookie_is_replayed(client):
    bootstrap(client)
    original = client.cookies.get("df_session")
    csrf = client.headers["X-DataFence-Token"]
    assert client.post("/api/auth/logout", json={}).status_code == 200
    assert not client.cookies.get("df_session")
    headers = {"Cookie": "df_session=" + original, "X-DataFence-Token": csrf}
    assert client.get("/api/events", headers=headers).status_code == 401
    assert client.post("/api/runs", json={}, headers=headers).status_code == 401


def test_disabled_user_cookie_and_csrf_stop_working_immediately(client):
    bootstrap(client)
    client.app.state.auth.create_user("analyst01", PASSWORD, "analyst")
    assert login(client, "analyst01").status_code == 200
    client.app.state.auth.set_enabled("analyst01", False)
    assert client.get("/api/events").status_code == 401
    assert client.post("/api/runs", json={}).status_code == 401


def test_validation_never_echoes_password_value(client):
    password = "secret-invalid-long-password-" * 20
    response = client.post("/api/auth/login", json={"username": "administrator", "password": password})
    assert response.status_code == 422 and password not in response.text and "input" not in response.text


def test_origin_and_forwarding_headers_cannot_bypass_local_boundary(tmp_path):
    app = create_app(tmp_path, customer_count=20)
    with TestClient(app, base_url="http://127.0.0.1", client=("192.0.2.10", 50123)) as remote:
        response = remote.post("/api/auth/bootstrap", json={"username": "administrator", "password": PASSWORD},
                               headers={"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"})
        assert response.status_code == 403 and not app.state.auth.initialized()


@pytest.mark.parametrize("headers", [
    {"Origin": "https://untrusted.invalid"},
    {"Origin": "http://127.0.0.1.evil.invalid"},
    {"Origin": "http://attacker@127.0.0.1"},
    {"Sec-Fetch-Site": "cross-site"},
])
def test_bootstrap_rejects_cross_site_requests(client, headers):
    response = client.post("/api/auth/bootstrap", json={"username": "administrator", "password": PASSWORD}, headers=headers)
    assert response.status_code == 403 and not client.app.state.auth.initialized()


def configure_lan(monkeypatch):
    monkeypatch.setenv("DATAFENCE_NETWORK_MODE", "lan")
    monkeypatch.setenv("DATAFENCE_ALLOWED_HOSTS", "datafence.internal")
    monkeypatch.setenv("DATAFENCE_ALLOWED_ORIGINS", "https://datafence.internal:8443")


def test_lan_requires_explicit_configuration_and_refuses_demo_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAFENCE_NETWORK_MODE", "lan")
    with pytest.raises(ValueError):
        create_app(tmp_path, customer_count=20)
    configure_lan(monkeypatch)
    with pytest.raises(ValueError):
        create_app(tmp_path, customer_count=20, auth_mode="local_demo")
    monkeypatch.setenv("DATAFENCE_ALLOWED_ORIGINS", "http://datafence.internal")
    with pytest.raises(ValueError):
        create_app(tmp_path, customer_count=20)


def test_lan_requires_local_initialization_before_server_starts(tmp_path, monkeypatch):
    configure_lan(monkeypatch)
    with pytest.raises(RuntimeError, match="Initialize an administrator"):
        with TestClient(create_app(tmp_path, customer_count=20), base_url="https://datafence.internal:8443",
                        client=("192.0.2.10", 50123)):
            pass


def test_lan_https_secure_cookie_exact_host_origin_and_bootstrap_denial(tmp_path, monkeypatch):
    configure_lan(monkeypatch)
    AuthStore(tmp_path / "auth.sqlite3").create_user("administrator", PASSWORD, "admin")
    app = create_app(tmp_path, customer_count=20)
    with TestClient(app, base_url="https://datafence.internal:8443", client=("192.0.2.10", 50123)) as remote:
        headers = {"Origin": "https://datafence.internal:8443"}
        assert remote.get("/api/auth/status").json()["bootstrap_allowed"] is False
        assert remote.get("/api/overview").status_code == 401
        response = remote.post("/api/auth/login", json={"username": "administrator", "password": PASSWORD}, headers=headers)
        assert response.status_code == 200 and "; secure" in response.headers["set-cookie"].lower()
        remote.headers["X-DataFence-Token"] = response.json()["token"]
        assert remote.get("/api/overview", headers=headers).status_code == 200
        assert remote.get("/api/overview", headers={"Host": "untrusted.internal"}).status_code == 400
        assert remote.get("/api/overview", headers={"Origin": "https://datafence.internal"}).status_code == 403
        assert remote.post("/api/auth/bootstrap", json={"username": "evil.admin", "password": PASSWORD},
                           headers={**headers, "X-Forwarded-For": "127.0.0.1"}).status_code == 403
        assert remote.get("http://datafence.internal:8443/api/health/live",
                          headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1"}).status_code == 403


def test_admin_account_management_and_last_admin_guard(client):
    bootstrap(client)
    response = client.post("/api/auth/users", json={"username": "analyst01", "password": PASSWORD, "role": "analyst"})
    assert response.status_code == 201 and "password_hash" not in response.text and PASSWORD not in response.text
    assert len(client.get("/api/auth/users").json()) == 2
    duplicate = client.post("/api/auth/users", json={"username": "analyst01", "password": PASSWORD, "role": "analyst"})
    assert duplicate.status_code == 409
    assert client.post("/api/auth/users/administrator", json={"enabled": False}).status_code == 409
    assert client.post("/api/auth/users/administrator", json={"role": "viewer"}).status_code == 409
    assert client.post("/api/auth/users/analyst01", json={"role": "viewer"}).json()["role"] == "viewer"
    assert client.post("/api/auth/users/analyst01", json={"enabled": False}).json()["enabled"] is False
    assert client.post("/api/auth/users/analyst01", json={"password": WRONG_PASSWORD}).status_code == 200


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_non_admin_cannot_list_or_manage_accounts(client, role):
    bootstrap(client)
    client.app.state.auth.create_user("operator01", PASSWORD, role)
    assert login(client, "operator01").status_code == 200
    assert client.get("/api/auth/users").status_code == 403
    assert client.post("/api/auth/users", json={"username": "injected", "password": PASSWORD, "role": "admin"}).status_code == 403
    assert client.post("/api/auth/users/administrator", json={"password": WRONG_PASSWORD}).status_code == 403
    assert len(client.app.state.auth.list_users()) == 2


def test_admin_multifield_update_cannot_partially_apply(client):
    bootstrap(client)
    client.app.state.auth.create_user("analyst01", PASSWORD, "analyst")
    response = client.post("/api/auth/users/analyst01", json={"enabled": False, "password": WRONG_PASSWORD})
    assert response.status_code == 422
    user = next(item for item in client.app.state.auth.list_users() if item["username"] == "analyst01")
    assert user["enabled"] is True
    assert login(client, "analyst01").status_code == 200


def test_api_auth_database_failure_never_fails_open(client, monkeypatch):
    bootstrap(client)
    def unavailable(*args):
        raise RuntimeError("synthetic database unavailable")
    monkeypatch.setattr(client.app.state.auth, "authenticate", unavailable)
    assert client.get("/api/overview").status_code == 503
    assert client.post("/api/runs", json={}).status_code == 503
