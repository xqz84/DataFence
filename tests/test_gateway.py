"""Real synthetic-row delivery, durable gates and evidence, with no cloud calls."""

from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timedelta
import io
import json
import sqlite3
import threading
from uuid import uuid4

import pytest
from pydantic import ValidationError

from datafence.gateway import AccessGateway, AccessRequest, GatewayError
from datafence.sandbox import BANK_TZ, build_bank, REGIONS


AT = datetime(2026, 9, 19, 10, 0, tzinfo=BANK_TZ)
ACTOR = {"id": "synthetic-operator-one", "username": "operator01", "role": "analyst", "enabled": True}
OTHER = {"id": "synthetic-operator-two", "username": "operator02", "role": "analyst", "enabled": True}


@pytest.fixture
def bank():
    return build_bank(customer_count=400)


def task(bank, *, export=False, limit=None):
    original = next(item for item in bank["tasks"] if item.employee_id == "E0038" and item.allow_export == export)
    return original.model_copy(update={"max_records": limit}) if limit is not None else original


def gateway(path, bank, tasks=None):
    return AccessGateway(path, bank["employees"], tasks or bank["tasks"], bank["customers"])


def request(grant, count=2, operation="query", **changes):
    data = dict(request_id=uuid4(), task_id=grant.id, operation=operation, record_count=count, regions=[grant.regions[0]])
    data.update(changes)
    return AccessRequest(**data)


def usage(gate, grant):
    actual = next(item for item in gate.tasks if item.id == grant.id)
    return gate.quota.summary(actual, actual.employee_id)


def test_query_returns_real_scope_limited_synthetic_rows_and_auditable_quota(tmp_path, bank):
    grant = task(bank)
    gate = gateway(tmp_path, bank)
    result = gate.execute(request(grant, 3), ACTOR, at=AT)
    expected = [row for row in bank["customers"] if row["region"] == grant.regions[0]][:3]
    assert result["allowed"] and result["rows"] == expected
    assert result["delivered_records"] == 3 and result["requested_records"] == 3
    assert all(row["synthetic"] is True for row in result["rows"])
    assert "csv" not in result and "customer_ids" not in result and "events" not in result
    assert result["quota"]["scope"] == "task_lifetime"
    assert result["quota"]["status"] == "confirmed" and result["quota"]["used_records"] == 3
    assert result["cloud_called"] is False
    assert gate.verify() == {"valid": True, "checked_operations": 1}
    assert "rows" not in gate.recent()[0] and "customer_ids" not in gate.recent()[0]


def test_approved_export_returns_actual_csv_and_counts_read_once(tmp_path, bank):
    grant = task(bank, export=True)
    gate = gateway(tmp_path, bank)
    result = gate.execute(request(grant, 5, "export", regions=REGIONS), ACTOR, at=AT)
    assert result["allowed"] and result["delivered_records"] == 5
    parsed = list(csv.DictReader(io.StringIO(result["csv"])))
    assert len(parsed) == 5
    assert [row["id"] for row in parsed] == [row["id"] for row in result["rows"]]
    assert [row["contact"] for row in parsed] == [row["contact"] for row in result["rows"]]
    assert usage(gate, grant)["used_records"] == 5
    with sqlite3.connect(gate.path) as db:
        saved = json.loads(db.execute("SELECT payload FROM deliveries").fetchone()[0])
    assert [item["event"]["event_type"] for item in saved["events"]] == ["QUERY", "EXPORT"]


@pytest.mark.parametrize("reason", ["scope", "export", "expired", "hours", "over_limit"])
def test_denied_grants_return_no_rows_or_csv_and_do_not_consume_quota(tmp_path, bank, reason):
    grant = task(bank, limit=5)
    if reason == "expired":
        grant = grant.model_copy(update={"valid_until": AT - timedelta(seconds=1)})
    if reason == "hours":
        grant = grant.model_copy(update={"allowed_hours": [15]})
    gate = gateway(tmp_path, bank, [grant])
    changes = {"regions": [next(region for region in REGIONS if region not in grant.regions)]} if reason == "scope" else {}
    command = request(grant, 6 if reason == "over_limit" else 2, "export" if reason == "export" else "query", **changes)
    result = gate.execute(command, ACTOR, at=AT)
    assert not result["allowed"] and result["analysis"]["blocked"]
    assert result["rows"] == [] and result["delivered_records"] == 0 and "csv" not in result
    assert usage(gate, grant)["used_records"] == 0
    assert gate.verify()["valid"]
    if reason != "over_limit":
        assert "GATEWAY_GRANT_DENIED" in result["analysis"]["rules"]
        assert result["analysis"]["risk_score"] >= 72 and result["analysis"]["dimensions"]["P"] == 100
    current_node = result["analysis"]["chain"][-1]
    assert current_node["event_id"] == result["analysis"]["event_id"]
    assert current_node["blocked"] and current_node["risk_score"] == result["analysis"]["risk_score"]


@pytest.mark.parametrize("role", ["viewer", "guest", "", None])
def test_disallowed_roles_cannot_deliver_or_consume_quota(tmp_path, bank, role):
    grant = task(bank)
    gate = gateway(tmp_path, bank)
    with pytest.raises(GatewayError, match="insufficient_role"):
        gate.execute(request(grant), dict(ACTOR, role=role), at=AT)
    assert usage(gate, grant)["used_records"] == 0 and gate.recent() == []


def test_request_contract_does_not_accept_identity_sql_sensitivity_or_time_override(bank):
    grant = task(bank)
    for name, value in {"employee_id": "E0001", "role": "admin", "sensitivity": 0,
                        "sql": "SELECT * FROM customers", "at": AT.isoformat(),
                        "channel": "external", "ground_truth": "NORMAL"}.items():
        with pytest.raises(ValidationError):
            request(grant, **{name: value})


def test_idempotent_replay_and_restart_do_not_charge_or_log_again(tmp_path, bank):
    grant = task(bank)
    gate = gateway(tmp_path, bank)
    command = request(grant, 3)
    original = gate.execute(command, ACTOR, at=AT)
    replay = gate.execute(command, ACTOR, at=AT + timedelta(seconds=2))
    assert replay["replayed"] and replay["rows"] == original["rows"]
    assert replay["evidence_hash"] == original["evidence_hash"]
    restarted = gateway(tmp_path, bank)
    again = restarted.execute(command, ACTOR, at=AT + timedelta(seconds=3))
    assert again["replayed"] and again["rows"] == original["rows"]
    assert usage(restarted, grant)["used_records"] == 3
    assert restarted.verify() == {"valid": True, "checked_operations": 1}
    changed = command.model_copy(update={"record_count": 4})
    with pytest.raises(GatewayError, match="idempotency_conflict"):
        restarted.execute(changed, ACTOR, at=AT)


def test_replay_cannot_return_prior_rows_after_grant_expires(tmp_path, bank):
    grant = task(bank).model_copy(update={"valid_until": AT + timedelta(seconds=1)})
    gate = gateway(tmp_path, bank, [grant])
    command = request(grant)
    assert gate.execute(command, ACTOR, at=AT)["allowed"]
    with pytest.raises(GatewayError, match="grant_expired_or_changed"):
        gate.execute(command, ACTOR, at=AT + timedelta(seconds=2))
    assert usage(gate, grant)["used_records"] == 2


def test_lifetime_quota_is_shared_by_operators_and_survives_restart(tmp_path, bank):
    grant = task(bank, limit=5)
    first = gateway(tmp_path, bank, [grant])
    allowed = first.execute(request(grant, 3), ACTOR, at=AT)
    assert allowed["allowed"]
    second = gateway(tmp_path, bank, [grant])
    denied = second.execute(request(grant, 3), OTHER, at=AT + timedelta(days=1))
    assert not denied["allowed"] and denied["rows"] == []
    assert denied["quota"]["reason"] == "quota_exceeded"
    assert usage(second, grant)["used_records"] == 3
    last = second.execute(request(grant, 2), OTHER, at=AT + timedelta(days=2))
    assert last["allowed"] and usage(second, grant)["used_records"] == 5


def test_concurrent_independent_gateways_cannot_exceed_shared_task_limit(tmp_path, bank):
    grant = task(bank, limit=5)
    gates = [gateway(tmp_path, bank, [grant]) for _ in range(4)]
    barrier = threading.Barrier(4)
    def call(index):
        barrier.wait(timeout=2)
        actor = dict(ACTOR, id=f"parallel-{index}", username=f"parallel{index}")
        return gates[index].execute(request(grant, 2), actor, at=AT)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(call, range(4)))
    assert sum(row["allowed"] for row in results) == 2
    assert sum(row["delivered_records"] for row in results) == 4
    assert usage(gates[0], grant)["used_records"] == 4
    assert gates[0].verify() == {"valid": True, "checked_operations": 4}


def test_concurrent_duplicate_request_only_consumes_once(tmp_path, bank):
    grant = task(bank)
    gates = [gateway(tmp_path, bank) for _ in range(3)]
    command = request(grant, 3)
    barrier = threading.Barrier(3)
    def call(gate):
        barrier.wait(timeout=2)
        return gate.execute(command, ACTOR, at=AT)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(call, gates))
    assert sum(not row["replayed"] for row in results) == 1
    assert len({row["evidence_hash"] for row in results}) == 1
    assert usage(gates[0], grant)["used_records"] == 3


def test_requested_records_and_actual_rows_are_reported_separately(tmp_path, bank):
    grant = task(bank, export=True)
    gate = gateway(tmp_path, bank)
    result = gate.execute(request(grant, 100, regions=[REGIONS[0]]), ACTOR, at=AT)
    assert result["allowed"] and result["delivered_records"] == 20
    assert result["requested_records"] == 100 and usage(gate, grant)["used_records"] == 100


def test_csv_cells_neutralize_formula_prefixes(tmp_path, bank):
    grant = task(bank, export=True)
    bank["customers"][0]["name"] = "=synthetic_formula()"
    gate = gateway(tmp_path, bank)
    result = gate.execute(request(grant, 1, "export", regions=REGIONS), ACTOR, at=AT)
    parsed = list(csv.DictReader(io.StringIO(result["csv"])))
    assert parsed[0]["name"] == "'=synthetic_formula()"


def test_rewriting_persisted_evidence_is_detected(tmp_path, bank):
    grant = task(bank)
    gate = gateway(tmp_path, bank)
    gate.execute(request(grant), ACTOR, at=AT)
    with sqlite3.connect(gate.path) as db:
        record = json.loads(db.execute("SELECT payload FROM deliveries").fetchone()[0])
        record["delivered_records"] = 999
        db.execute("UPDATE deliveries SET payload=?", (json.dumps(record),))
    assert gate.verify() == {"valid": False, "checked_operations": 0}


def test_frozen_session_rejects_old_cached_data_and_marks_new_denial_consistently(tmp_path, bank):
    grant = task(bank, export=True)
    gate = gateway(tmp_path, bank)
    first = request(grant, 2)
    assert gate.execute(first, ACTOR, at=AT)["allowed"]
    attack = request(grant, 300, "export", regions=["OUTSIDE-GRANT"])
    frozen = gate.execute(attack, ACTOR, at=AT + timedelta(seconds=1))
    assert not frozen["allowed"] and "FREEZE_SESSION" in frozen["analysis"]["actions"]
    with pytest.raises(GatewayError, match="session_frozen"):
        gate.execute(first, ACTOR, at=AT + timedelta(seconds=2))
    denied = gate.execute(request(grant, 1), ACTOR, at=AT + timedelta(seconds=3))
    assert not denied["allowed"] and not denied["rows"]
    assert "GATEWAY_SESSION_FROZEN" in denied["analysis"]["rules"]
    assert denied["analysis"]["risk_score"] >= 72 and denied["analysis"]["chain"][-1]["blocked"]
    assert usage(gate, grant)["used_records"] == 2


@pytest.mark.parametrize("damage", ["missing_hash", "invalid_json", "array", "modified_rows"])
def test_corrupt_evidence_fails_verification_and_cached_delivery_closed(tmp_path, bank, damage):
    grant = task(bank)
    gate = gateway(tmp_path, bank)
    command = request(grant, 2)
    gate.execute(command, ACTOR, at=AT)
    with gate.connect() as db:
        record = json.loads(db.execute("SELECT payload FROM deliveries").fetchone()[0])
        if damage == "missing_hash":
            del record["evidence_hash"]
        if damage == "modified_rows":
            record["customer_ids"] = [bank["customers"][0]["id"]]
        payload = "invalid JSON" if damage == "invalid_json" else "[]" if damage == "array" else json.dumps(record)
        db.execute("UPDATE deliveries SET payload=?", (payload,))
    assert gate.verify() == {"valid": False, "checked_operations": 0}
    with pytest.raises(GatewayError, match="invalid_evidence"):
        gate.execute(command, ACTOR, at=AT + timedelta(seconds=1))
    assert usage(gate, grant)["used_records"] == 2


def fail_delivery_insert(gate):
    with gate.connect() as db:
        db.executescript("""CREATE TRIGGER reject_test_delivery BEFORE INSERT ON deliveries
                            BEGIN SELECT RAISE(ABORT, 'synthetic delivery write failure'); END;""")


def test_confirmed_quota_without_delivery_rejects_later_retry_after_restart(tmp_path, bank):
    grant = task(bank)
    gate = gateway(tmp_path, bank)
    command = request(grant, 3)
    fail_delivery_insert(gate)
    with pytest.raises(sqlite3.IntegrityError, match="synthetic delivery write failure"):
        gate.execute(command, ACTOR, at=AT)
    assert gate.recent() == []
    assert usage(gate, grant)["confirmed_records"] == 3
    restarted = gateway(tmp_path, bank)
    with restarted.connect() as db:
        db.execute("DROP TRIGGER reject_test_delivery")
    for delay in (1, 60):
        with pytest.raises(GatewayError, match="^unresolved_reservation$"):
            restarted.execute(command, ACTOR, at=AT + timedelta(seconds=delay))
    assert usage(restarted, grant)["used_records"] == 3
    assert restarted.recent() == []


@pytest.mark.parametrize("failure", [ValueError("unrelated validation failure"), sqlite3.OperationalError("synthetic database failure")])
def test_unexpected_quota_errors_are_not_disguised_as_unresolved_reservations(tmp_path, bank, monkeypatch, failure):
    grant = task(bank)
    gate = gateway(tmp_path, bank)
    def reject(*args, **kwargs):
        raise failure
    monkeypatch.setattr(gate.quota, "reserve", reject)
    with pytest.raises(type(failure)) as raised:
        gate.execute(request(grant), ACTOR, at=AT)
    assert raised.value is failure
    assert not isinstance(raised.value, GatewayError)
    assert gate.recent() == []


def test_http_retry_after_delivery_insert_failure_returns_409_without_data_or_new_charge(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from datafence.api import create_app

    monkeypatch.setenv("DATAFENCE_NETWORK_MODE", "local")
    monkeypatch.setenv("DATAFENCE_LLM_PROVIDER", "ollama")
    monkeypatch.delenv("DATAFENCE_LLM_MODEL", raising=False)
    clock = [AT]
    class GatewayClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0].astimezone(tz) if tz else clock[0].replace(tzinfo=None)
    monkeypatch.setattr("datafence.gateway.datetime", GatewayClock)
    app = create_app(tmp_path, customer_count=100, auth_mode="required")
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50234),
                    raise_server_exceptions=False) as client:
        login = client.post("/api/auth/bootstrap", json={"username": "administrator", "password": "synthetic recovery test passphrase"})
        assert login.status_code == 200
        client.headers["X-DataFence-Token"] = login.json()["token"]
        gate = app.state.gateway
        grant = next(item for item in gate.tasks if item.employee_id == "E0038" and item.allow_export)
        payload = request(grant, 3, "export").model_dump(mode="json")
        assert "at" not in payload
        fail_delivery_insert(gate)
        failed = client.post("/api/access/execute", json=payload)
        assert failed.status_code == 500 and "SYN-C-" not in failed.text
        assert usage(gate, grant)["confirmed_records"] == 3 and gate.recent() == []
        with gate.connect() as db:
            db.execute("DROP TRIGGER reject_test_delivery")
        clock[0] += timedelta(minutes=2)
        for _ in range(2):
            response = client.post("/api/access/execute", json=payload)
            assert response.status_code == 409
            assert "unresolved_reservation" in response.json()["detail"]
            assert "rows" not in response.json() and "csv" not in response.json() and "SYN-C-" not in response.text
        assert usage(gate, grant)["confirmed_records"] == 3
        assert usage(gate, grant)["used_records"] == 3 and gate.recent() == []
