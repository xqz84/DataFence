import sqlite3

from fastapi.testclient import TestClient
import pytest

from datafence.api import create_app
from datafence.storage import Store, dump


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path, customer_count=5000, auth_mode="local_demo"), base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
        client.headers["X-DataFence-Token"] = client.get("/api/session").json()["token"]
        yield client


def run(client, scenario="combined", **kwargs):
    response = client.post("/api/runs", json=dict(scenario_id=scenario, record_count=2000, interval_ms=0, **kwargs))
    assert response.status_code == 202, response.text
    completed = client.get(f"/api/runs/{response.json()['id']}").json()
    assert completed["status"] == "completed", completed
    return completed


def test_empty_ui_has_no_invented_metrics(client):
    assert client.get("/api/overview").json()["total_events"] == 0
    assert client.get("/api/evaluations/latest").json() is None
    assert client.get("/api/health").json()["llm"]["enabled"] is False


def test_request_boundary_rejects_untrusted_requests(client):
    assert client.post("/api/runs", json={}, headers={"X-DataFence-Token": ""}).status_code == 403
    assert client.post("/api/runs", json={}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.get("/api/session", headers={"Host": "evil.example"}).status_code == 400
    assert client.post("/api/runs", json={"ground_truth": "ATTACK"}).status_code == 422
    assert client.post("/api/runs", json={"destination": "https://bank.example"}).status_code == 422
    assert client.post("/api/runs", json={"record_count": 50001}).status_code == 422
    assert client.post("/api/runs", json={"employee_id": "missing"}).status_code == 422
    assert client.post("/api/runs", content="x" * 17000,
                       headers={"Content-Type": "application/json"}).status_code == 413


def test_combined_is_prevented_and_evidence_is_valid(client):
    result = run(client)
    assert result["sink_records"] == 0
    assert result["blocked_events"] >= 1
    assert result["processed_events"] + result["skipped_events"] == result["planned_events"]
    assert client.get(f"/api/runs/{result['id']}/receipts").json() == []
    events = client.get("/api/events", params={"run_id": result["id"]}).json()
    assert any(item["outcome"] == "blocked" for item in events)
    assert client.get("/api/audit/verify").json()["valid"] is True
    for record in events:
        assert "ground_truth" not in record["event"]
        assert "attack_type" not in record["event"]
        assert record["received_at"] <= record["detected_at"] <= record["responded_at"]


def test_approved_batch_reaches_only_synthetic_sink(client):
    result = run(client, "approved_batch")
    assert result["blocked_events"] == 0
    assert result["sink_records"] == 2000
    receipts = client.get(f"/api/runs/{result['id']}/receipts").json()
    assert receipts[0]["record_count"] == 2000
    assert receipts[0]["channel"] == "approved_partner"
    assert receipts[0]["synthetic"] is True


def test_idempotency_prevents_duplicate_runs(client):
    payload = {"scenario_id": "normal", "record_count": 10, "interval_ms": 0}
    first = client.post("/api/runs", json=payload, headers={"Idempotency-Key": "replay-1"}).json()
    second = client.post("/api/runs", json=payload, headers={"Idempotency-Key": "replay-1"}).json()
    assert first["id"] == second["id"]
    assert len(client.get("/api/runs").json()) == 1
    changed = dict(payload, record_count=20)
    assert client.post("/api/runs", json=changed, headers={"Idempotency-Key": "replay-1"}).status_code == 409


def test_repeated_seed_produces_separate_execution_ids(client):
    first, second = run(client, "normal"), run(client, "normal")
    first_events = client.get("/api/events", params={"run_id": first["id"]}).json()
    second_events = client.get("/api/events", params={"run_id": second["id"]}).json()
    assert set(item["event"]["event_id"] for item in first_events).isdisjoint(
        item["event"]["event_id"] for item in second_events)


def test_evidence_survives_restart_and_detects_modification(tmp_path):
    with TestClient(create_app(tmp_path, 5000, auth_mode="local_demo"), base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as first:
        first.headers["X-DataFence-Token"] = first.get("/api/session").json()["token"]
        result = run(first, "normal")
    with TestClient(create_app(tmp_path, 5000, auth_mode="local_demo"), base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as second:
        assert second.get(f"/api/runs/{result['id']}").json()["status"] == "completed"
        assert second.get("/api/audit/verify").json()["valid"] is True
    store = Store(tmp_path)
    record = store.events()[0]
    record["analysis"]["risk_score"] = 99
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE events SET payload=? WHERE id=?", (dump(record), record["event"]["event_id"]))
    assert store.verify()["valid"] is False


def test_all_scenarios_and_employee_pages_share_real_data(client):
    scenario_ids = {item["id"] for item in client.get("/api/scenarios").json()}
    assert len(scenario_ids) == 8
    for scenario in scenario_ids:
        result = run(client, scenario)
        assert result["processed_events"] > 0
    profile = client.get("/api/employees/E0038").json()
    assert profile["events"]
    assert profile["latest_intent"]["evidence"]
    assert client.get("/api/overview").json()["total_events"] > 0


def test_receipt_tampering_is_part_of_audit(client):
    result = run(client, "approved_batch")
    store = client.app.state.service.store
    assert store.verify()["valid"] is True
    receipt = store.sink_receipts(result["id"])[0]
    receipt["customer_ids"] = ["SYN-C-TAMPERED"]
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE sinks SET payload=? WHERE event_id=?", (dump(receipt), receipt["event_id"]))
    assert store.verify()["valid"] is False


def test_remote_client_cannot_bootstrap_local_token(tmp_path):
    with TestClient(create_app(tmp_path, 100, auth_mode="local_demo"), base_url="http://127.0.0.1", client=("192.0.2.10", 40000)) as remote:
        assert remote.get("/api/session").status_code == 403


def test_model_failure_cannot_change_enforcement(client, monkeypatch):
    def unavailable(event, analysis):
        return {"status": "unavailable", "summary": "模拟本地模型超时", "evidence_event_ids": [],
                "suggested_actions": [], "elapsed_ms": 0, "model": "test-model"}
    monkeypatch.setattr(client.app.state.service.analyst, "analyze", unavailable)
    blocked = run(client, "combined")
    allowed = run(client, "approved_batch")
    assert blocked["sink_records"] == 0 and blocked["blocked_events"] > 0
    assert allowed["sink_records"] == 2000 and allowed["blocked_events"] == 0
    event = client.get("/api/events", params={"run_id": blocked["id"]}).json()[0]
    assert event["ai_analysis"]["status"] == "unavailable"
