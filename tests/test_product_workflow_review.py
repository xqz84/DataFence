"""Independent product acceptance: durable evidence, authorization and failure paths.

All operations use temporary databases and a recording model double. These are
development regression checks, not a new detection-quality or cloud benchmark.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import sqlite3
import threading
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from datafence.api import create_app
from datafence.storage import Store, dump
from datafence.workflows import WorkflowStore


PASSWORD = "isolated product review passphrase 2026"


class ForbiddenModel:
    model = "network-forbidden-review-double"
    info = {"enabled": True, "provider": "sensenova", "model": model,
            "configuration_status": "test_double"}

    def __init__(self):
        self.calls = []

    def analyze(self, *args):
        self.calls.append("advisory")
        raise RuntimeError("This acceptance test must not call a model")

    def analyze_prompt(self, *args):
        self.calls.append("semantic")
        raise RuntimeError("This acceptance test must not call a model")


@pytest.fixture(autouse=True)
def isolated_offline(monkeypatch, tmp_path):
    monkeypatch.setenv("DATAFENCE_NETWORK_MODE", "local")
    monkeypatch.setenv("DATAFENCE_AUTH_MODE", "required")
    monkeypatch.setenv("DATAFENCE_BEHAVIOR_MODEL", "legacy")
    monkeypatch.setenv("DATAFENCE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DATAFENCE_LLM_PROVIDER", "ollama")
    for name in ("DATAFENCE_LLM_MODEL", "DATAFENCE_SERVER_PORT", "DATAFENCE_ALLOWED_HOSTS",
                 "DATAFENCE_ALLOWED_ORIGINS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("datafence.service.create_analyst", lambda directory: ForbiddenModel())


def open_client(directory):
    return TestClient(create_app(directory, customer_count=1000), base_url="http://127.0.0.1",
                      client=("127.0.0.1", 45901))


def login(client, username="product.admin"):
    response = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    client.headers["X-DataFence-Token"] = response.json()["token"]


@pytest.fixture
def client(tmp_path):
    with open_client(tmp_path) as current:
        current.app.state.auth.create_user("product.admin", PASSWORD, "admin")
        login(current)
        yield current
        assert current.app.state.service.analyst.calls == []


def demo_body(**changes):
    return {"request_id": str(uuid4()), "employee_id": "E0038", **changes}


def start_demo(client, body=None):
    response = client.post("/api/demos", json=body or demo_body())
    assert response.status_code == 202, response.text
    demo = client.get(f"/api/demos/{response.json()['id']}").json()
    assert demo["status"] == "awaiting_review", demo
    return demo


def review_body(revision=0, disposition="confirmed_risk", **changes):
    return {"request_id": str(uuid4()), "expected_revision": revision,
            "disposition": disposition, "note": "核对当前事件与工单证据后的独立人工结论。", **changes}


def submit_review(client, event_id, body=None):
    response = client.post(f"/api/events/{event_id}/review", json=body or review_body())
    assert response.status_code == 200, response.text
    return response.json()


def quota_rows(client):
    with closing(sqlite3.connect(client.app.state.service.quota.path)) as db:
        return db.execute("SELECT * FROM quota_reservations ORDER BY event_id").fetchall()


def test_demo_uses_real_receipts_stops_attack_and_never_calls_configured_model(client):
    demo = start_demo(client)
    service = client.app.state.service
    assert demo["mode"] == "local" and demo["audit"]["valid"]
    assert len(demo["steps"]) == len({s["run_id"] for s in demo["steps"]}) == 3
    assert all(check["passed"] for check in demo["checks"])
    for step in demo["steps"]:
        run = service.store.get("runs", step["run_id"])
        records = service.store.events(run_id=run["id"])
        receipts = service.store.sink_receipts(run["id"])
        assert step["passed"] and run["status"] == "completed"
        assert len(records) == step["processed_events"] == run["processed_events"]
        assert run["planned_events"] == len(records) + step["skipped_events"]
        assert step["sink_records"] == sum(len(r["customer_ids"]) for r in receipts)
        observed = {r["event"]["event_id"] for r in records}
        for record in records:
            assert record["semantic_analysis"] is None
            assert record["ai_analysis"]["reason_code"] == "demo_local_mode"
            assert "ground_truth" not in record["event"] and "attack_type" not in record["event"]
            assert record["outcome"] != "blocked" or record["executed_records"] == 0
            assert all(node["event_id"] in observed for node in record["analysis"]["chain"])
        if step["id"] == "normal":
            assert run["blocked_events"] == 0
            assert any(r["event"]["event_type"] == "QUERY" and r["executed_records"] > 0 for r in records)
        elif step["id"] == "approved_batch":
            assert run["blocked_events"] == 0 and run["sink_records"] == 1000
            assert len(receipts) == 1 and receipts[0]["channel"] == "approved_partner"
        else:
            assert run["blocked_events"] > 0 and run["skipped_events"] > 0
            assert receipts == [] and run["sink_records"] == 0
            assert not any(r["event"]["event_type"] == "UPLOAD" for r in records)
            assert demo["selected_event_id"] in observed
    assert service.store.verify()["valid"] and service.analyst.calls == []


def test_same_actor_uuid_retry_is_nonexecuting_and_changed_content_conflicts(client):
    body = demo_body()
    first = start_demo(client, body)
    before = (client.app.state.service.store.events(), quota_rows(client))
    second = client.post("/api/demos", json=body)
    assert second.status_code == 202 and second.json()["id"] == first["id"]
    assert before == (client.app.state.service.store.events(), quota_rows(client))
    assert len(client.get("/api/runs").json()) == 3
    changed = client.post("/api/demos", json={**body, "employee_id": "E0001"})
    assert changed.status_code == 409
    assert len(client.get("/api/demos").json()) == 1


def test_same_uuid_is_scoped_to_actor_for_demos_and_reviews(client):
    body = demo_body()
    first = start_demo(client, body)
    event_id = first["selected_event_id"]
    finding = review_body()
    first_review = submit_review(client, event_id, finding)
    client.app.state.auth.create_user("product.analyst", PASSWORD, "analyst")
    login(client, "product.analyst")
    second = start_demo(client, body)
    assert second["id"] != first["id"] and second["actor"] == "product.analyst"
    assert {s["run_id"] for s in first["steps"]}.isdisjoint({s["run_id"] for s in second["steps"]})
    other_actor = submit_review(client, event_id, {**finding, "expected_revision": 1})
    assert other_actor["revision"] == 2
    assert [r["actor"] for r in other_actor["history"]] == ["product.admin", "product.analyst"]
    assert other_actor["history"][0] == first_review["current"]


def test_simultaneous_duplicate_demo_posts_schedule_only_three_runs(client, monkeypatch):
    service = client.app.state.service
    original, calls, lock = service.execute_run, [], threading.Lock()
    def observed(run_id, request, **kwargs):
        with lock:
            calls.append(run_id)
        return original(run_id, request, **kwargs)
    monkeypatch.setattr(service, "execute_run", observed)
    body, barrier = demo_body(), threading.Barrier(2)
    def submit():
        barrier.wait(timeout=5)
        return client.post("/api/demos", json=body)
    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(lambda _: submit(), range(2)))
    assert [r.status_code for r in replies] == [202, 202]
    assert len({r.json()["id"] for r in replies}) == 1
    assert len(calls) == len(set(calls)) == len(client.get("/api/runs").json()) == 3


def test_demo_preallocation_is_atomic_and_failed_request_id_can_be_reused(client, monkeypatch):
    service, body = client.app.state.service, demo_body()
    original, calls = service.prepare_run, []
    def fail_second(request):
        calls.append(request.scenario_id)
        if len(calls) == 2:
            raise ValueError("injected preparation failure")
        return original(request)
    monkeypatch.setattr(service, "prepare_run", fail_second)
    response = client.post("/api/demos", json=body)
    assert response.status_code == 422
    assert service.store.list("runs") == client.get("/api/demos").json() == []
    assert quota_rows(client) == []
    monkeypatch.setattr(service, "prepare_run", original)
    assert start_demo(client, body)["status"] == "awaiting_review"


def test_crash_recovery_preserves_ids_without_resuming_or_replaying(tmp_path, monkeypatch):
    scheduled = []
    monkeypatch.setattr("datafence.api.execute_demo", lambda service, workflows, demo_id: scheduled.append(demo_id))
    body = demo_body()
    with open_client(tmp_path) as first:
        first.app.state.auth.create_user("product.admin", PASSWORD, "admin")
        login(first)
        created = first.post("/api/demos", json=body).json()
        assert created["status"] == "running"
        ids = [s["run_id"] for s in created["steps"]]
        assert first.post("/api/demos", json=demo_body()).status_code == 409
        assert len(first.get("/api/runs").json()) == 3
    with open_client(tmp_path) as second:
        login(second)
        recovered = second.get(f"/api/demos/{created['id']}").json()
        assert recovered["status"] == "interrupted" and recovered["finished_at"]
        assert [s["run_id"] for s in recovered["steps"]] == ids
        assert all(s["status"] == "interrupted" and s["passed"] is None for s in recovered["steps"])
        assert all(second.get(f"/api/runs/{run_id}").json()["status"] == "interrupted" for run_id in ids)
        assert second.get("/api/events").json() == [] and quota_rows(second) == []
        replay = second.post("/api/demos", json=body)
        assert replay.status_code == 202 and replay.json() == recovered
        assert scheduled == [created["id"]]


@pytest.mark.parametrize("failure", ["raised", "recorded"])
def test_failed_child_stops_remaining_steps_and_does_not_fabricate_success(client, monkeypatch, failure):
    service, attempted = client.app.state.service, []
    def fail(run_id, request, **kwargs):
        attempted.append(run_id)
        if failure == "raised":
            raise RuntimeError("injected worker failure")
        run = service.store.get("runs", run_id)
        run.update(status="failed", phase="failed", error="injected persisted failure")
        service.store.save("runs", run)
    monkeypatch.setattr(service, "execute_run", fail)
    response = client.post("/api/demos", json=demo_body())
    assert response.status_code == 202
    demo = client.get(f"/api/demos/{response.json()['id']}").json()
    assert demo["status"] == "failed" and demo["error"]
    assert len(attempted) == 1
    assert all(s["status"] != "completed" and s["passed"] is not True for s in demo["steps"])
    assert all(service.store.get("runs", s["run_id"])["status"] in {"failed", "interrupted"} for s in demo["steps"])
    assert service.store.events() == [] and quota_rows(client) == []
    assert client.post(f"/api/demos/{demo['id']}/confirm", json={"review_revision": 1}).status_code == 409


def test_failure_after_completed_prefix_preserves_real_evidence_and_skips_attack(client, monkeypatch):
    from datafence.execution import SandboxExecutor

    original = SandboxExecutor.execute
    def interrupted_export(executor, event, blocked):
        if event.event_type == "EXPORT":
            raise RuntimeError("injected local export device failure")
        return original(executor, event, blocked)
    monkeypatch.setattr(SandboxExecutor, "execute", interrupted_export)
    response = client.post("/api/demos", json=demo_body())
    assert response.status_code == 202
    demo = client.get(f"/api/demos/{response.json()['id']}").json()
    normal, batch, attack = demo["steps"]
    service = client.app.state.service
    assert demo["status"] == "failed" and demo["selected_event_id"] is None
    assert normal["status"] == "completed" and normal["passed"] is True
    assert batch["status"] == "failed" and batch["passed"] is False
    assert attack["status"] == "interrupted" and attack["passed"] is None
    batch_events = service.store.events(run_id=batch["run_id"])
    assert batch_events and any(r["event"]["event_type"] == "QUERY" for r in batch_events)
    assert not any(r["event"]["event_type"] == "EXPORT" for r in batch_events)
    assert service.store.sink_receipts(batch["run_id"]) == []
    assert service.store.events(run_id=attack["run_id"]) == []
    assert service.store.verify()["valid"]
    assert quota_rows(client), "Already completed requests remain accounted for after a later step fails"


def test_selected_agent_workbench_stays_bound_to_older_demo_and_is_read_only(client):
    older, newer = start_demo(client), start_demo(client)
    service = client.app.state.service
    marker = "ISOLATED-LABEL-MUST-NEVER-BECOME-KNOWLEDGE-18973"
    (service.store.directory / "evaluation_labels" / "product-review-marker.json").write_text(
        json.dumps({"ground_truth": marker}), encoding="utf-8")
    before, quota_before = service.store.events(), quota_rows(client)
    selected = service.store.event(older["selected_event_id"])
    run_records = service.store.events(run_id=selected["run_id"])
    allowed_ids = {r["event"]["event_id"] for r in run_records}
    response = client.get("/api/agents/workbench", params={"event_id": older["selected_event_id"]})
    assert response.status_code == 200
    body = response.json()
    assert body["selected_event_id"] == older["selected_event_id"] != newer["selected_event_id"]
    assert body["event_count"] == len(run_records) and len(body["modules"]) == 6
    for module in body["modules"]:
        assert set(module["evidence_event_ids"]) <= allowed_ids
        assert {finding["event_id"] for finding in module["findings"]} <= allowed_ids
    assert body["llm"]["completed_calls"] == body["llm"]["failed_calls"] == 0
    assert body["llm"]["skipped_records"] == len(run_records)
    for citation in body["related_knowledge"]:
        document = client.get(f"/api/knowledge/documents/{citation['id']}").json()
        assert citation["sha256"] == document["sha256"]
        assert citation["excerpt"] in document["content"]
    knowledge = client.get("/api/knowledge/search", params={"q": marker}).json()
    # Echoing the user's search query is allowed; retrieved evidence is not.
    assert knowledge["matches"] == [] and knowledge["answer"] is None
    assert marker not in response.text
    assert service.store.events() == before and quota_rows(client) == quota_before
    assert service.analyst.calls == []


def test_viewer_reads_real_workflow_but_cannot_mutate_it_and_anonymous_cannot_read(client):
    demo = start_demo(client)
    event_id = demo["selected_event_id"]
    client.app.state.auth.create_user("product.viewer", PASSWORD, "viewer")
    login(client, "product.viewer")
    paths = ["/api/demos", f"/api/demos/{demo['id']}", f"/api/events/{event_id}/review", "/api/reviews/verify"]
    assert all(client.get(path).status_code == 200 for path in paths)
    for path, body in (("/api/demos", demo_body()),
                       (f"/api/events/{event_id}/review", review_body()),
                       (f"/api/demos/{demo['id']}/confirm", {"review_revision": 1})):
        assert client.post(path, json=body).status_code == 403
    assert len(client.get("/api/demos").json()) == 1
    assert client.get(f"/api/events/{event_id}/review").json()["revision"] == 0
    client.cookies.clear()
    assert all(client.get(path).status_code == 401 for path in paths)


def test_review_requires_csrf_known_event_and_valid_contract(client):
    demo = start_demo(client)
    path = f"/api/events/{demo['selected_event_id']}/review"
    assert client.post(path, json=review_body(), headers={"X-DataFence-Token": ""}).status_code == 403
    assert client.post(f"/api/events/{uuid4()}/review", json=review_body()).status_code == 404
    for change in ({"note": " \n "}, {"expected_revision": -1}, {"request_id": "not-a-uuid"},
                   {"disposition": "unfreeze_session"}, {"risk_score": 0}):
        assert client.post(path, json=review_body(**change)).status_code == 422
    assert client.get(path).json()["history"] == []


def test_concurrent_reviews_require_fresh_revision_and_preserve_winning_finding(client):
    demo = start_demo(client)
    path, barrier = f"/api/events/{demo['selected_event_id']}/review", threading.Barrier(2)
    def submit(disposition):
        barrier.wait(timeout=5)
        return client.post(path, json=review_body(disposition=disposition))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, ["confirmed_risk", "false_positive"]))
    assert sorted(r.status_code for r in results) == [200, 409]
    winner = next(r.json() for r in results if r.status_code == 200)
    persisted = client.get(path).json()
    assert persisted == winner and persisted["revision"] == len(persisted["history"]) == 1
    assert client.get("/api/reviews/verify").json() == {"valid": True, "checked_reviews": 1}


def test_review_retry_conflict_and_conclusion_never_rewrite_enforcement_or_labels(client):
    demo = start_demo(client)
    event_id, service = demo["selected_event_id"], client.app.state.service
    before = service.store.events()
    quota_before = quota_rows(client)
    receipts_before = [service.store.sink_receipts(s["run_id"]) for s in demo["steps"]]
    labels_before = {p.name: p.read_bytes() for p in (service.store.directory / "evaluation_labels").glob("*.jsonl")}
    body = review_body()
    first = submit_review(client, event_id, body)
    assert submit_review(client, event_id, body) == first
    conflict = client.post(f"/api/events/{event_id}/review", json={**body, "note": "另一个不同结论。"})
    assert conflict.status_code == 409
    second = submit_review(client, event_id, review_body(1, "false_positive"))
    assert second["revision"] == 2 and second["history"][0] == first["current"]
    assert second["current"]["event_evidence_hash"] == service.store.event(event_id)["evidence_hash"]
    assert service.store.events() == before and quota_rows(client) == quota_before
    assert [service.store.sink_receipts(s["run_id"]) for s in demo["steps"]] == receipts_before
    assert {p.name: p.read_bytes() for p in (service.store.directory / "evaluation_labels").glob("*.jsonl")} == labels_before
    reopened = WorkflowStore(Store(service.store.directory))
    assert reopened.review(event_id) == second and reopened.verify_reviews()["valid"]
    assert service.store.verify()["valid"]


def test_confirmation_requires_bound_event_resolved_latest_revision_and_is_idempotent(client):
    demo = start_demo(client)
    path = f"/api/demos/{demo['id']}/confirm"
    another = client.app.state.service.store.events(run_id=demo["steps"][0]["run_id"])[0]["event"]["event_id"]
    submit_review(client, another)
    assert client.post(path, json={"review_revision": 1}).status_code == 409
    submit_review(client, demo["selected_event_id"], review_body(disposition="needs_investigation"))
    assert client.post(path, json={"review_revision": 1}).status_code == 409
    submit_review(client, demo["selected_event_id"], review_body(1))
    assert client.post(path, json={"review_revision": 1}).status_code == 409
    completed = client.post(path, json={"review_revision": 2})
    assert completed.status_code == 200 and completed.json()["status"] == "completed"
    assert completed.json()["review_revision"] == 2 and completed.json()["confirmed_by"] == "product.admin"
    assert client.post(path, json={"review_revision": 2}).json() == completed.json()


@pytest.mark.parametrize("target", ["event", "review"])
def test_confirmation_refuses_modified_original_or_review_evidence(client, target):
    demo = start_demo(client)
    event_id = demo["selected_event_id"]
    submit_review(client, event_id)
    with client.app.state.service.store.connect() as db:
        if target == "event":
            row = db.execute("SELECT payload FROM events WHERE id=?", (event_id,)).fetchone()
            item = json.loads(row[0])
            item["analysis"]["risk_score"] = 0
            db.execute("UPDATE events SET payload=? WHERE id=?", (dump(item), event_id))
        else:
            row = db.execute("SELECT payload FROM case_reviews WHERE event_id=?", (event_id,)).fetchone()
            item = json.loads(row[0])
            item["note"] = "tampered after human review"
            db.execute("UPDATE case_reviews SET payload=? WHERE event_id=?", (dump(item), event_id))
    response = client.post(f"/api/demos/{demo['id']}/confirm", json={"review_revision": 1})
    assert response.status_code == 409
    assert client.get(f"/api/demos/{demo['id']}").json()["status"] == "awaiting_review"


@pytest.mark.parametrize("operation", ["review", "create", "confirm"])
def test_revoked_session_while_queued_cannot_commit_workflow_mutation(client, monkeypatch, operation):
    demo = start_demo(client)
    event_id, workflows = demo["selected_event_id"], client.app.state.workflows
    if operation == "confirm":
        submit_review(client, event_id)
    client.app.state.auth.create_user("product.operator", PASSWORD, "analyst")
    login(client, "product.operator")
    method = {"review": "append_review", "create": "create_demo", "confirm": "confirm"}[operation]
    original, entered, release = getattr(workflows, method), threading.Event(), threading.Event()
    def queued(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=5)
        return original(*args, **kwargs)
    monkeypatch.setattr(workflows, method, queued)
    path, body = {
        "review": (f"/api/events/{event_id}/review", review_body()),
        "create": ("/api/demos", demo_body()),
        "confirm": (f"/api/demos/{demo['id']}/confirm", {"review_revision": 1}),
    }[operation]
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client.post, path, json=body)
        try:
            assert entered.wait(timeout=5)
            client.app.state.auth.set_enabled("product.operator", False)
        finally:
            release.set()
        response = pending.result(timeout=10)
    assert response.status_code == 401
    assert len(workflows.demos()) == 1
    assert workflows.demo(demo["id"])["status"] == "awaiting_review"
    assert workflows.review(event_id)["revision"] == (1 if operation == "confirm" else 0)
