import pytest

from datafence.models import SimulationRequest
from datafence.scenarios import generate_scenario
from datafence.service import Service
from datafence.storage import dump


def configured_service(tmp_path, monkeypatch):
    service = Service(tmp_path, customer_count=1000)
    request = SimulationRequest(scenario_id="normal", record_count=2, interval_ms=0)
    events, labels = generate_scenario(request, service.employees, service.tasks)
    original = events[-1]
    task = next(t for t in service.tasks if t.id == original.task_id).model_copy(update={"quota_scope":"task_lifetime", "max_records":3})
    service.tasks = [task if t.id == task.id else t for t in service.tasks]
    with service.store.connect() as db:
        db.execute("UPDATE bank SET payload=? WHERE kind='tasks' AND id=?", (dump(task.model_dump(mode="json")),task.id))
    event = original.model_copy(update={"record_count":2})
    label = next(row for row in labels if row["event_id"] == original.event_id)
    monkeypatch.setattr("datafence.service.generate_scenario", lambda *args: ([event],[dict(label)]))
    return service, request, task


def execute(service, request):
    run=service.create_run(request)
    service.execute_run(run["id"],request)
    return service.store.get("runs",run["id"]), service.store.events(run_id=run["id"])


def test_task_lifetime_limit_stops_new_session_after_restart(tmp_path, monkeypatch):
    first, request, task = configured_service(tmp_path,monkeypatch)
    run, records = execute(first,request)
    assert run["status"] == "completed"
    assert records[0]["executed_records"] == 2
    assert records[0]["quota_decision"]["status"] == "confirmed"
    restored = Service(tmp_path,customer_count=1000)
    next_run, next_records = execute(restored,request)
    denied = next_records[0]
    assert next_run["status"] == "completed" and next_run["blocked_events"] == 1
    assert denied["event"]["session_id"] != records[0]["event"]["session_id"]
    assert denied["executed_records"] == 0 and denied["outcome"] == "blocked"
    assert denied["quota_decision"]["status"] == "rejected"
    assert "BLOCK_READ" in denied["analysis"]["actions"]
    assert restored.quota.summary(task,task.employee_id)["confirmed_records"] == 2
    assert restored.store.verify()["valid"]


def test_executor_failure_releases_only_unconfirmed_reservation(tmp_path,monkeypatch):
    service,request,task=configured_service(tmp_path,monkeypatch)
    def fail(*args):
        raise RuntimeError("synthetic executor failure")
    monkeypatch.setattr("datafence.execution.SandboxExecutor.execute",fail)
    run,records=execute(service,request)
    assert run["status"] == "failed" and not records
    assert service.quota.summary(task,task.employee_id)["used_records"] == 0


def test_evidence_write_failure_does_not_refund_completed_read(tmp_path,monkeypatch):
    service,request,task=configured_service(tmp_path,monkeypatch)
    def fail(*args):
        raise RuntimeError("synthetic audit write failure")
    monkeypatch.setattr(service.store,"append_event",fail)
    run,records=execute(service,request)
    assert run["status"] == "failed" and not records
    assert service.quota.summary(task,task.employee_id)["confirmed_records"] == 2
