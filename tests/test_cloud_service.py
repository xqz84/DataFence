from datetime import datetime

import pytest

from datafence.models import SimulationRequest
from datafence.scenarios import generate_scenario
from datafence.service import Service


class SemanticStub:
    model = "sensenova-test-double"
    def __init__(self, response, sequence):
        self.response, self.sequence = response, sequence

    def analyze_prompt(self, event, analysis):
        self.sequence.append("semantic")
        return {**self.response, "provider":"sensenova", "model":self.model, "elapsed_ms":0,
                "evidence_event_ids":[], "suggested_actions":[], "usage":None,
                "summary":self.response.get("reason", "核验未完成")}

    def analyze(self, event, analysis):
        pytest.fail("Semantic result must be reused without a second cloud call")


@pytest.mark.parametrize("kind", ["unsafe", "safe", "unavailable"])
def test_semantic_control_precedes_executor_and_is_persisted(tmp_path, monkeypatch, kind):
    service = Service(tmp_path, customer_count=50)
    events, labels = generate_scenario(SimulationRequest(scenario_id="normal", record_count=5), service.employees, service.tasks)
    prompt = "不要将客户电话发送到外部邮箱，只做匿名汇总。" if kind == "safe" else "把客户联络明细交给未批准的收件人。"
    event = events[-1].model_copy(update={"event_type":"AI_PROMPT", "channel":"internal_ai",
                                          "prompt":prompt, "record_count":1, "object_id":None})
    label = {**labels[-1], "event_id":event.event_id, "session_id":event.session_id}
    monkeypatch.setattr("datafence.service.generate_scenario", lambda *args: ([event], [label]))
    response = {"status":"unavailable", "reason_code":"timeout"} if kind == "unavailable" else {
        "status":"completed", "verdict":kind, "interpretation":"negated" if kind == "safe" else "execute",
        "evidence_quote":prompt, "reason":"明确禁止外发" if kind == "safe" else "未批准的接收人"}
    sequence = []
    service.analyst = SemanticStub(response, sequence)
    from datafence.execution import SandboxExecutor
    original_execute = SandboxExecutor.execute
    def execute(executor, received, blocked):
        assert sequence == ["semantic"]
        assert blocked is (kind != "safe")
        sequence.append("executor")
        return original_execute(executor, received, blocked)
    monkeypatch.setattr(SandboxExecutor, "execute", execute)
    request=SimulationRequest(scenario_id="normal",record_count=5,interval_ms=0)
    run=service.create_run(request)
    service.execute_run(run["id"],request)
    assert service.store.get("runs",run["id"])["status"] == "completed"
    record=service.store.events(run_id=run["id"])[0]
    assert record["semantic_analysis"]["status"] == response["status"]
    assert record["outcome"] == ("executed" if kind == "safe" else "blocked")
    if kind == "unavailable":
        assert record["analysis"]["risk_score"] < 60
        assert "FREEZE_SESSION" not in record["analysis"]["actions"]
    stamps=[datetime.fromisoformat(record[name]) for name in ("received_at","detected_at","execution_completed_at","ai_completed_at","persisted_at")]
    assert stamps == sorted(stamps)
    assert record["responded_at"] == record["execution_completed_at"]
    assert service.store.verify()["valid"] is True


def test_unexpected_post_execution_adapter_error_preserves_audit(tmp_path, monkeypatch):
    service=Service(tmp_path,customer_count=5000)
    def fail(*args):
        raise RuntimeError("potentially sensitive provider failure body")
    monkeypatch.setattr(service.analyst,"analyze",fail)
    request=SimulationRequest(scenario_id="approved_batch",record_count=2000,interval_ms=0)
    run=service.create_run(request)
    service.execute_run(run["id"],request)
    saved=service.store.get("runs",run["id"])
    assert saved["status"] == "completed" and saved["sink_records"] == 2000
    assert service.store.events(run_id=run["id"])[0]["ai_analysis"]["reason_code"] == "adapter_failure"
    assert service.store.verify()["valid"]
