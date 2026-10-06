"""No fabricated module outputs, model completions, or execution authority."""

from copy import deepcopy
import json
import socket

import pytest
from pydantic import ValidationError

from datafence.agent_workbench import build_agent_workbench
from datafence.engine import DetectionEngine
from datafence.models import SimulationRequest
from datafence.sandbox import build_bank
from datafence.scenarios import generate_scenario


@pytest.fixture
def record():
    bank = build_bank(customer_count=20)
    events, _ = generate_scenario(SimulationRequest(scenario_id="ai_leak", record_count=8), bank["employees"], bank["tasks"])
    detector = DetectionEngine(bank["employees"], bank["tasks"])
    for event in events:
        analysis = detector.analyze(event)
    return {"event": event.model_dump(mode="json"), "analysis": analysis.model_dump(mode="json"),
            "outcome": "blocked", "executed_records": 0, "ai_analysis": {"status": "not_configured"}}


def test_no_observations_do_not_pretend_modules_ran_or_model_was_called():
    result = build_agent_workbench([], model_info={"version": "iforest-v2"},
                                   llm_info={"enabled": True, "provider": "sensenova", "model": "test-model", "status": "configured"})
    assert len(result["modules"]) == 6
    assert all(row["status"] == "no_observations" and row["evaluated_events"] == 0 and not row["findings"] for row in result["modules"])
    assert result["llm"]["configured"] is True
    assert result["llm"]["completed_calls"] == result["llm"]["failed_calls"] == 0
    assert result["llm"]["last_status"] is None
    assert result["latest_event_id"] is None


def test_six_views_reference_actual_analysis_and_do_not_change_actions(record):
    before = deepcopy(record)
    result = build_agent_workbench([record])
    modules = {row["id"]: row for row in result["modules"]}
    assert set(modules) == {"classification", "behavior", "intent", "flow", "correlation", "response"}
    assert result["event_count"] == 1
    assert all(row["evaluated_events"] == 1 for row in modules.values())
    assert modules["behavior"]["execution_kind"] == "local_ml"
    assert modules["behavior"]["findings"][0]["values"]["anomaly_score"] == record["analysis"]["anomaly_score"]
    assert modules["intent"]["findings"][0]["values"]["trust"] == record["analysis"]["intent"]["trust"]
    response = modules["response"]["findings"][0]
    assert response["values"]["recorded_outcome"] == "blocked"
    assert response["values"]["executed_records"] == 0
    assert response["values"]["uses_model_suggestions_as_authority"] is False
    assert all(row["evidence_event_ids"] == [record["event"]["event_id"]] for row in modules.values())
    assert record == before


def test_semantic_reuse_counts_one_actual_completion_not_two_or_six(record):
    semantic = {"status": "completed", "provider": "sensenova", "model": "offline-fixture", "elapsed_ms": 420,
                "verdict": "unsafe", "interpretation": "execute"}
    record["semantic_analysis"] = semantic
    record["ai_analysis"] = {**semantic, "reused_semantic": True}
    summary = build_agent_workbench([record, deepcopy(record)])["llm"]
    assert summary["completed_calls"] == 1 and summary["failed_calls"] == 0
    assert len(summary["call_records"]) == 1
    assert summary["call_records"][0]["purpose"] == "semantic"
    assert summary["call_records"][0]["elapsed_ms"] == 420


@pytest.mark.parametrize("status,counter", [("unavailable", "failed_calls"), ("invalid_response", "failed_calls"),
                                            ("skipped", "skipped_records"), ("not_configured", "not_configured_records")])
def test_model_failure_skip_and_unconfigured_are_not_success(record, status, counter):
    record["ai_analysis"] = {"status": status, "provider": "sensenova", "model": "offline-fixture", "reason_code": "budget_limit"}
    result = build_agent_workbench([record])["llm"]
    assert result[counter] == 1 and result["completed_calls"] == 0
    assert result["last_status"] == status


def test_missing_execution_result_does_not_invent_completion(record):
    record.pop("outcome")
    record.pop("executed_records")
    record["ai_analysis"] = {"status": "completed", "suggested_actions": ["ALLOW", "DELETE_DATABASE"]}
    response = next(row for row in build_agent_workbench([record])["modules"] if row["id"] == "response")
    values = response["findings"][0]["values"]
    assert values["recorded_outcome"] is None and values["executed_records"] is None
    assert "DELETE_DATABASE" not in values["policy_actions"]
    assert "缺少实际执行状态" in response["findings"][0]["summary"]


def test_workbench_never_connects_and_excludes_prompts_labels_rows_and_unknown_metadata(record, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("workbench must never call network")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    record["ground_truth"] = "ATTACK-TOP-LEVEL-MARKER"
    record["customer_rows"] = [{"private": "RAW-CUSTOMER-MARKER"}]
    record["event"]["prompt"] = "RAW-UNTRUSTED-PROMPT-MARKER"
    record["analysis"]["chain"][0]["attack_type"] = "CHAIN-ANSWER-MARKER"
    record["ai_analysis"]["unknown_secret"] = "UNKNOWN-SECRET-MARKER"
    result = json.dumps(build_agent_workbench([record]), ensure_ascii=False)
    assert not any(marker in result for marker in ("ATTACK-TOP-LEVEL", "RAW-CUSTOMER", "RAW-UNTRUSTED", "CHAIN-ANSWER", "UNKNOWN-SECRET"))


def test_widened_or_mismatched_detector_inputs_are_rejected(record):
    original = deepcopy(record)
    record["event"]["ground_truth"] = "ATTACK"
    with pytest.raises(ValidationError):
        build_agent_workbench([record])
    original["analysis"]["event_id"] = "different-event-id"
    with pytest.raises(ValueError, match="same event"):
        build_agent_workbench([original])
