"""Regression tests for evidence boundaries, local recipes and detector behavior."""

from datetime import timedelta

import pytest
from pydantic import ValidationError

from datafence.engine import DetectionEngine, TRAINING_SEED
from datafence.models import SecurityEvent, SimulationRequest
from datafence.sandbox import build_bank
from datafence.scenarios import SCENARIOS, generate_scenario


@pytest.fixture(scope="module")
def bank():
    return build_bank(seed=101, customer_count=100)


def make_events(bank, scenario, **kwargs):
    return generate_scenario(SimulationRequest(scenario_id=scenario, **kwargs), bank["employees"], bank["tasks"])


def make_engine(bank, mode="full"):
    return DetectionEngine(bank["employees"], bank["tasks"], mode=mode)


def test_synthetic_bank_links_and_manifest(bank):
    assert len(bank["employees"]) == 100
    assert "E0038" in {row.id for row in bank["employees"]}
    customer_ids = {row["id"] for row in bank["customers"]}
    account_ids = {row["id"] for row in bank["accounts"]}
    assert all(row["customer_id"] in customer_ids for row in bank["accounts"] + bank["loans"])
    assert all(row["account_id"] in account_ids for row in bank["transactions"])
    assert bank["manifest"]["counts"]["customers"] == len(customer_ids)
    assert all(row["contact"].endswith("@example.invalid") for row in bank["customers"])
    assert bank == build_bank(seed=101, customer_count=100)


@pytest.mark.parametrize("scenario", [row["id"] for row in SCENARIOS])
def test_scenarios_have_reproducible_separate_labels(bank, scenario):
    events, labels = make_events(bank, scenario, seed=55)
    assert (events, labels) == make_events(bank, scenario, seed=55)
    assert len(events) == len(labels)
    assert [row["event_id"] for row in labels] == [event.event_id for event in events]
    assert len({event.event_id for event in events}) == len(events)
    assert all(set(event.model_dump()).isdisjoint({"ground_truth", "attack_type", "scenario_id", "run_id"}) for event in events)
    other_events, _ = make_events(bank, scenario, seed=56)
    assert events[0].session_id != other_events[0].session_id


@pytest.mark.parametrize("scenario", ["insider", "stolen_account", "bulk_export", "api_scraping", "ai_leak", "combined"])
def test_each_attack_is_detected_without_future_steps(bank, scenario):
    events, labels = make_events(bank, scenario)
    engine = make_engine(bank)
    observed = []
    detected = False
    for event, label in zip(events, labels):
        analysis = engine.analyze(event)
        observed.append(event.event_id)
        assert all(node["event_id"] in observed for node in analysis.chain)
        if label["ground_truth"] == "ATTACK" and analysis.risk_score >= 60:
            detected = True
        if "FREEZE_SESSION" in analysis.actions:
            break
    assert detected


@pytest.mark.parametrize("scenario", ["normal", "approved_batch"])
@pytest.mark.parametrize("seed", [2, 7, 11, 41, 99])
def test_supported_normal_work_and_approved_batch_are_allowed(bank, scenario, seed):
    events, labels = make_events(bank, scenario, seed=seed, record_count=35000)
    engine = make_engine(bank)
    for event in events:
        analysis = engine.analyze(event)
        assert analysis.intent.status == "supported"
        assert not analysis.blocked
        assert analysis.risk_score < 30
        assert analysis.actions == ["ALLOW"]
    assert all(label["ground_truth"] == "NORMAL" for label in labels)
    if scenario == "approved_batch":
        assert events[-1].event_type == "UPLOAD"
        assert events[-1].channel == "approved_partner"


def test_unknown_task_is_uncertainty_not_a_fabricated_purpose(bank):
    events, _ = make_events(bank, "normal")
    event = events[-1].model_copy(update={"task_id": None})
    analysis = make_engine(bank).analyze(event)
    assert analysis.intent.status == "insufficient_evidence"
    assert analysis.intent.purpose_match == 50
    assert "未知" in " ".join(analysis.intent.evidence)
    assert not analysis.blocked


def test_stolen_task_cannot_authorize_employee(bank):
    events, _ = make_events(bank, "approved_batch")
    foreign_task = next(task for task in bank["tasks"] if task.employee_id != events[-1].employee_id and task.allow_export)
    analysis = make_engine(bank).analyze(events[2].model_copy(update={"task_id": foreign_task.id}))
    assert analysis.intent.status == "mismatch"
    assert analysis.intent.trust <= 10
    assert "BLOCK_EXPORT" in analysis.actions


@pytest.mark.parametrize("field", ["ground_truth", "attack_type", "scenario_id", "run_id"])
def test_detector_contract_rejects_answer_metadata(bank, field):
    events, _ = make_events(bank, "normal")
    data = events[-1].model_dump()
    data[field] = "ATTACK"
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(data)
    with pytest.raises(TypeError):
        make_engine(bank).analyze(data)


def test_scores_do_not_depend_on_ids_or_generator_seed(bank):
    events, _ = make_events(bank, "combined")
    left = make_engine(bank)
    right = make_engine(bank)
    for index, event in enumerate(events):
        original = left.analyze(event)
        renamed = right.analyze(event.model_copy(update={"event_id": f"replacement-{index:08d}", "session_id": "unrelated-session-0001"}))
        assert original.risk_score == renamed.risk_score
        assert original.anomaly_score == renamed.anomaly_score
    other_bank = build_bank(seed=999, customer_count=10)
    assert make_engine(other_bank).model_info["training_seed"] == TRAINING_SEED


def test_real_isolation_forest_has_a_score_for_behavior_deviation(bank):
    events, _ = make_events(bank, "normal")
    normal = events[-1]
    suspicious = normal.model_copy(update={"event_id": "suspicious-event-0001", "session_id": "separate-session-0001",
                                          "record_count": 49000, "regions": [f"region-{i}" for i in range(20)],
                                          "device_id": "unknown-device", "channel": "external"})
    model = make_engine(bank, "behavior")
    ordinary_score = model.analyze(normal).anomaly_score
    suspicious_score = model.analyze(suspicious).anomaly_score
    assert model._model.n_estimators == 100
    assert len(model._model.estimators_) == 100
    assert suspicious_score > ordinary_score
    assert model.model_info["uses_evaluation_labels"] is False


def test_sensitive_outbound_data_blocked_even_without_task(bank):
    events, _ = make_events(bank, "normal")
    event = events[-1].model_copy(update={"event_type": "UPLOAD", "channel": "external", "task_id": None})
    result = make_engine(bank).analyze(event)
    assert result.blocked
    assert "BLOCK_UPLOAD" in result.actions
    assert result.risk_score >= 90


def test_chain_does_not_mix_sessions_or_unrelated_objects(bank):
    events, _ = make_events(bank, "approved_batch")
    login, query, export = events[:3]
    engine = make_engine(bank)
    engine.analyze(login)
    engine.analyze(query)
    unrelated = query.model_copy(update={"event_id": "other-object-query", "object_id": "other-dataset", "record_count": 1,
                                         "timestamp": query.timestamp + timedelta(microseconds=1)})
    engine.analyze(unrelated)
    chain = engine.analyze(export).chain
    assert {node["event_id"] for node in chain} == {login.event_id, query.event_id, export.event_id}
    other_session = export.model_copy(update={"event_id": "other-session-export", "session_id": "other-session-0001"})
    assert len(engine.analyze(other_session).chain) == 1
    other_employee = export.model_copy(update={"event_id": "other-employee-export", "employee_id": "E0001"})
    assert len(engine.analyze(other_employee).chain) == 1


def test_reset_and_temporal_boundary(bank):
    events, _ = make_events(bank, "normal")
    engine = make_engine(bank)
    engine.analyze(events[-1])
    with pytest.raises(ValueError, match="already analyzed"):
        engine.analyze(events[-1])
    with pytest.raises(ValueError, match="nondecreasing"):
        engine.analyze(events[0])
    engine.reset()
    assert len(engine.analyze(events[0]).chain) == 1


def test_task_time_is_checked_in_bank_timezone(bank):
    events, _ = make_events(bank, "normal")
    event = events[-1]
    from datetime import timezone
    equivalent = event.model_copy(update={"timestamp": event.timestamp.astimezone(timezone.utc)})
    assert make_engine(bank).analyze(equivalent).intent == make_engine(bank).analyze(event).intent


def test_approved_batch_differs_in_ablation_because_context_explains_scale(bank):
    events, _ = make_events(bank, "approved_batch", record_count=25000)
    full, rules = make_engine(bank), make_engine(bank, "rules")
    full_outputs = [full.analyze(event) for event in events]
    rules_outputs = [rules.analyze(event) for event in events]
    assert all(result.risk_score < 60 for result in full_outputs)
    assert any(result.risk_score >= 60 for result in rules_outputs)


def test_ai_prompt_requires_sensitive_content_and_outbound_intent(bank):
    events, _ = make_events(bank, "ai_leak", record_count=8)
    unsafe = make_engine(bank).analyze(events[-1])
    assert "BLOCK_AI_PROMPT" in unsafe.actions
    benign = events[-1].model_copy(update={"prompt": "请汇总已脱敏客户服务工单数量，不含任何个人字段。"})
    safe = make_engine(bank).analyze(benign)
    assert "BLOCK_AI_PROMPT" not in safe.actions


def test_explanation_distinguishes_weighted_base_from_policy_override(bank):
    import re
    events, _ = make_events(bank, "ai_leak")
    analysis = make_engine(bank).analyze(events[-1])
    match = re.search(r"五维加权基础分 ([0-9.]+)/100；确定性策略/关联调整后的最终风险 ([0-9.]+)/100", analysis.explanation)
    assert match is not None
    base, final = map(float, match.groups())
    assert base < final
    assert final == round(analysis.risk_score, 1)
    assert "权重为 PoC 初始值" in analysis.explanation
