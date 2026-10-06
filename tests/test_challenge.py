"""Business-label and reproducibility checks for diagnostic challenge cases."""

import json

import pytest

from datafence.challenge import (
    CANDIDATE_QUOTA,
    GROUPS,
    MISSING_APPROVAL,
    PRIMARY,
    build_challenge,
    run_challenge,
    verify_challenge,
)


def test_challenge_generation_is_independent_and_reproducible(monkeypatch):
    def must_not_run(*args, **kwargs):
        raise AssertionError("challenge labels must not use baseline recipes or detector judgments")
    monkeypatch.setattr("datafence.scenarios.generate_scenario", must_not_run)
    monkeypatch.setattr("datafence.engine.DetectionEngine", must_not_run)
    first = build_challenge(seed=123, variants=2)
    second = build_challenge(seed=123, variants=2)
    for index in (0, 1, 2):
        assert [item.model_dump(mode="json") for item in first[index]] == [item.model_dump(mode="json") for item in second[index]]
    assert first[3:] == second[3:]
    events, labels, manifest = first[2:]
    assert {case["group"] for case in manifest["cases"]} == set(GROUPS)
    assert len({event.event_id for event in events}) == len(events)
    assert {event.event_id for event in events} == {row["event_id"] for row in labels}
    for event in events:
        assert not {"ground_truth", "attack_type", "group", "partition", "case_id"}.intersection(event.model_dump())


def test_quota_labels_keep_legitimate_prefixes_and_separate_candidate_semantics():
    _, tasks, events, labels, manifest = build_challenge(42, 1)
    indexed_events = {event.event_id: event for event in events}
    for group in ("session_incremental_quota", "cross_session_total_quota", "cross_day_total_quota"):
        group_labels = [label for label in labels if label["group"] == group]
        query_labels = [label for label in group_labels if indexed_events[label["event_id"]].event_type == "QUERY"]
        total = 0
        for label in query_labels:
            event = indexed_events[label["event_id"]]
            total += event.record_count
            assert (label["ground_truth"] == "ATTACK") == (total > label["quota_limit"])
        assert query_labels[0]["ground_truth"] == "NORMAL"
        assert query_labels[-1]["ground_truth"] == "ATTACK"
        assert all(label["ground_truth"] == "NORMAL" for label in group_labels if indexed_events[label["event_id"]].event_type == "LOGIN")
        if group != "session_incremental_quota":
            assert {label["partition"] for label in group_labels} == {CANDIDATE_QUOTA}
            assert all(indexed_events[label["event_id"]].record_count < label["quota_limit"] for label in query_labels)
        else:
            assert {label["partition"] for label in group_labels} == {PRIMARY}


def test_device_approvals_and_ai_negation_have_explicit_normal_ground_truth():
    employees, _, events, labels, manifest = build_challenge(100, 6)
    employee_index = {employee.id: employee for employee in employees}
    event_index = {event.event_id: event for event in events}
    for label in labels:
        event = event_index[label["event_id"]]
        if label["group"] in ("approved_night", "approved_registered_device", "approved_device_without_contract_field", "ai_authorized_or_negated"):
            assert label["ground_truth"] == "NORMAL"
        if label["group"] == "approved_registered_device":
            assert employee_index[event.employee_id].known_device == event.device_id
        if label["group"] == "approved_device_without_contract_field":
            assert employee_index[event.employee_id].known_device != event.device_id
            assert label["partition"] == MISSING_APPROVAL
        if label["group"] == "ai_egress_paraphrase":
            assert (label["ground_truth"] == "ATTACK") == (event.event_type == "AI_PROMPT")
    case = next(case for case in manifest["cases"] if case["group"] == "approved_device_without_contract_field")
    assert case["device_approval"]["approved"] is True


def test_report_is_recomputable_and_does_not_mix_candidate_false_negatives(tmp_path, monkeypatch):
    report = run_challenge(tmp_path, seed=123, variants=1)
    primary = report["results"]["full"]["partitions"][PRIMARY]
    assert report["metrics"] == primary["metrics"]
    assert primary["event_count"] < report["event_count"]
    assert sum(part["event_count"] for part in report["results"]["full"]["partitions"].values()) == report["event_count"]
    def must_not_run(*args, **kwargs):
        raise AssertionError("verification must not call the detector")
    monkeypatch.setattr("datafence.challenge.predict_event_stream", must_not_run)
    assert verify_challenge(tmp_path) == report["results"]
    predictions = [json.loads(line) for line in (tmp_path / "predictions.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(row["response_executed"] is False for row in predictions)
    with (tmp_path / "labels.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{}\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_challenge(tmp_path)


@pytest.mark.parametrize("seed,variants", [(-1, 1), (True, 1), (0, 0), (0, 21)])
def test_invalid_challenge_settings_are_rejected(seed, variants):
    with pytest.raises(ValueError):
        build_challenge(seed, variants)
