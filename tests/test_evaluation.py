"""Evaluation integrity tests, independent of UI and response orchestration."""

import hashlib
import json

import pytest
from pydantic import ValidationError

from datafence.evaluation import (
    MODES,
    SCENARIO_IDS,
    _latency_statistics,
    calculate_metrics,
    generate_evaluation_dataset,
    predict_event_stream,
    recompute_evaluation,
    recompute_metrics,
    run_evaluation,
)
from datafence.models import SecurityEvent


def test_known_confusion_matrix_and_undefined_denominators():
    metrics = calculate_metrics(
        [True, True, True, True, False, False, False, False],
        [True, True, True, False, True, False, False, False],
    )
    assert metrics == {"tp": 3, "fp": 1, "tn": 3, "fn": 1,
                       "precision": .75, "recall": .75, "f1": .75, "fpr": .25}
    no_alerts = calculate_metrics([False, False], [False, False])
    assert no_alerts["precision"] is None
    assert no_alerts["recall"] is None
    assert no_alerts["f1"] is None
    assert no_alerts["fpr"] == 0
    only_misses = calculate_metrics([True], [False])
    assert only_misses["recall"] == 0
    assert only_misses["f1"] == 0
    assert only_misses["fpr"] is None
    with pytest.raises(ValueError, match="lengths differ"):
        calculate_metrics([True], [])
    with pytest.raises(ValueError, match="actual boolean"):
        calculate_metrics(["ATTACK"], [True])


def test_recomputation_separates_event_and_session_metrics():
    labels = [
        {"event_id": "login", "session_id": "attack_session", "ground_truth": "NORMAL", "scenario_id": "insider"},
        {"event_id": "query", "session_id": "attack_session", "ground_truth": "ATTACK", "scenario_id": "insider"},
        {"event_id": "normal", "session_id": "normal_session", "ground_truth": "NORMAL", "scenario_id": "normal"},
    ]
    predictions = [
        {"event_id": row["event_id"], "session_id": row["session_id"], "mode": "full", "detected": row["event_id"] == "query"}
        for row in labels
    ]
    result = recompute_metrics(labels, predictions)["full"]
    assert result["metrics"]["tn"] == 2
    assert result["session_metrics"]["tn"] == 1
    assert result["session_metrics"]["tp"] == 1
    normal = next(row for row in result["per_scenario"] if row["scenario_id"] == "normal")
    assert normal["recall"] is None
    assert normal["false_positive_rate"] == 0
    with pytest.raises(ValueError, match="incomplete"):
        recompute_metrics(labels, predictions[:-1])
    with pytest.raises(ValueError, match="duplicate prediction"):
        recompute_metrics(labels, predictions + predictions[:1])
    with pytest.raises(ValueError, match="duplicate ground truth"):
        recompute_metrics(labels + labels[:1], predictions)


def test_seeded_generation_is_identical_and_labels_stay_outside_events():
    _, events_one, labels_one, manifest_one = generate_evaluation_dataset(seed=20260919, sessions=16)
    _, events_two, labels_two, manifest_two = generate_evaluation_dataset(seed=20260919, sessions=16)
    event_dicts = [event.model_dump(mode="json") for event in events_one]
    assert event_dicts == [event.model_dump(mode="json") for event in events_two]
    assert labels_one == labels_two
    assert manifest_one == manifest_two
    assert set(manifest_one["scenario_counts"]) == set(SCENARIO_IDS)
    assert len({event.session_id for event in events_one}) == 16
    assert len({event.event_id for event in events_one}) == len(events_one)
    assert {event.event_id for event in events_one} == {row["event_id"] for row in labels_one}
    forbidden = {"ground_truth", "attack_type", "scenario_id", "run_id"}
    assert all(not forbidden.intersection(event) for event in event_dicts)
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate({**event_dicts[0], "ground_truth": "ATTACK"})
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate({**event_dicts[0], "scenario_id": "combined"})


def test_swapping_labels_does_not_change_detection(tmp_path):
    bank, events, labels, _ = generate_evaluation_dataset(seed=42, sessions=8)
    original_events = [event.model_dump(mode="json") for event in events]
    label_path = tmp_path / "labels.jsonl"
    label_path.write_text("\n".join(json.dumps(row) for row in labels), encoding="utf-8")
    first, _, _ = predict_event_stream(events, bank["employees"], bank["tasks"], "full")
    swapped = [
        {**row, "ground_truth": "NORMAL" if row["ground_truth"] == "ATTACK" else "ATTACK"}
        for row in labels
    ]
    label_path.write_text("\n".join(json.dumps(row) for row in swapped), encoding="utf-8")
    second, _, _ = predict_event_stream(events, bank["employees"], bank["tasks"], "full")
    # Wall-clock timing is measured anew and is intentionally nondeterministic.
    def without_timing(records):
        return [{key: value for key, value in row.items() if key != "processing_ms"} for row in records]
    assert without_timing(first) == without_timing(second)
    assert original_events == [event.model_dump(mode="json") for event in events]
    assert recompute_metrics(labels, first)["full"]["metrics"] != recompute_metrics(swapped, second)["full"]["metrics"]


def test_latency_distinguishes_misses_and_pre_onset_alerts():
    def label(event, session, actual):
        return {"event_id": event, "session_id": session, "ground_truth": actual, "scenario_id": "combined"}
    def prediction(event, session, second, detected):
        return {"event_id": event, "session_id": session, "timestamp": f"2026-09-19T00:00:{second:02d}+00:00",
                "detected": detected, "processing_ms": 2.0}
    labels = [label("a", "delayed", "ATTACK"), label("b", "delayed", "ATTACK"),
              label("c", "missed", "ATTACK"), label("d", "early", "NORMAL"), label("e", "early", "ATTACK")]
    predictions = [prediction("a", "delayed", 10, False), prediction("b", "delayed", 14, True),
                   prediction("c", "missed", 20, False), prediction("d", "early", 29, True), prediction("e", "early", 30, False)]
    result = _latency_statistics(labels, predictions)
    assert result["detection_delay_seconds_p50"] == 4
    assert result["detection_delay_samples"] == 1
    assert result["early_alert_sessions"] == 1
    assert result["missed_sessions"] == 1
    assert result["attack_sessions"] == 3
    assert result["response_time_ms"] is None
    assert result["responses_executed"] == 0


def test_run_artifacts_recalculate_all_modes_without_detector(tmp_path, monkeypatch):
    report = run_evaluation(seed=20260919, sessions=24, output_dir=tmp_path)
    labels = [json.loads(line) for line in (tmp_path / "labels.jsonl").read_text(encoding="utf-8").splitlines()]
    predictions = [json.loads(line) for line in (tmp_path / "predictions.jsonl").read_text(encoding="utf-8").splitlines()]
    independently_recomputed = recompute_metrics(labels, predictions)
    assert set(independently_recomputed) == set(MODES)
    assert len(predictions) == report["event_count"] * len(MODES)
    assert report["event_count"] == report["attack_events"] + report["normal_events"]
    assert report["metrics"] == independently_recomputed["full"]["metrics"]
    assert report["session_metrics"] == independently_recomputed["full"]["session_metrics"]
    assert report["per_scenario"] == independently_recomputed["full"]["per_scenario"]
    for ablation in report["ablations"]:
        for key, value in independently_recomputed[ablation["mode"]]["metrics"].items():
            assert ablation[key] == value
    for artifact in report["artifacts"].values():
        assert hashlib.sha256((tmp_path / artifact["file"]).read_bytes()).hexdigest() == artifact["sha256"]
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8")) == report
    assert all(row["response_executed"] is False for row in predictions)
    assert report["latency"]["response_time_ms"] is None
    assert report["protocol"]["llm_enabled"] is False
    assert "no OS" in report["protocol"]["label_isolation"]
    def detector_must_not_run(*args, **kwargs):
        raise AssertionError("recomputation must not invoke the detector")
    monkeypatch.setattr("datafence.evaluation.predict_event_stream", detector_must_not_run)
    assert recompute_evaluation(tmp_path) == independently_recomputed
    tampered_report = json.loads(json.dumps(report))
    tampered_report["ablations"][0]["session_metrics"]["fp"] += 1
    (tmp_path / "report.json").write_text(json.dumps(tampered_report), encoding="utf-8")
    with pytest.raises(ValueError, match="recomputed session_metrics"):
        recompute_evaluation(tmp_path)
    (tmp_path / "report.json").write_text(json.dumps(report), encoding="utf-8")
    with (tmp_path / "predictions.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{}\n")
    with pytest.raises(ValueError, match="digest mismatch"):
        recompute_evaluation(tmp_path)


@pytest.mark.parametrize("seed,sessions", [(-1, 24), (True, 24), (0, 7), (0, 1001), (0, True)])
def test_invalid_generation_configuration_rejected(seed, sessions):
    with pytest.raises(ValueError):
        generate_evaluation_dataset(seed=seed, sessions=sessions)


def test_existing_evaluation_artifact_is_preserved_before_detection(tmp_path, monkeypatch):
    prior = tmp_path / "report.json"
    prior.write_bytes(b'{"prior_experiment":"must remain byte-for-byte"}')
    before = prior.read_bytes()

    def should_not_generate(*args, **kwargs):
        raise AssertionError("existing experiments must be refused before new generation")

    monkeypatch.setattr("datafence.evaluation.generate_evaluation_dataset", should_not_generate)
    with pytest.raises(ValueError, match="already exists"):
        run_evaluation(seed=12, sessions=8, output_dir=tmp_path)
    assert prior.read_bytes() == before
    assert list(tmp_path.iterdir()) == [prior]


def test_failed_evaluation_keeps_exclusive_claim_to_preserve_partial_evidence(tmp_path, monkeypatch):
    def interrupted(*args, **kwargs):
        (tmp_path / "events.jsonl").write_bytes(b"partial synthetic evidence\n")
        raise RuntimeError("synthetic interruption")

    monkeypatch.setattr("datafence.evaluation._run_claimed_evaluation", interrupted)
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        run_evaluation(seed=12, sessions=8, output_dir=tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    with pytest.raises(ValueError, match="already exists"):
        run_evaluation(seed=13, sessions=8, output_dir=tmp_path)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_two_evaluations_cannot_claim_the_same_empty_directory(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    started, finish = Event(), Event()

    def one_writer(*args, **kwargs):
        started.set()
        assert finish.wait(5)
        return {"completed": True}

    monkeypatch.setattr("datafence.evaluation._run_claimed_evaluation", one_writer)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run_evaluation, 12, 8, tmp_path)
        try:
            assert started.wait(5)
            with pytest.raises(ValueError, match="already exists"):
                pool.submit(run_evaluation, 13, 8, tmp_path).result(timeout=5)
        finally:
            finish.set()
        assert first.result(timeout=5) == {"completed": True}
