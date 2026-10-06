import copy
import json

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from datafence import engine, model_artifacts, training
from datafence.engine import DetectionEngine, FEATURES
from datafence.model_artifacts import FORMAT, canonical, export_forest, load_artifact, model_directory, sha256
from datafence.models import SimulationRequest
from datafence.sandbox import build_bank
from datafence.scenarios import generate_scenario
from datafence.runtime_lock import RuntimeLock


@pytest.fixture
def registry(tmp_path, monkeypatch):
    directory = tmp_path / "models"
    for module in (engine, model_artifacts, training):
        monkeypatch.setattr(module, "MODEL_ROOT", directory)
    engine._registered_model.cache_clear()
    monkeypatch.delenv("DATAFENCE_BEHAVIOR_MODEL", raising=False)
    yield directory
    engine._registered_model.cache_clear()


@pytest.fixture(scope="module")
def fitted():
    values = training.normal_features(111, 600)
    return IsolationForest(n_estimators=10, max_samples=256, random_state=51).fit(values)


def artifact(fitted, name="unit-safe"):
    payload = {"format": FORMAT, "features": FEATURES, "forest": export_forest(fitted),
               "calibration": {"low": .4, "high": .7},
               "metadata": {"version": name, "training_seed": 51, "training_samples": 600,
                            "uses_evaluation_labels": False}}
    return {"payload": payload, "sha256": sha256(payload)}


def test_training_streams_are_deterministic_distinct_and_label_free():
    train = training.normal_features(training.TRAIN_SEED, 300)
    calibration = training.normal_features(training.CALIBRATION_SEED, 300)
    holdout = training.normal_features(training.HOLDOUT_NORMAL_SEED, 300)
    assert np.array_equal(train, training.normal_features(training.TRAIN_SEED, 300))
    assert train.shape == calibration.shape == holdout.shape == (300, len(FEATURES))
    assert np.isfinite(train).all()
    assert not {row.tobytes() for row in train}.intersection(row.tobytes() for row in calibration)
    assert not {row.tobytes() for row in train}.intersection(row.tobytes() for row in holdout)


def test_json_predictions_match_original_sklearn_forest(tmp_path, fitted):
    path = tmp_path / "model.json"
    path.write_bytes(canonical(artifact(fitted)))
    restored, low, high, _ = load_artifact(path, FEATURES)
    normal = training.normal_features(777, 400)
    probes, _ = training.holdout_probes(888, 300)
    matrix = np.concatenate([normal, probes])
    assert np.max(np.abs(fitted.score_samples(matrix) - restored.score_samples(matrix))) < 1e-12
    assert (low, high) == (.4, .7)
    assert restored.n_estimators == len(fitted.estimators_)
    with pytest.raises(ValueError, match="finite"):
        restored.score_samples([[float("nan")] * len(FEATURES)])


@pytest.mark.parametrize("mutate", [
    lambda p: p["features"].reverse(),
    lambda p: p["forest"]["trees"][0]["left"].__setitem__(0, 0),
    lambda p: p["forest"]["trees"][0]["feature"].__setitem__(0, 999),
    lambda p: p["forest"]["trees"][0]["sample_count"].__setitem__(0, 1),
    lambda p: p["calibration"].update(low=.8, high=.7),
])
def test_even_rehashed_invalid_model_structures_are_rejected(tmp_path, fitted, mutate):
    document = copy.deepcopy(artifact(fitted))
    mutate(document["payload"])
    document["sha256"] = sha256(document["payload"])
    path = tmp_path / "model.json"
    path.write_bytes(canonical(document))
    with pytest.raises(ValueError):
        load_artifact(path, FEATURES)


def test_digest_and_file_size_are_checked(tmp_path, fitted):
    document = artifact(fitted)
    document["payload"]["metadata"]["training_samples"] = 999
    path = tmp_path / "model.json"
    path.write_bytes(canonical(document))
    with pytest.raises(ValueError, match="digest"):
        load_artifact(path, FEATURES)
    with pytest.raises(ValueError, match="size"):
        model_artifacts.read_json(path, limit=50)


@pytest.mark.parametrize("name", ["../outside", "C:/external/model", "https://external.invalid/a", "active", "legacy"])
def test_registry_rejects_paths_and_reserved_names(registry, name):
    with pytest.raises(ValueError):
        model_directory(name)


def test_tiny_training_fails_fixed_promotion_gate_and_cannot_overwrite(registry):
    report = training.train_model("tiny-candidate", train_rows=600, calibration_rows=400,
                                  normal_test_rows=400, probe_test_rows=300, promote=True)
    assert report["quality_gate"]["checks"]["minimum_split_sizes"] is False
    assert report["quality_gate"]["passed"] is False and report["promoted"] is False
    assert not (registry / "active.json").exists()
    directory = registry / "tiny-candidate"
    assert (directory / "protocol.json").exists() and (directory / "holdout_labels.json").exists()
    with np.load(directory / "normal_train.npz", allow_pickle=False) as data:
        assert set(data.files) == {"features"}
        assert data["features"].shape == (600, len(FEATURES))
    with pytest.raises(ValueError, match="already exists"):
        training.train_model("tiny-candidate", train_rows=600, calibration_rows=400,
                             normal_test_rows=400, probe_test_rows=300)


def test_engine_loads_verified_promoted_model_or_safely_falls_back(registry, fitted):
    name = "unit-safe"
    directory = model_directory(name)
    directory.mkdir(parents=True)
    document = artifact(fitted, name)
    (directory / "model.json").write_bytes(canonical(document))
    report = {"name": name, "artifact_sha256": document["sha256"], "quality_gate": {"passed": True},
              "candidate": {"normal_fpr": .02}}
    (directory / "report.json").write_bytes(canonical(report))
    (directory / "promotion.json").write_bytes(canonical({"name": name, "artifact_sha256": document["sha256"],
                                                             "report_sha256": sha256(report), "promoted_at": "test"}))
    (registry / "active.json").write_bytes(canonical({"name": name, "artifact_sha256": document["sha256"], "report_sha256": sha256(report)}))
    bank = build_bank(customer_count=10)
    detector = DetectionEngine(bank["employees"], bank["tasks"])
    assert detector.model_info["version"] == name
    assert detector.model_info["model_source"] == "validated_json_artifact"
    (directory / "promotion.json").unlink()
    revoked_receipt = DetectionEngine(bank["employees"], bank["tasks"])
    assert revoked_receipt.model_info["version"] == "iforest-v1"
    assert "load_warning" in revoked_receipt.model_info
    legacy = DetectionEngine(bank["employees"], bank["tasks"], behavior_model="legacy")
    assert legacy.model_info["version"] == "iforest-v1"
    (registry / "active.json").write_text('{"name":"../outside"}', encoding="utf-8")
    fallback = DetectionEngine(bank["employees"], bank["tasks"])
    assert fallback.model_info["version"] == "iforest-v1" and "load_warning" in fallback.model_info


def test_missing_receipt_and_missing_active_are_visible_fallbacks(registry, fitted):
    directory = model_directory("receipt-check")
    directory.mkdir(parents=True)
    document = artifact(fitted, "receipt-check")
    report = {"name": "receipt-check", "artifact_sha256": document["sha256"],
              "quality_gate": {"passed": True}, "candidate": {"normal_fpr": .02}}
    (directory / "model.json").write_bytes(canonical(document))
    (directory / "report.json").write_bytes(canonical(report))
    (registry / "active.json").write_bytes(canonical({"name": "receipt-check",
        "artifact_sha256": document["sha256"], "report_sha256": sha256(report)}))
    missing_receipt = DetectionEngine([], [])
    assert missing_receipt.model_info["version"] == "iforest-v1"
    assert "load_warning" in missing_receipt.model_info
    (registry / "active.json").unlink()
    missing_active = DetectionEngine([], [])
    assert missing_active.model_info["version"] == "iforest-v1"
    assert "load_warning" in missing_active.model_info


def test_failed_receipt_write_cannot_activate_candidate(registry, monkeypatch):
    old = b'{"previous":"model"}'
    (registry / "active.json").parent.mkdir(parents=True, exist_ok=True)
    (registry / "active.json").write_bytes(old)
    monkeypatch.setattr(training, "GATES", {**training.GATES, "min_train_rows": 300,
        "min_calibration_rows": 300, "min_holdout_normal_rows": 300,
        "min_holdout_probe_rows": 300, "normal_fpr_wilson_upper_max": 1.0,
        "probe_recall_min": 0.0, "f1_regression_tolerance": 1.0,
        "export_max_abs_error": 1.0})
    write = training._write_json

    def fail_receipt(path, document):
        if path.name == "promotion.json":
            raise OSError("injected receipt failure")
        return write(path, document)

    monkeypatch.setattr(training, "_write_json", fail_receipt)
    with pytest.raises(OSError, match="injected receipt failure"):
        training.train_model("fault-candidate", train_rows=300, calibration_rows=300,
                             normal_test_rows=300, probe_test_rows=300, promote=True)
    assert (registry / "active.json").read_bytes() == old
    assert not (registry / "fault-candidate" / "promotion.json").exists()


def test_running_runtime_ownership_prevents_model_switch(registry, monkeypatch):
    old = b'{"previous":"model"}'
    registry.mkdir(parents=True, exist_ok=True)
    (registry / "active.json").write_bytes(old)
    monkeypatch.setattr(training, "GATES", {**training.GATES, "min_train_rows": 300,
        "min_calibration_rows": 300, "min_holdout_normal_rows": 300,
        "min_holdout_probe_rows": 300, "normal_fpr_wilson_upper_max": 1.0,
        "probe_recall_min": 0.0, "f1_regression_tolerance": 1.0,
        "export_max_abs_error": 1.0})
    with RuntimeLock(registry.parent):
        with pytest.raises(RuntimeError, match="占用"):
            training.train_model("busy-candidate", train_rows=300, calibration_rows=300,
                                 normal_test_rows=300, probe_test_rows=300, promote=True)
    assert (registry / "active.json").read_bytes() == old
    assert not (registry / "busy-candidate" / "promotion.json").exists()


def test_failed_pointer_write_keeps_previous_selection(registry, monkeypatch):
    registry.mkdir(parents=True, exist_ok=True)
    old = b'{"previous":"model"}'
    (registry / "active.json").write_bytes(old)
    monkeypatch.setattr(training, "GATES", {**training.GATES, "min_train_rows": 300,
        "min_calibration_rows": 300, "min_holdout_normal_rows": 300,
        "min_holdout_probe_rows": 300, "normal_fpr_wilson_upper_max": 1.0,
        "probe_recall_min": 0.0, "f1_regression_tolerance": 1.0,
        "export_max_abs_error": 1.0})
    write = training._write_json

    def fail_pointer(path, document):
        if path.name == "active.json":
            raise OSError("injected pointer failure")
        return write(path, document)

    monkeypatch.setattr(training, "_write_json", fail_pointer)
    with pytest.raises(OSError, match="injected pointer failure"):
        training.train_model("pointer-candidate", train_rows=300, calibration_rows=300,
                             normal_test_rows=300, probe_test_rows=300, promote=True)
    assert (registry / "active.json").read_bytes() == old
    assert (registry / "pointer-candidate" / "promotion.json").is_file()


@pytest.mark.parametrize("field", ["artifact_sha256", "report_sha256"])
@pytest.mark.parametrize("invalid", ["", None, False, 0, "a" * 63, "g" * 64, "f" * 64])
def test_active_pointer_cannot_disable_or_misstate_promotion_digest(registry, fitted, field, invalid):
    name = "digest-check"
    directory = model_directory(name)
    directory.mkdir(parents=True)
    document = artifact(fitted, name)
    (directory / "model.json").write_bytes(canonical(document))
    report = {"name": name, "artifact_sha256": document["sha256"], "quality_gate": {"passed": True},
              "candidate": {"normal_fpr": .02}}
    (directory / "report.json").write_bytes(canonical(report))
    (directory / "promotion.json").write_bytes(canonical({"name": name, "artifact_sha256": document["sha256"],
                                                             "report_sha256": sha256(report), "promoted_at": "test"}))
    pointer = {"name": name, "artifact_sha256": document["sha256"], "report_sha256": sha256(report)}
    pointer[field] = invalid
    (registry / "active.json").write_bytes(canonical(pointer))
    detector = DetectionEngine([], [], behavior_model="active")
    assert detector.model_info["version"] == "iforest-v1"
    assert "load_warning" in detector.model_info


def test_commit_replaces_only_latest_current_event_state(registry):
    bank = build_bank(customer_count=10)
    events, _ = generate_scenario(SimulationRequest(scenario_id="combined"), bank["employees"], bank["tasks"])
    detector = DetectionEngine(bank["employees"], bank["tasks"], behavior_model="legacy")
    first = detector.analyze(events[0])
    second = detector.analyze(events[1])
    final = second.model_copy(deep=True, update={"risk_score": 15.0, "blocked": False})
    final.chain[0]["risk_score"] = 0
    final.chain[-1]["event_type"] = "INJECTED"
    detector.commit_analysis(events[1], final)
    third = detector.analyze(events[2])
    assert third.chain[0]["risk_score"] == first.risk_score
    assert third.chain[-2]["risk_score"] == 15.0 and third.chain[-2]["blocked"] is False
    assert third.chain[-2]["event_type"] == "QUERY"
    assert final.chain[-1]["risk_score"] == 15.0
    with pytest.raises(ValueError, match="most recently"):
        detector.commit_analysis(events[1], final)
    with pytest.raises(ValueError, match="most recently"):
        detector.commit_analysis(events[2].model_copy(update={"session_id": "different-session"}), third)


def test_commit_rejects_forged_final_identifier_and_invalid_risk(registry):
    bank = build_bank(customer_count=10)
    events, _ = generate_scenario(SimulationRequest(scenario_id="normal"), bank["employees"], bank["tasks"])
    detector = DetectionEngine(bank["employees"], bank["tasks"], behavior_model="legacy")
    result = detector.analyze(events[0])
    with pytest.raises(ValueError):
        detector.commit_analysis(events[0], result.model_copy(update={"event_id": "other-event"}))
    with pytest.raises(ValueError):
        detector.commit_analysis(events[0], result.model_copy(update={"risk_score": float("nan")}))
    invalid_chain = result.model_copy(deep=True)
    invalid_chain.chain[-1]["event_id"] = "other-event"
    with pytest.raises(ValueError, match="chain"):
        detector.commit_analysis(events[0], invalid_chain)
