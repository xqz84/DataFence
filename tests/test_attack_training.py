import json

import pytest
from pydantic import ValidationError

from datafence.attack_training import run_experiment
from datafence.challenge import build_challenge
from datafence.models import SecurityEvent


def test_attack_answers_cannot_enter_detector_event():
    _, _, events, labels, _ = build_challenge(variants=1)
    event = events[0].model_dump(mode="json")
    event.update(ground_truth=labels[0]["ground_truth"], attack_type="forged")
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(event)


def test_labeled_candidate_is_offline_and_preserves_outputs(tmp_path):
    directory = tmp_path / "candidate"
    report = run_experiment(directory, sessions={"fit": 160, "calibration": 160, "template_holdout": 160})
    artifact = json.loads((directory / "candidate.json").read_bytes())
    assert report["dataset"]["fit"]["attacks"] > 0
    assert report["dataset"]["template_holdout"]["attacks"] > 0
    assert all(value == 0 for field in ("session_ids", "event_ids")
               for value in report["split_overlap"][field].values())
    assert any(value > 0 for value in report["split_overlap"]["employee_ids"].values())
    assert artifact["training_kind"] == "labeled synthetic sandbox events"
    assert artifact["runtime_compatible"] is False and artifact["promoted"] is False
    assert len(artifact["coefficients"]) == len(artifact["features"]) == 9
    assert report["calibration"]["fpr"] <= 0.05
    with pytest.raises(ValueError, match="already exists"):
        run_experiment(directory, sessions={"fit": 160, "calibration": 160, "template_holdout": 160})
