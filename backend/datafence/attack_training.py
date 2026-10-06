"""Offline, label-supervised *synthetic* attack experiment; never promotes a model.

This is deliberately separate from the production detector and its model registry.
Labels are joined only after feature extraction, and the development challenge is
read only after the classifier and threshold have been frozen.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import timedelta
import hashlib
import json
import math
from pathlib import Path
import platform

import numpy as np
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .challenge import PRIMARY, build_challenge
from .engine import DetectionEngine, FEATURES, _select_model
from .evaluation import calculate_metrics, generate_evaluation_dataset
from .model_artifacts import canonical


PROTOCOL = {
    "version": "synthetic-attack-supervised-v1",
    "seeds": {"fit": 11032026, "calibration": 21032026, "template_holdout": 31032026,
              "development_challenge": 20260919},
    "sessions": {"fit": 600, "calibration": 300, "template_holdout": 300},
    "classifier": {"name": "StandardScaler+LogisticRegression", "C": 0.5,
                   "class_weight": "balanced", "max_iter": 1000, "random_state": 43},
    "normal_calibration_max_alert_rate": 0.05,
    "feature_names": FEATURES,
    "forbidden_detector_fields": ["ground_truth", "attack_type", "scenario_id", "case_id", "partition", "reasons"],
    "promotion": "disabled; offline candidate only",
}


def extract_features(events, employees, tasks):
    """Replay the detector's nine numeric features without passing label dictionaries."""
    engine = DetectionEngine(employees, tasks, behavior_model="legacy")
    histories = defaultdict(list)
    output = []
    for event in events:
        key = (event.employee_id, event.session_id)
        history = histories[key]
        if history and event.timestamp < history[-1]["event"].timestamp:
            raise ValueError("out-of-order session")
        history[:] = [row for row in history if row["event"].timestamp >= event.timestamp - timedelta(minutes=30)][-127:]
        reads = sum(row["event"].record_count for row in history if row["event"].event_type in {"QUERY", "API"})
        if event.event_type in {"QUERY", "API"}:
            reads += event.record_count
        output.append(engine._features(event, engine.employees.get(event.employee_id), history, reads))
        history.append({"event": event})
    matrix = np.asarray(output, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURES) or not np.isfinite(matrix).all():
        raise ValueError("invalid behavior feature matrix")
    return matrix


def _dataset(seed, sessions):
    bank, events, labels, manifest = generate_evaluation_dataset(seed, sessions)
    matrix = extract_features(events, bank["employees"], bank["tasks"])
    truth = np.asarray([label["ground_truth"] == "ATTACK" for label in labels], dtype=bool)
    return matrix, truth, labels, manifest


def _digest(matrix, labels):
    # Include target bits in dataset provenance, never in the fitted feature matrix.
    return hashlib.sha256(matrix.astype("<f8").tobytes() + labels.astype("u1").tobytes()).hexdigest()


def _pairwise_overlap(groups):
    sets = {name: set(values) for name, values in groups.items()}
    names = list(sets)
    return {f"{names[left]}:{names[right]}": len(sets[names[left]] & sets[names[right]])
            for left in range(len(names)) for right in range(left + 1, len(names))}


def _score(y, probability, threshold, labels=None):
    predicted = probability >= threshold
    metrics = calculate_metrics(y.tolist(), predicted.tolist())
    if labels is not None:
        groups = sorted({label.get("scenario_id", label.get("group", "unknown")) for label in labels})
        metrics["by_group"] = {}
        for group in groups:
            selected = np.asarray([label.get("scenario_id", label.get("group", "unknown")) == group for label in labels])
            metrics["by_group"][group] = calculate_metrics(y[selected].tolist(), predicted[selected].tolist())
    return metrics


def _calibration_threshold(normal_scores, max_rate):
    # Choose on calibration normals only. The smallest threshold with <= allowed FP.
    ordered = np.sort(np.asarray(normal_scores, dtype=np.float64))
    if len(ordered) < 100:
        raise ValueError("too few normal calibration events")
    allowed = math.floor(len(ordered) * max_rate)
    return float(np.nextafter(ordered[len(ordered) - allowed - 1], math.inf))


def _safe_write(path: Path, payload: dict):
    with path.open("xb") as output:
        output.write(canonical(payload))


def run_experiment(output_dir: Path, *, sessions: dict | None = None) -> dict:
    sizes = dict(PROTOCOL["sessions"] if sessions is None else sessions)
    if set(sizes) != set(PROTOCOL["sessions"]) or any(type(value) is not int or value < 8 for value in sizes.values()):
        raise ValueError("all session split sizes must be integers >= 8")
    if output_dir.exists():
        raise ValueError("experiment output already exists; preserve old results")
    output_dir.mkdir(parents=True)
    _safe_write(output_dir / "protocol.json", {**PROTOCOL, "sessions": sizes})
    fit_x, fit_y, fit_labels, fit_manifest = _dataset(PROTOCOL["seeds"]["fit"], sizes["fit"])
    cal_x, cal_y, cal_labels, cal_manifest = _dataset(PROTOCOL["seeds"]["calibration"], sizes["calibration"])
    classifier = make_pipeline(StandardScaler(), LogisticRegression(**{key: value for key, value in PROTOCOL["classifier"].items() if key != "name"}))
    classifier.fit(fit_x, fit_y)
    cal_probability = classifier.predict_proba(cal_x)[:, 1]
    threshold = _calibration_threshold(cal_probability[~cal_y], PROTOCOL["normal_calibration_max_alert_rate"])
    scaler, linear = classifier.steps[0][1], classifier.steps[1][1]
    model = {
        "format": "datafence-offline-logistic-candidate-v1", "features": FEATURES,
        "mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist(),
        "coefficients": linear.coef_[0].tolist(), "intercept": float(linear.intercept_[0]),
        "threshold": threshold, "training_kind": "labeled synthetic sandbox events",
        "runtime_compatible": False, "promoted": False,
    }
    _safe_write(output_dir / "candidate.json", model)

    # Only after writing the frozen model/threshold do we instantiate final sets.
    held_x, held_y, held_labels, held_manifest = _dataset(PROTOCOL["seeds"]["template_holdout"], sizes["template_holdout"])
    employees, tasks, events, challenge_labels, challenge_manifest = build_challenge(PROTOCOL["seeds"]["development_challenge"])
    challenge_x = extract_features(events, employees, tasks)
    challenge_y = np.asarray([label["ground_truth"] == "ATTACK" for label in challenge_labels], dtype=bool)
    primary_mask = np.asarray([label["partition"] == PRIMARY for label in challenge_labels])

    def predict(matrix):
        return classifier.predict_proba(matrix)[:, 1]

    baseline, baseline_low, baseline_high, baseline_meta = _select_model("active")

    def old_scores(matrix):
        raw = -baseline.score_samples(matrix)
        return np.clip((raw - baseline_low) / (baseline_high - baseline_low) * 100, 0, 100)

    # Development challenge is known to the project and explicitly not sealed.
    report = {
        "protocol": {**PROTOCOL, "sessions": sizes},
        "environment": {"python": platform.python_version(), "sklearn": sklearn.__version__},
        "dataset": {
            "fit": {"events": len(fit_y), "attacks": int(fit_y.sum()), "sessions": sizes["fit"],
                    "sha256_features_and_labels": _digest(fit_x, fit_y), "scenario_counts": fit_manifest["scenario_counts"]},
            "calibration": {"events": len(cal_y), "attacks": int(cal_y.sum()), "sessions": sizes["calibration"],
                            "sha256_features_and_labels": _digest(cal_x, cal_y), "scenario_counts": cal_manifest["scenario_counts"]},
            "template_holdout": {"events": len(held_y), "attacks": int(held_y.sum()), "sessions": sizes["template_holdout"],
                                 "sha256_features_and_labels": _digest(held_x, held_y), "scenario_counts": held_manifest["scenario_counts"]},
            "development_challenge": {"events": len(challenge_y), "attacks": int(challenge_y.sum()),
                                      "cases": len(challenge_manifest["cases"]), "version": challenge_manifest["version"]},
        },
        "split_overlap": {
            "session_ids": _pairwise_overlap({"fit": (row["session_id"] for row in fit_labels),
                                              "calibration": (row["session_id"] for row in cal_labels),
                                              "template_holdout": (row["session_id"] for row in held_labels)}),
            "event_ids": _pairwise_overlap({"fit": (row["event_id"] for row in fit_labels),
                                            "calibration": (row["event_id"] for row in cal_labels),
                                            "template_holdout": (row["event_id"] for row in held_labels)}),
            "employee_ids": _pairwise_overlap({"fit": (row["request"]["employee_id"] for row in fit_manifest["session_manifest"]),
                                               "calibration": (row["request"]["employee_id"] for row in cal_manifest["session_manifest"]),
                                               "template_holdout": (row["request"]["employee_id"] for row in held_manifest["session_manifest"])}),
        },
        "threshold_from_normal_calibration": threshold,
        "calibration": _score(cal_y, cal_probability, threshold, cal_labels),
        "template_holdout": _score(held_y, predict(held_x), threshold, held_labels),
        "template_holdout_active_iforest": _score(held_y, old_scores(held_x), 60.0, held_labels),
        "development_challenge_primary": _score(challenge_y[primary_mask], predict(challenge_x[primary_mask]), threshold,
                                                [row for row, selected in zip(challenge_labels, primary_mask) if selected]),
        "development_challenge_primary_active_iforest": _score(challenge_y[primary_mask], old_scores(challenge_x[primary_mask]), 60.0,
                                                                [row for row, selected in zip(challenge_labels, primary_mask) if selected]),
        "development_challenge_all": _score(challenge_y, predict(challenge_x), threshold, challenge_labels),
        "active_baseline_version": baseline_meta.get("version"),
        "label_boundary": "Only SecurityEvent fields reach extract_features; labels join downstream for fitting/scoring.",
        "limitations": [
            "All labeled attacks are authored synthetic scenarios; this is not training on real bank incidents.",
            "Template holdout uses the same eight scenario recipes with new seeds; it is not unseen-attack generalization.",
            "Fit, calibration and template holdout can share employee identities; their sessions and events do not overlap.",
            "Development challenge was previously inspected by the project; it is a diagnostic, not sealed external validation.",
            "Behavior features alone cannot represent business approval semantics, prompt meaning, or cross-session task totals.",
            "No model promotion or runtime execution is authorized by this experiment.",
        ],
    }
    if (any(report["split_overlap"]["session_ids"].values())
            or any(report["split_overlap"]["event_ids"].values())):
        raise ValueError("session/event identifier overlap across splits")
    _safe_write(output_dir / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_experiment(args.output)
    print(json.dumps({"dataset": report["dataset"], "template_holdout": report["template_holdout"],
                      "development_challenge_primary": report["development_challenge_primary"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
