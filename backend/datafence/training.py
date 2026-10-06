"""Reproducible offline training and gated promotion of the behavior-only model.

Run: python -m datafence.training --name iforest-v2 --promote
No scenarios, challenge labels, client records, network or LLM are read here.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
from time import perf_counter
from uuid import uuid4

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from .model_artifacts import FORMAT, MODEL_ROOT, canonical, export_forest, load_artifact, model_directory, read_json, sha256
from .runtime_lock import RuntimeLock


TRAIN_SEED = 712367
CALIBRATION_SEED = 918273
HOLDOUT_NORMAL_SEED = 102938
HOLDOUT_PROBE_SEED = 564738
ALERT_THRESHOLD = 60.0
FIXED_PARAMETERS = {"n_estimators": 100, "max_samples": 256, "contamination": "auto",
                    "max_features": 1.0, "bootstrap": False, "random_state": TRAIN_SEED, "n_jobs": 1}
GATES = {"normal_fpr_wilson_upper_max": 0.04, "probe_recall_min": 0.65,
         "f1_regression_tolerance": 0.01, "export_max_abs_error": 1e-12,
         "min_train_rows": 5000, "min_calibration_rows": 2000,
         "min_holdout_normal_rows": 2000, "min_holdout_probe_rows": 1000}


def _features(records, regions, hour, new_device, external, export, reads, api_calls):
    return [math.log1p(records), regions, math.sin(hour * math.tau / 24), math.cos(hour * math.tau / 24),
            float(new_device), float(external), float(export), math.log1p(reads), api_calls]


def normal_features(seed: int, count: int) -> np.ndarray:
    """Independent NORMAL workload mixture, never fitted from test/challenge data.

    Includes normal batch reconciliations, shift work, approved device changes and
    public low-volume external transfers; behavior alone cannot infer purpose.
    """
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(count):
        kind = rng.choice(["retail", "batch", "shift", "api", "public"], p=[.64, .16, .08, .10, .02])
        hour = rng.uniform(8, 18) if kind != "shift" else rng.uniform(0, 8)
        login = rng.random() < .12
        new_device = rng.random() < .015
        export = kind == "batch" and rng.random() < .45
        external = kind == "public" and not login
        api_calls = int(rng.integers(1, 5)) if kind == "api" else 0
        if login:
            records, regions, reads, api_calls, export, external = 0, 1, 0, 0, False, False
        elif kind == "batch":
            records = int(rng.integers(300, 50001))
            regions = int(rng.integers(max(1, math.ceil(records / 2500)), 21))
            reads = records
        else:
            records = int(rng.integers(1, 13 if kind == "api" else 43))
            regions = 1
            reads = records * api_calls if kind == "api" else records + int(rng.integers(0, 35))
        rows.append(_features(records, regions, hour, new_device, external, export, reads, api_calls))
    return np.asarray(rows, dtype=np.float64)


def holdout_probes(seed: int, count: int) -> tuple[np.ndarray, list[str]]:
    """Frozen synthetic distribution-shift probes, generated only AFTER fitting.

    These labels mean deliberately unusual feature combinations, not confirmed
    real-bank attacks. They neither train trees nor set calibration thresholds.
    """
    rng = np.random.default_rng(seed)
    rows, kinds = [], []
    for index in range(count):
        kind = ("bulk_new_device_night", "api_burst", "unusual_external_flow")[index % 3]
        if kind == "bulk_new_device_night":
            records = int(rng.integers(5000, 50001))
            row = _features(records, int(rng.integers(10, 21)), rng.uniform(0, 5), True,
                            rng.random() < .5, True, records * 2, 0)
        elif kind == "api_burst":
            row = _features(int(rng.integers(50, 401)), int(rng.integers(1, 5)), rng.uniform(8, 18),
                            False, False, False, int(rng.integers(2000, 30001)), int(rng.integers(20, 101)))
        else:
            row = _features(int(rng.integers(500, 2001)), int(rng.integers(3, 9)), rng.uniform(18, 24),
                            rng.random() < .5, True, True, int(rng.integers(5000, 10001)), int(rng.integers(5, 16)))
        rows.append(row)
        kinds.append(kind)
    return np.asarray(rows, dtype=np.float64), kinds


def _matrix_info(matrix: np.ndarray, seed: int, role: str) -> dict:
    return {"rows": len(matrix), "features": matrix.shape[1], "seed": seed, "role": role,
            "sha256_float64_le": hashlib.sha256(matrix.astype("<f8").tobytes()).hexdigest()}


def _wilson_upper(positives: int, size: int) -> float:
    z = 1.96
    p = positives / size
    return (p + z * z / (2 * size) + z * math.sqrt(p * (1 - p) / size + z * z / (4 * size * size))) / (1 + z * z / size)


def _metrics(scores: np.ndarray, normal_count: int) -> dict:
    detected = scores >= ALERT_THRESHOLD
    fp, tp = int(detected[:normal_count].sum()), int(detected[normal_count:].sum())
    tn, fn = normal_count - fp, len(scores) - normal_count - tp
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "normal_fpr": fp / normal_count, "normal_fpr_wilson_upper": _wilson_upper(fp, normal_count),
            "anomaly_threshold": ALERT_THRESHOLD}


def _scores(model, low: float, high: float, matrix: np.ndarray) -> np.ndarray:
    return np.clip((-model.score_samples(matrix) - low) / (high - low) * 100, 0, 100)


def _write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        with temporary.open("wb") as output:
            output.write(canonical(document))
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def train_model(name: str = "iforest-v2", *, train_rows: int = 12000, calibration_rows: int = 4000,
                normal_test_rows: int = 4000, probe_test_rows: int = 2000, promote: bool = False) -> dict:
    from .engine import FEATURES, _trained_model

    if any(type(size) is not int or not 300 <= size <= 100000 for size in (train_rows, calibration_rows, normal_test_rows, probe_test_rows)):
        raise ValueError("each split size must be in 300..100000")
    directory = model_directory(name)
    if directory.exists():
        raise ValueError("training output already exists; choose a new model name to preserve provenance")
    directory.mkdir(parents=True)
    started = perf_counter()
    protocol = {"name": name, "parameters": FIXED_PARAMETERS, "gates": GATES,
                "calibration_protocol": {"normal_quantile_at_60": .98, "normal_quantile_at_100": .999},
                "split_sizes": [train_rows, calibration_rows, normal_test_rows, probe_test_rows],
                "seeds": [TRAIN_SEED, CALIBRATION_SEED, HOLDOUT_NORMAL_SEED, HOLDOUT_PROBE_SEED],
                "features": FEATURES, "frozen_before_holdout": True}
    # The protocol is persisted before any fit/evaluation. No search or tuning loop.
    _write_json(directory / "protocol.json", protocol)
    train = normal_features(TRAIN_SEED, train_rows)
    calibration = normal_features(CALIBRATION_SEED, calibration_rows)
    fitted = IsolationForest(**FIXED_PARAMETERS).fit(train)
    calibration_raw = -fitted.score_samples(calibration)
    anchor, high = map(float, np.quantile(calibration_raw, [.98, .999]))
    low = anchor - 1.5 * (high - anchor)
    if high - low < 1e-8:
        raise ValueError("normal-only calibration is degenerate")
    frozen_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "format": FORMAT, "features": FEATURES, "forest": export_forest(fitted),
        "calibration": {"low": low, "high": high, "source": "independent normal calibration split",
                        "quantile_at_60": .98, "quantile_at_100": .999},
        "metadata": {"algorithm": "IsolationForest", "version": name, "training_seed": TRAIN_SEED,
                     "training_samples": train_rows, "calibration_samples": calibration_rows,
                     "training_data": "independent synthetic normal workload mixture v2",
                     "uses_evaluation_labels": False, "uses_evaluation_events": False,
                     "uses_challenge_data": False, "sklearn_version": sklearn.__version__,
                     "numpy_version": np.__version__, "python_version": platform.python_version(),
                     "parameters": FIXED_PARAMETERS, "protocol_sha256": sha256(protocol),
                     "frozen_at": frozen_at, "llm_enabled": False},
    }
    document = {"payload": payload, "sha256": sha256(payload)}
    _write_json(directory / "model.json", document)
    restored, restored_low, restored_high, _ = load_artifact(directory / "model.json", FEATURES)

    # This is the first construction/use of the untouched holdout streams.
    holdout_normal = normal_features(HOLDOUT_NORMAL_SEED, normal_test_rows)
    probes, probe_kinds = holdout_probes(HOLDOUT_PROBE_SEED, probe_test_rows)
    holdout = np.concatenate([holdout_normal, probes])
    export_error = float(np.max(np.abs(restored.score_samples(holdout) - fitted.score_samples(holdout))))
    candidate_scores = _scores(restored, restored_low, restored_high, holdout)
    legacy, legacy_low, legacy_high = _trained_model()
    legacy_scores = _scores(legacy, legacy_low, legacy_high, holdout)
    candidate, baseline = _metrics(candidate_scores, normal_test_rows), _metrics(legacy_scores, normal_test_rows)
    row_sets = [{row.tobytes() for row in split} for split in (train, calibration, holdout_normal, probes)]
    overlaps = {f"{left}-{right}": len(row_sets[left] & row_sets[right]) for left in range(4) for right in range(left + 1, 4)}
    checks = {
        "minimum_split_sizes": train_rows >= GATES["min_train_rows"] and calibration_rows >= GATES["min_calibration_rows"]
                               and normal_test_rows >= GATES["min_holdout_normal_rows"] and probe_test_rows >= GATES["min_holdout_probe_rows"],
        "normal_fpr_upper_bound": candidate["normal_fpr_wilson_upper"] <= GATES["normal_fpr_wilson_upper_max"],
        "synthetic_probe_recall": candidate["recall"] >= GATES["probe_recall_min"],
        "no_material_f1_regression": candidate["f1"] + GATES["f1_regression_tolerance"] >= baseline["f1"],
        "json_prediction_equivalence": export_error <= GATES["export_max_abs_error"],
        "no_row_overlap": all(value == 0 for value in overlaps.values()),
    }
    passed = all(checks.values())
    per_probe = []
    for kind in sorted(set(probe_kinds)):
        mask = np.asarray([value == kind for value in probe_kinds])
        per_probe.append({"name": kind, "rows": int(mask.sum()),
                          "candidate_recall": float((candidate_scores[normal_test_rows:][mask] >= ALERT_THRESHOLD).mean()),
                          "legacy_recall": float((legacy_scores[normal_test_rows:][mask] >= ALERT_THRESHOLD).mean())})
    inference_times = []
    for row in holdout[:100]:
        tick = perf_counter()
        restored.score_samples(row.reshape(1, -1))
        inference_times.append((perf_counter() - tick) * 1000)
    report = {
        "name": name, "created_at": datetime.now(timezone.utc).isoformat(), "synthetic": True,
        "protocol": protocol, "artifact_sha256": document["sha256"],
        "splits": {"train": _matrix_info(train, TRAIN_SEED, "normal_fit_only"),
                   "calibration": _matrix_info(calibration, CALIBRATION_SEED, "normal_calibration_only"),
                   "holdout_normal": _matrix_info(holdout_normal, HOLDOUT_NORMAL_SEED, "untouched_normal_evaluation"),
                   "holdout_probes": _matrix_info(probes, HOLDOUT_PROBE_SEED, "untouched_distribution_shift_evaluation")},
        "cross_split_duplicate_rows": overlaps, "candidate": candidate, "legacy": baseline,
        "per_probe": per_probe, "quality_gate": {"passed": passed, "checks": checks, "thresholds": GATES},
        "json_export_max_abs_error": export_error,
        "inference_ms": {"p50": float(np.quantile(inference_times, .5)), "p95": float(np.quantile(inference_times, .95))},
        "elapsed_seconds": round(perf_counter() - started, 3), "promoted": False,
        "limitations": ["Synthetic feature distributions are not real bank traffic; no real-bank accuracy claim.",
                        "Probe positives are deliberate feature distribution shifts, not verified attacks.",
                        "Normal holdout uses the same generator family with an independent seed; this is not cross-bank generalization.",
                        "Thresholds were set on independent normal calibration only; the holdout gates choose deployment, not model parameters.",
                        "Purpose mismatch, prompt paraphrases, low-and-slow and cross-session attacks still require the separate deterministic/context pipeline.",
                        "Existing scenario and challenge labels were not read, and this evaluation does not replace end-to-end regression tests.",
                        "Artifact hash detects accidental modification but is not an external signature against a trusted local administrator."],
    }
    np.savez_compressed(directory / "normal_train.npz", features=train)
    np.savez_compressed(directory / "normal_calibration.npz", features=calibration)
    np.savez_compressed(directory / "holdout_features.npz", features=holdout)
    _write_json(directory / "holdout_labels.json", {"labels": [0] * normal_test_rows + [1] * probe_test_rows,
                                                    "probe_kinds": [None] * normal_test_rows + probe_kinds})
    _write_json(directory / "report.json", report)
    if promote and passed:
        # A running service owns the same runtime lock. Do not change its model
        # registry underneath it, and serialize competing offline promotions.
        with RuntimeLock(MODEL_ROOT.parent):
            # Verify the receipt before the atomic pointer switch. If receipt
            # writing fails, the previous active model remains selected.
            selection = {"name": name, "artifact_sha256": document["sha256"], "report_sha256": sha256(report)}
            _write_json(directory / "promotion.json", {**selection, "promoted_at": datetime.now(timezone.utc).isoformat()})
            receipt = read_json(directory / "promotion.json", limit=8192)
            if any(receipt.get(key) != value for key, value in selection.items()):
                raise ValueError("promotion receipt verification failed")
            _write_json(MODEL_ROOT / "active.json", selection)
        return {**report, "promoted": True}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="iforest-v2")
    parser.add_argument("--promote", action="store_true")
    args = parser.parse_args()
    report = train_model(args.name, promote=args.promote)
    print(json.dumps({"name": report["name"], "quality_gate": report["quality_gate"],
                      "candidate": report["candidate"], "legacy": report["legacy"],
                      "promoted": report["promoted"], "artifact_directory": str(model_directory(args.name)),
                      "elapsed_seconds": report["elapsed_seconds"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
