"""Bounded JSON-only Isolation Forest inference; never deserialize Python objects."""

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re

import numpy as np


MODEL_ROOT = Path(os.environ.get("DATAFENCE_DATA_DIR", Path(__file__).resolve().parents[2] / "runtime")) / "models"
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
FORMAT = "datafence-isolation-forest-json-v1"
MODEL_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: Path, limit: int = MAX_ARTIFACT_BYTES) -> dict:
    if path.stat().st_size > limit:
        raise ValueError("model document exceeds size limit")
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("model document exceeds size limit")

    def object_pairs(pairs):
        output = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON key")
            output[key] = value
        return output

    def reject_constant(value):
        raise ValueError("nonfinite JSON number")

    result = json.loads(raw, object_pairs_hook=object_pairs, parse_constant=reject_constant)
    if not isinstance(result, dict):
        raise ValueError("model document must be an object")
    return result


def average_path_length(count: int) -> float:
    if count <= 1:
        return 0.0
    if count == 2:
        return 1.0
    return 2.0 * (math.log(count - 1) + np.euler_gamma) - 2.0 * (count - 1) / count


@dataclass(frozen=True)
class JsonTree:
    left: tuple[int, ...]
    right: tuple[int, ...]
    feature: tuple[int, ...]
    threshold: tuple[float, ...]
    sample_count: tuple[int, ...]


class JsonIsolationForest:
    """Only finite numeric tree arrays are interpreted, with bounded tree depth."""
    def __init__(self, trees: tuple[JsonTree, ...], max_samples: int, feature_count: int):
        self.estimators_ = trees
        self.n_estimators = len(trees)
        self.max_samples_ = max_samples
        self.n_features_in_ = feature_count
        self._denominator = self.n_estimators * average_path_length(max_samples)

    def score_samples(self, matrix) -> np.ndarray:
        # sklearn's tree traversal converts inputs to float32 before comparisons.
        rows = np.asarray(matrix, dtype=np.float32)
        if rows.ndim != 2 or rows.shape[1] != self.n_features_in_ or not np.isfinite(rows).all():
            raise ValueError("model input must be finite and match feature schema")
        scores = []
        for row in rows:
            depth_sum = 0.0
            for tree in self.estimators_:
                node, depth = 0, 0
                while tree.left[node] != -1:
                    node = tree.left[node] if float(row[tree.feature[node]]) <= tree.threshold[node] else tree.right[node]
                    depth += 1
                depth_sum += depth + average_path_length(tree.sample_count[node])
            scores.append(-(2.0 ** (-depth_sum / self._denominator)))
        return np.asarray(scores)


def export_forest(model) -> dict:
    if model.max_features != 1.0 or model.bootstrap:
        raise ValueError("only full-feature, non-bootstrap forests are supported")
    trees = []
    for estimator, selected in zip(model.estimators_, model.estimators_features_):
        tree = estimator.tree_
        features = [int(selected[index]) if index >= 0 else -2 for index in tree.feature]
        trees.append({"left": tree.children_left.tolist(), "right": tree.children_right.tolist(),
                      "feature": features, "threshold": tree.threshold.tolist(),
                      "sample_count": tree.n_node_samples.tolist()})
    return {"max_samples": int(model.max_samples_), "trees": trees}


def parse_forest(document: dict, feature_count: int) -> JsonIsolationForest:
    if not isinstance(document, dict) or set(document) != {"max_samples", "trees"}:
        raise ValueError("invalid forest structure")
    maximum = document["max_samples"]
    if type(maximum) is not int or not 2 <= maximum <= 1024:
        raise ValueError("invalid maximum sample count")
    items = document["trees"]
    if not isinstance(items, list) or not 1 <= len(items) <= 256:
        raise ValueError("invalid tree count")
    trees = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"left", "right", "feature", "threshold", "sample_count"}:
            raise ValueError("invalid tree fields")
        if any(not isinstance(values, list) for values in item.values()):
            raise ValueError("tree fields must be arrays")
        size = len(item["left"])
        if not 1 <= size <= 2047 or any(len(values) != size for values in item.values()):
            raise ValueError("invalid tree array lengths")
        parents = [0] * size
        depths = [0] * size
        for node in range(size):
            left, right, feature, threshold, count = [item[key][node] for key in ("left", "right", "feature", "threshold", "sample_count")]
            if any(type(value) is not int for value in (left, right, feature, count)):
                raise ValueError("tree index and counts must be integers")
            if type(threshold) not in {int, float} or not math.isfinite(threshold) or abs(threshold) > 1e6:
                raise ValueError("invalid threshold")
            if not 1 <= count <= maximum:
                raise ValueError("invalid node sample count")
            if left == -1 and right == -1:
                if feature != -2:
                    raise ValueError("leaf must not reference a feature")
            elif not (node < left < size and node < right < size and left != right and 0 <= feature < feature_count):
                raise ValueError("tree must be acyclic and reference valid forward children")
            else:
                for child in (left, right):
                    parents[child] += 1
                    depths[child] = depths[node] + 1
                if item["sample_count"][left] + item["sample_count"][right] != count:
                    raise ValueError("child counts do not match parent")
        if parents[0] != 0 or any(count != 1 for count in parents[1:]) or max(depths) > 16:
            raise ValueError("tree contains unreachable, shared or excessive-depth nodes")
        if item["sample_count"][0] != maximum:
            raise ValueError("root count does not match fitted sample count")
        trees.append(JsonTree(*(tuple(item[key]) for key in ("left", "right", "feature", "threshold", "sample_count"))))
    return JsonIsolationForest(tuple(trees), maximum, feature_count)


def load_artifact(path: Path, features: list[str]) -> tuple[JsonIsolationForest, float, float, dict]:
    document = read_json(path)
    if set(document) != {"payload", "sha256"} or not isinstance(document["payload"], dict):
        raise ValueError("invalid model envelope")
    payload = document["payload"]
    if sha256(payload) != document["sha256"]:
        raise ValueError("model digest does not match")
    if payload.get("format") != FORMAT or payload.get("features") != features:
        raise ValueError("unsupported format or feature schema")
    metadata, calibration = payload.get("metadata"), payload.get("calibration")
    if not isinstance(metadata, dict) or not isinstance(calibration, dict):
        raise ValueError("model metadata or calibration is missing")
    low, high = calibration.get("low"), calibration.get("high")
    if any(type(value) not in {int, float} or not math.isfinite(value) for value in (low, high)) or not -1 <= low < high <= 1 or high - low < 1e-8:
        raise ValueError("invalid calibration range")
    model = parse_forest(payload.get("forest"), len(features))
    return model, float(low), float(high), {**metadata, "artifact_sha256": document["sha256"], "calibration": calibration}


def model_directory(name: str) -> Path:
    if not MODEL_NAME.fullmatch(name) or name in {"active", "legacy"}:
        raise ValueError("model selection must be a registered safe name, not a path")
    path = (MODEL_ROOT / name).resolve()
    if not path.is_relative_to(MODEL_ROOT.resolve()):
        raise ValueError("model must stay within local registry")
    return path
