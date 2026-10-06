"""Independent synthetic evaluation; labels never enter the detector contract.

This module owns labels and offline scoring. It does not execute suggested
responses, and does not claim operating-system isolation from its caller.
"""

from __future__ import annotations

import hashlib
import json
import math
import platform
import random
import statistics
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .models import SecurityEvent, SimulationRequest


EVALUATION_VERSION = "synthetic-offline-v1"
GENERATOR_PROTOCOL_VERSION = "mixed-session-v1"
DETECTION_THRESHOLD = 60.0
BANK_SEED = 314159
MODES = ("rules", "behavior", "full")
SCENARIO_IDS = (
    "normal", "approved_batch", "insider", "stolen_account",
    "bulk_export", "api_scraping", "ai_leak", "combined",
)


def calculate_metrics(y_true: Sequence[bool], y_pred: Sequence[bool]) -> dict:
    """Calculate a binary confusion matrix, retaining undefined denominators."""
    if len(y_true) != len(y_pred):
        raise ValueError("truth and prediction lengths differ")
    if any(type(value) is not bool for value in (*y_true, *y_pred)):
        raise ValueError("binary metrics require actual boolean labels")
    tp = sum(actual and predicted for actual, predicted in zip(y_true, y_pred))
    fp = sum(not actual and predicted for actual, predicted in zip(y_true, y_pred))
    tn = sum(not actual and not predicted for actual, predicted in zip(y_true, y_pred))
    fn = sum(actual and not predicted for actual, predicted in zip(y_true, y_pred))

    def divide(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    return {
        "precision": divide(tp, tp + fp),
        "recall": divide(tp, tp + fn),
        "f1": divide(2 * tp, 2 * tp + fp + fn),
        "fpr": divide(fp, fp + tn),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def recompute_metrics(labels: Sequence[dict], predictions: Sequence[dict]) -> dict:
    """Recompute each mode solely from persisted labels and predictions.

    Reject incomplete or ambiguous joins rather than silently dropping events.
    A session is positive when any of its events is positive. A session is
    alerted when any prediction in that session reaches the recorded threshold.
    """
    truth: dict[str, dict] = {}
    for label in labels:
        event_id = label["event_id"]
        if event_id in truth:
            raise ValueError(f"duplicate ground truth event: {event_id}")
        if label["ground_truth"] not in ("NORMAL", "ATTACK"):
            raise ValueError("ground truth must be NORMAL or ATTACK")
        if label.get("scenario_id") not in SCENARIO_IDS:
            raise ValueError("evaluation labels must identify their scenario")
        truth[event_id] = label

    grouped: dict[str, dict[str, dict]] = defaultdict(dict)
    for prediction in predictions:
        mode = prediction["mode"]
        if mode not in MODES:
            raise ValueError(f"unsupported evaluation mode: {mode}")
        event_id = prediction["event_id"]
        if event_id not in truth:
            raise ValueError(f"prediction has no ground truth: {event_id}")
        if event_id in grouped[mode]:
            raise ValueError(f"duplicate prediction for {mode}: {event_id}")
        if prediction["session_id"] != truth[event_id]["session_id"]:
            raise ValueError("prediction and label disagree on session")
        if type(prediction["detected"]) is not bool:
            raise ValueError("detected must be a boolean")
        grouped[mode][event_id] = prediction

    result: dict[str, dict] = {}
    for mode, indexed in grouped.items():
        if indexed.keys() != truth.keys():
            raise ValueError(f"incomplete predictions for mode {mode}")
        sessions: dict[str, dict] = {}
        for event_id, label in truth.items():
            session = sessions.setdefault(label["session_id"], {
                "truth": False, "detected": False, "scenario_id": label["scenario_id"],
            })
            if session["scenario_id"] != label["scenario_id"]:
                raise ValueError("a session cannot belong to multiple scenarios")
            session["truth"] |= label["ground_truth"] == "ATTACK"
            session["detected"] |= indexed[event_id]["detected"]

        per_scenario = []
        for scenario_id in SCENARIO_IDS:
            selected = [item for item in sessions.values() if item["scenario_id"] == scenario_id]
            positive = [item for item in selected if item["truth"]]
            negative = [item for item in selected if not item["truth"]]
            detected = sum(item["detected"] for item in positive)
            false_alerts = sum(item["detected"] for item in negative)
            per_scenario.append({
                "scenario_id": scenario_id, "sessions": len(selected),
                "attack_sessions": len(positive), "detected": detected,
                "recall": detected / len(positive) if positive else None,
                "normal_sessions": len(negative), "false_alert_sessions": false_alerts,
                "false_positive_rate": false_alerts / len(negative) if negative else None,
            })
        result[mode] = {
            "metrics": calculate_metrics(
                [label["ground_truth"] == "ATTACK" for label in truth.values()],
                [indexed[event_id]["detected"] for event_id in truth],
            ),
            "session_metrics": calculate_metrics(
                [item["truth"] for item in sessions.values()],
                [item["detected"] for item in sessions.values()],
            ),
            "per_scenario": per_scenario,
        }
    if truth and not grouped:
        raise ValueError("nonempty labels require predictions")
    return result


def generate_evaluation_dataset(seed: int, sessions: int) -> tuple[dict, list[SecurityEvent], list[dict], dict]:
    """Generate complete held-out sessions; never split events across datasets."""
    from .sandbox import build_bank
    from .scenarios import generate_scenario

    if type(seed) is not int or not 0 <= seed <= 2147483647:
        raise ValueError("seed must be an integer between 0 and 2147483647")
    if type(sessions) is not int or not 8 <= sessions <= 1000:
        raise ValueError("sessions must be an integer between 8 and 1000")
    bank = build_bank(seed=BANK_SEED, customer_count=5000)
    randomizer = random.Random(seed)
    # Coverage is guaranteed; remaining sessions mix plausible normal controls
    # with attacks. The resulting prevalence is recorded, not called realistic.
    scenarios = list(SCENARIO_IDS)
    scenarios.extend(randomizer.choices(
        SCENARIO_IDS, weights=(30, 24, 8, 8, 8, 8, 7, 7), k=sessions - len(scenarios),
    ))
    randomizer.shuffle(scenarios)
    scenario_seeds = randomizer.sample(range(2147483648), k=sessions)
    events: list[SecurityEvent] = []
    labels: list[dict] = []
    manifest_sessions: list[dict] = []
    session_ids: set[str] = set()
    event_ids: set[str] = set()
    for scenario_id, scenario_seed in zip(scenarios, scenario_seeds):
        employee = randomizer.choice(bank["employees"])
        if scenario_id == "normal":
            record_count = randomizer.randint(1, max(2, employee.baseline_daily_records))
        elif scenario_id == "approved_batch":
            record_count = randomizer.randint(1000, 22000)
        else:
            record_count = randomizer.randint(500, 24000)
        request = SimulationRequest(
            scenario_id=scenario_id, employee_id=employee.id,
            seed=scenario_seed, record_count=record_count, interval_ms=0,
            export=True, compress=True, upload=True,
        )
        session_events, session_labels = generate_scenario(request, bank["employees"], bank["tasks"])
        if not session_events:
            raise ValueError("scenario generator returned no observable events")
        generated_session_ids = {event.session_id for event in session_events}
        if len(generated_session_ids) != 1 or generated_session_ids & session_ids:
            raise ValueError("each evaluation scenario must produce one fresh session")
        session_id = next(iter(generated_session_ids))
        session_ids.add(session_id)
        indexed_labels = {item["event_id"]: item for item in session_labels}
        if len(indexed_labels) != len(session_labels):
            raise ValueError("scenario generator returned duplicate labels")
        if indexed_labels.keys() != {event.event_id for event in session_events}:
            raise ValueError("scenario labels must cover all and only generated events")
        for event in session_events:
            if event.event_id in event_ids:
                raise ValueError("scenario generator returned duplicate event IDs")
            event_ids.add(event.event_id)
            label = indexed_labels[event.event_id]
            if label["session_id"] != event.session_id:
                raise ValueError("scenario label has incorrect session ID")
            # Copy only into an evaluator-owned structure; no event mutation.
            labels.append({
                "event_id": event.event_id, "session_id": event.session_id,
                "ground_truth": label["ground_truth"],
                "attack_type": label.get("attack_type"), "scenario_id": scenario_id,
            })
        events.extend(session_events)
        manifest_sessions.append({
            "session_id": session_id, "scenario_id": scenario_id,
            "request": request.model_dump(mode="json"), "event_count": len(session_events),
        })
    # Stable sorting preserves generator order at identical timestamps.
    events.sort(key=lambda event: event.timestamp)
    label_index = {label["event_id"]: label for label in labels}
    labels = [label_index[event.event_id] for event in events]
    manifest = {
        "protocol_version": GENERATOR_PROTOCOL_VERSION, "seed": seed,
        "bank_seed": BANK_SEED, "sessions": sessions, "synthetic": True,
        "scenario_counts": dict(Counter(scenarios)),
        "session_manifest": manifest_sessions,
        "split": "all generated sessions are evaluation-only; no test fitting or threshold selection",
        "coverage": "eight shared generator templates; parameter variation, not unseen-template validation",
    }
    return bank, events, labels, manifest


def predict_event_stream(events: Sequence[SecurityEvent], employees: list, tasks: list, mode: str) -> tuple[list[dict], dict, float]:
    """Detector-facing function: intentionally accepts no label or manifest."""
    from .engine import DetectionEngine

    if mode not in MODES:
        raise ValueError("unsupported detector mode")
    initialized_at = time.perf_counter()
    engine = DetectionEngine(employees, tasks, mode=mode)
    initialization_ms = (time.perf_counter() - initialized_at) * 1000
    predictions = []
    for event in events:
        started_at = time.perf_counter()
        analysis = engine.analyze(event)
        processing_ms = (time.perf_counter() - started_at) * 1000
        risk_score = float(analysis.risk_score)
        if not math.isfinite(risk_score) or not 0 <= risk_score <= 100:
            raise ValueError("detector returned an invalid risk score")
        predictions.append({
            "event_id": event.event_id, "session_id": event.session_id,
            "timestamp": event.timestamp.isoformat(), "mode": mode,
            "risk_score": risk_score, "risk_level": analysis.risk_level,
            "detected": risk_score >= DETECTION_THRESHOLD,
            "detection_threshold": DETECTION_THRESHOLD,
            "processing_ms": processing_ms,
            "action_recommendations": list(analysis.actions),
            "would_block": bool(analysis.blocked), "response_executed": False,
        })
    return predictions, dict(engine.model_info), initialization_ms


def _percentile(values: Sequence[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _latency_statistics(labels: Sequence[dict], predictions: Sequence[dict]) -> dict:
    truth = {label["event_id"]: label for label in labels}
    per_session: dict[str, list[dict]] = defaultdict(list)
    for prediction in predictions:
        per_session[prediction["session_id"]].append(prediction)
    delays: list[float] = []
    session_latencies: list[dict] = []
    missed = 0
    early = 0
    for session_id, records in per_session.items():
        attacks = [item for item in records if truth[item["event_id"]]["ground_truth"] == "ATTACK"]
        if not attacks:
            continue
        onset = min(datetime.fromisoformat(item["timestamp"]) for item in attacks)
        alerts = [datetime.fromisoformat(item["timestamp"]) for item in records if item["detected"]]
        row: dict[str, Any] = {
            "session_id": session_id, "attack_onset": onset.isoformat(),
            "first_detection": min(alerts).isoformat() if alerts else None,
            "detection_delay_seconds": None, "early_alert_lead_seconds": None,
            "missed": not alerts,
        }
        if not alerts:
            missed += 1
        else:
            delay = (min(alerts) - onset).total_seconds()
            if delay < 0:
                # Never disguise a pre-onset false positive as a zero-second
                # detection. Report separately from nonnegative latency samples.
                early += 1
                row["early_alert_lead_seconds"] = -delay
            else:
                delays.append(delay)
                row["detection_delay_seconds"] = delay
        session_latencies.append(row)
    processing = [item["processing_ms"] for item in predictions]
    return {
        "processing_ms_p50": statistics.median(processing) if processing else None,
        "processing_ms_p95": _percentile(processing, .95),
        "processing_samples": len(processing),
        "detection_delay_seconds_p50": statistics.median(delays) if delays else None,
        "detection_delay_seconds_p95": _percentile(delays, .95),
        "detection_delay_samples": len(delays),
        "missed_sessions": missed, "early_alert_sessions": early,
        "attack_sessions": len(session_latencies), "session_latencies": session_latencies,
        "response_time_ms": None, "responses_executed": 0,
        "processing_clock": "local perf_counter; analyze() only; excludes model initialization and I/O",
        "detection_clock": "synthetic event timestamps; not wall-clock security response performance",
        "response_time_reason": "offline complete-flow detection; recommendations are never executed",
    }


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _write_jsonl(path: Path, rows: Sequence[dict]) -> dict:
    digest = hashlib.sha256()
    with path.open("wb") as handle:
        for row in rows:
            line = _json_bytes(row)
            handle.write(line)
            digest.update(line)
    return {"path": str(path.resolve()), "file": path.name, "sha256": digest.hexdigest(), "rows": len(rows)}


def run_evaluation(seed: int, sessions: int, output_dir: Path) -> dict:
    """Run once in an empty directory, preserving successful or partial runs."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ValueError("evaluation output already exists; choose an empty directory to preserve prior results")
    claim = output_dir / ".evaluation-claim.json"
    try:
        with claim.open("xb") as handle:
            handle.write(_json_bytes({"format": "datafence-evaluation-claim-v1", "seed": seed, "sessions": sessions}))
    except FileExistsError:
        raise ValueError("evaluation output already exists; another run claimed this directory") from None
    if any(path != claim for path in output_dir.iterdir()):
        claim.unlink()
        raise ValueError("evaluation output already exists; refusing to replace prior results")
    # Keep the exclusive claim on failure as well: an incomplete experiment must
    # not be silently replaced by a later run with a different seed or version.
    return _run_claimed_evaluation(seed, sessions, output_dir)


def _run_claimed_evaluation(seed: int, sessions: int, output_dir: Path) -> dict:
    """Run all ablations on the same complete, independently labelled stream."""
    bank, events, labels, manifest = generate_evaluation_dataset(seed, sessions)
    all_predictions: list[dict] = []
    model_information: dict[str, dict] = {}
    initialization: dict[str, float] = {}
    per_mode_latency: dict[str, dict] = {}
    for mode in MODES:
        predictions, model_info, initialization_ms = predict_event_stream(
            events, bank["employees"], bank["tasks"], mode,
        )
        all_predictions.extend(predictions)
        model_information[mode] = model_info
        initialization[mode] = initialization_ms
        per_mode_latency[mode] = _latency_statistics(labels, predictions)
    recomputed = recompute_metrics(labels, all_predictions)
    artifacts = {
        "events": _write_jsonl(output_dir / "events.jsonl", [event.model_dump(mode="json") for event in events]),
        "labels": _write_jsonl(output_dir / "labels.jsonl", labels),
        "predictions": _write_jsonl(output_dir / "predictions.jsonl", all_predictions),
    }
    context_path = output_dir / "context.json"
    context_bytes = _json_bytes({
        "employees": [item.model_dump(mode="json") for item in bank["employees"]],
        "tasks": [item.model_dump(mode="json") for item in bank["tasks"]],
    })
    context_path.write_bytes(context_bytes)
    artifacts["context"] = {
        "path": str(context_path.resolve()), "file": context_path.name,
        "sha256": hashlib.sha256(context_bytes).hexdigest(),
    }
    manifest_path = output_dir / "manifest.json"
    manifest_bytes = _json_bytes(manifest)
    manifest_path.write_bytes(manifest_bytes)
    artifacts["manifest"] = {
        "path": str(manifest_path.resolve()), "file": manifest_path.name,
        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    full = recomputed["full"]
    report = {
        "id": f"eval_{uuid.uuid4().hex}", "created_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed, "sessions": sessions, "event_count": len(events),
        "attack_events": sum(label["ground_truth"] == "ATTACK" for label in labels),
        "normal_events": sum(label["ground_truth"] == "NORMAL" for label in labels),
        "metrics": full["metrics"], "session_metrics": full["session_metrics"],
        "confusion_matrix": {
            "label_order": ["NORMAL", "ATTACK"], "rows": "truth", "columns": "prediction",
            "values": [[full["metrics"]["tn"], full["metrics"]["fp"]], [full["metrics"]["fn"], full["metrics"]["tp"]]],
        },
        "latency": per_mode_latency["full"], "latency_by_mode": per_mode_latency,
        "model_initialization_ms": initialization,
        "per_scenario": full["per_scenario"],
        "ablations": [{
            "mode": mode, **recomputed[mode]["metrics"],
            "session_metrics": recomputed[mode]["session_metrics"],
            "per_scenario": recomputed[mode]["per_scenario"],
        } for mode in MODES],
        "artifacts": artifacts,
        "input_sha256": artifacts["events"]["sha256"],
        "scenario_counts": manifest["scenario_counts"],
        "protocol": {
            "detection_threshold": DETECTION_THRESHOLD,
            "threshold_selected_on_test": False,
            "flow": "complete offline event flow; no prevention truncation",
            "event_positive": "risk_score >= 60", "session_positive": "any detected event",
            "synthetic": True, "llm_enabled": False, "llm_status": "not_configured",
            "label_isolation": "single-process logical isolation; no OS access-control isolation",
            "training": "fixed synthetic normal baseline owned by DetectionEngine; no evaluation fitting",
        },
        "versions": {
            "application": __version__, "python": platform.python_version(),
            "evaluation": EVALUATION_VERSION, "generator_protocol": GENERATOR_PROTOCOL_VERSION,
            "bank_manifest": bank["manifest"], "model_by_mode": model_information,
            "source_sha256": {
                name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                for name in ("evaluation.py", "engine.py", "scenarios.py", "sandbox.py", "models.py")
            },
        },
        "limitations": [
            "全部为合成银行沙盒数据；结果不能外推为真实银行检测准确率。",
            "使用八种固定生成模板及参数变化；未证明对未见攻击模板或真实业务分布的泛化。",
            "正常和攻击占比由评测协议控制，不代表实际银行攻击发生率。",
            "record_count 是场景事件的模拟访问规模，不代表从实体客户库实际查询并导出的不同客户数。",
            "训练使用固定合成正常行为基线，测试会话不参与拟合或阈值选择；仍可能存在共同设计假设偏差。",
            "标签与检测输入仅作单进程逻辑隔离，尚未实现操作系统身份、权限或进程隔离。",
            "本离线评测不调用LLM或执行前云语义门；意图评分与解释来自确定性业务核验，不代表大模型或多智能体效果。",
            "本次为完整流离线检测评测，响应仅为建议，未测量真实阻断效果或响应完成时间。",
            "处理耗时为本机 analyze() 用时；首次检测延迟使用合成事件时间，不等于生产实时性能。",
            "会话级任一事件报警即计为报警；攻击开始前的报警另列，不进入非负检测延迟统计。",
        ],
    }
    # A report cannot contain its own digest. Digests of immutable inputs and
    # predictions are stored inside it; report identity is its evaluation ID.
    (output_dir / "report.json").write_bytes(_json_bytes(report))
    return report


def recompute_evaluation(output_dir: Path) -> dict:
    """Verify artifact digests and reconstruct metrics without a detector."""
    output_dir = Path(output_dir)
    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    for artifact in report["artifacts"].values():
        filename = artifact["file"]
        if Path(filename).name != filename:
            raise ValueError("artifact names must refer to files in the evaluation directory")
        content = (output_dir / filename).read_bytes()
        if hashlib.sha256(content).hexdigest() != artifact["sha256"]:
            raise ValueError(f"artifact digest mismatch: {filename}")
    labels = [json.loads(line) for line in (output_dir / "labels.jsonl").read_text(encoding="utf-8").splitlines()]
    predictions = [json.loads(line) for line in (output_dir / "predictions.jsonl").read_text(encoding="utf-8").splitlines()]
    result = recompute_metrics(labels, predictions)
    if set(result) != set(MODES):
        raise ValueError("persisted evaluation must contain all three detector modes")
    for key in ("metrics", "session_metrics", "per_scenario"):
        if result["full"][key] != report[key]:
            raise ValueError(f"report does not match recomputed {key}")
    if len(report["ablations"]) != len(MODES) or {row["mode"] for row in report["ablations"]} != set(MODES):
        raise ValueError("report ablations must contain each mode exactly once")
    for ablation in report["ablations"]:
        for key, value in result[ablation["mode"]]["metrics"].items():
            if ablation[key] != value:
                raise ValueError(f"ablation does not match recomputation: {ablation['mode']}")
        for key in ("session_metrics", "per_scenario"):
            if ablation[key] != result[ablation["mode"]][key]:
                raise ValueError(f"ablation does not match recomputed {key}: {ablation['mode']}")
    for mode in MODES:
        mode_latency = _latency_statistics(labels, [row for row in predictions if row["mode"] == mode])
        if mode_latency != report["latency_by_mode"][mode]:
            raise ValueError(f"report does not match recomputed latency: {mode}")
    if report["latency"] != report["latency_by_mode"]["full"]:
        raise ValueError("report primary latency does not match full mode")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Synthetic DataFence offline evaluation")
    parser.add_argument("--seed", type=int, default=20260919)
    parser.add_argument("--sessions", type=int, default=160)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--recompute", type=Path, help="verify and recompute an existing artifact directory")
    arguments = parser.parse_args()
    if arguments.recompute is not None:
        print(json.dumps(recompute_evaluation(arguments.recompute), ensure_ascii=False, indent=2, allow_nan=False))
    else:
        if arguments.output_dir is None:
            parser.error("--output-dir is required for a new evaluation")
        result = run_evaluation(arguments.seed, arguments.sessions, arguments.output_dir)
        print(json.dumps({"id": result["id"], "metrics": result["metrics"],
                          "output_dir": str(arguments.output_dir.resolve())}, ensure_ascii=False, indent=2, allow_nan=False))
