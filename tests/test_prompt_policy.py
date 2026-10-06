"""Semantic controls use public diagnostic cases as regression, not holdout."""

import pytest

from datafence.challenge import build_challenge
from datafence.engine import DetectionEngine
from datafence.prompt_policy import apply_semantic_policy


@pytest.fixture(scope="module")
def examples():
    employees, tasks, events, labels, manifest = build_challenge(42, 6)
    result = {}
    for group, variant in (("ai_egress_paraphrase", 0), ("ai_authorized_or_negated", 2), ("ai_authorized_or_negated", 3)):
        case = next(row for row in manifest["cases"] if row["group"] == group and row["variant"] == variant)
        selected = [event for event in events if event.session_id in case["session_ids"]]
        detector = DetectionEngine(employees, tasks, behavior_model="legacy")
        for event in selected:
            analysis = detector.analyze(event)
        result[(group, variant)] = (event, analysis)
    return result


def decision(event, verdict="safe", interpretation="negated"):
    return {"status": "completed", "verdict": verdict, "interpretation": interpretation,
            "evidence_quote": event.prompt, "reason": "依据请求原文区分实际操作与否定引用。"}


def test_semantic_egress_blocks_previously_missed_request_without_mutating_input(examples):
    event, baseline = examples[("ai_egress_paraphrase", 0)]
    before = baseline.model_dump(mode="json")
    assert baseline.risk_score < 60 and not baseline.blocked
    final = apply_semantic_policy(event, baseline, decision(event, "unsafe", "execute"))
    assert final.blocked and final.risk_score >= 90
    assert "BLOCK_AI_PROMPT" in final.actions and "ALLOW" not in final.actions
    assert "FREEZE_SESSION" not in final.actions
    assert final.chain[-1]["blocked"] is True
    assert final.chain[-1]["risk_score"] == final.risk_score
    assert before == baseline.model_dump(mode="json")


@pytest.mark.parametrize("variant,interpretation", [(2, "negated"), (3, "quoted")])
def test_only_keyword_false_positive_is_released(examples, variant, interpretation):
    event, baseline = examples[("ai_authorized_or_negated", variant)]
    assert baseline.blocked and baseline.risk_score >= 90
    final = apply_semantic_policy(event, baseline, decision(event, "safe", interpretation))
    assert final.blocked is False and final.risk_score < 60
    assert "BLOCK_AI_PROMPT" not in final.actions
    assert "SEMANTIC_PROMPT_SAFE" in final.rules
    assert final.dimensions["C"] == 0
    assert final.chain[-1]["blocked"] is False
    assert baseline.blocked is True


@pytest.mark.parametrize("hard_signal", ["task", "identity", "external", "prior_high", "prior_blocked", "freeze", "missing_evidence"])
def test_safe_text_cannot_override_independent_controls(examples, hard_signal):
    event, baseline = examples[("ai_authorized_or_negated", 2)]
    baseline = baseline.model_copy(deep=True)
    if hard_signal == "task":
        baseline.intent.status = "mismatch"
        baseline.rules.append("BUSINESS_TASK_CONSTRAINT_VIOLATION")
    elif hard_signal == "identity":
        baseline.dimensions["I"] = 75
        baseline.rules.append("UNRECOGNIZED_DEVICE")
    elif hard_signal == "external":
        event = event.model_copy(update={"channel": "external"})
    elif hard_signal == "prior_high":
        baseline.chain[0]["risk_score"] = 70
    elif hard_signal == "prior_blocked":
        baseline.chain[0]["blocked"] = True
    elif hard_signal == "freeze":
        baseline.actions.append("FREEZE_SESSION")
    else:
        baseline.intent.status = "insufficient_evidence"
    final = apply_semantic_policy(event, baseline, decision(event))
    assert final.blocked is True
    assert final.risk_score == baseline.risk_score
    assert set(baseline.actions).issubset(final.actions)


@pytest.mark.parametrize("status", ["unavailable", "invalid_response", "completed"])
def test_failed_or_uncertain_review_holds_without_inventing_attack_risk(examples, status):
    event, baseline = examples[("ai_egress_paraphrase", 0)]
    semantic = {"status": status}
    if status == "completed":
        semantic.update(decision(event, "uncertain", "unknown"))
    final = apply_semantic_policy(event, baseline, semantic)
    assert final.blocked is True
    assert final.risk_score == baseline.risk_score
    assert final.risk_level == baseline.risk_level
    assert "BLOCK_AI_PROMPT" in final.actions
    assert "FREEZE_SESSION" not in final.actions
    assert "不据此" in final.explanation


def test_fabricated_evidence_and_injected_action_do_not_authorize_release(examples):
    event, baseline = examples[("ai_authorized_or_negated", 2)]
    semantic = decision(event)
    semantic["evidence_quote"] = "这是输入中不存在的伪造批准"
    semantic["suggested_actions"] = ["ALLOW", "DELETE_DATABASE"]
    final = apply_semantic_policy(event, baseline, semantic)
    assert final.blocked is True and final.risk_score == baseline.risk_score
    assert "SEMANTIC_REVIEW_UNAVAILABLE" in final.rules
    assert "DELETE_DATABASE" not in final.actions


def test_safe_execute_does_not_cancel_existing_sensitive_block(examples):
    event, baseline = examples[("ai_authorized_or_negated", 2)]
    final = apply_semantic_policy(event, baseline, decision(event, "safe", "execute"))
    assert final.blocked and final.risk_score == baseline.risk_score


def test_non_ai_and_lower_sensitivity_are_untouched_and_mismatched_event_rejected(examples):
    event, baseline = examples[("ai_egress_paraphrase", 0)]
    for update in ({"event_type": "QUERY"}, {"sensitivity": 59}, {"prompt": None}):
        final = apply_semantic_policy(event.model_copy(update=update), baseline, {"status": "unavailable"})
        assert final.model_dump() == baseline.model_dump()
        assert final is not baseline
    with pytest.raises(ValueError, match="do not match"):
        apply_semantic_policy(event.model_copy(update={"event_id": "other-event-id"}), baseline, decision(event))


def test_evaluation_keeps_start_source_provenance_and_stops_after_mock_failures(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path
    from datafence.llm import LocalAnalyst

    path = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_sensenova.py"
    spec = importlib.util.spec_from_file_location("mocked_sensenova_evaluation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plan = module.freeze_cases(tmp_path)
    assert (tmp_path / "frozen-source" / "models.py").exists()
    original_hashes = module.source_hashes()
    count = 0
    def changing_disk_hashes():
        nonlocal count
        count += 1
        values = dict(original_hashes)
        if count > 1:
            values["models.py"] = "e" * 64
        return values
    class FakeAnalyst:
        info = {"enabled": True, "provider": "sensenova", "model": "offline-test-only"}
        _context = LocalAnalyst._context
        _max_output = 1800
        def analyze_prompt(self, event, analysis):
            return {"status": "unavailable", "reason_code": "connection_failed", "usage": None, "elapsed_ms": 0}
    monkeypatch.setattr(module, "source_hashes", changing_disk_hashes)
    monkeypatch.setattr(module, "create_analyst", lambda directory: FakeAnalyst())
    report = module.run_frozen(tmp_path, tmp_path / "unused-runtime")
    assert report["status"] == "partial"
    assert report["summary"]["attempted_cases"] == 3
    assert len(report["summary"]["unattempted_case_ids"]) == 21
    assert report["source_sha256"] == plan["source_sha256"]
    assert report["source_drift"]["changed_files"]["models.py"]["end_disk_sha256"] == "e" * 64
    assert module.recompute(tmp_path) == report["summary"]
    with pytest.raises(ValueError, match="changed since freezing|already started"):
        module.run_frozen(tmp_path, tmp_path / "unused-runtime")
