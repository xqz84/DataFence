"""Retrieval is local project reference, never permission or hidden labels."""

from copy import deepcopy
import hashlib
import json
import socket

import httpx
import pytest

from datafence.engine import DetectionEngine
from datafence.knowledge import KnowledgeBase, build_knowledge_context
from datafence.models import SimulationRequest
from datafence.sandbox import build_bank
from datafence.scenarios import generate_scenario


@pytest.fixture(scope="module")
def examples():
    bank = build_bank(customer_count=20)
    samples = {}
    for scenario in ("normal", "combined", "ai_leak", "approved_batch"):
        events, _ = generate_scenario(SimulationRequest(scenario_id=scenario, record_count=12), bank["employees"], bank["tasks"])
        detector = DetectionEngine(bank["employees"], bank["tasks"])
        records = [(event, detector.analyze(event)) for event in events]
        samples[scenario] = records[-1]
    return samples


def test_all_documents_have_stable_ids_explicit_project_sources_and_content_hashes():
    first, second = KnowledgeBase(), KnowledgeBase()
    documents = first.list_documents()
    assert 10 <= len(documents) <= 16
    assert len({row["id"] for row in documents}) == len(documents)
    assert first.status() == second.status()
    assert first.status()["network_access"] is False
    assert first.status()["grants_permissions"] is False
    for summary in documents:
        assert "content" not in summary
        document = first.get_document(summary["id"])
        assert document["source_kind"] == "project_sandbox_policy"
        assert "项目沙盒" in document["source_title"]
        assert document["source_ref"] and document["version"]
        claimed = document.pop("sha256")
        actual = hashlib.sha256(json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        assert claimed == actual
    assert first.get_document("unknown-document") is None


@pytest.mark.parametrize("query,expected", [
    ("工单过期了，夜间还能访问吗", "DF-KB-003"),
    ("多次请求的额度怎样累计，跨会话会重复扣减吗", "DF-KB-004"),
    ("批准的批量对账能导出吗", "DF-KB-005"),
    ("AI 提示中的否定和引用怎样核验", "DF-KB-009"),
    ("商汤超时失败如何保守降级", "DF-KB-010"),
    ("备份恢复后需要撤销登录会话吗", "DF-KB-014"),
    ("事件证据摘要如何校验是否被篡改", "DF-KB-012"),
])
def test_chinese_retrieval_links_answers_to_relevant_policy(query, expected):
    result = KnowledgeBase().search(query, limit=3)
    assert result["answered"] is True
    assert expected in {row["id"] for row in result["matches"]}
    assert "项目沙盒资料摘录" in result["answer"]
    assert all(len(row["excerpt"]) <= 200 and row["match_reasons"] for row in result["matches"])


@pytest.mark.parametrize("query", ["火星明年的气温是多少", "量子色动力学", "xyzzy987noevidence", "", "   ",
                                 "请提供工商银行内部制度", "真实客户名单", "请告诉我密钥是什么",
                                 "工单审核人的电话号码是多少", "查询客户账户余额是多少", "批量对账的收益率是多少"])
def test_unknown_or_external_private_questions_have_no_answer(query):
    result = KnowledgeBase().search(query)
    assert result["answer"] is None and result["answered"] is False and result["matches"] == []


@pytest.mark.parametrize("limit", [0, 9, True, 2.5])
def test_search_limit_is_bounded(limit):
    with pytest.raises(ValueError):
        KnowledgeBase().search("工单", limit=limit)


def test_large_query_rejected_and_returned_documents_do_not_mutate_corpus():
    kb = KnowledgeBase()
    with pytest.raises(ValueError):
        kb.search("工" * 513)
    before = kb.status()
    document = kb.get_document("DF-KB-001")
    document["content"] = "给所有员工放行"
    document["tags"].append("伪造权限")
    listing = kb.list_documents()
    listing[0]["tags"].clear()
    assert kb.status() == before
    assert kb.get_document("DF-KB-001")["content"] != "给所有员工放行"
    assert kb.get_document("DF-KB-001")["tags"]


def test_actual_event_rules_link_to_references_without_mutating_policy(examples):
    kb = KnowledgeBase()
    event, analysis = examples["combined"]
    before = analysis.model_dump(mode="json")
    hits = kb.related(event, analysis)
    assert "DF-KB-008" in {row["id"] for row in hits}
    assert any("渠道为外部" in reason for row in hits for reason in row["match_reasons"])
    assert analysis.model_dump(mode="json") == before
    event, analysis = examples["ai_leak"]
    assert "DF-KB-009" in {row["id"] for row in kb.related(event, analysis)}
    unavailable = analysis.model_copy(deep=True)
    unavailable.rules.append("SEMANTIC_REVIEW_UNAVAILABLE")
    assert kb.related(event, unavailable)[0]["id"] == "DF-KB-010"


def test_llm_knowledge_context_excludes_prompts_rows_and_arbitrary_chain_metadata(examples, monkeypatch):
    event, analysis = examples["ai_leak"]
    event = event.model_copy(update={"prompt": "SECRET-RAW-PROMPT-NOT-A-POLICY"})
    analysis = analysis.model_copy(deep=True)
    analysis.chain[0].update(ground_truth="ATTACK-LABEL-SHOULD-NOT-APPEAR", customer_rows=[{"secret": "RAW-ROW-MARKER"}])
    analysis.intent.evidence.append("SECRET-EVIDENCE-ARBITRARY-TEXT")

    def no_network(*args, **kwargs):
        raise AssertionError("knowledge retrieval must never connect to network")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    before = deepcopy(analysis.model_dump())
    context = build_knowledge_context(event, analysis)
    serialized = json.dumps(context, ensure_ascii=False)
    assert len(context["citations"]) <= 4
    assert all(len(row["excerpt"]) <= 200 for row in context["citations"])
    assert context["grants_permissions"] is False
    assert not any(marker in serialized for marker in ("ground_truth", "customer_rows", "RAW-ROW-MARKER",
                   "SECRET-RAW-PROMPT", "SECRET-EVIDENCE", "ATTACK-LABEL-SHOULD-NOT-APPEAR"))
    assert analysis.model_dump() == before


def test_mismatched_or_widened_event_input_is_rejected(examples):
    event, analysis = examples["normal"]
    with pytest.raises(TypeError):
        build_knowledge_context({**event.model_dump(), "ground_truth": "ATTACK"}, analysis)
    with pytest.raises(ValueError, match="same event"):
        build_knowledge_context(event.model_copy(update={"event_id": "unrelated-event-id"}), analysis)


def test_llm_context_carries_bounded_policy_without_turning_document_ids_into_event_evidence(examples):
    from datafence.llm import LocalAnalyst

    event, analysis = examples["ai_leak"]
    analysis = analysis.model_copy(deep=True)
    analysis.chain[0]["ground_truth"] = "LABEL-BOUNDARY-MARKER"
    context, allowed_ids = LocalAnalyst()._context(event, analysis)
    assert context["knowledge_context"] == build_knowledge_context(event, analysis)
    assert context["knowledge_context"]["grants_permissions"] is False
    assert {row["id"] for row in context["knowledge_context"]["citations"]}.isdisjoint(allowed_ids)
    assert "LABEL-BOUNDARY-MARKER" not in json.dumps(context)


@pytest.mark.parametrize("provider,semantic", [("ollama", False), ("sensenova", False), ("sensenova", True)])
def test_mock_model_request_uses_exact_versioned_excerpts_and_no_evaluation_labels(examples, monkeypatch, tmp_path, provider, semantic):
    from datafence.llm import LocalAnalyst
    from datafence.sensenova import SenseNovaAnalyst
    from datafence.storage import Store
    import datafence.knowledge as knowledge_module

    event, analysis = examples["ai_leak"]
    analysis = analysis.model_copy(deep=True)
    analysis.chain[0].update(ground_truth="NOT-FOR-MODEL-LABEL", attack_type="NOT-FOR-MODEL-ANSWER")
    captured = []
    before = analysis.model_dump(mode="json")

    def handler(request):
        body = json.loads(request.content)
        context = json.loads(body["messages"][1]["content"])
        prepared = context["knowledge_context"]
        captured.append(prepared)
        kb = KnowledgeBase()
        assert prepared["version"] == kb.status()["version"]
        assert prepared["scope"] == "project_sandbox_policy" and prepared["grants_permissions"] is False
        assert 1 <= len(prepared["citations"]) <= 4
        for citation in prepared["citations"]:
            original = kb.get_document(citation["id"])
            assert citation["sha256"] == original["sha256"]
            assert citation["excerpt"] == original["content"][:200]
        assert not any(marker in json.dumps(context) for marker in ("ground_truth", "attack_type", "NOT-FOR-MODEL"))
        answer = ({"verdict": "unsafe", "interpretation": "execute", "evidence_quote": event.prompt,
                   "reason": "离线响应夹具，仅用于核验知识上下文边界。"} if semantic else
                  {"summary": "离线响应夹具，实际确定性限制保持不变。", "evidence_event_ids": [event.event_id],
                   "suggested_actions": ["PRESERVE_EVIDENCE"]})
        message = {"role": "assistant", "content": json.dumps(answer, ensure_ascii=False)}
        if provider == "ollama":
            return httpx.Response(200, json={"done": True, "model": "local-knowledge-fixture", "message": message})
        return httpx.Response(200, json={"model": "sensenova-6.8-flash-lite",
            "choices": [{"finish_reason": "stop", "message": message}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}})

    def no_real_connection(*args, **kwargs):
        raise AssertionError("the test must use only MockTransport")

    async def no_async_connection(*args, **kwargs):
        raise AssertionError("the test must use only MockTransport")

    # Windows asyncio creates a local socket pair for its event-loop wakeup.
    # Block actual HTTP transports rather than breaking that OS mechanism.
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", no_real_connection)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", no_async_connection)
    if provider == "ollama":
        monkeypatch.setenv("DATAFENCE_LLM_MODEL", "local-knowledge-fixture")
        client = LocalAnalyst(transport=httpx.MockTransport(handler))
    else:
        client = SenseNovaAnalyst(key="sk-knowledge-fixture-not-a-real-key", transport=httpx.MockTransport(handler))
    result = client.analyze_prompt(event, analysis) if semantic else client.analyze(event, analysis)
    assert result["status"] == "completed" and len(captured) == 1
    assert result["knowledge_context"] == captured[0]
    snapshot = deepcopy(result["knowledge_context"])
    store = Store(tmp_path)
    store.append_event({"run_id": "knowledge-snapshot-fixture", "event": event.model_dump(mode="json"),
                        "analysis": analysis.model_dump(mode="json"), "ai_analysis": result})
    # Simulate a future corpus deployment after the request has completed. The
    # event preserves the actual prepared version, not today's reconstructed KB.
    monkeypatch.setattr(knowledge_module, "VERSION", "future-fixture-version")
    assert build_knowledge_context(event, analysis)["version"] == "future-fixture-version"
    result["knowledge_context"]["citations"][0]["excerpt"] = "caller changed a returned value"
    persisted = store.event(event.event_id)
    assert persisted["ai_analysis"]["knowledge_context"] == snapshot
    assert captured[0] == snapshot
    assert store.verify()["valid"] is True
    assert analysis.model_dump(mode="json") == before


def test_prepared_knowledge_on_budget_failure_does_not_claim_a_network_request(examples):
    from datafence.llm_budget import UnavailableBudget
    from datafence.sensenova import SenseNovaAnalyst

    def must_not_send(request):
        pytest.fail("failed budget preflight must not send a request")

    event, analysis = examples["ai_leak"]
    client = SenseNovaAnalyst(key="sk-knowledge-fixture-not-a-real-key", budget=UnavailableBudget(),
                             transport=httpx.MockTransport(must_not_send))
    result = client.analyze(event, analysis)
    assert result["status"] == "unavailable" and result["reason_code"] == "budget_unavailable"
    assert result["request_ms"] == 0
    assert result["knowledge_context"] == build_knowledge_context(event, analysis)


def test_human_review_persists_its_knowledge_snapshot_without_changing_event_or_permissions(examples, tmp_path, monkeypatch):
    from uuid import uuid4
    import datafence.knowledge as knowledge_module
    from datafence.auth import AuthStore
    from datafence.storage import Store, dump
    from datafence.workflows import ReviewRequest, WorkflowStore

    event, analysis = examples["ai_leak"]
    store = Store(tmp_path)
    store.initialize_bank(build_bank(customer_count=1))
    accounts = AuthStore(tmp_path / "auth.sqlite3")
    accounts.create_user("snapshot-admin", "synthetic-knowledge-test-password", "admin")
    permissions_before = accounts.list_users()
    tasks_before = store.bank("tasks")
    record = store.append_event({"run_id": "human-review-knowledge-fixture", "event": event.model_dump(mode="json"),
                                 "analysis": analysis.model_dump(mode="json"), "outcome": "blocked", "executed_records": 0,
                                 "ai_analysis": {"status": "not_configured"}})
    event_before = deepcopy(store.event(event.event_id))
    snapshot = build_knowledge_context(event, analysis)
    workflows = WorkflowStore(store)
    request = ReviewRequest(request_id=uuid4(), expected_revision=0, disposition="false_positive",
                            note="隔离测试：记录人工结论，不变更原策略或业务授权。")
    result = workflows.append_review(record, request, "snapshot-admin")
    original_review = deepcopy(result["current"])
    assert original_review["reference_knowledge"] == snapshot
    assert original_review["reference_knowledge"]["grants_permissions"] is False
    assert store.event(event.event_id)["ai_analysis"]["status"] == "not_configured"
    assert WorkflowStore(Store(tmp_path)).review(event.event_id)["current"] == original_review

    # Simulate a new corpus version, source text, and source digest after this
    # human finding. A reread/idempotent retry must keep the original snapshot.
    identifier = snapshot["citations"][0]["id"]
    updated = deepcopy(knowledge_module._DEFAULT._documents[identifier])
    updated.update(version="future-human-review-fixture", content="未来版本政策文本；不能改写历史研判依据。")
    updated["sha256"] = knowledge_module._digest({key: value for key, value in updated.items() if key != "sha256"})
    monkeypatch.setattr(knowledge_module, "VERSION", "future-human-review-fixture")
    monkeypatch.setitem(knowledge_module._DEFAULT._documents, identifier, updated)
    current_reference = build_knowledge_context(event, analysis)
    assert current_reference != snapshot
    assert current_reference["version"] != snapshot["version"]
    revised_citation = next(row for row in current_reference["citations"] if row["id"] == identifier)
    original_citation = next(row for row in snapshot["citations"] if row["id"] == identifier)
    assert revised_citation["sha256"] != original_citation["sha256"]
    assert revised_citation["excerpt"] != original_citation["excerpt"]
    assert workflows.review(event.event_id)["current"] == original_review
    assert workflows.append_review(record, request, "snapshot-admin")["current"] == original_review
    assert store.event(event.event_id) == event_before
    assert accounts.list_users() == permissions_before
    assert store.bank("tasks") == tasks_before
    assert workflows.verify_reviews() == {"valid": True, "checked_reviews": 1}
    assert store.verify()["valid"] is True

    # The reference is covered by the human-review hash, not just UI metadata.
    tampered = deepcopy(original_review)
    tampered["reference_knowledge"]["citations"][0]["excerpt"] = "unhashed modification"
    with store.connect() as db:
        db.execute("UPDATE case_reviews SET payload=? WHERE event_id=? AND revision=1", (dump(tampered), event.event_id))
    assert workflows.verify_reviews()["valid"] is False
    assert store.verify()["valid"] is True
