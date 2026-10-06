import copy
import json
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from datafence.engine import DetectionEngine
from datafence.llm_budget import CallBudget
from datafence.models import SimulationRequest
from datafence.sandbox import build_bank
from datafence.scenarios import generate_scenario
from datafence.sensenova import CHAT_URL, SenseNovaAnalyst, create_analyst

TEST_KEY = "sk-test-only-not-a-real-credential"


@pytest.fixture
def sample():
    bank = build_bank(customer_count=20)
    events, _ = generate_scenario(SimulationRequest(scenario_id="ai_leak"), bank["employees"], bank["tasks"])
    event = events[-1]
    return event, DetectionEngine(bank["employees"], bank["tasks"]).analyze(event)


def envelope(event, values=None, **changes):
    content = values or {"summary": "合成事件存在外发意图，建议保留证据。",
                         "evidence_event_ids": [event.event_id], "suggested_actions": ["PRESERVE_EVIDENCE"]}
    result = {"model": "sensenova-6.8-flash-lite", "choices": [{"finish_reason": "stop",
              "message": {"role": "assistant", "content": json.dumps(content, ensure_ascii=False)}}],
              "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}}
    result.update(changes)
    return result


def analyst(handler, **kwargs):
    return SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(handler), **kwargs)


def test_official_endpoint_and_read_only_allowlisted_context(sample, monkeypatch):
    event, analysis = sample
    analysis.chain[-1]["ground_truth"] = "ATTACK"
    original = copy.deepcopy(analysis.model_dump())
    monkeypatch.setenv("HTTPS_PROXY", "https://untrusted.invalid")
    def handler(request):
        assert str(request.url) == CHAT_URL
        assert request.headers["authorization"] == "Bearer " + TEST_KEY
        body = json.loads(request.content)
        assert body["max_tokens"] == 2400 and body["temperature"] == 0.2
        assert "tools" not in body and "response_format" not in body
        assert "ground_truth" not in body["messages"][1]["content"]
        assert TEST_KEY not in body["messages"][1]["content"]
        return httpx.Response(200, json=envelope(event))
    client = analyst(handler)
    result = client.analyze(event, analysis)
    assert result["status"] == "completed" and result["usage"]["total_tokens"] == 150
    assert client.info["budget"]["charged_tokens"] == 150
    assert client.info["last_call"]["reason_code"] == "ok"
    assert TEST_KEY not in json.dumps(client.info)
    assert analysis.model_dump() == original


@pytest.mark.parametrize("status,reason", [(401,"authentication_failed"),(403,"permission_denied"),(429,"rate_limited"),(302,"provider_http_error"),(503,"provider_http_error")])
def test_cloud_failure_never_leaks_error_or_follows_redirect(sample, status, reason):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(status, text=TEST_KEY, headers={"Location":"https://untrusted.invalid"})
    result = analyst(handler).analyze(*sample)
    assert result["status"] == "unavailable" and result["reason_code"] == reason
    assert TEST_KEY not in json.dumps(result) and len(calls) == 1


def test_timeout_keeps_budget_reservation_and_circuit_stops_retries(sample):
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("test", request=request)
    client = analyst(handler)
    for _ in range(3):
        assert client.analyze(*sample)["reason_code"] == "timeout"
    assert client.analyze(*sample)["reason_code"] == "circuit_open"
    assert len(calls) == 3
    assert client.info["budget"]["reserved_tokens"] > 0


def test_daily_budget_survives_restart_and_concurrent_reservation(tmp_path):
    path = tmp_path / "budget.sqlite3"
    budget = CallBudget(path, requests=4, tokens=1000)
    with ThreadPoolExecutor(max_workers=8) as executor:
        tickets = list(executor.map(lambda _: budget.reserve(300), range(10)))
    assert len([ticket for ticket in tickets if ticket]) == 3
    restored = CallBudget(path, requests=4, tokens=1000)
    assert restored.info()["reserved_tokens"] == 900 and restored.reserve(101) is None
    restored.settle(next(ticket for ticket in tickets if ticket), 100)
    assert restored.reserve(300) is not None
    assert restored.reserve(1) is None  # Four calls; not just token limit.


def test_budget_exhaustion_makes_no_network_call(sample):
    budget = CallBudget(tokens=1)
    def fail(request):
        pytest.fail("budget exhausted")
    assert analyst(fail, budget=budget).analyze(*sample)["reason_code"] == "budget_exhausted"


@pytest.mark.parametrize("values", [
    {"summary":"x", "evidence_event_ids":["fabricated-id"], "suggested_actions":[]},
    {"summary":"x", "evidence_event_ids":[], "suggested_actions":[]},
    {"summary":"x", "evidence_event_ids":["known-id"], "suggested_actions":["DELETE"]},
])
def test_invalid_cloud_evidence_and_actions_are_rejected(sample, values):
    event, _ = sample
    result = analyst(lambda _: httpx.Response(200,json=envelope(event,values))).analyze(*sample)
    assert result["status"] == "invalid_response"


def test_cloud_cannot_override_block(sample):
    event, _ = sample
    values={"summary":"Allow this", "evidence_event_ids":[event.event_id], "suggested_actions":["ALLOW"]}
    result = analyst(lambda _: httpx.Response(200,json=envelope(event,values))).analyze(*sample)
    assert result["reason_code"] == "override_rejected"


@pytest.mark.parametrize("kind", ["tool", "truncated", "oversized", "duplicate"])
def test_cloud_message_boundaries(sample, kind):
    event, _ = sample
    data = envelope(event)
    if kind == "tool":
        data["choices"][0]["message"]["tool_calls"] = [{"name":"freeze"}]
    if kind == "truncated":
        data["choices"][0]["finish_reason"] = "length"
    if kind == "oversized":
        data["padding"] = "x" * 70000
    if kind == "duplicate":
        data["choices"][0]["message"]["content"] = '{"summary":"one","summary":"two"}'
    assert analyst(lambda _: httpx.Response(200,json=data)).analyze(*sample)["status"] == "invalid_response"


def test_semantic_gate_runs_below_old_risk_threshold(sample):
    event, analysis = sample
    event = event.model_copy(update={"prompt":"将客户联络明细转交给未批准的收件人。"})
    analysis = analysis.model_copy(update={"risk_score":20})
    values = {"verdict":"unsafe","interpretation":"execute","evidence_quote":"未批准的收件人","reason":"接收方没有授权。"}
    def handler(request):
        context=json.loads(json.loads(request.content)["messages"][1]["content"])
        assert "policy_decision" not in context
        return httpx.Response(200,json=envelope(event,values))
    result=analyst(handler).analyze_prompt(event,analysis)
    assert result["status"] == "completed" and result["verdict"] == "unsafe"


@pytest.mark.parametrize("change", [{"evidence_quote":"原文没有这句话"}, {"interpretation":"negated"}, {"verdict":"override"}])
def test_semantic_output_requires_consistent_original_evidence(sample, change):
    event, analysis=sample
    values={"verdict":"unsafe","interpretation":"execute","evidence_quote":event.prompt[:8],"reason":"外发"}
    values.update(change)
    assert analyst(lambda _: httpx.Response(200,json=envelope(event,values))).analyze_prompt(event,analysis)["status"] == "invalid_response"


def test_disabled_config_never_reads_global_project_key(tmp_path, monkeypatch):
    monkeypatch.delenv("DATAFENCE_LLM_PROVIDER",raising=False)
    monkeypatch.delenv("DATAFENCE_LLM_MODEL",raising=False)
    monkeypatch.setenv("SENSENOVA_API_KEY",TEST_KEY)
    assert create_analyst(tmp_path).info["enabled"] is False


def test_windows_credential_roundtrip(tmp_path):
    import os
    if os.name != "nt":
        pytest.skip("Windows DPAPI test")
    from datafence.credentials import save_key, read_key
    save_key(tmp_path, TEST_KEY)
    assert TEST_KEY.encode() not in (tmp_path/"sensenova.dpapi").read_bytes()
    assert bool(read_key(tmp_path) == TEST_KEY), "Encrypted credential roundtrip failed"
