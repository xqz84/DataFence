import copy
import json

import httpx
import pytest

from datafence.engine import DetectionEngine
from datafence.llm import LocalAnalyst, MAX_RESPONSE_BYTES, OLLAMA_CHAT_URL
from datafence.models import SimulationRequest
from datafence.sandbox import build_bank
from datafence.scenarios import generate_scenario


@pytest.fixture
def sample():
    bank = build_bank(customer_count=20)
    events, _ = generate_scenario(SimulationRequest(scenario_id="ai_leak"), bank["employees"], bank["tasks"])
    event = events[-1]
    return event, DetectionEngine(bank["employees"], bank["tasks"]).analyze(event)


@pytest.fixture(autouse=True)
def clean_configuration(monkeypatch):
    monkeypatch.delenv("DATAFENCE_LLM_MODEL", raising=False)


def response(event, **changes):
    advice = {"summary": "工单范围与敏感数据外发意图存在冲突，建议保留证据。",
              "evidence_event_ids": [event.event_id], "suggested_actions": ["PRESERVE_EVIDENCE"]}
    advice.update(changes)
    return httpx.Response(200, json={"model": "local-test:small", "done": True,
                                   "message": {"role": "assistant", "content": json.dumps(advice, ensure_ascii=False)}})


def configured(monkeypatch, handler):
    monkeypatch.setenv("DATAFENCE_LLM_MODEL", "local-test:small")
    return LocalAnalyst(transport=httpx.MockTransport(handler))


def test_unconfigured_never_connects(sample):
    def fail(request):
        pytest.fail("disabled adapter must not connect")
    analyst = LocalAnalyst(transport=httpx.MockTransport(fail))
    assert analyst.info == {"enabled": False, "status": "not_configured", "model": None}
    assert analyst.analyze(*sample)["status"] == "not_configured"


def test_low_risk_is_skipped_without_request(monkeypatch, sample):
    def fail(request):
        pytest.fail("low-risk event must not connect")
    analyst = configured(monkeypatch, fail)
    event, analysis = sample
    assert analyst.analyze(event, analysis.model_copy(update={"risk_score": 59.9}))["status"] == "skipped"


def test_success_is_read_only_and_context_is_allowlisted(monkeypatch, sample):
    event, analysis = sample
    analysis.chain[-1]["ground_truth"] = "ATTACK"
    analysis.chain[-1]["attack_type"] = "hidden-answer"
    original = copy.deepcopy((event.model_dump(), analysis.model_dump()))
    seen = []

    def handler(request):
        assert str(request.url) == OLLAMA_CHAT_URL
        assert request.method == "POST"
        assert "authorization" not in request.headers
        assert request.headers["accept-encoding"] == "identity"
        assert all(value <= 2 for value in request.extensions["timeout"].values())
        payload = json.loads(request.content)
        assert payload["stream"] is False and "tools" not in payload
        assert payload["format"]["additionalProperties"] is False
        context = json.loads(payload["messages"][1]["content"])
        assert "ground_truth" not in json.dumps(context) and "attack_type" not in json.dumps(context)
        assert "customer_ids" not in json.dumps(context)
        assert context["current_event"]["untrusted_prompt"] == event.prompt
        assert "不可信" in payload["messages"][0]["content"]
        seen.append(request)
        return response(event)

    result = configured(monkeypatch, handler).analyze(event, analysis)
    assert result["status"] == "completed"
    assert result["evidence_event_ids"] == [event.event_id]
    assert result["elapsed_ms"] >= 0
    assert len(seen) == 1
    assert (event.model_dump(), analysis.model_dump()) == original


def test_timeout_downgrades_without_retry(monkeypatch, sample):
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("simulated timeout", request=request)
    result = configured(monkeypatch, handler).analyze(*sample)
    assert result["status"] == "unavailable" and len(calls) == 1
    assert result["suggested_actions"] == []


@pytest.mark.parametrize("status", [302, 404, 500])
def test_http_failure_and_redirect_are_not_followed(monkeypatch, sample, status):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(status, headers={"Location": "https://external.invalid/steal"})
    assert configured(monkeypatch, handler).analyze(*sample)["status"] == "unavailable"
    assert len(calls) == 1


@pytest.mark.parametrize("changes", [
    {"suggested_actions": ["DELETE_DATABASE"]},
    {"suggested_actions": ["ALLOW"]},
    {"evidence_event_ids": ["fabricated-event-id"]},
    {"evidence_event_ids": []},
    {"summary": "   "},
    {"summary": 123},
    {"risk_score": 0},
])
def test_invalid_or_unauthorized_model_advice_is_rejected(monkeypatch, sample, changes):
    event, analysis = sample
    result = configured(monkeypatch, lambda _: response(event, **changes)).analyze(event, analysis)
    assert result["status"] == "invalid_response"
    assert not result["suggested_actions"] and not result["evidence_event_ids"]


def test_tool_calls_are_rejected(monkeypatch, sample):
    envelope = {"model": "local-test:small", "done": True,
                "message": {"role": "assistant", "content": "{}", "tool_calls": [{"function": {"name": "freeze"}}]}}
    assert configured(monkeypatch, lambda _: httpx.Response(200, json=envelope)).analyze(*sample)["status"] == "invalid_response"


class OversizedStream(httpx.SyncByteStream):
    def __iter__(self):
        for _ in range(10):
            yield b"x" * 8192


def test_streamed_body_limit_without_content_length(monkeypatch, sample):
    handler = lambda _: httpx.Response(200, headers={"Content-Type": "application/json"}, stream=OversizedStream())
    result = configured(monkeypatch, handler).analyze(*sample)
    assert result["status"] == "invalid_response" and "64 KiB" in result["summary"]


def test_declared_body_limit_checked_before_parsing(monkeypatch, sample):
    handler = lambda _: httpx.Response(200, content=b"{}", headers={"Content-Type": "application/json", "Content-Length": str(MAX_RESPONSE_BYTES + 1)})
    assert configured(monkeypatch, handler).analyze(*sample)["status"] == "invalid_response"


@pytest.mark.parametrize("body", [b"not json", b'{"done":true,"done":false}', b"[]", b'{"done":NaN}'])
def test_malformed_response_downgrades(monkeypatch, sample, body):
    handler = lambda _: httpx.Response(200, content=body, headers={"Content-Type": "application/json"})
    assert configured(monkeypatch, handler).analyze(*sample)["status"] == "invalid_response"


@pytest.mark.parametrize("model", ["gemma4:cloud", "model-cloud:latest", "https://external.invalid/model"])
def test_explicit_cloud_or_url_models_never_connect(monkeypatch, sample, model):
    monkeypatch.setenv("DATAFENCE_LLM_MODEL", model)
    def fail(request):
        pytest.fail("disallowed model must not connect")
    analyst = LocalAnalyst(transport=httpx.MockTransport(fail))
    assert analyst.info["enabled"] is False
    assert analyst.analyze(*sample)["status"] == "unavailable"


def test_proxy_environment_cannot_redirect_ollama(monkeypatch, sample):
    monkeypatch.setenv("HTTP_PROXY", "http://external.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "http://external.invalid:8080")
    event, _ = sample
    def handler(request):
        assert str(request.url) == OLLAMA_CHAT_URL
        return response(event)
    assert configured(monkeypatch, handler).analyze(*sample)["status"] == "completed"
