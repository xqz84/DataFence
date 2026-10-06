"""Offline fault injection only: no real credentials or provider calls."""

import asyncio
import json
import sqlite3
import threading
import time

import httpx
import pytest

from datafence.engine import DetectionEngine
from datafence.llm_budget import CallBudget
from datafence.models import SimulationRequest
from datafence.sandbox import build_bank
from datafence.scenarios import generate_scenario
from datafence.sensenova import CHAT_URL, SenseNovaAnalyst, create_analyst


TEST_KEY = "sk-resilience-synthetic-key-not-real"


@pytest.fixture(scope="module")
def sample():
    bank = build_bank(customer_count=20)
    events, _ = generate_scenario(SimulationRequest(scenario_id="ai_leak"), bank["employees"], bank["tasks"])
    event = events[-1]
    return event, DetectionEngine(bank["employees"], bank["tasks"]).analyze(event)


def advice(event):
    return {"summary": "合成事件需要保留证据。", "evidence_event_ids": [event.event_id],
            "suggested_actions": ["PRESERVE_EVIDENCE"]}


def envelope(content, **changes):
    result = {"choices": [{"finish_reason": "stop", "message": {
        "role": "assistant", "content": json.dumps(content, ensure_ascii=False)}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}}
    result.update(changes)
    return result


def forbid_network(request):
    pytest.fail("A request must not reach even the mock network in this case")


@pytest.mark.parametrize("method", ["analyze", "analyze_prompt"])
def test_budget_reservation_exception_is_a_safe_result(sample, method):
    class BrokenBudget:
        def reserve(self, amount):
            raise sqlite3.OperationalError(TEST_KEY)
        def info(self):
            raise sqlite3.OperationalError(TEST_KEY)
    client = SenseNovaAnalyst(key=TEST_KEY, budget=BrokenBudget(), transport=httpx.MockTransport(forbid_network))
    result = getattr(client, method)(*sample)
    assert result["status"] == "unavailable" and result["reason_code"] == "budget_unavailable"
    assert result["request_ms"] == 0
    assert client.info["status"] == "unavailable" and client.info["enabled"] is False
    assert client.info["budget"]["requests"] is None
    assert TEST_KEY not in json.dumps([result, client.info])


def test_bad_durable_budget_does_not_reset_allowance_or_prevent_factory_start(tmp_path, monkeypatch, sample):
    monkeypatch.setenv("DATAFENCE_LLM_PROVIDER", "sensenova")
    monkeypatch.setattr("datafence.sensenova.read_key", lambda _: TEST_KEY)
    path = tmp_path / "llm-budget.sqlite3"
    original = b"deliberately damaged synthetic ledger"
    path.write_bytes(original)
    client = create_analyst(tmp_path)
    client._transport = httpx.MockTransport(forbid_network)
    assert client.info["enabled"] is False
    assert client.info["budget"]["status"] == "unavailable"
    assert client.analyze(*sample)["reason_code"] == "budget_unavailable"
    assert path.read_bytes() == original


def test_factory_default_request_policy_and_explicit_cap(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAFENCE_LLM_PROVIDER", "sensenova")
    monkeypatch.setattr("datafence.sensenova.read_key", lambda _: TEST_KEY)
    client = create_analyst(tmp_path)
    assert client.info["request_policy"] == {
        "max_output_tokens": 2400, "temperature": 0.2, "network_deadline_seconds": 40, "auto_retries": 0}
    assert SenseNovaAnalyst(key=TEST_KEY, max_output_tokens=999999).info["request_policy"]["max_output_tokens"] == 2400


@pytest.mark.parametrize("failure", ["closed", "sqlite_lock", "thread_lock"])
def test_budget_health_is_nonblocking_and_does_not_claim_zero_usage(tmp_path, failure):
    budget = CallBudget(tmp_path / "budget.sqlite3")
    assert budget.reserve(123) is not None
    blocker = None
    release = threading.Event()
    worker = None
    if failure == "closed":
        budget._db.close()
    elif failure == "sqlite_lock":
        blocker = sqlite3.connect(tmp_path / "budget.sqlite3")
        blocker.execute("BEGIN EXCLUSIVE")
    else:
        ready = threading.Event()
        def hold_lock():
            with budget._lock:
                ready.set()
                release.wait(timeout=2)
        worker = threading.Thread(target=hold_lock)
        worker.start()
        assert ready.wait(timeout=1)
    try:
        started = time.perf_counter()
        result = budget.info()
        assert time.perf_counter() - started < 0.5
        assert result["status"] == "unavailable"
        assert result["requests"] is None and result["reserved_tokens"] is None
    finally:
        if blocker:
            blocker.rollback()
            blocker.close()
        release.set()
        if worker:
            worker.join(timeout=1)
    if failure != "closed":
        assert budget.info()["reserved_tokens"] == 123


def test_budget_settlement_failure_keeps_existing_reservation(sample, monkeypatch):
    budget = CallBudget()
    def fail_settlement(*args):
        raise sqlite3.OperationalError(TEST_KEY)
    monkeypatch.setattr(budget, "settle", fail_settlement)
    client = SenseNovaAnalyst(key=TEST_KEY, budget=budget, transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json=envelope(advice(sample[0])))))
    result = client.analyze(*sample)
    assert result["reason_code"] == "budget_unavailable"
    assert budget.info()["reserved_tokens"] > 0 and budget.info()["charged_tokens"] == 0
    assert TEST_KEY not in json.dumps(result)


@pytest.mark.parametrize("request_id", [TEST_KEY, "req-" + TEST_KEY, "sk-different-secret-shape", "SK-UPPER-SECRET"])
def test_request_ids_cannot_echo_secrets(sample, request_id):
    client = SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(lambda _: httpx.Response(
        200, json=envelope(advice(sample[0]), request_id=request_id))))
    result = client.analyze(*sample)
    assert result["status"] == "completed" and result["provider_request_id"] is None
    assert TEST_KEY not in json.dumps([result, client.info])


@pytest.mark.parametrize("field", [TEST_KEY, "private.provider.debug.field", "arbitrary-untrusted-key"])
def test_unknown_validation_field_names_are_not_reflected(sample, field):
    content = dict(advice(sample[0]), **{field: "extra value"})
    client = SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json=envelope(content))))
    result = client.analyze(*sample)
    assert result["reason_code"] == "schema_validation"
    assert result["validation_issues"] == [{"field": "<extra>", "type": "extra_forbidden"}]
    assert field not in json.dumps(result)


def test_known_validation_fields_stay_diagnostic_without_echoing_bad_values(sample):
    content = dict(advice(sample[0]), suggested_actions=[TEST_KEY])
    client = SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json=envelope(content))))
    result = client.analyze(*sample)
    assert result["validation_issues"] == [{"field": "suggested_actions.0", "type": "literal_error"}]
    assert TEST_KEY not in json.dumps(result)


def test_scrubbing_covers_nested_info_model_skips_and_evidence_ids(sample):
    class NestedBudget(CallBudget):
        def info(self):
            return dict(super().info(), diagnostic={TEST_KEY: ["echo " + TEST_KEY]})
    event, analysis = sample
    client = SenseNovaAnalyst(key=TEST_KEY, model="sensenova-" + TEST_KEY, budget=NestedBudget())
    assert TEST_KEY not in json.dumps(client.info)
    assert TEST_KEY not in json.dumps(client.analyze(event, analysis.model_copy(update={"risk_score": 0})))
    event = event.model_copy(update={"event_id": TEST_KEY})
    analysis = analysis.model_copy(update={"event_id": TEST_KEY})
    client = SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json=envelope(advice(event)))))
    assert TEST_KEY not in json.dumps(client.analyze(event, analysis))


def test_request_total_deadline_cancels_trickle_and_closes_stream(sample, monkeypatch):
    monkeypatch.setattr("datafence.sensenova.REQUEST_TIMEOUT_SECONDS", 0.06)
    class Trickle(httpx.AsyncByteStream):
        chunks, cancelled, closed = 0, False, False
        async def __aiter__(self):
            try:
                while True:
                    await asyncio.sleep(0.01)
                    self.chunks += 1
                    yield b" "
            finally:
                self.cancelled = True
        async def aclose(self):
            self.closed = True
    stream = Trickle()
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=stream)
    client = SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(handler))
    started = time.perf_counter()
    result = client.analyze(*sample)
    assert time.perf_counter() - started < 1
    assert result["status"] == "unavailable" and result["reason_code"] == "timeout"
    assert 0 < stream.chunks < 100 and stream.cancelled and stream.closed
    assert calls == [CHAT_URL]
    assert client.info["budget"]["reserved_tokens"] > 0
    # Windows asyncio can schedule a timeout early within its coarse monotonic
    # clock resolution, while request_ms uses higher-resolution perf_counter.
    # Assert bounded measured work, not a minimum wait on these different clocks.
    assert 0 < result["request_ms"] < 1000


def test_request_deadline_also_cancels_wait_for_headers(sample, monkeypatch):
    monkeypatch.setattr("datafence.sensenova.REQUEST_TIMEOUT_SECONDS", 0.03)
    cancelled = []
    async def handler(request):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)
    client = SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(handler))
    started = time.perf_counter()
    result = client.analyze(*sample)
    assert time.perf_counter() - started < 1
    assert result["reason_code"] == "timeout" and cancelled == [True]


def test_streamed_body_limit_without_content_length(sample):
    class LargeBody(httpx.AsyncByteStream):
        chunks, closed = 0, False
        async def __aiter__(self):
            for _ in range(100):
                self.chunks += 1
                yield b" " * 1024
        async def aclose(self):
            self.closed = True
    stream = LargeBody()
    client = SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(lambda _: httpx.Response(
        200, headers={"content-type": "application/json"}, stream=stream)))
    assert client.analyze(*sample)["reason_code"] == "response_too_large"
    assert stream.chunks == 65 and stream.closed


def test_budget_preflight_is_measured_separately_from_network_deadline(sample, monkeypatch):
    monkeypatch.setattr("datafence.sensenova.REQUEST_TIMEOUT_SECONDS", 0.03)
    class SlowPreflight(CallBudget):
        def reserve(self, amount):
            time.sleep(0.07)
            return super().reserve(amount)
    client = SenseNovaAnalyst(key=TEST_KEY, budget=SlowPreflight(), transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json=envelope(advice(sample[0])))))
    result = client.analyze(*sample)
    assert result["status"] == "completed"
    assert result["preflight_ms"] >= 60 and result["elapsed_ms"] >= 60
    assert result["request_ms"] < result["preflight_ms"]


def test_sync_adapter_called_inside_async_loop_degrades_without_budget_or_coroutine_warning(sample):
    client = SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(forbid_network))
    async def invoke():
        return client.analyze(*sample)
    result = asyncio.run(invoke())
    assert result["reason_code"] == "unsupported_call_context"
    assert client.info["budget"]["requests"] == 0


def test_invalid_context_cannot_escape_or_spend_budget(sample):
    event, analysis = sample
    analysis = analysis.model_copy(deep=True)
    analysis.chain[-1]["risk_score"] = float("nan")
    client = SenseNovaAnalyst(key=TEST_KEY, transport=httpx.MockTransport(forbid_network))
    result = client.analyze(event, analysis)
    assert result["reason_code"] == "context_unavailable"
    assert client.info["budget"]["requests"] == 0
