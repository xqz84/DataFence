from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import threading

import pytest

from datafence.models import BusinessTask, SecurityEvent
from datafence.quota import METRIC, QuotaLedger, demo
from datafence.sandbox import BANK_TZ


def task(scope="task_lifetime", employee="E0038", task_id="quota-task-0001", limit=10):
    return BusinessTask(id=task_id, employee_id=employee, purpose="合成额度验证", regions=["合成区域01"],
                        max_records=limit, quota_scope=scope, valid_from=datetime(2026, 1, 1, tzinfo=BANK_TZ),
                        valid_until=datetime(2026, 12, 31, tzinfo=BANK_TZ), allowed_hours=list(range(24)))


def event(index=1, count=6, session="quota-session-01", employee="E0038", task_id="quota-task-0001", kind="QUERY"):
    return SecurityEvent(event_id=f"quota-event-{index:08d}", session_id=session, employee_id=employee,
                         timestamp=datetime(2026, 9, 19, 10, tzinfo=BANK_TZ) + timedelta(seconds=index),
                         task_id=task_id, event_type=kind, record_count=count, regions=["合成区域01"])


def test_lifetime_quota_accumulates_across_sessions_and_restart(tmp_path):
    path = tmp_path / "quota.sqlite3"
    ledger = QuotaLedger(path)
    first = event()
    assert ledger.reserve(first, task())["status"] == "reserved"
    assert ledger.confirm(first.event_id)["confirmed_records"] == 6
    restarted = QuotaLedger(path)
    second = restarted.reserve(event(2, session="quota-session-02"), task())
    assert not second["allowed"] and second["reason"] == "quota_exceeded"
    assert second["used_records"] == 6 and second["remaining_records"] == 4
    assert restarted.summary(task(), "E0038")["metric"] == METRIC


def test_default_scope_is_session_and_different_sessions_keep_separate_quota(tmp_path):
    data = task().model_dump()
    del data["quota_scope"]
    current = BusinessTask.model_validate(data)
    assert current.quota_scope == "session"
    ledger = QuotaLedger(tmp_path / "quota.sqlite3")
    first, second = event(), event(2, session="quota-session-02")
    assert ledger.reserve(first, current)["allowed"]
    ledger.confirm(first.event_id)
    assert ledger.reserve(second, current)["allowed"]
    assert ledger.summary(current, "E0038", first.session_id)["used_records"] == 6
    assert ledger.summary(current, "E0038", second.session_id)["used_records"] == 6


def test_policy_blocked_requests_and_flow_operations_do_not_consume(tmp_path):
    ledger = QuotaLedger(tmp_path / "quota.sqlite3")
    assert not ledger.reserve(event(), task(), blocked=True)["allowed"]
    for index, kind in enumerate(["LOGIN", "EXPORT", "COMPRESS", "UPLOAD", "AI_PROMPT"], 10):
        result = ledger.reserve(event(index, count=500, kind=kind), task())
        assert result["status"] == "not_applicable"
    assert ledger.summary(task(), "E0038")["used_records"] == 0


def test_block_after_preflight_releases_unconfirmed_reservation(tmp_path):
    ledger = QuotaLedger(tmp_path / "quota.sqlite3")
    read = event()
    ledger.reserve(read, task())
    decision = ledger.reserve(read, task(), blocked=True)
    assert decision["status"] == "cancelled" and decision["used_records"] == 0
    assert not ledger.reserve(read, task())["allowed"]


def test_confirm_is_idempotent_and_cannot_be_cancelled(tmp_path):
    ledger = QuotaLedger(tmp_path / "quota.sqlite3")
    read = event()
    first = ledger.reserve(read, task())
    replay = ledger.reserve(read, task())
    assert first["used_records"] == replay["used_records"] == 6
    assert replay["already_seen"]
    ledger.confirm(read.event_id)
    assert ledger.confirm(read.event_id)["already_seen"]
    assert ledger.reserve(read, task())["status"] == "confirmed"
    with pytest.raises(ValueError, match="cannot be cancelled"):
        ledger.cancel(read.event_id)
    with pytest.raises(ValueError, match="retroactively"):
        ledger.reserve(read, task(), blocked=True)
    assert ledger.summary(task(), "E0038")["confirmed_records"] == 6


def test_cancel_releases_capacity_and_is_idempotent(tmp_path):
    ledger = QuotaLedger(tmp_path / "quota.sqlite3")
    read = event()
    ledger.reserve(read, task())
    assert ledger.cancel(read.event_id)["used_records"] == 0
    assert ledger.cancel(read.event_id)["already_seen"]
    with pytest.raises(ValueError, match="only a reserved"):
        ledger.confirm(read.event_id)
    assert ledger.reserve(event(2, count=10), task())["allowed"]


def test_unconfirmed_reservations_remain_occupied_after_restart(tmp_path):
    path = tmp_path / "quota.sqlite3"
    first = QuotaLedger(path)
    first.reserve(event(), task())
    second = QuotaLedger(path)
    assert second.summary(task(), "E0038")["reserved_records"] == 6
    assert not second.reserve(event(2, session="quota-session-02"), task())["allowed"]
    second.cancel(event().event_id, reason="manual_verified_not_executed")
    assert second.reserve(event(3, session="quota-session-03"), task())["allowed"]


def test_changed_payload_cannot_reuse_event_identifier(tmp_path):
    ledger = QuotaLedger(tmp_path / "quota.sqlite3")
    ledger.reserve(event(), task())
    with pytest.raises(ValueError, match="different quota request"):
        ledger.reserve(event(count=1), task())
    with pytest.raises(ValueError, match="different quota request"):
        ledger.reserve(event(session="different-session"), task())
    assert ledger.summary(task(), "E0038")["used_records"] == 6


def test_employee_and_task_buckets_are_isolated(tmp_path):
    ledger = QuotaLedger(tmp_path / "quota.sqlite3")
    ledger.reserve(event(count=10), task())
    another_employee = task(employee="E0001")
    assert ledger.reserve(event(2, count=10, employee="E0001"), another_employee)["allowed"]
    another_task = task(task_id="quota-task-0002")
    assert ledger.reserve(event(3, count=10, task_id=another_task.id), another_task)["allowed"]
    wrong = ledger.reserve(event(4, employee="E0002"), task())
    assert not wrong["allowed"] and wrong["reason"] == "business_task_binding_mismatch"
    assert ledger.summary(task(), "E0038")["used_records"] == 10


def test_parallel_connections_cannot_over_reserve(tmp_path):
    path = tmp_path / "quota.sqlite3"
    ledgers = [QuotaLedger(path) for _ in range(10)]
    barrier = threading.Barrier(len(ledgers))
    current = task(limit=10)
    def reserve(index):
        barrier.wait()
        return ledgers[index].reserve(event(index + 1, count=3, session=f"parallel-session-{index:02d}"), current)
    with ThreadPoolExecutor(max_workers=len(ledgers)) as pool:
        results = list(pool.map(reserve, range(len(ledgers))))
    assert sum(result["allowed"] for result in results) == 3
    assert ledgers[0].summary(current, "E0038")["used_records"] == 9


def test_quota_counts_accepted_request_not_actual_unique_rows(tmp_path):
    ledger = QuotaLedger(tmp_path / "quota.sqlite3")
    current = task(limit=12)
    first, second = event(count=6), event(2, count=6, kind="API")
    for read in (first, second):
        assert ledger.reserve(read, current)["allowed"]
        # Even if only one actual customer was returned, the declared metric is
        # accepted request volume. A repeated object is not deduplicated here.
        ledger.confirm(read.event_id)
    assert ledger.summary(current, "E0038")["confirmed_records"] == 12


def test_no_task_is_unknown_not_implicitly_authorized(tmp_path):
    ledger = QuotaLedger(tmp_path / "quota.sqlite3")
    result = ledger.reserve(event(), None)
    assert result["status"] == "not_applicable" and result["reason"] == "no_verified_business_task"
    assert result["remaining_records"] is None
    # allowed here means the quota module has no decision; the policy engine
    # remains responsible for whether this unknown-purpose request may execute.
    assert result["applicable"] is False


def test_demo_uses_a_dedicated_synthetic_lifetime_task(tmp_path):
    output = demo(tmp_path / "demo.sqlite3")
    assert output["synthetic"] and output["task"]["id"].startswith("QUOTA-DEMO-")
    assert [result["status"] for result in output["decisions"]] == ["confirmed", "rejected"]
    assert output["summary"]["confirmed_records"] == 8
    assert output["summary"]["remaining_records"] == 4
