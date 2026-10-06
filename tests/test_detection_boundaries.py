"""Business totals survive bounded context and remain independent by task."""

from datetime import datetime, timedelta

import pytest

from datafence.engine import DetectionEngine
from datafence.models import BusinessTask, Employee, SecurityEvent
from datafence.sandbox import BANK_TZ


@pytest.fixture
def context():
    employee = Employee(id="review-employee", name="Synthetic reviewer", region="北京", known_device="review-device")
    task = BusinessTask(id="review-task-a", employee_id=employee.id, purpose="授权客户服务", regions=[employee.region],
                        max_records=8, valid_from=datetime(2026, 9, 19, 0, tzinfo=BANK_TZ),
                        valid_until=datetime(2026, 9, 20, 0, tzinfo=BANK_TZ), allowed_hours=list(range(24)))
    return employee, task


def request(employee, task, index, count=6, minutes=0, session="review-session-a", event_type="QUERY"):
    return SecurityEvent(event_id=f"review-event-{index:04d}", session_id=session, employee_id=employee.id,
                         timestamp=datetime(2026, 9, 19, 9, tzinfo=BANK_TZ) + timedelta(minutes=minutes, seconds=index),
                         event_type=event_type, task_id=task.id, purpose=task.purpose, record_count=count,
                         regions=[employee.region], device_id=employee.known_device, sensitivity=85,
                         object_id=f"review-object-{index:04d}")


def test_separate_tasks_in_one_session_do_not_consume_each_others_scope(context):
    employee, task = context
    other = task.model_copy(update={"id": "review-task-b"})
    detector = DetectionEngine([employee], [task, other])
    first = detector.analyze(request(employee, task, 1))
    second = detector.analyze(request(employee, other, 2))
    assert first.intent.status == second.intent.status == "supported"
    assert first.risk_score < 60 and second.risk_score < 60
    assert "累计 6 条" in " ".join(second.intent.evidence)
    exceeded = detector.analyze(request(employee, task, 3, count=3))
    assert exceeded.intent.status == "mismatch" and exceeded.risk_score >= 60


def test_task_total_does_not_expire_when_context_reaches_thirty_minutes(context):
    employee, task = context
    detector = DetectionEngine([employee], [task])
    detector.analyze(request(employee, task, 1))
    result = detector.analyze(request(employee, task, 2, minutes=31))
    assert result.intent.status == "mismatch" and result.risk_score >= 60
    assert "累计 12 条" in " ".join(result.intent.evidence)
    # The bounded explanatory context remains bounded; totals are separate.
    assert [node["event_id"] for node in result.chain] == ["review-event-0002"]


def test_129th_read_does_not_disappear_at_the_context_row_limit(context):
    employee, task = context
    task = task.model_copy(update={"max_records": 128})
    detector = DetectionEngine([employee], [task])
    for index in range(1, 129):
        assert detector.analyze(request(employee, task, index, count=1)).intent.status == "supported"
    result = detector.analyze(request(employee, task, 129, count=1))
    assert result.intent.status == "mismatch" and result.risk_score >= 60
    assert "累计 129 条" in " ".join(result.intent.evidence)


def test_task_total_stays_per_session_and_reset_clears_it(context):
    employee, task = context
    detector = DetectionEngine([employee], [task])
    detector.analyze(request(employee, task, 1))
    separate = detector.analyze(request(employee, task, 2, session="review-session-b"))
    assert separate.intent.status == "supported"
    exceeded = detector.analyze(request(employee, task, 3, count=3))
    assert exceeded.intent.status == "mismatch"
    detector.reset()
    assert detector.analyze(request(employee, task, 4)).intent.status == "supported"


def test_file_steps_do_not_duplicate_observed_query_or_api_requests(context):
    employee, task = context
    task = task.model_copy(update={"allow_export": True})
    detector = DetectionEngine([employee], [task])
    for index, operation in enumerate(("QUERY", "EXPORT", "COMPRESS"), start=1):
        assert detector.analyze(request(employee, task, index, event_type=operation)).intent.status == "supported"
    result = detector.analyze(request(employee, task, 4, count=2, event_type="API"))
    assert result.intent.status == "supported"
    assert "累计 8 条" in " ".join(result.intent.evidence)
    result = detector.analyze(request(employee, task, 5, count=1, event_type="API"))
    assert result.intent.status == "mismatch"
