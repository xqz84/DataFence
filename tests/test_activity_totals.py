"""Daily metrics must not inherit the bounded event-detail display window."""

from datetime import datetime, timedelta, timezone

from datafence.service import Service
from datafence.storage import Store, dump


def insert_events(store, values):
    with store.connect() as db:
        for index, (employee, at, event_type, count, regions) in enumerate(values):
            event_id = f"activity-fixture-{index}"
            record = {"detected_at": at.isoformat(), "event": {
                "event_id": event_id, "employee_id": employee, "event_type": event_type,
                "record_count": count, "regions": regions}, "analysis": {"intent": None}}
            db.execute("INSERT INTO events(id,run_id,employee_id,payload) VALUES(?,?,?,?)",
                       (event_id, "projection-fixture", employee, dump(record)))


def test_daily_metrics_cover_all_events_while_detail_remains_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAFENCE_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("DATAFENCE_LLM_MODEL", "")
    monkeypatch.setenv("DATAFENCE_BEHAVIOR_MODEL", "legacy")
    service = Service(tmp_path, customer_count=100)
    instant = datetime.now(timezone.utc)
    values = [("E0038", instant, "EXPORT", 7, ["earlier-region"])]
    values += [("E0038", instant, "QUERY", 1, ["recent-region"])] * 501
    values += [("E0039", instant, "QUERY", 900, ["other-employee"])]
    insert_events(service.store, values)
    result = service.employee_detail("E0038")
    assert len(result["events"]) == 500
    assert result["current"] == {"records": 501, "queries": 501, "regions": 2, "exports": 1}


def test_daily_boundaries_use_shanghai_day_and_exact_microseconds(tmp_path):
    store = Store(tmp_path)
    start = datetime(2026, 9, 19, tzinfo=timezone(timedelta(hours=8)))
    end = start + timedelta(days=1)
    values = [
        ("E0038", start - timedelta(microseconds=1), "QUERY", 900, ["previous"]),
        ("E0038", start.astimezone(timezone.utc), "QUERY", 2, ["start"]),
        ("E0038", (end - timedelta(microseconds=1)).astimezone(timezone.utc), "API", 3, ["last"]),
        ("E0038", end, "QUERY", 800, ["next"]),
    ]
    insert_events(store, values)
    assert store.employee_activity("E0038", start, end) == {
        "records": 5, "queries": 2, "regions": 2, "exports": 0}
