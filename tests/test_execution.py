from datetime import datetime, timezone

import pytest

from datafence.execution import SandboxExecutor
from datafence.models import SecurityEvent, SimulationRequest
from datafence.sandbox import REGIONS, build_bank
from datafence.scenarios import generate_scenario


@pytest.fixture
def customers():
    return [{"id": f"SYN-C-{index:03d}", "region": "区域甲" if index < 5 else "区域乙", "synthetic": True}
            for index in range(10)]


def event(kind, **changes):
    return SecurityEvent(event_id=f"event-{kind}-0001", session_id="session-0001", employee_id="E0038",
                         timestamp=datetime(2026, 9, 19, tzinfo=timezone.utc), event_type=kind,
                         **changes)


def test_query_respects_scope_and_available_records(customers):
    executor = SandboxExecutor(customers)
    query = event("QUERY", record_count=20, regions=["区域甲"], object_id="dataset")
    assert executor.execute(query, False)["record_count"] == 5
    upload = event("UPLOAD", record_count=20, channel="approved_partner", parent_object_id="dataset")
    receipt = executor.execute(upload, False)["receipt"]
    assert receipt["customer_ids"] == [row["id"] for row in customers if row["region"] == "区域甲"]
    assert receipt["synthetic"] is True


def test_blocked_read_never_creates_an_uploadable_object(customers):
    executor = SandboxExecutor(customers)
    query = event("QUERY", record_count=3, regions=["区域甲"], object_id="dataset")
    assert executor.execute(query, True) == {"record_count": 0, "receipt": None}
    with pytest.raises(ValueError, match="not been materialized"):
        executor.execute(event("UPLOAD", parent_object_id="dataset"), False)


def test_export_compress_and_upload_inherit_exact_parent_snapshot(customers):
    executor = SandboxExecutor(customers)
    executor.execute(event("QUERY", record_count=3, regions=["区域乙"], object_id="dataset"), False)
    exported = executor.execute(event("EXPORT", record_count=50000, object_id="file", parent_object_id="dataset"), False)
    compressed = executor.execute(event("COMPRESS", record_count=50000, object_id="archive", parent_object_id="file"), False)
    received = executor.execute(event("UPLOAD", record_count=50000, parent_object_id="archive"), False)
    assert exported["record_count"] == compressed["record_count"] == received["record_count"] == 3
    assert received["receipt"]["customer_ids"] == [row["id"] for row in customers[5:8]]
    assert received["receipt"]["source_object_id"] == "archive"


def test_blocked_export_does_not_create_downstream_file(customers):
    executor = SandboxExecutor(customers)
    executor.execute(event("QUERY", record_count=3, regions=["区域甲"], object_id="dataset"), False)
    assert executor.execute(event("EXPORT", object_id="file", parent_object_id="dataset"), True)["record_count"] == 0
    with pytest.raises(ValueError, match="not been materialized"):
        executor.execute(event("COMPRESS", object_id="archive", parent_object_id="file"), False)
    with pytest.raises(ValueError, match="not been materialized"):
        executor.execute(event("UPLOAD", parent_object_id="file"), False)


def test_blocked_upload_has_no_receipt(customers):
    executor = SandboxExecutor(customers)
    executor.execute(event("QUERY", record_count=3, regions=["区域甲"], object_id="dataset"), False)
    assert executor.execute(event("UPLOAD", parent_object_id="dataset"), True) == {"record_count": 0, "receipt": None}


def test_upload_requires_existing_parent_and_correct_session(customers):
    executor = SandboxExecutor(customers)
    executor.execute(event("QUERY", record_count=3, regions=["区域甲"], object_id="dataset"), False)
    with pytest.raises(ValueError, match="requires an existing parent"):
        executor.execute(event("UPLOAD", object_id="dataset"), False)
    wrong_session = event("UPLOAD", parent_object_id="dataset").model_copy(update={"session_id": "session-0002"})
    with pytest.raises(ValueError, match="not been materialized"):
        executor.execute(wrong_session, False)
    wrong_employee = event("UPLOAD", parent_object_id="dataset").model_copy(update={"employee_id": "E0001"})
    with pytest.raises(ValueError, match="not been materialized"):
        executor.execute(wrong_employee, False)


def test_api_pages_accumulate_without_invented_or_repeated_records(customers):
    executor = SandboxExecutor(customers)
    call = event("API", record_count=3, regions=["区域乙"], object_id="dataset")
    assert executor.execute(call, False)["record_count"] == 3
    assert executor.execute(call.model_copy(update={"event_id": "api-page-0002"}), False)["record_count"] == 2
    assert executor.execute(call.model_copy(update={"event_id": "api-page-0003"}), False)["record_count"] == 0
    received = executor.execute(event("UPLOAD", parent_object_id="dataset"), False)
    assert received["record_count"] == 5
    assert len(set(received["receipt"]["customer_ids"])) == 5


def test_new_query_replaces_snapshot_without_mutating_exported_snapshot(customers):
    executor = SandboxExecutor(customers)
    executor.execute(event("QUERY", record_count=2, regions=["区域甲"], object_id="dataset"), False)
    executor.execute(event("EXPORT", object_id="file", parent_object_id="dataset"), False)
    executor.execute(event("QUERY", record_count=4, regions=["区域乙"], object_id="dataset"), False)
    assert executor.execute(event("UPLOAD", parent_object_id="file"), False)["record_count"] == 2
    assert executor.execute(event("UPLOAD", parent_object_id="dataset"), False)["record_count"] == 4


def test_approved_batch_full_scope_can_reach_entire_bank():
    bank = build_bank(customer_count=50)
    events, _ = generate_scenario(SimulationRequest(scenario_id="approved_batch", record_count=50), bank["employees"], bank["tasks"])
    executor = SandboxExecutor(bank["customers"])
    outputs = [executor.execute(row, False) for row in events]
    assert set(events[1].regions) == set(REGIONS)
    assert outputs[-1]["record_count"] == 50
    assert set(outputs[-1]["receipt"]["customer_ids"]) == {row["id"] for row in bank["customers"]}


def test_customer_rows_must_be_explicitly_synthetic():
    with pytest.raises(ValueError, match="synthetic"):
        SandboxExecutor([{"id": "real-looking-identifier", "region": "区域甲", "synthetic": False}])
