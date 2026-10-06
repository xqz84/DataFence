import csv
import io
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from datafence.ingestion import ImportRequest, ImportStore, parse_events
from datafence.models import SimulationRequest
from datafence.sandbox import build_bank
from datafence.scenarios import generate_scenario


@pytest.fixture
def source():
    bank = build_bank(customer_count=100)
    events, _ = generate_scenario(SimulationRequest(scenario_id="normal", record_count=5), bank["employees"], bank["tasks"])
    rows = [e.model_dump(mode="json") for e in events]
    return bank, rows


def request(rows, **kwargs):
    return ImportRequest(source_name="test-source", content="\n".join(json.dumps(x) for x in rows), **kwargs)


def test_observation_persists_without_execution_or_cloud(tmp_path, source):
    bank, rows = source
    store = ImportStore(tmp_path / "imports.sqlite3")
    result = store.ingest(request(rows), bank["employees"], bank["tasks"], "analyst")
    assert result["row_count"] == 2 and result["executed_actions"] == 0
    reopened = ImportStore(tmp_path / "imports.sqlite3")
    detail = reopened.detail(result["id"])
    assert len(detail["observations"]) == 2
    assert all(not r["actions_executed"] and not r["cloud_called"] for r in detail["observations"])
    assert not (tmp_path / "quota.sqlite3").exists()
    assert not (tmp_path / "llm-budget.sqlite3").exists()


def test_idempotency_across_independent_connections(tmp_path, source):
    bank, rows = source
    stores = [ImportStore(tmp_path / "imports.sqlite3") for _ in range(4)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda s: s.ingest(request(rows),bank["employees"],bank["tasks"],"analyst"), stores))
    assert len({r["id"] for r in results}) == 1
    assert sum(not r["replayed"] for r in results) == 1
    changed = [dict(row) for row in rows]
    changed[-1]["record_count"] += 1
    with pytest.raises(ValueError, match="相同事件ID"):
        stores[0].ingest(request(changed),bank["employees"],bank["tasks"],"analyst")
    assert len(stores[0].list()) == 1


@pytest.mark.parametrize("mutation", ["truth", "real", "unknown_employee", "wrong_task", "out_of_order", "duplicate"])
def test_invalid_batch_leaves_no_rows(tmp_path, source, mutation):
    bank, rows = source
    if mutation == "truth": rows[-1]["ground_truth"] = "ATTACK"
    if mutation == "real": rows[-1]["synthetic"] = False
    if mutation == "unknown_employee": rows[-1]["employee_id"] = "unknown"
    if mutation == "wrong_task": rows[-1]["task_id"] = "not-a-task"
    if mutation == "out_of_order": rows = rows[::-1]
    if mutation == "duplicate": rows += rows[:1]
    store = ImportStore(tmp_path / "imports.sqlite3")
    with pytest.raises(ValueError):
        store.ingest(request(rows), bank["employees"],bank["tasks"],"analyst")
    assert store.list() == []


def test_csv_and_jsonl_equivalent(source):
    _, rows = source
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=list(rows[0]))
    writer.writeheader()
    for row in rows:
        writer.writerow(dict(row, regions=json.dumps(row["regions"]), synthetic="true"))
    parsed = parse_events(ImportRequest(source_name="csv-source", format="csv", content=buf.getvalue()))
    assert [e.model_dump(mode="json") for e in parsed] == rows


def test_duplicate_keys_size_and_error_redaction(source):
    _, rows = source
    with pytest.raises(ValueError):
        parse_events(ImportRequest(source_name="bad", content='{"synthetic":true,"synthetic":false}'))
    with pytest.raises(ValueError, match="1 MiB"):
        parse_events(ImportRequest(source_name="bad", content="数" * 400000))
    rows[0]["sk-secret-marker"] = "do-not-echo"
    with pytest.raises(ValueError) as error:
        parse_events(request(rows))
    assert "sk-secret-marker" not in str(error.value) and "do-not-echo" not in str(error.value)


def test_malformed_csv_header_is_controlled_error():
    with pytest.raises(ValueError, match="表头"):
        parse_events(ImportRequest(source_name="bad", format="csv", content='"unterminated header'))
