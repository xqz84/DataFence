"""Actual HTTP acceptance of the isolated private-deployment fixture only.

Never bootstraps an administrator, starts scenarios/evaluations, or calls a model.
The known account is test-only and must already exist in the isolated runtime.
"""

import argparse
import asyncio
from collections import Counter
import copy
import csv
import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import ssl
import subprocess
from time import perf_counter
from urllib.parse import urlsplit
from uuid import uuid4

import httpx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = (PROJECT_ROOT / "output" / "private-acceptance").resolve()
TEST_PASSWORD = "Acceptance-only-test-2026!"
ADMIN = "test-admin"
VIEWER = "test-viewer"
GET_PATHS = {"/api/auth/status", "/api/health", "/api/overview", "/api/session", "/api/auth/users",
             "/api/import-template", "/api/imports", "/api/datasets", "/api/access/tasks",
             "/api/access/operations", "/api/access/verify", "/api/audit/verify"}
POST_PATHS = {"/api/auth/login", "/api/auth/logout", "/api/auth/users", "/api/imports", "/api/access/execute",
              "/api/auth/users/" + VIEWER}


class AcceptanceFailure(RuntimeError):
    """Fixed check identifier only; never embed response bodies or credentials."""


def require(condition, name):
    if not condition:
        raise AcceptanceFailure(name)


def validated_base(value):
    parsed = urlsplit(value)
    # 8766 is occupied by another application; this run deliberately refuses it.
    require(parsed.scheme in {"http", "https"} and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            and parsed.port == 8767 and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment
            and not parsed.username and not parsed.password, "isolated_test_origin_required")
    return value.rstrip("/")


def allowed_route(method, path):
    if method == "GET" and (path in GET_PATHS or re.fullmatch(r"/api/imports/[0-9a-f-]{36}", path)):
        return True
    return method == "POST" and path in POST_PATHS


def checked_runtime(path, port):
    directory = Path(path).resolve()
    require(directory == FIXTURE_ROOT or directory.is_relative_to(FIXTURE_ROOT), "isolated_runtime_required")
    marker = directory / "server-state.json"
    require(marker.is_file() and marker.stat().st_size < 8192, "test_server_marker_required")
    state = json.loads(marker.read_text(encoding="utf-8"))
    require(Path(state["data_dir"]).resolve() == directory and state["port"] == port
            and type(state["pid"]) is int and state["pid"] > 0, "server_marker_mismatch")
    require(os.name == "nt", "windows_server_cpu_measurement_required")
    command = (f"@(Get-NetTCPConnection -State Listen -LocalPort {port} -ErrorAction Stop | "
               "Select-Object -ExpandProperty OwningProcess | Sort-Object -Unique) | ConvertTo-Json -Compress")
    process = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                             capture_output=True, text=True, timeout=20, check=False,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    require(process.returncode == 0, "listener_identity_unavailable")
    owners = json.loads(process.stdout)
    owners = owners if isinstance(owners, list) else [owners]
    require(owners and set(owners) == {state["pid"]}, "listener_pid_mismatch")
    return directory, state["pid"]


class ServerCPU:
    """Windows process CPU (kernel+user), distinct from request wall time."""

    def __init__(self, pid):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        self.kernel.GetProcessTimes.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.OpenProcess(0x1000, False, pid)
        require(bool(self.handle), "server_cpu_handle_unavailable")

    def seconds(self):
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        require(self.kernel.GetProcessTimes(self.handle, ctypes.byref(created), ctypes.byref(exited),
                                            ctypes.byref(kernel), ctypes.byref(user)), "server_cpu_sample_failed")
        require(exited.dwLowDateTime == 0 and exited.dwHighDateTime == 0, "test_server_exited")
        ticks = lambda t: (t.dwHighDateTime << 32) + t.dwLowDateTime
        return (ticks(kernel) + ticks(user)) / 10_000_000

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def percentile(values, proportion):
    ordered = sorted(values)
    index = (len(ordered) - 1) * proportion
    low, high = math.floor(index), math.ceil(index)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def fingerprint(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


class Acceptance:
    def __init__(self, base, verify, report, cpu):
        self.base, self.verify, self.report, self.cpu = base, verify, report, cpu
        self.calls = Counter()
        self.sensitive = {TEST_PASSWORD}
        self.clients = []

    def client(self):
        result = httpx.Client(base_url=self.base, trust_env=False, follow_redirects=False,
                              verify=self.verify, timeout=30)
        self.clients.append(result)
        return result

    def call(self, client, method, path, *, expected=200, **kwargs):
        require(allowed_route(method, path), "route_outside_acceptance_allowlist")
        self.calls[method + " " + path] += 1
        response = client.request(method, path, **kwargs)
        require(response.status_code == expected,
                f"http_status_{method.lower()}_{path.replace('/', '_')}_{response.status_code}_expected_{expected}")
        return response

    def check(self, name, **evidence):
        self.report["checks"].append({"name": name, "passed": True, "evidence": evidence})

    def login(self, client, username):
        response = self.call(client, "POST", "/api/auth/login", json={"username": username, "password": TEST_PASSWORD})
        body = response.json()
        value, credential = body.get("token"), client.cookies.get("df_session")
        require(isinstance(value, str) and bool(credential) and value != credential, "separate_session_and_write_credential")
        self.sensitive.update((value, credential))
        client.headers["X-DataFence-Token"] = value
        flags = response.headers.get("set-cookie", "").lower()
        require("httponly" in flags and "samesite=strict" in flags, "session_flags_missing")
        if self.base.startswith("https:"):
            require("secure" in flags, "tls_session_secure_flag_missing")
        return body["user"]

    def expect_delivery(self, result, count):
        rows = result.get("rows")
        require(result.get("allowed") is True and result.get("delivered_records") == count
                and isinstance(rows, list) and len(rows) == count, "gateway_actual_delivery_count")
        require(all(row.get("synthetic") is True and str(row.get("id", "")).startswith("SYN-") for row in rows),
                "gateway_delivers_only_synthetic_rows")
        require(result.get("cloud_called") is False, "gateway_must_not_call_cloud")
        return rows

    def run(self):
        anonymous, admin, viewer = self.client(), self.client(), self.client()
        status = self.call(anonymous, "GET", "/api/auth/status").json()
        require(status.get("authentication_required") is True and status.get("initialized") is True,
                "preinitialized_authentication_required")
        self.call(anonymous, "GET", "/api/overview", expected=401)
        self.call(anonymous, "GET", "/api/session", expected=401)
        user = self.login(admin, ADMIN)
        require(user.get("username") == ADMIN and user.get("role") == "admin", "test_administrator_identity")
        health = self.call(admin, "GET", "/api/health").json()
        require(health.get("llm", {}).get("enabled") is False, "test_runtime_must_disable_models")
        self.call(admin, "POST", "/api/imports", expected=403, headers={"X-DataFence-Token": ""},
                  json={"source_name": "test-no-write-credential", "content": "{}"})
        self.check("authenticated_boundary", anonymous_read_status=401, missing_write_credential_status=403,
                   authentication_required=True, network_mode=status.get("network_mode"), models_enabled=False)

        users = self.call(admin, "GET", "/api/auth/users").json()
        existed = any(item["username"] == VIEWER for item in users)
        if not existed:
            self.call(admin, "POST", "/api/auth/users", expected=201,
                      json={"username": VIEWER, "password": TEST_PASSWORD, "role": "viewer"})
        else:
            for change in ({"password": TEST_PASSWORD}, {"enabled": True}, {"role": "viewer"}):
                self.call(admin, "POST", "/api/auth/users/" + VIEWER, json=change)
        require(self.login(viewer, VIEWER)["role"] == "viewer", "test_viewer_identity")
        self.call(viewer, "GET", "/api/overview")
        self.call(viewer, "GET", "/api/auth/users", expected=403)
        template = self.call(admin, "GET", "/api/import-template").json()
        events = [json.loads(line) for line in template["content"].splitlines() if line.strip()]
        require(events and all(e.get("synthetic") is True and e.get("event_type") != "AI_PROMPT" for e in events),
                "template_is_offline_synthetic_only")
        source = "private-acceptance-" + uuid4().hex
        payload = {"source_name": source, "format": template["format"], "content": template["content"]}
        self.call(viewer, "POST", "/api/imports", expected=403, json=payload)
        self.call(viewer, "POST", "/api/access/execute", expected=403, json={})
        self.call(admin, "POST", "/api/auth/users/" + VIEWER, json={"enabled": False})
        self.call(viewer, "GET", "/api/overview", expected=401)
        self.call(admin, "POST", "/api/auth/users/" + VIEWER, json={"enabled": True})
        self.call(viewer, "GET", "/api/overview", expected=401)
        self.login(viewer, VIEWER)
        self.call(viewer, "POST", "/api/auth/logout", json={})
        self.call(viewer, "GET", "/api/overview", expected=401)
        self.call(admin, "POST", "/api/auth/users/" + VIEWER, json={"enabled": False})
        self.check("viewer_and_account_lifecycle", account_created=not existed, writes_denied=True,
                   disable_revokes_active_session=True, reenable_does_not_restore_session=True,
                   logout_revokes_session=True, viewer_left_disabled=True)

        before = self.call(admin, "GET", "/api/imports").json()
        invalid = copy.deepcopy(events)
        invalid[-1]["employee_id"] = "not-a-registered-employee"
        invalid_payload = {"source_name": source + "-invalid", "format": "jsonl",
                           "content": "\n".join(json.dumps(e) for e in invalid)}
        self.call(admin, "POST", "/api/imports", expected=422, json=invalid_payload)
        self.call(admin, "POST", "/api/imports", expected=422,
                  json={"source_name": source + "-bad-csv", "format": "csv", "content": '"unterminated header'})
        require(self.call(admin, "GET", "/api/imports").json() == before, "invalid_import_batch_is_atomic")
        imported = self.call(admin, "POST", "/api/imports", expected=201, json=payload).json()
        require(imported.get("mode") == "observe" and imported.get("row_count") == len(events)
                and imported.get("executed_actions") == 0 and imported.get("replayed") is False,
                "import_observation_only")
        detail = self.call(admin, "GET", "/api/imports/" + imported["id"]).json()
        require(len(detail["observations"]) == len(events) and all(
            row.get("cloud_called") is False and row.get("actions_executed") is False for row in detail["observations"]),
            "import_has_no_execution_or_cloud")
        replay = self.call(admin, "POST", "/api/imports", expected=201, json=payload).json()
        require(replay.get("replayed") is True and replay["id"] == imported["id"], "import_idempotent_replay")
        changed = copy.deepcopy(events)
        changed[-1]["record_count"] += 1
        self.call(admin, "POST", "/api/imports", expected=422,
                  json={**payload, "content": "\n".join(json.dumps(e) for e in changed)})
        listed = self.call(admin, "GET", "/api/imports").json()
        require(sum(row["source_name"] == source for row in listed) == 1, "import_single_committed_batch")
        self.check("observation_import", imported_rows=len(events), invalid_batch_status=422, malformed_csv_status=422,
                   atomic_failure=True, replay_same_batch=True, altered_event_rejected=True, executed_actions=0,
                   cloud_called=False, source_sha256=imported["source_sha256"])

        datasets = self.call(admin, "GET", "/api/datasets").json()
        dataset = next((row for row in datasets if row.get("id") == "uci-bank-marketing"), None)
        require(dataset and dataset.get("status") == "imported" and dataset.get("source_integrity") is True
                and dataset.get("row_count") == 45211 and dataset.get("column_count") == 17,
                "public_dataset_actual_45211_rows")
        require(dataset.get("security_labels_available") is False and dataset.get("llm_access") is False,
                "public_business_data_scope")
        self.check("public_dataset_aggregation", rows=dataset["row_count"], columns=dataset["column_count"],
                   source_integrity=True, invalid_rows=dataset["quality"]["invalid_rows"],
                   unknown_cells=dataset["quality"]["unknown_cells"], security_labels_available=False)

        tasks = self.call(admin, "GET", "/api/access/tasks").json()
        now = datetime.now(timezone.utc)
        hour = now.astimezone(timezone(timedelta(hours=8))).hour
        current = lambda t: datetime.fromisoformat(t["valid_from"]) <= now <= datetime.fromisoformat(t["valid_until"])
        usable = [t for t in tasks if t.get("allow_export") and current(t) and hour in t["allowed_hours"]
                  and t["quota"]["remaining_records"] >= 20]
        usable.sort(key=lambda t: (t["employee_id"] != "E0038", t["id"]))
        denied = [t for t in tasks if not t.get("allow_export") and current(t)]
        denied.sort(key=lambda t: (hour not in t["allowed_hours"], t["employee_id"] != "E0038", t["id"]))
        require(usable and denied, "suitable_acceptance_tasks_required")
        task, restricted = usable[0], denied[0]
        request = {"request_id": str(uuid4()), "task_id": task["id"], "operation": "query",
                   "record_count": 5, "regions": [task["regions"][0]]}
        query = self.call(admin, "POST", "/api/access/execute", json=request).json()
        query_rows = self.expect_delivery(query, 5)
        require(all(row["region"] in request["regions"] for row in query_rows), "query_region_materialization")
        repeated = self.call(admin, "POST", "/api/access/execute", json=request).json()
        require(repeated.get("replayed") is True and repeated["rows"] == query_rows
                and repeated["evidence_hash"] == query["evidence_hash"]
                and repeated["quota"]["used_records"] == query["quota"]["used_records"], "gateway_replay_without_extra_quota")
        exported = self.call(admin, "POST", "/api/access/execute",
                             json={**request, "request_id": str(uuid4()), "operation": "export"}).json()
        exported_rows = self.expect_delivery(exported, 5)
        exported_csv = exported.get("csv")
        require(isinstance(exported_csv, str), "actual_export_csv_required")
        csv_rows = list(csv.DictReader(io.StringIO(exported_csv)))
        require(len(csv_rows) == 5 and {r["id"] for r in csv_rows} == {r["id"] for r in exported_rows},
                "export_csv_matches_delivered_rows")
        refusal = self.call(admin, "POST", "/api/access/execute", expected=403,
                            json={"request_id": str(uuid4()), "task_id": restricted["id"], "operation": "export",
                                  "record_count": 1, "regions": [restricted["regions"][0]]}).json()
        require(refusal.get("allowed") is False and refusal.get("delivered_records") == 0
                and refusal.get("rows") == [] and not refusal.get("csv") and refusal.get("cloud_called") is False,
                "denied_export_has_no_data")
        self.call(admin, "POST", "/api/access/execute", expected=409, json={**request, "record_count": 6})
        self.check("gateway_actual_delivery_and_denial", query_rows=5, export_rows=5,
                   query_rows_sha256=fingerprint(query_rows), csv_sha256=fingerprint(exported_csv.encode()),
                   csv_bytes=len(exported_csv.encode()), denied_status=403, denied_rows=0,
                   denied_task_allows_export=False, denied_task_within_allowed_hours=hour in restricted["allowed_hours"],
                   replay_without_extra_quota=True, altered_request_same_id_status=409, cloud_called=False)

        self.report["read_latency"] = asyncio.run(self.concurrent_reads(admin))
        samples = []
        for index in range(5):
            cpu_before, wall_before = self.cpu.seconds(), perf_counter()
            result = self.call(admin, "POST", "/api/access/execute",
                               json={**request, "request_id": str(uuid4()), "record_count": 1}).json()
            wall_ms = (perf_counter() - wall_before) * 1000
            cpu_ms = (self.cpu.seconds() - cpu_before) * 1000
            self.expect_delivery(result, 1)
            require(cpu_ms >= 0, "monotonic_server_cpu")
            samples.append({"index": index + 1, "http_wall_ms": round(wall_ms, 4),
                            "server_process_cpu_ms": round(cpu_ms, 4), "delivered_rows": 1})
        self.report["gateway_cpu"] = {"samples": samples, "total_cpu_ms": round(sum(r["server_process_cpu_ms"] for r in samples), 4),
                                      "basis": "Windows GetProcessTimes kernel+user for the verified service PID; includes other process work in each interval",
                                      "exclusive_per_request_cpu": False}
        access_audit = self.call(admin, "GET", "/api/access/verify").json()
        event_audit = self.call(admin, "GET", "/api/audit/verify").json()
        require(access_audit.get("valid") is True and event_audit.get("valid") is True, "separate_audit_chains_valid")
        require(access_audit.get("checked_operations", 0) >= 8, "gateway_audit_includes_actual_attempts")
        final_health = self.call(admin, "GET", "/api/health").json()
        require(final_health.get("llm", {}).get("enabled") is False, "models_remained_disabled")
        self.check("audit_integrity", gateway_checked_operations=access_audit["checked_operations"],
                   scenario_checked_events=event_audit["checked_events"], both_valid=True,
                   note="Gateway chain is separate; an empty scenario-event chain does not validate gateway operations.")
        self.call(admin, "POST", "/api/auth/logout", json={})

    async def concurrent_reads(self, admin):
        started = asyncio.Event()
        async with httpx.AsyncClient(base_url=self.base, cookies=admin.cookies, trust_env=False,
                                     follow_redirects=False, verify=self.verify, timeout=30,
                                     limits=httpx.Limits(max_connections=50, max_keepalive_connections=50)) as client:
            async def one(index):
                path = "/api/overview"
                require(allowed_route("GET", path), "read_benchmark_route")
                await started.wait()
                began = perf_counter()
                response = await client.get(path)
                elapsed = (perf_counter() - began) * 1000
                require(response.status_code == 200, "concurrent_read_status")
                require(isinstance(response.json(), dict), "concurrent_read_payload")
                return {"index": index, "status": response.status_code, "wall_ms": round(elapsed, 4)}
            jobs = [asyncio.create_task(one(index + 1)) for index in range(50)]
            began = perf_counter()
            started.set()
            samples = await asyncio.gather(*jobs)
            total = (perf_counter() - began) * 1000
        self.calls["GET /api/overview"] += len(samples)
        values = [row["wall_ms"] for row in samples]
        return {"requests": 50, "concurrency": 50, "endpoint": "/api/overview", "samples": samples,
                "p50_ms": round(percentile(values, .5), 4), "p95_ms": round(percentile(values, .95), 4),
                "maximum_ms": max(values), "batch_wall_ms": round(total, 4),
                "basis": "Client monotonic wall time including HTTP/queueing; not CPU or production SLA"}

    def close(self):
        for client in self.clients:
            client.close()


def save_report(path, report, sensitive):
    path = Path(path).resolve()
    require(path.is_relative_to(FIXTURE_ROOT) and path.suffix == ".json", "report_must_stay_in_test_output")
    serialized = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    require(not any(secret and secret in serialized for secret in sensitive), "sensitive_value_in_report")
    require(not re.search(r'"(?:password|cookie|csrf|csrf_token|token|authorization|set-cookie)"\s*:', serialized, re.I),
            "sensitive_field_in_report")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(serialized)


def offline_checks():
    require(validated_base("http://127.0.0.1:8767") == "http://127.0.0.1:8767", "default_test_origin")
    for value in ("http://127.0.0.1:8765", "http://127.0.0.1:8766", "http://example.com:8767",
                  "http://user@localhost:8767", "http://localhost:8767/api", "http://localhost:8767?x=1"):
        try:
            validated_base(value)
        except AcceptanceFailure:
            continue
        raise AcceptanceFailure("unsafe_origin_accepted")
    require(not any(allowed_route(method, path) for method in ("GET", "POST")
                    for path in ("/api/runs", "/api/evaluations", "/api/auth/bootstrap", "https://example.com")),
            "forbidden_route_allowlist")
    require(percentile([0, 10, 20], .95) == 19, "percentile_calculation")
    print(json.dumps({"offline_safety_checks": "passed", "network_requests": 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8767")
    parser.add_argument("--test-runtime", type=Path, default=FIXTURE_ROOT)
    parser.add_argument("--ca-file", type=Path, help="Explicit trusted test CA for HTTPS; certificate verification remains enabled")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-check", action="store_true", help="Offline guards only; no HTTP or accounts")
    args = parser.parse_args()
    if args.self_check:
        offline_checks()
        return 0
    report = {"version": "private-http-acceptance-v1", "started_at": datetime.now(timezone.utc).isoformat(),
              "status": "failed", "checks": [], "cloud_requests_by_script": 0,
              "scope": "Dedicated Windows loopback fixture; authentication, observation import and synthetic-row gateway",
              "limitations": ["No real bank data, no attack accuracy benchmark, no LAN load certification.",
                              "Gateway returns synthetic rows; imported logs remain observe-only.",
                              "Read latency is wall time; process CPU includes all service work during measured intervals."]}
    execution, cpu = None, None
    output = args.output or FIXTURE_ROOT / "reports" / (datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid4().hex[:8] + ".json")
    try:
        base = validated_base(args.base_url)
        directory, pid = checked_runtime(args.test_runtime, urlsplit(base).port)
        verify = ssl.create_default_context(cafile=str(args.ca_file)) if args.ca_file else True
        cpu = ServerCPU(pid)
        report["target"] = {"base_url": base, "isolated_runtime_verified": True, "listener_pid": pid,
                            "certificate_verification": "explicit_test_ca" if args.ca_file else "system_default"}
        execution = Acceptance(base, verify, report, cpu)
        execution.run()
        report["status"] = "passed"
    except Exception as exc:
        report["failure"] = str(exc) if isinstance(exc, AcceptanceFailure) else type(exc).__name__
    finally:
        if execution:
            execution.close()
            report["request_counts"] = dict(execution.calls)
        if cpu:
            cpu.close()
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        save_report(output, report, execution.sensitive if execution else {TEST_PASSWORD})
    print(json.dumps({"status": report["status"], "checks_passed": len(report["checks"]),
                      "report": str(Path(output).resolve()), "failure": report.get("failure")}, ensure_ascii=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
