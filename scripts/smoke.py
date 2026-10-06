"""Exercise the running loopback server. Creates synthetic demonstration runs."""

import json
import getpass
import sys
import warnings
from pathlib import Path
import time

import httpx


with httpx.Client(base_url="http://127.0.0.1:8765", timeout=30, trust_env=False) as client:
    status = client.get("/api/auth/status")
    status.raise_for_status()
    if status.json()["authentication_required"]:
        if not sys.stdin.isatty():
            raise RuntimeError("请在交互终端登录后运行演练验收，密码不能作为命令参数")
        username = input("DataFence username: ").strip()
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("DataFence password (hidden): ")
        login = client.post("/api/auth/login", json={"username": username, "password": password})
        password = None
        login.raise_for_status()
    client.get("/api/health").raise_for_status()
    token_response = client.get("/api/session")
    token_response.raise_for_status()
    client.headers["X-DataFence-Token"] = token_response.json()["token"]
    results = []
    for scenario in ("normal", "approved_batch", "insider", "stolen_account", "bulk_export", "api_scraping", "ai_leak", "combined"):
        created = client.post("/api/runs", json={"scenario_id": scenario, "record_count": 18000, "interval_ms": 0})
        created.raise_for_status()
        run_id = created.json()["id"]
        deadline = time.monotonic() + 180
        while True:
            response = client.get(f"/api/runs/{run_id}")
            response.raise_for_status()
            run = response.json()
            if run["status"] != "running":
                break
            if time.monotonic() > deadline:
                raise TimeoutError(f"run did not complete: {run_id}")
            time.sleep(0.1)
        if run["status"] != "completed":
            raise RuntimeError(run)
        if scenario == "approved_batch":
            assert run["sink_records"] == 18000 and run["blocked_events"] == 0, run
        elif scenario == "combined":
            assert run["sink_records"] == 0 and run["blocked_events"] >= 1, run
        results.append(run)
    audit = client.get("/api/audit/verify").json()
    assert audit["valid"], audit
    output = {"runs": results, "audit": audit, "synthetic": True}
    Path("runtime").mkdir(exist_ok=True)
    Path("runtime/smoke.json").write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"scenarios_completed": len(results), "audit": audit,
                      "approved_sink_records": results[1]["sink_records"],
                      "combined_sink_records": results[-1]["sink_records"]}, ensure_ascii=False, indent=2))
