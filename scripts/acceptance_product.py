"""Run the complete local demo on the existing isolated 8767 test fixture."""

import json
from pathlib import Path
import time
from uuid import uuid4

import httpx

from acceptance_private import ADMIN, TEST_PASSWORD, FIXTURE_ROOT, checked_runtime


def main():
    checked_runtime(FIXTURE_ROOT, 8767)
    with httpx.Client(base_url="http://127.0.0.1:8767", timeout=30) as client:
        client.post("/api/auth/login", json=dict(username=ADMIN, password=TEST_PASSWORD)).raise_for_status()
        client.headers["X-DataFence-Token"] = client.get("/api/session").json()["token"]
        prior_completed = [item for item in client.get("/api/demos").json() if item["status"] == "completed"]
        for prior in prior_completed:
            detail = client.get("/api/demos/" + prior["id"]).json()
            assert detail["status"] == "completed" and detail["review_revision"] >= 1
            history = client.get(f"/api/events/{detail['selected_event_id']}/review").json()
            assert history["revision"] >= detail["review_revision"]
        request = dict(request_id=str(uuid4()), employee_id="E0038")
        response = client.post("/api/demos", json=request)
        response.raise_for_status()
        demo_id = response.json()["id"]
        for _ in range(90):
            demo = client.get("/api/demos/" + demo_id).json()
            if demo["status"] != "running":
                break
            time.sleep(0.5)
        assert demo["status"] == "awaiting_review", demo
        replay = client.post("/api/demos", json=request)
        assert replay.json()["id"] == demo_id
        event_id = demo["selected_event_id"]
        event = client.get("/api/events/" + event_id).json()
        workbench = client.get("/api/agents/workbench", params=dict(event_id=event_id)).json()
        assert len(workbench["modules"]) == 6 and workbench["related_knowledge"]
        assert workbench["llm"]["completed_calls"] == 0
        for step in demo["steps"]:
            records = client.get("/api/events", params=dict(run_id=step["run_id"], limit=500)).json()
            assert records and all(r["ai_analysis"]["reason_code"] == "demo_local_mode" for r in records)
        query = client.get("/api/knowledge/search", params=dict(q="已审批批量导出为什么可以放行")).json()
        assert query["answered"] and query["matches"]
        unknown = client.get("/api/knowledge/search", params=dict(q="宇宙暗物质食谱xyz123")).json()
        assert unknown["answered"] is False and unknown["answer"] is None
        review_body = dict(request_id=str(uuid4()), expected_revision=0, disposition="confirmed_risk",
                           note="验收：已核对工单范围、实际阻断及零外发回执，保留证据。")
        review = client.post(f"/api/events/{event_id}/review", json=review_body)
        review.raise_for_status()
        assert review.json()["revision"] == 1
        assert review.json()["current"]["reference_knowledge"]["grants_permissions"] is False
        assert client.get("/api/events/" + event_id).json() == event
        confirmed = client.post(f"/api/demos/{demo_id}/confirm", json=dict(review_revision=1))
        confirmed.raise_for_status()
        demo = confirmed.json()
        assert demo["status"] == "completed" and demo["audit"]["valid"]
        report = dict(demo=demo, knowledge=client.get("/api/knowledge/status").json(),
                      workbench_module_count=len(workbench["modules"]),
                      cloud_calls=workbench["llm"]["completed_calls"],
                      known_query_answered=True, unknown_query_answered=False,
                      review_did_not_mutate_event=True, idempotent_replay=True,
                      previous_completed_demos_read=len(prior_completed),
                      reviews=client.get("/api/reviews/verify").json())
    output = Path(__file__).resolve().parents[1] / "output/product-upgrade"
    output.mkdir(exist_ok=True, parents=True)
    path = output / f"http-acceptance-{demo_id}.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(dict(report=str(path), demo_id=demo_id, status=demo["status"],
                         steps=[dict(id=s["id"], passed=s["passed"], sink_records=s["sink_records"],
                                     processed=s["processed_events"], skipped=s["skipped_events"]) for s in demo["steps"]]), ensure_ascii=True))


if __name__ == "__main__":
    main()
