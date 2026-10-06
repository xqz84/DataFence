import hashlib
import json

from fastapi.testclient import TestClient

from datafence.api import create_app


def test_cloud_reports_are_read_only_aggregates_and_verify_artifacts(tmp_path):
    folder=tmp_path/"evaluations"/"cloud-diagnostic"
    folder.mkdir(parents=True)
    report={"provider":"sensenova","model":"sensenova-6.8-flash-lite","status":"completed",
            "version":"test-protocol","created_at":"2026-09-19T00:00:00+00:00",
            "summary":{"planned_cases":24,"completed_reviews":20,"review_coverage":20/24,
                       "secret_internal_field":"must-not-leave-evaluation"}}
    for name,key in (("responses.jsonl","responses_sha256"),("plan.json","plan_sha256"),
                     ("dataset.json","dataset_sha256"),("labels.jsonl","labels_sha256")):
        content=json.dumps({"ground_truth":"DO_NOT_EXPOSE"}).encode()
        (folder/name).write_bytes(content)
        report[key]=hashlib.sha256(content).hexdigest()
    (folder/"report.json").write_text(json.dumps(report),encoding="utf-8")
    with TestClient(create_app(tmp_path,100, auth_mode="local_demo"),base_url="http://127.0.0.1",client=("127.0.0.1",50000)) as client:
        response=client.get("/api/model-experiments")
        assert response.status_code==200
        record=response.json()[0]
        assert record["artifact_digests_valid"] is True
        assert record["summary"]["completed_reviews"]==20
        assert "ground_truth" not in response.text and "must-not-leave-evaluation" not in response.text
        (folder/"responses.jsonl").write_text("tampered",encoding="utf-8")
        assert client.get("/api/model-experiments").json()[0]["artifact_digests_valid"] is False
