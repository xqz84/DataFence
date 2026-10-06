import json
import os
from pathlib import Path
import shutil
import sys

import pytest

from datafence import engine, model_artifacts, model_initialization, server
from datafence.model_artifacts import canonical, sha256
from datafence.model_initialization import initialize_runtime_model, require_runtime_model
from datafence.runtime_lock import RuntimeLock


@pytest.fixture
def release(tmp_path):
    """Only copy public model artifacts; never use the live account/key stores."""
    project = tmp_path / "release"
    directory = project / "runtime" / "models" / "iforest-v2"
    directory.mkdir(parents=True)
    original = Path(__file__).resolve().parents[1] / "runtime" / "models" / "iforest-v2"
    for name in model_initialization._ARTIFACTS:
        shutil.copyfile(original / name, directory / name)
    artifact = json.loads((directory / "model.json").read_bytes())
    report = json.loads((directory / "report.json").read_bytes())
    (directory.parent / "active.json").write_bytes(canonical({
        "name": "iforest-v2", "artifact_sha256": artifact["sha256"], "report_sha256": sha256(report)}))
    # These unneeded or sensitive-looking files must not enter the new runtime.
    (directory / "holdout_labels.json").write_text('{"synthetic_test_only":true}')
    (project / "runtime" / "test-only-secret.dpapi").write_bytes(b"not-a-real-key")
    return project


def files_under(directory):
    return {str(path.relative_to(directory)): path.read_bytes()
            for path in directory.rglob("*") if path.is_file()}


def test_new_custom_runtime_loads_the_validated_v2_only(release, tmp_path, monkeypatch):
    target = tmp_path / "new-runtime"
    source_before = files_under(release)
    result = initialize_runtime_model(target, release)
    assert result == {"status": "initialized", "model": "iforest-v2"}
    registry = target / "models"
    assert {path.relative_to(registry).as_posix() for path in registry.rglob("*") if path.is_file()} == {
        "active.json", *(f"iforest-v2/{name}" for name in model_initialization._ARTIFACTS)}
    assert not (target / "test-only-secret.dpapi").exists()
    assert files_under(release) == source_before
    monkeypatch.setattr(engine, "MODEL_ROOT", registry)
    monkeypatch.setattr(model_artifacts, "MODEL_ROOT", registry)
    engine._registered_model.cache_clear()
    try:
        detector = engine.DetectionEngine([], [], behavior_model="active")
        assert detector.model_info["version"] == "iforest-v2"
        assert detector.model_info["model_source"] == "validated_json_artifact"
        assert detector.model_info["quality_gate_passed"] is True
        assert "load_warning" not in detector.model_info
    finally:
        engine._registered_model.cache_clear()


def test_required_model_readiness_checks_receipt_and_digest(release, tmp_path):
    target = tmp_path / "new-runtime"
    initialize_runtime_model(target, release)
    selection = json.loads((target / "models" / "active.json").read_bytes())
    assert require_runtime_model(target, "iforest-v2", selection["artifact_sha256"]) == selection
    with pytest.raises(ValueError, match="required release"):
        require_runtime_model(target, "iforest-v2", "0" * 64)
    (target / "models" / "iforest-v2" / "promotion.json").unlink()
    with pytest.raises(ValueError):
        require_runtime_model(target, "iforest-v2")


def test_existing_registry_is_not_overwritten_or_read_from_release(release, tmp_path):
    target = tmp_path / "custom-runtime"
    registry = target / "models"
    registry.mkdir(parents=True)
    (registry / "active.json").write_text('{"my_existing_selection":"preserve"}')
    (registry / "operator-owned.json").write_text("preserve existing artifacts")
    before = files_under(registry)
    assert initialize_runtime_model(target, tmp_path / "missing-release")["status"] == "existing"
    assert files_under(registry) == before


def test_existing_empty_registry_is_preserved_with_explicit_status(release, tmp_path):
    target = tmp_path / "custom-runtime"
    (target / "models").mkdir(parents=True)
    assert initialize_runtime_model(target, release)["status"] == "existing_without_active"
    assert list((target / "models").iterdir()) == []


def test_default_release_registry_is_unchanged_and_does_not_acquire_its_lock(release):
    before = files_under(release)
    assert initialize_runtime_model(release / "runtime", release)["status"] == "existing"
    assert files_under(release) == before
    assert not (release / "runtime" / ".runtime.lock").exists()


def test_missing_bundle_is_reported_without_fake_model(tmp_path):
    target = tmp_path / "runtime"
    assert initialize_runtime_model(target, tmp_path / "missing-release") == {"status": "source_missing", "model": None}
    assert not (target / "models").exists()


@pytest.mark.parametrize("document", ["model.json", "report.json", "promotion.json", "protocol.json"])
def test_corrupt_artifact_never_publishes_active_or_partial_registry(release, tmp_path, document):
    path = release / "runtime" / "models" / "iforest-v2" / document
    content = json.loads(path.read_bytes())
    if document == "model.json":
        content["payload"]["metadata"]["version"] = "tampered-model"
    else:
        content["name"] = "tampered-model"
    path.write_bytes(canonical(content))
    target = tmp_path / "runtime"
    with pytest.raises(ValueError):
        initialize_runtime_model(target, release)
    assert not (target / "models").exists()
    assert list(target.glob(".model-init-*")) == []
    with RuntimeLock(target):
        pass


def test_pointer_cannot_select_an_external_path(release, tmp_path):
    pointer = release / "runtime" / "models" / "active.json"
    content = json.loads(pointer.read_bytes())
    content["name"] = "../outside"
    pointer.write_bytes(canonical(content))
    target = tmp_path / "runtime"
    with pytest.raises(ValueError, match="pointer"):
        initialize_runtime_model(target, release)
    assert not (target / "models").exists()


def test_initialization_requires_exclusive_runtime_ownership(release, tmp_path):
    target = tmp_path / "runtime"
    with RuntimeLock(target):
        with pytest.raises(RuntimeError):
            initialize_runtime_model(target, release)
    assert not (target / "models").exists()
    assert initialize_runtime_model(target, release)["status"] == "initialized"


def test_write_failure_leaves_no_partial_registry(release, tmp_path, monkeypatch):
    target = tmp_path / "runtime"
    original_write = model_initialization._write

    def fail_before_pointer(path, content):
        if path.name == "active.json":
            raise OSError("synthetic disk failure")
        original_write(path, content)

    monkeypatch.setattr(model_initialization, "_write", fail_before_pointer)
    with pytest.raises(OSError, match="synthetic disk failure"):
        initialize_runtime_model(target, release)
    assert not (target / "models").exists()
    assert list(target.glob(".model-init-*")) == []


@pytest.mark.parametrize("bundled", [True, False])
def test_launcher_initializes_before_uvicorn_and_reports_missing_bundle(release, tmp_path, monkeypatch, capsys, bundled):
    import uvicorn
    from datafence.deployment import Deployment

    project = release if bundled else tmp_path / "empty-release"
    target = tmp_path / "custom-runtime"
    monkeypatch.setattr(server, "__file__", str(project / "backend" / "datafence" / "server.py"))
    argv = ["datafence.server", "--data-dir", str(target), "--port", "19001"]
    if bundled:
        argv += ["--require-model", "iforest-v2"]
    monkeypatch.setattr(sys, "argv", argv)
    # Register environment restoration before main mutates process environment.
    for key in ("DATAFENCE_DATA_DIR", "DATAFENCE_NETWORK_MODE", "DATAFENCE_AUTH_MODE", "DATAFENCE_SERVER_PORT",
                "DATAFENCE_ALLOWED_HOSTS", "DATAFENCE_ALLOWED_ORIGINS"):
        monkeypatch.setenv(key, os.environ.get(key, ""))
    monkeypatch.setattr(Deployment, "load", lambda: None)
    started = []

    def capture_start(*args, **kwargs):
        assert (target / "models" / "active.json").is_file() is bundled
        assert os.environ["DATAFENCE_DATA_DIR"] == str(target.resolve())
        assert os.environ["DATAFENCE_AUTH_MODE"] == "required"
        assert kwargs["proxy_headers"] is False
        assert kwargs["host"] == "127.0.0.1"
        started.append(True)

    monkeypatch.setattr(uvicorn, "run", capture_start)
    server.main()
    assert started == [True]
    output = capsys.readouterr()
    assert ("Initialized trained behavior model: iforest-v2" in output.out if bundled
            else "known legacy baseline" in output.err)
    if bundled:
        assert "Required model validated: iforest-v2" in output.out
