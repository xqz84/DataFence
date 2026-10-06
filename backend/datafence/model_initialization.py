"""Initialize an empty private runtime from the fixed, validated release model.

No existing registry is replaced. This is deployment initialization, not a model
promotion API; both paths come from the local server launcher.
"""

import os
from pathlib import Path
import re
import tempfile

from .engine import FEATURES
from .model_artifacts import MODEL_NAME, canonical, load_artifact, read_json, sha256
from .runtime_lock import RuntimeLock


_ARTIFACTS = {"model.json": 16 * 1024 * 1024, "report.json": 512 * 1024,
              "protocol.json": 512 * 1024, "promotion.json": 8192}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _regular(path: Path, root: Path, *, directory: bool = False) -> None:
    if (path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(root)
            or not (path.is_dir() if directory else path.is_file())):
        raise ValueError("Bundled model must use regular files inside the release directory")


def _write(path: Path, content: bytes) -> None:
    with path.open("xb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def _validate_registry(directory: Path, selection: dict) -> None:
    name = selection["name"]
    model, _, _, metadata = load_artifact(directory / "model.json", FEATURES)
    report = read_json(directory / "report.json", limit=_ARTIFACTS["report.json"])
    protocol = read_json(directory / "protocol.json", limit=_ARTIFACTS["protocol.json"])
    promotion = read_json(directory / "promotion.json", limit=_ARTIFACTS["promotion.json"])
    if (metadata.get("version") != name or report.get("name") != name
            or metadata["artifact_sha256"] != selection["artifact_sha256"]
            or report.get("artifact_sha256") != selection["artifact_sha256"]
            or sha256(report) != selection["report_sha256"]):
        raise ValueError("Bundled model or report does not match the active model hashes")
    gate = report.get("quality_gate")
    if not isinstance(gate, dict) or gate.get("passed") is not True or not isinstance(report.get("candidate"), dict):
        raise ValueError("Bundled model has not passed its deployment quality gate")
    if protocol.get("name") != name or protocol.get("features") != FEATURES:
        raise ValueError("Bundled model protocol does not match the model feature schema")
    if any(promotion.get(key) != selection[key] for key in selection):
        raise ValueError("Bundled model promotion receipt does not match the active model")
    # Parsing every tree above checks bounded, finite numeric inference data. The
    # hashes detect corruption; they are not a publisher's cryptographic signature.
    if model.n_features_in_ != len(FEATURES):
        raise ValueError("Bundled model has an incompatible feature count")


def require_runtime_model(data_directory: Path, expected_name: str, expected_sha256: str | None = None) -> dict:
    """Fail a deployment readiness check if its explicitly required model is absent."""
    if (not MODEL_NAME.fullmatch(expected_name) or expected_name in {"active", "legacy"}
            or expected_sha256 is not None and not _DIGEST.fullmatch(expected_sha256)):
        raise ValueError("Invalid required model name or digest")
    root = (data_directory.resolve() / "models")
    pointer = root / "active.json"
    _regular(root, root.resolve(), directory=True)
    _regular(pointer, root.resolve())
    selection = read_json(pointer, limit=8192)
    if set(selection) != {"name", "artifact_sha256", "report_sha256"}:
        raise ValueError("Runtime active pointer has invalid fields")
    if selection["name"] != expected_name or expected_sha256 is not None and selection["artifact_sha256"] != expected_sha256:
        raise ValueError("Runtime active model does not match the required release")
    if (not _DIGEST.fullmatch(selection["artifact_sha256"])
            or not _DIGEST.fullmatch(selection["report_sha256"])):
        raise ValueError("Runtime active model has invalid digests")
    directory = root / expected_name
    _regular(directory, root.resolve(), directory=True)
    for filename in _ARTIFACTS:
        _regular(directory / filename, root.resolve())
    _validate_registry(directory, selection)
    return selection


def initialize_runtime_model(data_directory: Path, project_root: Path) -> dict:
    """Copy only active + four model JSONs if the target registry is absent.

    A missing release registry is reported explicitly to the launcher. An invalid
    registry fails initialization. Existing target registries are never altered.
    """
    data = data_directory.resolve()
    project = project_root.resolve()
    source = project / "runtime" / "models"
    target = data / "models"
    if target == source:
        return {"status": "existing" if (target / "active.json").is_file() else "source_missing", "model": None}
    with RuntimeLock(data):
        if os.path.lexists(target):
            return {"status": "existing" if (target / "active.json").is_file() else "existing_without_active", "model": None}
        if not os.path.lexists(source):
            return {"status": "source_missing", "model": None}
        _regular(source.parent, project, directory=True)
        _regular(source, project, directory=True)
        pointer = source / "active.json"
        _regular(pointer, source.resolve())
        selection = read_json(pointer, limit=8192)
        if (set(selection) != {"name", "artifact_sha256", "report_sha256"}
                or not isinstance(selection.get("name"), str)
                or not MODEL_NAME.fullmatch(selection["name"])
                or selection["name"] in {"active", "legacy"}
                or any(not isinstance(selection[key], str) or not _DIGEST.fullmatch(selection[key])
                       for key in ("artifact_sha256", "report_sha256"))):
            raise ValueError("Bundled active model pointer is invalid")
        source_model = source / selection["name"]
        _regular(source_model, source.resolve(), directory=True)
        # The temporary directory is created under the explicitly selected data
        # directory, contains only files we create, and never contains links.
        with tempfile.TemporaryDirectory(prefix=".model-init-", dir=data) as temporary:
            staging = Path(temporary) / "models"
            staged_model = staging / selection["name"]
            staged_model.mkdir(parents=True)
            for name, limit in _ARTIFACTS.items():
                original = source_model / name
                _regular(original, source.resolve())
                with original.open("rb") as source_file:
                    content = source_file.read(limit + 1)
                if len(content) > limit:
                    raise ValueError("Bundled model document exceeds its size limit")
                _write(staged_model / name, content)
            _validate_registry(staged_model, selection)
            # Publish the pointer only after validation, then publish the whole
            # registry together. A failed copy cannot expose a partial active model.
            _write(staging / "active.json", canonical(selection))
            if os.path.lexists(target):
                raise RuntimeError("Target model registry appeared during initialization")
            staging.rename(target)
        return {"status": "initialized", "model": selection["name"]}
