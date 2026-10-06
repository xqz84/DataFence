"""Create an allowlisted Windows source+web+trained-model release without secrets."""

import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(output: Path):
    if output.exists():
        raise ValueError("Release output already exists; select a new filename")
    files = {}
    for path in ROOT.glob("*.md"):
        files[path.relative_to(ROOT).as_posix()] = path
    for name in ("pyproject.toml", "requirements.txt", "requirements.lock.txt", ".env.example", ".gitignore"):
        files[name] = ROOT / name
    for folder, suffixes in (("backend", {".py"}), ("scripts", {".py", ".ps1"}), ("tests", {".py"}),
                             ("frontend/src", {".ts", ".tsx", ".css"}), ("frontend/dist", {".html", ".js", ".css", ".svg"})):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and path.suffix in suffixes and "__pycache__" not in path.parts:
                files[path.relative_to(ROOT).as_posix()] = path
    for path in (ROOT / "frontend").iterdir():
        if path.is_file() and path.suffix in {".json", ".ts", ".html"}:
            files[path.relative_to(ROOT).as_posix()] = path
    for path in (ROOT / "frontend" / "public").glob("*"):
        if path.is_file() and path.suffix == ".svg":
            files[path.relative_to(ROOT).as_posix()] = path
    pointer = ROOT / "runtime/models/active.json"
    model_name = json.loads(pointer.read_text())["name"]
    from datafence.model_artifacts import MODEL_NAME
    if not MODEL_NAME.fullmatch(model_name):
        raise ValueError("Invalid model registry name")
    files["runtime/models/active.json"] = pointer
    for name in ("model.json", "report.json", "protocol.json", "promotion.json"):
        key = f"runtime/models/{model_name}/{name}"
        files[key] = ROOT / key
    # Explicitly exclude every database, DPAPI/PEM secret, run, cloud configuration,
    # CERT archive, session, local test account, private log and arbitrary runtime file.
    if not (ROOT / "frontend/dist/index.html").is_file():
        raise ValueError("Build the frontend before packaging")
    manifest = {"format": "datafence-windows-release-v1", "contains_credentials": False,
                "contains_public_source_rows": False, "model": model_name, "files": []}
    payloads = []
    for name, path in sorted(files.items()):
        if not path.is_file() or path.is_symlink():
            raise ValueError("Missing or linked release input: " + name)
        content = path.read_bytes()
        manifest["files"].append({"path": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
        payloads.append((name, content))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, content in payloads:
            archive.writestr(name, content)
        archive.writestr("RELEASE_MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    with zipfile.ZipFile(output) as archive:
        for item in manifest["files"]:
            if hashlib.sha256(archive.read(item["path"])).hexdigest() != item["sha256"]:
                raise ValueError("Release verification failed")
    return {"archive": str(output.resolve()), "files": len(files), "bytes": output.stat().st_size,
            "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "verified": True,
            "credentials_included": False, "trained_model": model_name}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    print(json.dumps(build(parser.parse_args().output), ensure_ascii=True, indent=2))
