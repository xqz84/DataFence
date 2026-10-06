"""Offline, verified runtime snapshots. Restore only into a new empty directory."""

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import tempfile

from .runtime_lock import RuntimeLock
from .storage import now

MAX_TOTAL_BYTES = 10 * 1024**3
SKIP_NAMES = {".runtime.lock", "server.pid", "server-state.json"}


def _sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_target(root: Path, relative: str):
    part = PurePosixPath(relative)
    if part.is_absolute() or not part.parts or any(p in {"..", "."} or ":" in p or "\\" in p for p in part.parts):
        raise ValueError("Unsafe snapshot entry")
    target = root.joinpath(*part.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("Snapshot path escapes root")
    return target


def verify_snapshot(snapshot: Path):
    snapshot = snapshot.resolve()
    manifest_file = snapshot / "snapshot.json"
    if manifest_file.stat().st_size > 8 * 1024**2 or manifest_file.is_symlink():
        raise ValueError("Invalid snapshot manifest")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if manifest.get("format") != "datafence-offline-snapshot-v1" or not isinstance(manifest.get("files"), list):
        raise ValueError("Invalid snapshot format")
    seen, total = set(), 0
    for entry in manifest["files"]:
        relative = entry["path"]
        if relative in seen:
            raise ValueError("Duplicate snapshot entry")
        seen.add(relative)
        path = _safe_target(snapshot, relative)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or linked snapshot file")
        total += path.stat().st_size
        if total > MAX_TOTAL_BYTES or path.stat().st_size != entry["bytes"] or _sha(path) != entry["sha256"]:
            raise ValueError("Snapshot integrity check failed")
        if path.suffix == ".sqlite3":
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("SQLite snapshot is corrupt")
    return manifest


def backup(source: Path, destination: Path):
    source, destination = source.resolve(), destination.resolve()
    if not source.is_dir() or destination.exists() or destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError("Snapshot destination must be a new directory outside runtime")
    with RuntimeLock(source):
        # The same exclusive runtime lock is held throughout all DB snapshots:
        # cross-database quota/event state cannot change between copies.
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Stage on the same filesystem. A copy, quota or verification failure
        # must not leave an apparently usable snapshot at the requested path.
        with tempfile.TemporaryDirectory(prefix=".datafence-backup-", dir=destination.parent) as temporary:
            staging = Path(temporary) / "snapshot"
            staging.mkdir()
            files, total = [], 0
            for path in sorted(source.rglob("*")):
                if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()) or not path.resolve().is_relative_to(source):
                    raise ValueError("Runtime symlinks are not supported")
                if not path.is_file() or path.name in SKIP_NAMES or path.name.endswith(("-wal", "-shm", ".log")):
                    continue
                if total + path.stat().st_size > MAX_TOTAL_BYTES:
                    raise ValueError("Runtime exceeds snapshot size limit")
                relative = path.relative_to(source).as_posix()
                output = _safe_target(staging, relative)
                output.parent.mkdir(parents=True, exist_ok=True)
                if path.suffix == ".sqlite3":
                    src = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
                    dst = sqlite3.connect(output)
                    try:
                        src.backup(dst)
                    finally:
                        src.close()
                        dst.close()
                else:
                    shutil.copy2(path, output)
                total += output.stat().st_size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError("Runtime exceeds snapshot size limit")
                files.append(dict(path=relative, bytes=output.stat().st_size, sha256=_sha(output)))
            manifest = dict(format="datafence-offline-snapshot-v1", created_at=now(), files=files,
                            contains_credentials=True, sessions_restored=False,
                            notes=["Local SHA256 consistency, not an external signature.",
                                   "Windows DPAPI secrets require the same Windows identity; reconfigure on another host."])
            (staging / "snapshot.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            verify_snapshot(staging)
            if os.path.lexists(destination):
                raise ValueError("Snapshot destination appeared during backup; refusing to overwrite")
            staging.rename(destination)
    return dict(directory=str(destination), files=len(files), bytes=sum(x["bytes"] for x in files), verified=True)


def restore(snapshot: Path, destination: Path):
    snapshot, destination = snapshot.resolve(), destination.resolve()
    manifest = verify_snapshot(snapshot)
    if destination.exists() or destination.is_relative_to(snapshot) or snapshot.is_relative_to(destination):
        raise ValueError("Restore target must be a new directory; existing data are never overwritten")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".datafence-restore-", dir=destination.parent) as temporary:
        staging = Path(temporary) / "runtime"
        with RuntimeLock(staging):
            for entry in manifest["files"]:
                origin = _safe_target(snapshot, entry["path"])
                output = _safe_target(staging, entry["path"])
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(origin, output)
                if _sha(output) != entry["sha256"]:
                    raise ValueError("Restore copy failed integrity check")
            # Revoke sessions before publication. A failed restoration must never
            # expose old credentials or only part of the data/quota databases.
            auth = staging / "auth.sqlite3"
            if auth.exists():
                with closing(sqlite3.connect(auth)) as db, db:
                    names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if "auth_sessions" in names:
                        db.execute("DELETE FROM auth_sessions")
        if os.path.lexists(destination):
            raise ValueError("Restore destination appeared during copy; refusing to overwrite")
        staging.rename(destination)
    return dict(directory=str(destination), files=len(manifest["files"]), verified=True, sessions_revoked=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("backup", "restore"):
        command = sub.add_parser(name)
        command.add_argument("source", type=Path)
        command.add_argument("destination", type=Path)
    check = sub.add_parser("verify")
    check.add_argument("source", type=Path)
    args = parser.parse_args()
    if args.command == "backup":
        result = backup(args.source, args.destination)
    elif args.command == "restore":
        result = restore(args.source, args.destination)
    else:
        result = dict(verified=True, files=len(verify_snapshot(args.source)["files"]))
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
