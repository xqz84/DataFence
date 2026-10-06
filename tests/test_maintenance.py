import json
import os
import sqlite3

import pytest

from datafence.auth import AuthStore
from datafence.maintenance import backup, restore, verify_snapshot
from datafence.runtime_lock import RuntimeLock


def test_lock_excludes_other_owner_and_releases(tmp_path):
    with RuntimeLock(tmp_path):
        with pytest.raises(RuntimeError):
            RuntimeLock(tmp_path)
    with RuntimeLock(tmp_path):
        pass


def test_consistent_backup_restore_revokes_sessions(tmp_path):
    source, snapshot, target = tmp_path / "runtime", tmp_path / "backup", tmp_path / "restored"
    source.mkdir()
    auth = AuthStore(source / "auth.sqlite3")
    auth.create_user("admin", "a-long-private-test-password", "admin")
    session = auth.login("admin", "a-long-private-test-password", "127.0.0.1")
    with sqlite3.connect(source / "example.sqlite3") as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE data(value TEXT)")
        db.execute("INSERT INTO data VALUES('kept')")
    (source / "model.json").write_text('{"kept":true}', encoding="utf-8")
    result = backup(source, snapshot)
    assert result["verified"]
    assert verify_snapshot(snapshot)["format"].endswith("v1")
    restored = restore(snapshot, target)
    assert restored["sessions_revoked"]
    restored_auth = AuthStore(target / "auth.sqlite3")
    assert restored_auth.authenticate(session["token"]) is None
    assert restored_auth.login("admin", "a-long-private-test-password", "127.0.0.2")["user"]["role"] == "admin"
    with sqlite3.connect(target / "example.sqlite3") as db:
        assert db.execute("SELECT value FROM data").fetchone()[0] == "kept"
    assert (target / "model.json").read_bytes() == (source / "model.json").read_bytes()
    with pytest.raises(ValueError): restore(snapshot, source)


def test_backup_requires_stopped_runtime_and_rejects_tampering(tmp_path):
    source, snapshot = tmp_path / "runtime", tmp_path / "backup"
    source.mkdir()
    (source / "data.json").write_text("kept")
    with RuntimeLock(source):
        with pytest.raises(RuntimeError): backup(source, snapshot)
    assert not snapshot.exists()
    backup(source, snapshot)
    (snapshot / "data.json").write_text("changed")
    with pytest.raises(ValueError): restore(snapshot, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_restore_rejects_path_escape(tmp_path):
    source, snapshot = tmp_path / "runtime", tmp_path / "backup"
    source.mkdir()
    (source / "data.json").write_text("kept")
    backup(source, snapshot)
    path = snapshot / "snapshot.json"
    manifest = json.loads(path.read_text())
    manifest["files"][0]["path"] = "../escape"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError): verify_snapshot(snapshot)


@pytest.mark.parametrize("operation", ["backup", "restore"])
def test_interrupted_copy_never_publishes_partial_directory(tmp_path, monkeypatch, operation):
    import shutil

    source, snapshot, target = tmp_path / "source", tmp_path / "snapshot", tmp_path / "target"
    source.mkdir()
    (source / "a-data.json").write_text('{"records": 5}')
    (source / "b-quota.json").write_text('{"consumed": 5}')
    if operation == "restore":
        backup(source, snapshot)
    original_copy = shutil.copy2

    def fail_second(origin, destination, *args, **kwargs):
        if origin.name == "b-quota.json":
            raise OSError("Injected full disk")
        return original_copy(origin, destination, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr("datafence.maintenance.shutil.copy2", fail_second)
        with pytest.raises(OSError, match="full disk"):
            (backup if operation == "backup" else restore)(source if operation == "backup" else snapshot, target)
    assert not target.exists()
    assert (source / "b-quota.json").read_text() == '{"consumed": 5}'
    assert not list(tmp_path.glob(".datafence-*"))
    # The same requested path remains usable after fixing the storage fault.
    result = (backup if operation == "backup" else restore)(source if operation == "backup" else snapshot, target)
    assert result["verified"]
    assert (target / "a-data.json").is_file() and (target / "b-quota.json").is_file()


@pytest.mark.parametrize("operation", ["backup", "restore"])
def test_destination_created_during_copy_is_not_overwritten(tmp_path, monkeypatch, operation):
    import shutil

    source, snapshot, target = tmp_path / "source", tmp_path / "snapshot", tmp_path / "target"
    source.mkdir()
    (source / "data.json").write_text("original")
    if operation == "restore":
        backup(source, snapshot)
    original_copy = shutil.copy2

    def competing_destination(origin, destination, *args, **kwargs):
        target.mkdir(exist_ok=True)
        (target / "other-owner.txt").write_text("do not replace")
        return original_copy(origin, destination, *args, **kwargs)

    monkeypatch.setattr("datafence.maintenance.shutil.copy2", competing_destination)
    with pytest.raises(ValueError, match="appeared"):
        (backup if operation == "backup" else restore)(source if operation == "backup" else snapshot, target)
    assert (target / "other-owner.txt").read_text() == "do not replace"
    assert not (target / "data.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction boundary regression")
def test_windows_junction_cannot_copy_files_outside_runtime(tmp_path):
    import _winapi

    source, outside, snapshot = tmp_path / "runtime", tmp_path / "outside", tmp_path / "snapshot"
    source.mkdir()
    outside.mkdir()
    marker = outside / "synthetic-external-marker.txt"
    marker.write_text("synthetic fixture outside runtime", encoding="utf-8")
    junction = source / "outside-junction"
    assert source.resolve().parent == tmp_path.resolve()
    assert outside.resolve().parent == tmp_path.resolve()
    assert junction.parent.resolve() == source.resolve()
    # Native Windows junction creation, no shell and no administrator-only
    # symbolic-link permission. Both target and junction are controlled fixtures.
    _winapi.CreateJunction(str(outside), str(junction))
    try:
        assert junction.is_junction() and not junction.is_symlink()
        assert junction.resolve() == outside.resolve()
        with pytest.raises(ValueError, match="symlinks"):
            backup(source, snapshot)
        assert not (snapshot / "outside-junction" / marker.name).exists()
        assert marker.read_text(encoding="utf-8") == "synthetic fixture outside runtime"
    finally:
        # Remove only this verified reparse-point entry. Never call rmtree or
        # recursively delete/move through the junction's resolved target.
        assert junction.parent.resolve() == source.resolve()
        assert junction.is_junction() and junction.resolve() == outside.resolve()
        junction.rmdir()
    assert not junction.exists()
    assert outside.is_dir() and marker.read_text(encoding="utf-8") == "synthetic fixture outside runtime"
