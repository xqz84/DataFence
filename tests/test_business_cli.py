"""Exercise the real offline account CLI parser and existing bank catalog."""

import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest

from datafence.auth import AuthStore
from datafence.runtime_lock import RuntimeLock
from datafence.sandbox import build_bank
from datafence.storage import Store


PASSWORD = "offline-business-review-passphrase"


@pytest.fixture
def cli(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts" / "manage_users.py"
    spec = importlib.util.spec_from_file_location("business_cli_review", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(module.getpass, "getpass", lambda _: PASSWORD)
    return module


@pytest.fixture
def initialized(tmp_path):
    Store(tmp_path).initialize_bank(build_bank(customer_count=20))
    auth = AuthStore(tmp_path / "auth.sqlite3")
    auth.create_user("review.admin", PASSWORD, "admin")
    return auth


def test_cli_create_business_binding_is_real_and_password_not_printed(cli, initialized, capsys):
    result = cli.main(["--database", str(initialized.path), "create", "review.business", "--role", "business",
                       "--employee-id", "E0038"])
    assert result == 0
    output = capsys.readouterr()
    created = json.loads(output.out)
    assert created["role"] == "business" and created["employee_id"] == "E0038"
    assert PASSWORD not in output.out + output.err and "password_hash" not in output.out
    session = initialized.login("review.business", PASSWORD, "127.0.0.1")
    assert session["user"]["employee_id"] == "E0038"


def test_cli_bind_revokes_existing_business_session(cli, initialized, capsys):
    initialized.create_user("review.business", PASSWORD, "business", employee_id="E0038")
    session = initialized.login("review.business", PASSWORD, "127.0.0.1")
    assert cli.main(["--database", str(initialized.path), "bind", "review.business", "E0039"]) == 0
    assert json.loads(capsys.readouterr().out)["employee_id"] == "E0039"
    assert initialized.authenticate(session["token"]) is None


def test_cli_missing_bank_refuses_without_generating_bank_or_auth(cli, tmp_path, capsys):
    assert cli.main(["--database", str(tmp_path / "auth.sqlite3"), "create", "review.business", "--role", "business",
                     "--employee-id", "E0038"]) == 2
    assert "employee_catalog_unavailable" in capsys.readouterr().err
    assert not (tmp_path / "datafence.sqlite3").exists()
    assert not (tmp_path / "auth.sqlite3").exists()


@pytest.mark.parametrize("target", ["E0000", "E0101", "E0038 ", "e0038", "E００３８"])
def test_cli_invalid_binding_refuses_before_account_or_password_work(cli, initialized, monkeypatch, capsys, target):
    def forbidden_password(_):
        pytest.fail("invalid binding must be rejected before asking for a password")
    monkeypatch.setattr(cli.getpass, "getpass", forbidden_password)
    assert cli.main(["--database", str(initialized.path), "create", "review.business", "--role", "business",
                     "--employee-id", target]) == 2
    assert "invalid_employee_id" in capsys.readouterr().err
    assert len(initialized.list_users()) == 1


def test_cli_missing_employee_in_existing_catalog_does_not_rebind(cli, initialized, capsys):
    initialized.create_user("review.business", PASSWORD, "business", employee_id="E0038")
    session = initialized.login("review.business", PASSWORD, "127.0.0.1")
    with sqlite3.connect(initialized.path.parent / "datafence.sqlite3") as db:
        db.execute("DELETE FROM bank WHERE kind='employees' AND id='E0039'")
    assert cli.main(["--database", str(initialized.path), "bind", "review.business", "E0039"]) == 2
    assert "unknown_employee" in capsys.readouterr().err
    assert initialized.authenticate(session["token"])["user"]["employee_id"] == "E0038"


def test_cli_corrupt_employee_catalog_refuses_without_account_changes(cli, initialized, capsys):
    with sqlite3.connect(initialized.path.parent / "datafence.sqlite3") as db:
        db.execute("UPDATE bank SET payload='not-json' WHERE kind='employees' AND id='E0038'")
    assert cli.main(["--database", str(initialized.path), "create", "review.business", "--role", "business",
                     "--employee-id", "E0038"]) == 2
    assert "employee_catalog_unavailable" in capsys.readouterr().err
    assert len(initialized.list_users()) == 1


def test_cli_bind_refuses_while_runtime_is_owned(cli, initialized, capsys):
    initialized.create_user("review.business", PASSWORD, "business", employee_id="E0038")
    session = initialized.login("review.business", PASSWORD, "127.0.0.1")
    with RuntimeLock(initialized.path.parent):
        assert cli.main(["--database", str(initialized.path), "bind", "review.business", "E0039"]) == 3
    assert "stop the service" in capsys.readouterr().err
    assert initialized.authenticate(session["token"])["user"]["employee_id"] == "E0038"


def test_cli_existing_viewer_can_be_bound_then_promoted(cli, initialized, capsys):
    initialized.create_user("review.viewer", PASSWORD, "viewer")
    assert cli.main(["--database", str(initialized.path), "bind", "review.viewer", "E0038"]) == 0
    assert cli.main(["--database", str(initialized.path), "role", "review.viewer", "business"]) == 0
    capsys.readouterr()
    assert initialized.login("review.viewer", PASSWORD, "127.0.0.1")["user"]["employee_id"] == "E0038"
