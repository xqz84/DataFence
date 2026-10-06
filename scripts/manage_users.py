"""Trusted local operator CLI. Passwords are read from a terminal, never argv/env."""

import argparse
import getpass
import json
from pathlib import Path
import re
import sqlite3
import sys
import warnings

from datafence.auth import AuthError, AuthStore, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, ROLES
from datafence.models import Employee
from datafence.runtime_lock import RuntimeLock


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unknown arguments, potentially including an
        # accidentally supplied --password value. Never reflect argv here.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid command-line arguments; use --help. Passwords must be entered interactively.\n")


def _new_password() -> str:
    if not sys.stdin.isatty():
        raise AuthError("interactive_terminal_required")
    with warnings.catch_warnings():
        # getpass must never silently fall back to an echoed input stream.
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass(f"New password ({MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters): ")
            confirm = getpass.getpass("Confirm password: ")
        except (getpass.GetPassWarning, EOFError):
            raise AuthError("secure_password_input_unavailable") from None
    if password != confirm:
        raise AuthError("password_confirmation_mismatch")
    return password


def _verified_employee(database: Path, employee_id: str) -> str:
    """Resolve an explicit grant against the existing, adjacent bank catalog.

    Never initialize a bank just to make a binding pass. The shared RuntimeLock
    is already owned by main while checking this catalog and changing accounts.
    """
    if not re.fullmatch(r"E[0-9]{4}", employee_id) or not 1 <= int(employee_id[1:]) <= 100:
        raise AuthError("invalid_employee_id")
    bank_path = database.resolve().parent / "datafence.sqlite3"
    if not bank_path.is_file():
        raise AuthError("employee_catalog_unavailable")
    db = None
    try:
        # Read-only mode also prevents creating an empty SQLite file if the
        # catalog disappears between the file check and this connection.
        db = sqlite3.connect(bank_path.as_uri() + "?mode=ro", uri=True, timeout=5)
        manifest = db.execute("SELECT payload FROM meta WHERE key='manifest'").fetchone()
        if not manifest or json.loads(manifest[0]).get("synthetic") is not True:
            raise AuthError("employee_catalog_unavailable")
        row = db.execute("SELECT payload FROM bank WHERE kind='employees' AND id=?", (employee_id,)).fetchone()
        if row is None:
            raise AuthError("unknown_employee")
        employee = Employee.model_validate_json(row[0])
        if employee.id != employee_id:
            raise AuthError("employee_catalog_unavailable")
    except (sqlite3.Error, ValueError, TypeError, AttributeError) as error:
        if isinstance(error, AuthError):
            raise
        raise AuthError("employee_catalog_unavailable") from None
    finally:
        if db is not None:
            db.close()
    return employee_id


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--database", type=Path, default=PROJECT_ROOT / "runtime" / "auth.sqlite3",
                        help="Local operator-selected authentication DB; defaults to runtime/auth.sqlite3")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Create an account; the first account must be admin")
    create.add_argument("username")
    create.add_argument("--role", choices=sorted(ROLES), default="viewer")
    create.add_argument("--employee-id", help="Existing synthetic employee in the adjacent datafence.sqlite3; required for business")
    commands.add_parser("list", help="List public account fields only")
    for name in ("disable", "enable", "passwd"):
        command = commands.add_parser(name)
        command.add_argument("username")
    role = commands.add_parser("role", help="Change role and revoke existing sessions")
    role.add_argument("username")
    role.add_argument("role", choices=sorted(ROLES))
    bind = commands.add_parser("bind", help="Bind to an existing bank employee and revoke existing sessions")
    bind.add_argument("username")
    bind.add_argument("employee_id")
    args = parser.parse_args(argv)
    try:
        # Share ownership with the server and offline snapshot maintenance.
        # CLI changes require the service to be stopped; running deployments
        # use the authenticated administrator API instead.
        with RuntimeLock(args.database.resolve().parent):
            if args.command == "create" and args.role == "business" and args.employee_id is None:
                raise AuthError("employee_binding_required")
            if args.command in {"create", "bind"} and args.employee_id is not None:
                _verified_employee(args.database, args.employee_id)
            password = _new_password() if args.command in {"create", "passwd"} else None
            store = AuthStore(args.database)
            if args.command == "create":
                result = store.create_user(args.username, password, args.role, employee_id=args.employee_id)
            elif args.command == "list":
                result = store.list_users()
            elif args.command in {"disable", "enable"}:
                result = store.set_enabled(args.username, args.command == "enable")
            elif args.command == "passwd":
                result = store.set_password(args.username, password)
            elif args.command == "bind":
                result = store.set_employee_id(args.username, args.employee_id)
            else:
                result = store.set_role(args.username, args.role)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except AuthError as error:
        print(f"Account operation refused: {error.code}", file=sys.stderr)
        return 2
    except (sqlite3.Error, OSError, RuntimeError):
        print("Account database unavailable or in use; stop the service and maintenance tasks before using this CLI.", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("Account operation cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
