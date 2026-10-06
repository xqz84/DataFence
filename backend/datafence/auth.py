"""Local account/session storage; HTTP cookies and route authorization live in API.

No automatic login, default account/password, credential logging, cloud access,
or path taken from HTTP input. All public user records use an explicit allowlist.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import math
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from typing import Callable
from uuid import uuid4


ROLES = frozenset({"admin", "analyst", "viewer", "business"})
MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128
SESSION_TTL_SECONDS = 8 * 60 * 60
LOGIN_WINDOW_SECONDS = 5 * 60
USERNAME_ATTEMPT_LIMIT = 5
IP_ATTEMPT_LIMIT = 30
SCRYPT_N, SCRYPT_R, SCRYPT_P = 32768, 8, 3
SCRYPT_MAXMEM = 64 * 1024 * 1024
_HASH_WORKERS = threading.BoundedSemaphore(4)
_USERNAME = re.compile(r"[a-z0-9][a-z0-9_.-]{2,63}")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_PASSWORD_HASH = re.compile(r"scrypt\$1\$32768\$8\$3\$([0-9a-f]{32})\$([0-9a-f]{128})")


class AuthError(ValueError):
    """Only a fixed code reaches callers; no passwords, token or database path."""

    def __init__(self, code: str, *, retry_after: int | None = None):
        self.code = code
        self.retry_after = retry_after
        super().__init__(code)


def _username(value: str) -> str:
    if not isinstance(value, str) or len(value) > 128:
        raise AuthError("invalid_input")
    result = value.strip().lower()
    if not _USERNAME.fullmatch(result):
        raise AuthError("invalid_input")
    return result


def _password_bytes(value: str) -> bytes:
    if not isinstance(value, str) or not MIN_PASSWORD_LENGTH <= len(value) <= MAX_PASSWORD_LENGTH:
        raise AuthError("invalid_password")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise AuthError("invalid_password") from None
    if len(encoded) > 512:
        raise AuthError("invalid_password")
    # Spaces and Unicode are preserved; passwords are never trimmed/truncated.
    return encoded


def _derive(password: bytes, salt: bytes) -> bytes:
    # Bound concurrent memory use within one server process, including CLI/API
    # account creation. Cross-process rate reservations are handled in SQLite.
    if not _HASH_WORKERS.acquire(timeout=1):
        raise AuthError("rate_limited", retry_after=1)
    try:
        return hashlib.scrypt(password, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                              maxmem=SCRYPT_MAXMEM, dklen=64)
    finally:
        _HASH_WORKERS.release()


def _hash_password(password: str) -> str:
    encoded = _password_bytes(password)
    salt = secrets.token_bytes(16)
    result = _derive(encoded, salt)
    return f"scrypt$1${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${result.hex()}"


def _verify_password(password: str, stored: str | None) -> bool:
    valid_password = True
    try:
        encoded = _password_bytes(password)
    except AuthError:
        valid_password, encoded = False, b"invalid supplied password"
    match = _PASSWORD_HASH.fullmatch(stored) if isinstance(stored, str) else None
    # Unknown/disabled users and malformed hashes still take one bounded scrypt
    # operation. DB content cannot select weak or unbounded KDF parameters.
    salt = bytes.fromhex(match[1]) if match else b"DataFence-dummy!!"
    expected = bytes.fromhex(match[2]) if match else bytes(64)
    candidate = _derive(encoded, salt)
    return hmac.compare_digest(candidate, expected) and match is not None and valid_password


def _iso(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _public(row) -> dict:
    return {"id": row["id"], "username": row["username"], "role": row["role"],
            "employee_id": row["employee_id"],
            "enabled": bool(row["enabled"]), "created_at": _iso(row["created_at"]),
            "updated_at": _iso(row["updated_at"])}


def _employee_id(value: str | None) -> str | None:
    # This sandbox has 100 stable employees. The HTTP boundary additionally
    # checks membership in the active bank; a free-form username is not a grant.
    if value is not None and (not isinstance(value, str) or not re.fullmatch(r"E[0-9]{4}", value)
                              or not 1 <= int(value[1:]) <= 100):
        raise AuthError("invalid_employee_id")
    return value


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _csrf(token: str) -> str:
    # Independent, domain-separated value. A CSRF response does not reveal the
    # HttpOnly session credential; the database stores neither raw value.
    return hmac.new(token.encode("ascii"), b"DataFence/session-csrf/v1", hashlib.sha256).hexdigest()


class AuthStore:
    def __init__(self, path: Path, session_ttl_seconds: int = SESSION_TTL_SECONDS,
                 *, clock: Callable[[], float] = time.time):
        if type(session_ttl_seconds) is not int or not 60 <= session_ttl_seconds <= 86400:
            raise AuthError("invalid_input")
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.session_ttl_seconds = session_ttl_seconds
        self._clock = clock
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS auth_users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer','business')),
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    auth_version INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    employee_id TEXT,
                    CHECK(role!='business' OR employee_id IS NOT NULL)
                );
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES auth_users(id),
                    auth_version INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
                );
                CREATE INDEX IF NOT EXISTS auth_session_user ON auth_sessions(user_id);
                CREATE INDEX IF NOT EXISTS auth_session_expiry ON auth_sessions(expires_at);
                CREATE TABLE IF NOT EXISTS auth_login_attempts (
                    id TEXT PRIMARY KEY,
                    username_bucket TEXT NOT NULL,
                    ip_bucket TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','failed','success'))
                );
                CREATE INDEX IF NOT EXISTS auth_attempt_username ON auth_login_attempts(username_bucket,created_at);
                CREATE INDEX IF NOT EXISTS auth_attempt_ip ON auth_login_attempts(ip_bucket,created_at);
            """)
        self._migrate_employee_binding()

    def _migrate_employee_binding(self) -> None:
        # SQLite cannot alter the old role CHECK. Rebuild only this table in one
        # serialized transaction, keeping IDs/hashes/versions and session FKs.
        # Foreign keys must be disabled *before* BEGIN to permit the replacement;
        # all links are checked before commit. A failure leaves the old DB intact.
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in db.execute("PRAGMA table_info(auth_users)")}
            schema = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='auth_users'").fetchone()[0]
            if "employee_id" not in columns or "'business'" not in schema:
                db.execute("""CREATE TABLE auth_users_employee_migration (
                    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer','business')),
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    auth_version INTEGER NOT NULL, created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL, employee_id TEXT,
                    CHECK(role!='business' OR employee_id IS NOT NULL))""")
                employee_column = "employee_id" if "employee_id" in columns else "NULL"
                db.execute(f"""INSERT INTO auth_users_employee_migration
                    (id,username,password_hash,role,enabled,auth_version,created_at,updated_at,employee_id)
                    SELECT id,username,password_hash,role,enabled,auth_version,created_at,updated_at,{employee_column}
                    FROM auth_users""")
                db.execute("DROP TABLE auth_users")
                db.execute("ALTER TABLE auth_users_employee_migration RENAME TO auth_users")
                if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise AuthError("auth_unavailable")
            db.execute("COMMIT")
        except Exception:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @contextmanager
    def _connect(self, *, write: bool = False):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if db.in_transaction:
                db.execute("COMMIT")
        except Exception:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def _now(self) -> int:
        value = self._clock()
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise AuthError("auth_unavailable")
        return int(value)

    def initialized(self) -> bool:
        with self._connect() as db:
            return db.execute("SELECT EXISTS(SELECT 1 FROM auth_users)").fetchone()[0] == 1

    def list_users(self) -> list[dict]:
        with self._connect() as db:
            return [_public(row) for row in db.execute("SELECT * FROM auth_users ORDER BY username")]

    def create_user(self, username: str, password: str, role: str = "viewer", *, require_uninitialized: bool = False,
                    employee_id: str | None = None) -> dict:
        username = _username(username)
        if not isinstance(role, str) or role not in ROLES or type(require_uninitialized) is not bool:
            raise AuthError("invalid_input")
        employee_id = _employee_id(employee_id)
        if role == "business" and employee_id is None:
            raise AuthError("employee_binding_required")
        password_hash = _hash_password(password)
        now = self._now()
        with self._connect(write=True) as db:
            initialized = bool(db.execute("SELECT EXISTS(SELECT 1 FROM auth_users)").fetchone()[0])
            if require_uninitialized and initialized:
                raise AuthError("already_initialized")
            if not initialized and role != "admin":
                raise AuthError("first_user_must_be_admin")
            if db.execute("SELECT 1 FROM auth_users WHERE username=?", (username,)).fetchone():
                raise AuthError("username_taken")
            user_id = str(uuid4())
            db.execute("""INSERT INTO auth_users
                       (id,username,password_hash,role,enabled,auth_version,created_at,updated_at,employee_id)
                       VALUES(?,?,?,?,1,1,?,?,?)""",
                       (user_id, username, password_hash, role, now, now, employee_id))
            return _public(db.execute("SELECT * FROM auth_users WHERE id=?", (user_id,)).fetchone())

    @staticmethod
    def _existing(db, username):
        row = db.execute("SELECT * FROM auth_users WHERE username=?", (username,)).fetchone()
        if row is None:
            raise AuthError("user_not_found")
        return row

    @staticmethod
    def _guard_last_admin(db, user, *, enabled: bool, role: str):
        if user["enabled"] and user["role"] == "admin" and (not enabled or role != "admin"):
            count = db.execute("SELECT COUNT(*) FROM auth_users WHERE enabled=1 AND role='admin'").fetchone()[0]
            if count <= 1:
                raise AuthError("last_admin_required")

    @staticmethod
    def _revoke_user(db, user_id):
        db.execute("UPDATE auth_sessions SET revoked=1 WHERE user_id=?", (user_id,))

    def set_enabled(self, username: str, enabled: bool) -> dict:
        username = _username(username)
        if type(enabled) is not bool:
            raise AuthError("invalid_input")
        with self._connect(write=True) as db:
            user = self._existing(db, username)
            self._guard_last_admin(db, user, enabled=enabled, role=user["role"])
            if bool(user["enabled"]) != enabled:
                db.execute("UPDATE auth_users SET enabled=?,auth_version=auth_version+1,updated_at=? WHERE id=?",
                           (int(enabled), self._now(), user["id"]))
                self._revoke_user(db, user["id"])
            return _public(self._existing(db, username))

    def set_role(self, username: str, role: str) -> dict:
        username = _username(username)
        if not isinstance(role, str) or role not in ROLES:
            raise AuthError("invalid_input")
        with self._connect(write=True) as db:
            user = self._existing(db, username)
            if role == "business" and _employee_id(user["employee_id"]) is None:
                raise AuthError("employee_binding_required")
            self._guard_last_admin(db, user, enabled=bool(user["enabled"]), role=role)
            if role != user["role"]:
                db.execute("UPDATE auth_users SET role=?,auth_version=auth_version+1,updated_at=? WHERE id=?",
                           (role, self._now(), user["id"]))
                self._revoke_user(db, user["id"])
            return _public(self._existing(db, username))

    def set_employee_id(self, username: str, employee_id: str | None) -> dict:
        username = _username(username)
        employee_id = _employee_id(employee_id)
        with self._connect(write=True) as db:
            user = self._existing(db, username)
            if user["role"] == "business" and employee_id is None:
                raise AuthError("employee_binding_required")
            if employee_id != user["employee_id"]:
                db.execute("UPDATE auth_users SET employee_id=?,auth_version=auth_version+1,updated_at=? WHERE id=?",
                           (employee_id, self._now(), user["id"]))
                self._revoke_user(db, user["id"])
            return _public(self._existing(db, username))

    def set_password(self, username: str, password: str) -> dict:
        username = _username(username)
        password_hash = _hash_password(password)
        with self._connect(write=True) as db:
            user = self._existing(db, username)
            db.execute("UPDATE auth_users SET password_hash=?,auth_version=auth_version+1,updated_at=? WHERE id=?",
                       (password_hash, self._now(), user["id"]))
            self._revoke_user(db, user["id"])
            return _public(self._existing(db, username))

    def _reserve_attempt(self, username: str, client_ip: str, now: int) -> tuple[str, sqlite3.Row | None]:
        if not isinstance(client_ip, str) or len(client_ip) > 64:
            raise AuthError("invalid_input")
        try:
            address = ipaddress.ip_address(client_ip)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            ip_bucket = _digest("ip:" + address.compressed)
        except (TypeError, ValueError, UnicodeError):
            raise AuthError("invalid_input") from None
        username_bucket = _digest("username:" + username)
        cutoff = now - LOGIN_WINDOW_SECONDS
        with self._connect(write=True) as db:
            # Pending attempts count before slow hashing; a concurrent batch
            # cannot all observe the same unconsumed quota. Crashes remain
            # conservative until this fixed window expires.
            db.execute("DELETE FROM auth_login_attempts WHERE created_at<=?", (cutoff,))
            user_attempts = db.execute("SELECT COUNT(*),MIN(created_at) FROM auth_login_attempts WHERE username_bucket=? AND state!='success'",
                                       (username_bucket,)).fetchone()
            ip_attempts = db.execute("SELECT COUNT(*),MIN(created_at) FROM auth_login_attempts WHERE ip_bucket=?",
                                     (ip_bucket,)).fetchone()
            waits = [first + LOGIN_WINDOW_SECONDS - now for (count, first), limit in
                     ((user_attempts, USERNAME_ATTEMPT_LIMIT), (ip_attempts, IP_ATTEMPT_LIMIT)) if count >= limit]
            if waits:
                raise AuthError("rate_limited", retry_after=max(1, max(waits)))
            attempt_id = str(uuid4())
            db.execute("INSERT INTO auth_login_attempts VALUES(?,?,?,?,'pending')",
                       (attempt_id, username_bucket, ip_bucket, now))
            user = db.execute("SELECT * FROM auth_users WHERE username=?", (username,)).fetchone()
            return attempt_id, user

    def login(self, username: str, password: str, client_ip: str) -> dict:
        try:
            username = _username(username)
        except AuthError:
            # All malformed usernames share an intentionally constrained bucket;
            # still charge IP attempts and perform dummy work to avoid enumeration.
            username = "<invalid>"
        attempt_id, user = self._reserve_attempt(username, client_ip, self._now())
        verified = _verify_password(password, user["password_hash"] if user else None)
        token = secrets.token_urlsafe(32)
        now = self._now()
        session = None
        with self._connect(write=True) as db:
            current = db.execute("SELECT * FROM auth_users WHERE id=?", (user["id"],)).fetchone() if user else None
            # Recheck inside the committing transaction so a concurrent password
            # reset, role change or disable cannot mint a stale authorized session.
            accepted = bool(verified and current and current["enabled"] and user
                            and current["auth_version"] == user["auth_version"])
            db.execute("UPDATE auth_login_attempts SET state=? WHERE id=?",
                       ("success" if accepted else "failed", attempt_id))
            if accepted:
                expires = now + self.session_ttl_seconds
                db.execute("DELETE FROM auth_sessions WHERE expires_at<=?", (now,))
                db.execute("INSERT INTO auth_sessions VALUES(?,?,?,?,?,0)",
                           (_digest(token), current["id"], current["auth_version"], now, expires))
                session = {"token": token, "csrf_token": _csrf(token), "user": _public(current),
                           "expires_at": _iso(expires), "expires_unix": expires}
        if session is None:
            raise AuthError("invalid_credentials")
        return session

    def authenticate(self, token: str | None) -> dict | None:
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            return None
        with self._connect() as db:
            row = db.execute("""SELECT u.*,s.expires_at AS session_expires FROM auth_sessions AS s
                                JOIN auth_users AS u ON u.id=s.user_id
                                WHERE s.token_hash=? AND s.revoked=0 AND s.expires_at>?
                                  AND u.enabled=1 AND u.auth_version=s.auth_version""",
                             (_digest(token), self._now())).fetchone()
        if row is None:
            return None
        return {"user": _public(row), "csrf_token": _csrf(token),
                "expires_at": _iso(row["session_expires"]), "expires_unix": row["session_expires"]}

    def verify_csrf(self, token: str | None, csrf_token: str | None) -> bool:
        if not isinstance(csrf_token, str) or not re.fullmatch(r"[0-9a-f]{64}", csrf_token):
            return False
        session = self.authenticate(token)
        return session is not None and hmac.compare_digest(session["csrf_token"], csrf_token)

    def logout(self, token: str | None) -> None:
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            return
        with self._connect(write=True) as db:
            db.execute("UPDATE auth_sessions SET revoked=1 WHERE token_hash=?", (_digest(token),))
