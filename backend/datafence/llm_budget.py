"""Persistent daily request/token reservations, shared by server and evaluation.

The byte-based reservation is conservative, not a provider billing estimate.
Unknown timeout usage stays reserved; restarts cannot silently reset the budget.
"""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import threading
from uuid import uuid4


class BudgetUnavailable(RuntimeError):
    """Fixed diagnostic: never include database paths or underlying exceptions."""


class UnavailableBudget:
    """Fail closed when the durable ledger cannot be opened; never reset it."""

    def __init__(self, requests: int = 100, tokens: int = 200000):
        self.requests, self.tokens = requests, tokens

    def info(self):
        return dict(status="unavailable", reason_code="budget_unavailable",
                    date=datetime.now(timezone.utc).date().isoformat(), requests=None,
                    request_limit=self.requests, charged_tokens=None, reserved_tokens=None,
                    token_limit=self.tokens)

    def reserve(self, upper_tokens: int):
        raise BudgetUnavailable("budget_unavailable")

    def settle(self, ticket: str, total_tokens: int):
        raise BudgetUnavailable("budget_unavailable")


class CallBudget:
    def __init__(self, path: Path | None = None, requests: int = 100, tokens: int = 200000):
        self.requests, self.tokens = requests, tokens
        self._lock = threading.RLock()
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path) if path else ":memory:", check_same_thread=False, timeout=10)
        try:
            self._db.execute("CREATE TABLE IF NOT EXISTS calls (id TEXT PRIMARY KEY, day TEXT, reserved INTEGER, charged INTEGER)")
            self._db.commit()
        except Exception:
            self._db.close()
            raise

    def _day(self):
        return datetime.now(timezone.utc).date().isoformat()

    def _counts(self, day):
        return self._db.execute("SELECT COUNT(*), COALESCE(SUM(charged),0), COALESCE(SUM(CASE WHEN charged IS NULL THEN reserved ELSE 0 END),0) FROM calls WHERE day=?", (day,)).fetchone()

    def info(self):
        # Health must not queue behind a pending writer or wait ten seconds for
        # another process's SQLite lock. Unknown usage is not reported as zero.
        fallback = UnavailableBudget(self.requests, self.tokens).info()
        if not self._lock.acquire(blocking=False):
            return fallback
        try:
            self._db.execute("PRAGMA busy_timeout=0")
            day = self._day()
            count, charged, reserved = self._counts(day)
            return dict(status="available", date=day, requests=count, request_limit=self.requests,
                        charged_tokens=charged, reserved_tokens=reserved, token_limit=self.tokens)
        except sqlite3.Error:
            return fallback
        finally:
            try:
                self._db.execute("PRAGMA busy_timeout=10000")
            except sqlite3.Error:
                pass
            self._lock.release()

    def reserve(self, upper_tokens: int) -> str | None:
        if upper_tokens <= 0:
            raise ValueError("Reservation must be positive")
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                day = self._day()
                count, charged, reserved = self._counts(day)
                if count >= self.requests or charged + reserved + upper_tokens > self.tokens:
                    self._db.rollback()
                    return None
                ticket = str(uuid4())
                self._db.execute("INSERT INTO calls VALUES (?,?,?,NULL)", (ticket, day, upper_tokens))
                self._db.commit()
                return ticket
            except Exception:
                self._db.rollback()
                raise

    def settle(self, ticket: str, total_tokens: int):
        if isinstance(total_tokens, bool) or not isinstance(total_tokens, int) or total_tokens < 0:
            raise ValueError("Invalid token usage")
        with self._lock, self._db:
            self._db.execute("UPDATE calls SET charged=? WHERE id=? AND charged IS NULL", (total_tokens, ticket))
