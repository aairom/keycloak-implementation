"""Persistence layer of the log dashboard: PostgreSQL in the stack, SQLite for tests and quick local runs.

All timestamps are stored as epoch milliseconds (BIGINT), the same unit Keycloak uses for ``event_time``,
so no time zone conversions are needed in SQL. SQL is written once with ``?`` placeholders and translated
for psycopg (``%s``).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator

DAY_MS = 86_400_000

_COLUMNS = ("ts", "source", "kind", "event_type", "username", "user_id", "client_id", "session_id", "ip",
            "method", "path", "status", "duration_ms", "error", "detail", "dedupe_key")


def _ddl(postgres: bool) -> list[str]:
    pk = "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY" if postgres else "INTEGER PRIMARY KEY AUTOINCREMENT"
    return [
        # Every observable event: HTTP access, auth, token lifecycle, service-to-service, Keycloak events.
        f"""CREATE TABLE IF NOT EXISTS app_events (
            id {pk}, ts BIGINT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, event_type TEXT NOT NULL,
            username TEXT, user_id TEXT, client_id TEXT, session_id TEXT, ip TEXT,
            method TEXT, path TEXT, status INTEGER, duration_ms INTEGER, error TEXT, detail TEXT,
            dedupe_key TEXT UNIQUE)""",
        "CREATE INDEX IF NOT EXISTS ix_events_ts ON app_events (ts)",
        "CREATE INDEX IF NOT EXISTS ix_events_type ON app_events (event_type)",
        "CREATE INDEX IF NOT EXISTS ix_events_user ON app_events (username)",
        # One row per login of this application (token material is NOT stored here).
        """CREATE TABLE IF NOT EXISTS user_sessions (
            sid TEXT PRIMARY KEY, username TEXT, user_id TEXT, kc_session_id TEXT, roles TEXT, ip TEXT,
            login_at BIGINT NOT NULL, last_seen_at BIGINT NOT NULL, access_expires_at BIGINT,
            refreshes INTEGER NOT NULL DEFAULT 0, logout_at BIGINT, end_reason TEXT)""",
        "CREATE INDEX IF NOT EXISTS ix_sessions_user ON user_sessions (username)",
        # Who looked at / did what in the admin area of this application.
        f"""CREATE TABLE IF NOT EXISTS audit_log (
            id {pk}, ts BIGINT NOT NULL, actor TEXT, action TEXT NOT NULL, target TEXT, ip TEXT,
            outcome TEXT NOT NULL)""",
        "CREATE TABLE IF NOT EXISTS sync_state (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
    ]


def dedupe_key(*parts: Any) -> str:
    """Stable identity of an upstream event (Keycloak's REST events have no id)."""
    return hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()[:40]


class Store:
    """Thin DB-API wrapper. ``url`` is ``postgresql://...`` or ``sqlite:///relative.db`` / ``sqlite:///:memory:``."""

    def __init__(self, url: str, schema: str = "logapp"):
        self.postgres = url.startswith(("postgresql:", "postgres:"))
        self.url, self.schema = url, schema
        self._memory = None
        self._memory_lock = threading.RLock()  # the single in-memory connection is shared by all threads
        if not self.postgres:
            # SQLAlchemy convention: sqlite:///rel.db, sqlite:////abs/path.db, sqlite:///:memory:
            path = url[len("sqlite://"):][1:] if url.startswith("sqlite://") else url
            self.path = ":memory:" if path in ("", ":memory:") else path
            if self.path == ":memory:":  # one shared connection, otherwise every connect() is a new DB
                self._memory = sqlite3.connect(":memory:", check_same_thread=False)

    # ---- connection handling -------------------------------------------------------------------
    @contextmanager
    def _conn(self) -> Iterator[Any]:
        if self.postgres:
            import psycopg
            conn = psycopg.connect(self.url, connect_timeout=5, options=f"-csearch_path={self.schema}")
        else:
            conn = self._memory or sqlite3.connect(self.path, timeout=10)
        lock = self._memory_lock if conn is self._memory else None
        if lock:
            lock.acquire()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if lock:
                lock.release()
            else:
                conn.close()

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.postgres else sql

    def _exec(self, sql: str, params: tuple = ()) -> None:
        with self._conn() as c:
            c.execute(self._sql(sql), params)

    def _all(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._conn() as c:
            cur = c.execute(self._sql(sql), params)
            names = [d[0] for d in cur.description]
            return [dict(zip(names, row)) for row in cur.fetchall()]

    def _one(self, sql: str, params: tuple = ()) -> Any:
        rows = self._all(sql, params)
        return next(iter(rows[0].values())) if rows else None

    def init_schema(self) -> None:
        if self.postgres:
            import psycopg
            with psycopg.connect(self.url, connect_timeout=5, autocommit=True) as c:
                c.execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
        for stmt in _ddl(self.postgres):
            self._exec(stmt)

    def ping(self) -> bool:
        try:
            return self._one("SELECT 1") == 1
        except Exception:
            return False

    # ---- events --------------------------------------------------------------------------------
    def add_event(self, *, event_type: str, kind: str, source: str = "app", ts: int | None = None,
                  detail: dict | None = None, **fields: Any) -> bool:
        """Insert one event; returns False when an event with the same ``dedupe_key`` already exists."""
        unknown = set(fields) - set(_COLUMNS)
        if unknown:
            raise ValueError(f"unknown event fields: {sorted(unknown)}")
        row = {c: None for c in _COLUMNS}
        row.update(fields, ts=ts if ts is not None else int(time.time() * 1000), source=source, kind=kind,
                   event_type=event_type, detail=json.dumps(detail, sort_keys=True) if detail else None)
        cols = ", ".join(_COLUMNS)
        marks = ", ".join("?" for _ in _COLUMNS)
        with self._conn() as c:
            cur = c.execute(self._sql(f"INSERT INTO app_events ({cols}) VALUES ({marks}) "
                                      "ON CONFLICT (dedupe_key) DO NOTHING"),
                            tuple(row[k] for k in _COLUMNS))
            return cur.rowcount == 1

    @staticmethod
    def _where(f: dict) -> tuple[str, list]:
        clauses, params = [], []
        if f.get("username_exact"):
            clauses.append("username = ?")
            params.append(f["username_exact"])
        if f.get("username"):
            clauses.append("LOWER(username) LIKE ?")
            params.append(f"%{f['username'].lower()}%")
        for column in ("event_type", "kind", "source"):
            if f.get(column):
                clauses.append(f"{column} = ?")
                params.append(f[column])
        if f.get("date_from") is not None:
            clauses.append("ts >= ?")
            params.append(int(f["date_from"]))
        if f.get("date_to") is not None:
            clauses.append("ts < ?")
            params.append(int(f["date_to"]))
        status = f.get("status")
        if status:  # "404" exact, "4xx" class
            if len(status) == 3 and status[1:].lower() == "xx" and status[0].isdigit():
                clauses.append("status >= ? AND status < ?")
                params += [int(status[0]) * 100, int(status[0]) * 100 + 100]
            elif status.isdigit():
                clauses.append("status = ?")
                params.append(int(status))
        if f.get("q"):
            clauses.append("(LOWER(COALESCE(path,'')) LIKE ? OR LOWER(COALESCE(error,'')) LIKE ?)")
            params += [f"%{f['q'].lower()}%"] * 2
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    def query_events(self, filters: dict, page: int = 1, page_size: int = 25) -> tuple[list[dict], int]:
        where, params = self._where(filters)
        total = self._one(f"SELECT COUNT(*) FROM app_events{where}", tuple(params)) or 0
        page = max(1, page)
        rows = self._all(f"SELECT * FROM app_events{where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
                         tuple(params) + (page_size, (page - 1) * page_size))
        return rows, int(total)

    def event_types(self) -> list[str]:
        return [r["event_type"] for r in self._all("SELECT DISTINCT event_type FROM app_events ORDER BY 1")]

    # ---- sessions ------------------------------------------------------------------------------
    def start_session(self, sid: str, *, username: str, user_id: str | None, kc_session_id: str | None,
                      roles: list[str], ip: str | None, access_expires_at: int | None, now: int) -> None:
        self._exec("INSERT INTO user_sessions (sid, username, user_id, kc_session_id, roles, ip, login_at, "
                   "last_seen_at, access_expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                   (sid, username, user_id, kc_session_id, ",".join(roles), ip, now, now, access_expires_at))

    def touch_session(self, sid: str, now: int, access_expires_at: int | None = None,
                      refreshed: bool = False) -> None:
        self._exec("UPDATE user_sessions SET last_seen_at = ?, access_expires_at = COALESCE(?, access_expires_at), "
                   "refreshes = refreshes + ? WHERE sid = ? AND logout_at IS NULL",
                   (now, access_expires_at, 1 if refreshed else 0, sid))

    def end_session(self, sid: str, now: int, reason: str) -> None:
        self._exec("UPDATE user_sessions SET logout_at = ?, end_reason = ? WHERE sid = ? AND logout_at IS NULL",
                   (now, reason, sid))

    def get_session(self, sid: str) -> dict | None:
        rows = self._all("SELECT * FROM user_sessions WHERE sid = ?", (sid,))
        return rows[0] if rows else None

    def username_for_user_id(self, user_id: str) -> str | None:
        return self._one("SELECT username FROM app_events WHERE user_id = ? AND username IS NOT NULL "
                         "ORDER BY ts DESC LIMIT 1", (user_id,))

    def recent_sessions(self, limit: int = 10) -> list[dict]:
        return self._all("SELECT * FROM user_sessions ORDER BY login_at DESC LIMIT ?", (limit,))

    # ---- audit log -----------------------------------------------------------------------------
    def audit(self, actor: str | None, action: str, outcome: str, target: str | None = None,
              ip: str | None = None, now: int | None = None) -> None:
        self._exec("INSERT INTO audit_log (ts, actor, action, target, ip, outcome) VALUES (?,?,?,?,?,?)",
                   (now if now is not None else int(time.time() * 1000), actor, action, target, ip, outcome))

    def recent_audit(self, limit: int = 15) -> list[dict]:
        return self._all("SELECT * FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?", (limit,))

    # ---- sync state ----------------------------------------------------------------------------
    def get_state(self, name: str, default: str | None = None) -> str | None:
        value = self._one("SELECT value FROM sync_state WHERE name = ?", (name,))
        return default if value is None else value

    def set_state(self, name: str, value: str) -> None:
        self._exec("INSERT INTO sync_state (name, value) VALUES (?, ?) "
                   "ON CONFLICT (name) DO UPDATE SET value = excluded.value", (name, value))

    # ---- statistics ----------------------------------------------------------------------------
    def stats(self, since_ms: int, now_ms: int, idle_ms: int, days: int = 7) -> dict:
        def count(extra: str) -> int:
            return int(self._one(f"SELECT COUNT(*) FROM app_events WHERE ts >= ? AND {extra}", (since_ms,)) or 0)

        kc = "source = 'keycloak'"
        top = self._all("SELECT username, COUNT(*) AS logins FROM app_events WHERE ts >= ? AND source = 'keycloak' "
                        "AND event_type = 'LOGIN' AND username IS NOT NULL GROUP BY username "
                        "ORDER BY logins DESC, username LIMIT 5", (since_ms,))
        http = self._all("SELECT COUNT(*) AS n, AVG(duration_ms) AS avg_ms, "
                         "SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors "
                         "FROM app_events WHERE ts >= ? AND kind IN ('access','s2s')", (since_ms,))[0]
        first_day = now_ms // DAY_MS - (days - 1)
        series: dict[int, dict[str, int]] = {}
        for r in self._all("SELECT ts / ? AS day, event_type, COUNT(*) AS n FROM app_events WHERE ts >= ? AND "
                           "source = 'keycloak' AND event_type IN ('LOGIN','LOGIN_ERROR') GROUP BY 1, 2",
                           (DAY_MS, first_day * DAY_MS)):
            series.setdefault(int(r["day"]), {})[r["event_type"]] = int(r["n"])
        daily = []
        for day in range(first_day, first_day + days):
            counts = series.get(day, {})
            daily.append({"day_ms": day * DAY_MS, "logins": counts.get("LOGIN", 0),
                          "failed": counts.get("LOGIN_ERROR", 0)})
        active = self._one("SELECT COUNT(*) FROM user_sessions WHERE logout_at IS NULL AND last_seen_at >= ?",
                           (now_ms - idle_ms,))
        return {
            "total_logins": count(f"{kc} AND event_type = 'LOGIN'"),
            "failed_logins": count(f"{kc} AND event_type = 'LOGIN_ERROR'"),
            "app_logins": count("source = 'app' AND event_type = 'LOGIN'"),
            "token_refreshes": count("source = 'app' AND event_type = 'TOKEN_REFRESH'"),
            "expiry_warnings": count("event_type IN ('TOKEN_EXPIRY_WARNING','TOKEN_EXPIRED')"),
            "s2s_requests": count("kind = 's2s'"),
            "http_requests": int(http["n"] or 0),
            "http_errors": int(http["errors"] or 0),
            "avg_duration_ms": round(float(http["avg_ms"] or 0), 1),
            "active_sessions": int(active or 0),
            "top_users": top,
            "daily": daily,
        }
