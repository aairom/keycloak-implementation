"""Pull Keycloak's own event log (logins, failures, logouts, token refreshes) into the dashboard database.

Keycloak stores events in ``event_entity`` and exposes them at ``GET /admin/realms/<realm>/events``.
The REST events have no id, so each one gets a content hash (``dedupe_key``): syncing the same window
twice never creates duplicates, which also makes it safe to run in several gunicorn workers.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

import requests

from store import Store, dedupe_key

log = logging.getLogger("logapp.sync")

PAGE = 200            # events requested per HTTP call
MAX_PAGES = 25        # safety valve: at most 5000 events per sync run
STATE_KEY = "keycloak_events_watermark_ms"


def normalize(raw: dict, store: Store) -> dict:
    """Map one Keycloak event JSON object to ``Store.add_event`` keyword arguments."""
    details = raw.get("details") or {}
    user_id = raw.get("userId")
    username = details.get("username") or (store.username_for_user_id(user_id) if user_id else None)
    if not username and raw.get("type", "").startswith("CLIENT_LOGIN") and raw.get("clientId"):
        username = f"service-account-{raw['clientId']}"
    extra = {k: v for k, v in details.items() if k != "username"}
    return {
        "ts": int(raw["time"]), "source": "keycloak", "kind": "auth",
        "event_type": raw.get("type", "UNKNOWN"), "username": username, "user_id": user_id,
        "client_id": raw.get("clientId"), "session_id": raw.get("sessionId"), "ip": raw.get("ipAddress"),
        "error": raw.get("error"), "detail": extra or None,
        "dedupe_key": dedupe_key("kc", raw.get("time"), raw.get("type"), user_id, raw.get("sessionId"),
                                 raw.get("clientId"), raw.get("ipAddress"), raw.get("error"),
                                 details.get("code_id"), details.get("username")),
    }


class KeycloakEventSync:
    """Incrementally copies Keycloak events into the store."""

    def __init__(self, store: Store, tokens, admin_api_base: str, http=requests, interval: int = 10):
        self.store, self.tokens, self.base, self._http, self.interval = store, tokens, admin_api_base, http, interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None
        self.last_run_ms: int | None = None

    def _fetch(self, date_from: str, first: int) -> list[dict]:
        resp = self._http.get(f"{self.base}/events", timeout=10,
                              params={"dateFrom": date_from, "first": first, "max": PAGE},
                              headers={"Authorization": f"Bearer {self.tokens.token()}"})
        if resp.status_code == 401:
            self.tokens.invalidate()
        resp.raise_for_status()
        return resp.json()

    def sync_once(self) -> int:
        """Fetch events at or after the watermark's day; returns how many new rows were stored."""
        watermark = int(self.store.get_state(STATE_KEY, "0") or 0)
        date_from = datetime.fromtimestamp(watermark / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
        new, newest, first = 0, watermark, 0
        for _ in range(MAX_PAGES):
            batch = self._fetch(date_from, first)
            for raw in batch:
                if "time" not in raw:
                    continue
                if self.store.add_event(**normalize(raw, self.store)):
                    new += 1
                newest = max(newest, int(raw["time"]))
            if len(batch) < PAGE:
                break
            first += PAGE
        # The next run re-reads the whole UTC day of the watermark (the REST filter has day granularity);
        # the dedupe key makes that overlap harmless.
        self.store.set_state(STATE_KEY, str(newest))
        return new

    def run_safely(self) -> int:
        try:
            n = self.sync_once()
            self.last_error = None
            return n
        except Exception as exc:  # Keycloak down or token refused: keep the app alive, report on the dashboard
            self.last_error = f"{type(exc).__name__}: {exc}"
            log.warning("keycloak event sync failed: %s", self.last_error)
            return 0
        finally:
            self.last_run_ms = int(time.time() * 1000)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        def loop():
            while not self._stop.is_set():
                self.run_safely()
                self._stop.wait(self.interval)

        self._thread = threading.Thread(target=loop, name="keycloak-event-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
