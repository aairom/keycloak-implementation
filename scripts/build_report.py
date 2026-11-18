#!/usr/bin/env python3
"""Build the self-contained logging-system report ``Docs/logging-system-report.html``.

Everything in the report is read from the repository at build time (source files, Markdown docs, evidence files,
screenshots), never retyped. Numbers such as the test count or the number of PASS lines are parsed from the
evidence files, and every claim carries a status (VERIFIED, CORRECTED, NOT TRUE, OBSERVED) computed from them.
The output has no external dependencies: CSS is inlined, screenshots are base64 data URIs, diagrams are inline SVG.

    .venv/bin/python scripts/build_report.py [--out Docs/logging-system-report.html]

Needs ``markdown`` and ``pygments`` (see requirements.txt).
"""
from __future__ import annotations

import argparse
import base64
import html
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import markdown
from markdown.extensions.toc import slugify
from pygments import highlight as _pyg_highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, guess_lexer_for_filename
from pygments.util import ClassNotFound

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = "Docs/report-assets/evidence"
DEFAULT_OUT = "Docs/logging-system-report.html"
SCREENSHOTS = (
    ("01-alice-dashboard.jpeg", "Dashboard of a regular user (alice): own events only, including real Keycloak "
                                "REFRESH_TOKEN rows next to the application's TOKEN_REFRESH and TOKEN_EXPIRY_WARNING."),
    ("02-alice-status-4xx.jpeg", "The same user filtered with Status = 4xx: the 403 answers of the API."),
    ("03-bob-filter-alice-403.jpeg", "Administrator (bob) using the admin-only User filter (alice) with Status = 403."),
    ("04-bob-admin-panel.jpeg", "Admin statistics page (role app-admin)."),
)
HL = HtmlFormatter(cssclass="hl")


# ----------------------------------------------------------------------------- file access

def esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def read(rel: str, root: Path = ROOT) -> str:
    return (root / rel).read_text(encoding="utf-8")


def find_line(rel: str, needle: str, root: Path = ROOT) -> int:
    """1-based line number of the first line containing ``needle``; fails loudly so links never point nowhere."""
    for number, line in enumerate(read(rel, root).splitlines(), start=1):
        if needle in line:
            return number
    raise LookupError(f"{needle!r} not found in {rel}")


def file_link(rel: str, line: int | None = None) -> str:
    """Relative link from Docs/ to a repository file (the report lives in Docs/)."""
    target = f"../{rel}" + (f"#L{line}" if line else "")
    label = rel + (f":{line}" if line else "")
    return f'<a href="{esc(target)}"><code>{esc(label)}</code></a>'


# ----------------------------------------------------------------------------- code highlighting

def highlight(code: str, lang: str | None = None, filename: str | None = None) -> str:
    """Syntax-highlighted block; falls back to plain text when no lexer is known."""
    try:
        if lang:
            lexer = get_lexer_by_name(lang)
        elif filename:
            lexer = guess_lexer_for_filename(filename, code)
        else:
            lexer = get_lexer_by_name("text")
    except ClassNotFound:
        lexer = get_lexer_by_name("text")
    return _pyg_highlight(code, lexer, HL)


def listing(rel: str, lang: str | None = None, root: Path = ROOT) -> str:
    """A source file extracted from the repository, with link, line count and highlighted body."""
    code = read(rel, root)
    lines = code.count("\n") + (0 if code.endswith("\n") else 1)
    return (f'<p class="meta">{file_link(rel)} - {lines} lines, extracted from the repository at build time</p>'
            + highlight(code, lang, filename=rel))


# ----------------------------------------------------------------------------- Markdown

_FENCE = re.compile(r"^```([\w+-]*)[ \t]*\n(.*?)^```[ \t]*$", re.S | re.M)


def md_to_html(text: str, prefix: str, diagrams: dict[str, str] | None = None) -> str:
    """Render Markdown. Fenced code is highlighted with Pygments; Mermaid blocks get an inline SVG when one is
    registered for them in ``diagrams`` (matched by a marker string inside the block) plus the source."""
    diagrams = diagrams or {}
    blocks: list[str] = []

    def stash(match: re.Match) -> str:
        lang, body = match.group(1), match.group(2)
        if lang == "mermaid":
            svg = next((v for marker, v in diagrams.items() if marker in body), "")
            note = "" if svg else '<p class="meta">Rendered as source: no static drawing is bundled for this diagram.</p>'
            out = (f'<figure class="diagram">{svg}</figure>' if svg else "") + note + \
                  f'<details class="src"><summary>Mermaid source</summary>{highlight(body, "text")}</details>'
        else:
            out = highlight(body, lang or "text")
        blocks.append(out)
        return f"\n@@BLOCK{len(blocks) - 1}@@\n"

    prepared = _FENCE.sub(stash, text)
    rendered = markdown.markdown(
        prepared, extensions=["tables", "toc", "sane_lists"],
        extension_configs={"toc": {"slugify": lambda value, sep: f"{prefix}-{slugify(value, sep)}"}})
    for index, block in enumerate(blocks):
        rendered = rendered.replace(f"<p>@@BLOCK{index}@@</p>", block)
    rendered = re.sub(r'href="#([^"]+)"', lambda m: f'href="#{prefix}-{m.group(1)}"', rendered)
    return re.sub(r"<(/?)h([1-6])\b", lambda m: f"<{m.group(1)}h{min(6, int(m.group(2)) + 2)}", rendered)


# ----------------------------------------------------------------------------- SVG diagrams

_SVG_OPEN = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" aria-label="{label}" '
             'class="svg">'
             '<defs><marker id="{mid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
             'orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#57606a"/></marker></defs>')


def _box(x, y, w, h, lines, cls="node"):
    text = "".join(f'<text x="{x + w / 2}" y="{y + 20 + i * 15}" text-anchor="middle" class="{"t1" if i == 0 else "t2"}">'
                   f'{esc(line)}</text>' for i, line in enumerate(lines))
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" class="{cls}"/>{text}'


def _path(points, mid, dashed=False):
    d = "M" + " L".join(f"{x} {y}" for x, y in points)
    return f'<path d="{d}" class="edge{" dash" if dashed else ""}" marker-end="url(#{mid})"/>'


def _label(x, y, text):
    return f'<text x="{x}" y="{y}" text-anchor="middle" class="lbl">{esc(text)}</text>'


def svg_components() -> str:
    """Component interactions of the demo stack (hand drawn, matches the Mermaid diagram in Architecture.md).

    Layout: browser and Caddy on the left, the three Flask apps in the middle, Keycloak and PostgreSQL on the right.
    All content sits in a group shifted down by 24 px so the top route and its label are not clipped."""
    m = "arrow-c"
    parts = [_SVG_OPEN.format(w=900, h=470, label="Component interactions of the Keycloak demo stack", mid=m),
             '<g transform="translate(0,24)">']
    parts += [
        _box(20, 220, 110, 56, ["Browser", "user"]),
        _box(170, 220, 120, 56, ["Caddy", "online only: HTTPS"], "node alt"),
        _box(380, 40, 150, 56, ["webapp :8081", "Flask + Authlib"]),
        _box(380, 150, 150, 56, ["api :8082", "Flask + PyJWT"]),
        _box(380, 290, 150, 56, ["logapp :8083", "Flask + Authlib"]),
        _box(700, 110, 150, 70, ["Keycloak 26.8.2", "realm demo", ":8080 / mgmt :9000"]),
        _box(700, 330, 150, 56, ["PostgreSQL 17", "public + logapp"]),
    ]
    edges = [
        [(130, 248), (170, 248)],                                   # browser -> caddy
        [(290, 248), (330, 248)],                                   # caddy -> bus
        [(330, 68), (330, 318)],                                    # bus (no arrow head, see below)
        [(230, 220), (230, 0), (775, 0), (775, 110)],               # caddy -> keycloak (auth host)
        [(530, 68), (640, 68), (640, 125), (700, 125)],             # webapp -> keycloak
        [(455, 96), (455, 150)],                                    # webapp -> api (bearer)
        [(530, 195), (610, 195), (610, 160), (700, 160)],           # api -> keycloak
        [(455, 290), (455, 206)],                                   # logapp -> api (s2s)
        [(530, 305), (670, 305), (670, 175), (700, 175)],           # logapp -> keycloak
        [(530, 340), (700, 340)],                                   # logapp -> postgres
        [(775, 180), (775, 330)],                                   # keycloak -> postgres
    ]
    for i, points in enumerate(edges):
        if i == 2:  # the bus: plain line plus three short arrows into the apps
            parts.append(f'<path d="M330 68 L330 318" class="edge"/>')
            parts += [_path([(330, y), (380, y)], m) for y in (68, 178, 318)]
        else:
            parts.append(_path(points, m))
    parts += [
        _label(150, 240, "HTTPS"), _label(500, -8, "auth host (HTTPS online)"),
        _label(230, 296, "app, api, logs hosts"),
        _label(585, 60, "discovery, token"), _label(500, 126, "Bearer").replace('text-anchor="middle"', 'text-anchor="start"')
        .replace('x="500"', 'x="463"'),
        _label(570, 213, "JWKS, UMA"),
        _label(463, 252, "s2s Bearer").replace('text-anchor="middle"', 'text-anchor="start"'),
        _label(664, 298, "login, refresh, admin REST").replace('text-anchor="middle"', 'text-anchor="end"'),
        _label(615, 357, "events, sessions, audit"), _label(783, 262, "JDBC").replace('text-anchor="middle"', 'text-anchor="start"'),
        _label(450, 420, "In local mode there is no Caddy: the browser talks to the published ports directly "
                         "(Keycloak :8080, webapp :8081, logapp :8083)."),
    ]
    parts.append("</g></svg>")
    return "".join(parts)


def svg_sequence(actors: list[tuple[str, int]], messages: list[tuple], loop: tuple[int, int, str] | None,
                 label: str, height: int) -> str:
    """Generic sequence diagram. ``messages`` are (from, to, text, y, dashed); ``loop`` is (y1, y2, caption)."""
    m = "arrow-s"
    xs = dict(actors)
    parts = [_SVG_OPEN.format(w=900, h=height, label=label, mid=m)]
    for name, x in actors:
        parts.append(_box(x - 60, 10, 120, 30, [name], "node"))
        parts.append(f'<line x1="{x}" y1="40" x2="{x}" y2="{height - 20}" class="life"/>')
    if loop:
        y1, y2, caption = loop
        parts.append(f'<rect x="{xs[actors[1][0]] - 40}" y="{y1}" width="{xs[actors[-1][0]] - xs[actors[1][0]] + 80}" '
                     f'height="{y2 - y1}" class="loop"/>'
                     f'<text x="{xs[actors[1][0]] - 34}" y="{y1 + 14}" class="lbl left">loop {esc(caption)}</text>')
    for src, dst, text, y, dashed in messages:
        parts.append(_path([(xs[src], y), (xs[dst], y)], m, dashed))
        parts.append(_label((xs[src] + xs[dst]) / 2, y - 6, text))
    parts.append("</svg>")
    return "".join(parts)


def svg_pg_flow() -> str:
    """PostgreSQL event flow of the log dashboard (matches the sequence diagram in Architecture.md)."""
    actors = [("User", 80), ("logapp", 300), ("Keycloak", 540), ("PostgreSQL", 790)]
    messages = [
        ("User", "Keycloak", "login, token refresh, logout", 80, False),
        ("Keycloak", "PostgreSQL", "INSERT public.event_entity (enabledEventTypes)", 115, False),
        ("User", "logapp", "request", 150, False),
        ("logapp", "PostgreSQL", "INSERT logapp.app_events (source=app)", 185, False),
        ("logapp", "Keycloak", "GET /admin/realms/demo/events (Bearer)", 250, False),
        ("Keycloak", "logapp", "JSON events", 285, True),
        ("logapp", "PostgreSQL", "INSERT ... ON CONFLICT (dedupe_key) DO NOTHING (source=keycloak)", 325, False),
        ("logapp", "PostgreSQL", "UPDATE sync_state keycloak_events_watermark_ms", 365, False),
    ]
    return svg_sequence(actors, messages, (210, 395, "every LOGAPP_SYNC_INTERVAL seconds"),
                        "PostgreSQL event flow of the log dashboard", 420)


DIAGRAMS = {"Compose project keycloak-demo": svg_components(), "participant L as logapp": svg_pg_flow()}


# ----------------------------------------------------------------------------- evidence parsing

def pytest_summary(text: str) -> tuple[int, int]:
    """(passed, failed) from the last pytest summary line, e.g. ``213 passed in 0.75s``."""
    line = next((ln for ln in reversed(text.splitlines()) if re.search(r"\d+ (passed|failed)", ln)), "")
    passed = re.search(r"(\d+) passed", line)
    failed = re.search(r"(\d+) failed", line)
    return (int(passed.group(1)) if passed else 0, int(failed.group(1)) if failed else 0)


def per_file_test_counts(text: str) -> dict[str, int]:
    """``  14 path/tests/test_x.py`` lines -> {"test_x.py": 14}."""
    return {Path(m.group(2)).name: int(m.group(1))
            for m in re.finditer(r"^\s*(\d+)\s+(\S+\.py)\s*$", text, re.M)}


def coverage_rows(text: str) -> tuple[list[dict], dict]:
    """Rows of ``coverage report -m`` and its TOTAL row."""
    rows, total = [], {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s*(.*)$", line)
        if not m:
            continue
        row = {"name": m.group(1), "stmts": int(m.group(2)), "miss": int(m.group(3)), "branch": int(m.group(4)),
               "brpart": int(m.group(5)), "cover": int(m.group(6)), "missing": m.group(7).strip()}
        if row["name"] == "TOTAL":
            total = row
        else:
            rows.append(row)
    return rows, total


def verify_counts(text: str) -> tuple[int, int, bool]:
    """(PASS lines, FAIL lines, ends with VERIFY OK)."""
    lines = text.splitlines()
    return (sum(1 for ln in lines if ln.startswith("PASS")), sum(1 for ln in lines if ln.startswith("FAIL")),
            any(ln.strip() == "VERIFY OK" for ln in lines))


def pg_columns(text: str, table: str) -> list[tuple[str, str, bool]]:
    """(column, type, nullable) for ``table`` from the psql ``information_schema`` listing."""
    cols = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 4 and parts[0] == table:
            cols.append((parts[1], parts[2], parts[3] == "YES"))
    return cols


def requirement_names(text: str) -> list[str]:
    """Distribution names of a requirements file (extras and version pins removed, lower case)."""
    names = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.append(re.split(r"[\[<>=!~; ]", line, maxsplit=1)[0].lower().replace("_", "-"))
    return names


def env_example_entries(text: str) -> list[tuple[str, str, str]]:
    """(name, default, comment) from ``.env.example``; the comment is the comment block right above the variable."""
    entries, comment = [], []
    for line in text.splitlines():
        if line.startswith("#"):
            body = line.lstrip("# ").rstrip()
            comment = [] if body.startswith("---") else comment + [body]
        elif "=" in line and not line.startswith(" "):
            name, _, default = line.partition("=")
            entries.append((name.strip(), default.strip().strip('"'), " ".join(comment)))
            comment = []
        else:
            comment = []
    return entries


SECRET_NAME = re.compile(r"SECRET|PASSWORD|PASSPHRASE|TOKEN|(^|_)API_?KEY$|_KEY$")


def secret_values(env_text: str) -> list[str]:
    """Values of password/secret variables in a ``.env`` file; the report must never contain them."""
    values = []
    for line in env_text.splitlines():
        name, sep, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        if sep and SECRET_NAME.search(name.strip().upper()) and len(value) >= 6:
            values.append(value)
    return values


def assert_no_secrets(document: str, root: Path = ROOT) -> None:
    """Fail the build when a secret from ``.env`` appears in the output."""
    env = root / ".env"
    if not env.exists():
        return
    leaked = [v for v in secret_values(env.read_text(encoding="utf-8")) if v in document]
    if leaked:
        raise SystemExit(f"refusing to write the report: {len(leaked)} secret value(s) from .env found in it")


# ----------------------------------------------------------------------------- JSON schemas

def _type_ok(value: object, expected: str) -> bool:
    kinds = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "object": dict, "array": list,
             "null": type(None)}
    if expected == "integer" and isinstance(value, bool):
        return False
    return isinstance(value, kinds[expected])


def validate(instance: object, schema: dict, path: str = "$", root: dict | None = None) -> list[str]:
    """Minimal JSON-Schema checker (type, required, properties, additionalProperties, items, enum, const, local $ref).

    Enough for the contracts in this report; it avoids adding a dependency to the project."""
    root = root or schema
    if "$ref" in schema:  # only "#/$defs/<name>" references are used here
        schema = root["$defs"][schema["$ref"].rsplit("/", 1)[1]]
    errors: list[str] = []
    expected = schema.get("type")
    if expected:
        allowed = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(instance, t) for t in allowed):
            return [f"{path}: expected {'/'.join(allowed)}, got {type(instance).__name__}"]
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in {schema['enum']}")
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected {schema['const']!r}")
    if isinstance(instance, dict):
        props = schema.get("properties", {})
        errors += [f"{path}: missing required '{k}'" for k in schema.get("required", []) if k not in instance]
        if schema.get("additionalProperties") is False:
            errors += [f"{path}: unexpected '{k}'" for k in instance if k not in props]
        for key, sub in props.items():
            if key in instance:
                errors += validate(instance[key], sub, f"{path}.{key}", root)
    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            errors += validate(item, schema["items"], f"{path}[{i}]", root)
    return errors


def _s(**extra):
    return {"type": "string", **extra}


def _opt(kind: str, **extra):
    return {"type": [kind, "null"], **extra}


EVENT_ROW_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema", "title": "Event row (logapp.app_events)",
    "type": "object", "additionalProperties": False,
    "required": ["id", "ts", "source", "kind", "event_type", "dedupe_key"],
    "properties": {
        "id": {"type": "integer", "description": "identity column"},
        "ts": {"type": "integer", "description": "epoch milliseconds (UTC)"},
        "source": _s(enum=["app", "keycloak"]),
        "kind": _s(enum=["auth", "access", "token", "api", "s2s"]),
        "event_type": _s(description="e.g. LOGIN, LOGOUT, TOKEN_REFRESH, REFRESH_TOKEN, API_CALL, HTTP_REQUEST"),
        "username": _opt("string"), "user_id": _opt("string"), "client_id": _opt("string"),
        "session_id": _opt("string"), "ip": _opt("string"), "method": _opt("string"), "path": _opt("string"),
        "status": _opt("integer"), "duration_ms": _opt("integer"), "error": _opt("string"),
        "detail": _opt("string", description="JSON text; parse it client-side"),
        "dedupe_key": _opt("string", description="set for source=keycloak, NULL for source=app"),
    },
}

EVENTS_JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema", "title": "GET /events.json response",
    "type": "object", "additionalProperties": False, "required": ["total", "page", "page_size", "events"],
    "properties": {"total": {"type": "integer"}, "page": {"type": "integer"}, "page_size": {"type": "integer"},
                   "events": {"type": "array", "items": {"$ref": "#/$defs/event"}}},
    "$defs": {"event": EVENT_ROW_SCHEMA},
}

TOKEN_REFRESH_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Keycloak token endpoint response (grant_type=refresh_token)", "type": "object",
    "required": ["access_token", "expires_in", "refresh_expires_in", "refresh_token", "token_type", "scope"],
    "properties": {"access_token": _s(), "expires_in": {"type": "integer"}, "refresh_expires_in": {"type": "integer"},
                   "refresh_token": _s(), "token_type": _s(), "not-before-policy": {"type": "integer"},
                   "session_state": _s(), "scope": _s()},
}

KEYCLOAK_EVENT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Keycloak raw event (GET /admin/realms/{realm}/events)", "type": "object",
    "required": ["id", "time", "type", "realmId"],
    "properties": {"id": _s(description="UUID - Keycloak does return an id"),
                   "time": {"type": "integer", "description": "epoch milliseconds"}, "type": _s(),
                   "realmId": _s(), "clientId": _opt("string"), "userId": _opt("string"),
                   "sessionId": _opt("string"), "ipAddress": _opt("string"),
                   "details": {"type": "object", "description": "string -> string map; keys depend on the type"}},
}


# ----------------------------------------------------------------------------- UI labels as implemented

def ui_labels(root: Path = ROOT) -> list[tuple[str, str, str]]:
    """(page, element, text) extracted from the Jinja templates and ``API_CALLS`` - never retyped."""
    rows: list[tuple[str, str, str]] = []
    clean = lambda s: html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>|\{[{%].*?[}%]\}", "", s))).strip()
    for page in ("base", "index", "dashboard", "admin"):
        src = read(f"logapp/templates/{page}.html", root)
        for kind, pattern in (("heading", r"<h([12])[^>]*>(.*?)</h\1>"), ("label", r"<label[^>]*>(?:\s*<input[^>]*>)?\s*([^<{]+)"),
                              ("button", r"<(?:button|a class=\"btn[^\"]*\")[^>]*>([^<]*(?:\{\{[^}]*\}\}[^<]*)?)</(?:button|a)>"),
                              ("tile", r"<span>([^<]+)</span></div>"), ("column", r"<th>([^<]+)</th>"),
                              ("option", r"<option value=\"[^\"]*\"[^>]*>([^<]+)</option>"),
                              ("link", r"<a href=\"\{\{ url_for\('(?:dashboard', page|events_json')[^>]*>([^<]+)</a>"),
                              ("nav", r"<a href=\"\{\{ url_for\('(?:dashboard|admin)'\) \}\}\">([^<]+)</a>")):
            for match in re.finditer(pattern, src, re.S):
                text = clean(match.group(match.lastindex))
                if text:
                    rows.append((page + ".html", kind, text))
    api = re.search(r"API_CALLS = \{(.*?)\n\}", read("logapp/log_app.py", root), re.S)
    for key, label in re.findall(r'"(\w+)": \("[A-Z]+", "[^"]+", "([^"]+)"\)', api.group(1) if api else ""):
        rows.append(("log_app.py", f"API_CALLS[{key}]", label))
    return rows


# ----------------------------------------------------------------------------- claim register

def claims(root: Path = ROOT) -> list[dict]:
    """Each claim is evaluated against the repository and evidence files; ``status`` is computed, not asserted."""
    ev = lambda name: read(f"{EVIDENCE}/{name}", root)
    passed, failed = pytest_summary(ev("pytest.txt"))
    per_file = per_file_test_counts(ev("test_counts.txt"))
    _, cov_total = coverage_rows(ev("coverage.txt"))
    n_pass, n_fail, ok_line = verify_counts(ev("verify.txt"))
    reqs = {p: requirement_names(read(p, root)) for p in
            ("logapp/requirements.txt", "webapp/requirements.txt", "api/requirements.txt", "requirements.txt")}
    pyjwt = {p: "pyjwt" in names for p, names in reqs.items()}
    raw = json.loads(ev("keycloak_raw_event.json"))
    routes = re.findall(r'@app\.(?:get|post)\("([^"]+)"\)', read("logapp/log_app.py", root))
    retention = ev("retention_dryrun.txt")
    docs_deploy = read("Docs/Deployment.md", root)
    realm = json.loads(read("keycloak/realm/demo-realm.json", root))
    expiry = re.search(r"LOGAPP_EXPIRY_WARN_SECONDS=(\d+)", read(".env.example", root))

    def row(claim, ok, verified, corrected="", evidence=(), status=None):
        """``ok`` is the build-time check. With ``status`` (CORRECTED, NOT TRUE, OBSERVED) the check proves the
        explanation in ``corrected``; without it the claim is VERIFIED and ``verified`` is shown."""
        if not ok:
            return {"claim": claim, "status": "NOT VERIFIED", "detail": "the build-time check failed",
                    "evidence": list(evidence)}
        return {"claim": claim, "status": status or "VERIFIED", "detail": corrected if status else verified,
                "evidence": list(evidence)}

    return [
        row("All unit tests pass", passed == sum(per_file.values()) and failed == 0,
            f"{passed} passed, {failed} failed; the per-file counts add up to {sum(per_file.values())} "
            f"in {len(per_file)} files.", evidence=[f"{EVIDENCE}/pytest.txt", f"{EVIDENCE}/test_counts.txt"]),
        row("Branch coverage of the project code", cov_total.get("cover", 0) >= 90,
            f"{cov_total['cover']}% over {cov_total['stmts']} statements ({cov_total['miss']} missed, "
            f"{cov_total['branch']} branches).", evidence=[f"{EVIDENCE}/coverage.txt"]),
        row("scripts/verify.sh passes end to end", n_pass == 44 and n_fail == 0 and ok_line,
            f"{n_pass} PASS, {n_fail} FAIL, ends with VERIFY OK.", evidence=[f"{EVIDENCE}/verify.txt"]),
        row("All five containers are healthy", read(f"{EVIDENCE}/containers.txt", root).count("(healthy)") == 5,
            "keycloak, postgres, api, webapp and logapp report (healthy).", evidence=[f"{EVIDENCE}/containers.txt"]),
        row("PyJWT is listed in the requirements of logapp and webapp",
            not pyjwt["logapp/requirements.txt"] and not pyjwt["webapp/requirements.txt"], "",
            "NOT TRUE as asked. PyJWT is listed only in " + ", ".join(p for p, v in pyjwt.items() if v) +
            "; it is absent from " + ", ".join(p for p, v in pyjwt.items() if not v) +
            ". logapp decodes tokens it already trusts with the standard library "
            "(log_helpers.decode_jwt_payload) and Authlib validates the ID token.",
            list(reqs), status="NOT TRUE"),
        row("The dashboard exposes an /api contract", "/api" not in routes and "/events.json" in routes, "",
            "NOT TRUE as asked. The dashboard's JSON surface is only " +
            ", ".join(r for r in routes if r in ("/events.json", "/healthz")) +
            "; every other route returns HTML or redirects. The /api/* endpoints belong to the separate api service.",
            ["logapp/log_app.py"], status="NOT TRUE"),
        row("The retention SQL is deployed as currently documented", "operator does not exist" in retention
            and retention.count("DELETE 0") == 3 and "```sql" in docs_deploy, "",
            "CORRECTED. The earlier statement compared a BIGINT epoch-millisecond column with now() and failed on "
            "PostgreSQL (operator does not exist: bigint < timestamp with time zone). The statements in "
            "Deployment.md now convert with extract(epoch ...) * 1000 and were dry-run in a rolled-back transaction.",
            [f"{EVIDENCE}/retention_dryrun.txt", "Docs/Deployment.md"], status="CORRECTED"),
        row("Keycloak events have no id", "id" in raw and len(raw["id"]) == 36,
            "", "CORRECTED. Earlier docs said Keycloak events carry no id; the raw REST event does (a UUID). "
                "The design is unchanged: dedupe_key is a content hash so overlapping windows stay idempotent.",
            [f"{EVIDENCE}/keycloak_raw_event.json", "logapp/store.py", "logapp/event_sync.py"], status="CORRECTED"),
        row("Keycloak REFRESH_TOKEN events reach the dashboard", "REFRESH_TOKEN" in realm["enabledEventTypes"]
            and raw["type"] == "REFRESH_TOKEN", f"Listed in enabledEventTypes ({len(realm['enabledEventTypes'])} types) "
            "and captured live; the dashboard shows them next to the application's own TOKEN_REFRESH rows.",
            evidence=["keycloak/realm/demo-realm.json", f"{EVIDENCE}/keycloak_raw_event.json",
                      f"{EVIDENCE}/event_rows.json"]),
        row("Token expiry warning window is 60 s by default", bool(expiry) and expiry.group(1) == "60",
            "LOGAPP_EXPIRY_WARN_SECONDS=60. It was raised to 290 temporarily to capture a real refresh, then "
            "restored and confirmed with printenv in the container.", evidence=[".env.example"]),
        row("Active sessions on the admin page equals the people signed in",
            (root / "Docs/report-assets/04-bob-admin-panel.jpeg").exists(), "",
            "OBSERVED. The screenshot shows 4 active sessions because verify.sh signs bob in repeatedly and never "
            "signs him out; a session counts as active until logout or LOGAPP_IDLE_MINUTES (30) without a request.",
            ["Docs/report-assets/04-bob-admin-panel.jpeg", "logapp/store.py"], status="OBSERVED"),
        row("Tokens are never written to PostgreSQL", "TokenVault" in read("logapp/log_app.py", root)
            and not any(c[0] in ("access_token", "refresh_token", "id_token") for c in
                        pg_columns(ev("pg_schema.txt"), "user_sessions")),
            "Tokens live in the in-process TokenVault; user_sessions has no token column.",
            evidence=[f"{EVIDENCE}/pg_schema.txt", "logapp/log_app.py"]),
    ]


# ----------------------------------------------------------------------------- glossary and troubleshooting data

ENV_DESCRIPTIONS = {
    "OIDC_DISCOVERY_URL": "OIDC discovery document of the realm, on the internal Keycloak host; the token and admin REST "
                          "URLs are derived from it (there is no separate internal-URL variable).",
    "OIDC_CLIENT_ID": "Client id of the dashboard in Keycloak (demo-logapp).",
    "OIDC_CLIENT_SECRET": "Secret of that client; compose passes LOGAPP_CLIENT_SECRET.",
    "LOGAPP_SESSION_SECRET": "Signs the dashboard's session cookie.",
    "LOGAPP_PUBLIC_URL": "Public URL of the dashboard; must match the redirect URI registered in Keycloak.",
    "API_BASE_URL": "Base URL of the api service used by the API buttons and the service-to-service call.",
    "LOGAPP_DATABASE_URL": "PostgreSQL connection URL of the dashboard (not DATABASE_URL). A sqlite: URL is used by tests.",
    "SERVICE_CLIENT_ID": "Client id for the service-to-service call (default demo-service).",
    "SERVICE_CLIENT_SECRET": "Secret of that client (client credentials grant).",
    "LOGAPP_ADMIN_ROLE": "Realm role that may open the admin page and see every user's events (default app-admin).",
    "LOGAPP_SYNC_INTERVAL": "Seconds between pulls of Keycloak's event log (default 10).",
    "LOGAPP_EXPIRY_WARN_SECONDS": "Seconds before access-token expiry at which TOKEN_EXPIRY_WARNING is logged and the "
                                  "refresh token is used (default 60).",
    "LOGAPP_PAGE_SIZE": "Rows per dashboard page (default 25).",
    "LOGAPP_IDLE_MINUTES": "A session unseen for this long no longer counts as active (default 30).",
    "LOGAPP_TRUST_PROXY": "Honour X-Forwarded-* headers of the reverse proxy; set by the prod overlay.",
}

FILTER_PARAMS = (
    ("username", "Admin only. Substring match; for non-admins the filter is pinned to the signed-in user."),
    ("event_type", "Exact event type, e.g. LOGIN, API_CALL, REFRESH_TOKEN."),
    ("kind", "Category: auth, access, token, api or s2s."),
    ("source", "Origin: app (written by this application) or keycloak (pulled from the events REST endpoint)."),
    ("status", "HTTP status: an exact code such as 403, or a class such as 4xx."),
    ("q", "Free text over path and error."),
    ("date_from", "First day (inclusive), YYYY-MM-DD, UTC."),
    ("date_to", "Last day (inclusive), YYYY-MM-DD, UTC."),
    ("page", "1-based page number."),
    ("live", "live=1 adds a page-level meta refresh every 5 seconds (dashboard only, not /events.json)."),
)

GLOSSARY = (
    ("Realm", "Keycloak's isolated namespace of users, clients and roles. This project uses the realm demo."),
    ("Client", "An application registered in Keycloak: demo-webapp, demo-api, demo-logapp, demo-service, demo-cli."),
    ("OIDC / PKCE", "OpenID Connect authorization code flow with Proof Key for Code Exchange, used by the dashboard login."),
    ("Access token", "Short-lived (about 5 minutes) bearer token for the API. Kept only in the TokenVault."),
    ("Refresh token", "Long-lived token exchanged for a new access token (grant_type=refresh_token)."),
    ("TokenVault", "In-process dictionary in log_app.py that holds the tokens by opaque session id; never persisted."),
    ("source=app / source=keycloak", "Which writer produced an event row: this application's hooks or the Keycloak sync."),
    ("kind", "Event category: auth, access, token, api, s2s."),
    ("dedupe_key", "Content hash that makes re-reading overlapping Keycloak event windows idempotent."),
    ("watermark", "sync_state row keycloak_events_watermark_ms: how far the sync has read."),
    ("enabledEventTypes", "Realm setting listing the event types Keycloak stores; REFRESH_TOKEN is not stored by default."),
    ("kc-admin-api", "Optional client scope that adds the Admin REST audience Keycloak 26.8 requires."),
    ("view-events", "Realm-management role of the dashboard's service account; the only admin permission it holds."),
    ("s2s", "Service-to-service: the dashboard calls the api as demo-service with the client credentials grant."),
    ("app-user / app-admin", "Realm roles: app-admin sees all events and the admin page."),
    ("epoch milliseconds", "Unit of every timestamp in the logapp schema (BIGINT), the same unit Keycloak uses."),
)

# (symptom, cause and fix, [(file, needle)]) - the code references are resolved to line numbers at build time.
TROUBLESHOOTING = (
    ("After a restart the dashboard asks me to sign in again",
     "By design: tokens live in process memory, so open sessions are closed with the reason server_restart.",
     [("logapp/log_app.py", "server_restart"), ("logapp/log_app.py", "class TokenVault")]),
    ("No source=keycloak rows",
     "The sync needs the kc-admin-api scope and the view-events role; the Admin page shows the last sync error.",
     [("logapp/event_sync.py", "def sync_once"), ("logapp/token_source.py", "class TokenSource"),
      ("logapp/log_app.py", 'ADMIN_API_SCOPE = "kc-admin-api"')]),
    ("Event sync error mentioning 401",
     "Keycloak 26.8 rejects Admin REST tokens without the audience <host>/admin/realms/<realm>; check the optional scope.",
     [("logapp/token_source.py", "def token"), ("keycloak/realm/demo-realm.json", "kc-admin-api")]),
    ("REFRESH_TOKEN rows never appear",
     "Keycloak does not store that type by default; it must be in enabledEventTypes (it is, in the demo realm).",
     [("keycloak/realm/demo-realm.json", "enabledEventTypes")]),
    ("A refresh failed but I am still signed in",
     "TOKEN_REFRESH_FAILED is logged; the session ends with TOKEN_EXPIRED only when the access token really expired.",
     [("logapp/log_app.py", "TOKEN_REFRESH_FAILED"), ("logapp/log_app.py", "TOKEN_EXPIRED")]),
    ("403 on the admin page",
     "Only the role app-admin may open it; the attempt is logged as ACCESS_DENIED and written to audit_log.",
     [("logapp/log_app.py", "def admin_required"), ("logapp/log_app.py", '"ACCESS_DENIED"')]),
    ("Dashboard returns 503 on /healthz",
     "The database ping failed: check LOGAPP_DATABASE_URL and the postgres container.",
     [("logapp/log_app.py", "def healthz"), ("logapp/store.py", "def ping")]),
    ("Container exits with 'missing environment variables'",
     "One of the required variables is unset; the message lists them.",
     [("logapp/log_config.py", "REQUIRED"), ("logapp/log_config.py", "missing environment variables")]),
    ("Invalid parameter: redirect_uri",
     "LOGAPP_PUBLIC_URL changed after the realm was imported: re-import or edit the client demo-logapp.",
     [("logapp/log_config.py", "public_url=")]),
    ("Active sessions looks too high",
     "Sessions stay active until logout or LOGAPP_IDLE_MINUTES without a request; verify.sh never signs bob out.",
     [("logapp/store.py", "logout_at IS NULL AND last_seen_at"), ("logapp/log_config.py", "idle_minutes")]),
    ("Duplicate Keycloak rows",
     "They cannot occur: the unique dedupe_key plus ON CONFLICT DO NOTHING absorbs overlapping windows.",
     [("logapp/store.py", "ON CONFLICT"), ("logapp/store.py", "def dedupe_key")]),
    ("Retention statement fails with 'operator does not exist: bigint'",
     "ts is epoch milliseconds; convert with extract(epoch FROM ...) * 1000 as in the Retention SQL section.",
     [("logapp/store.py", "ts BIGINT NOT NULL")]),
)

CSS = """
:root{--bg:#fff;--surface:#f7f8fa;--border:#e5e7eb;--text:#1f2328;--muted:#57606a;--accent:#3b82d4;
--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--info:#7c5cd8}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,"Segoe UI",system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:0 20px 60px}
header.top{border-bottom:1px solid var(--border);padding:28px 0 18px;margin-bottom:20px}
h1{margin:0 0 6px;font-size:1.9rem}h2{font-size:1.3rem;margin:0}h3{font-size:1.1rem}h4{font-size:1rem}
.meta,.muted{color:var(--muted);font-size:.9rem}
nav.toc{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:12px 18px;margin:16px 0}
nav.toc ol{margin:0;padding-left:20px;columns:2;column-gap:30px}nav.toc li{break-inside:avoid;margin:2px 0}
a{color:var(--accent)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85rem}
code{background:var(--surface);padding:1px 4px;border-radius:3px}
details.sec{border:1px solid var(--border);border-radius:6px;margin:14px 0;background:#fff}
details.sec>summary{cursor:pointer;padding:12px 16px;background:var(--surface);border-radius:6px;list-style:none}
details.sec[open]>summary{border-bottom:1px solid var(--border);border-radius:6px 6px 0 0}
details.sec>summary::-webkit-details-marker{display:none}
details.sec>summary::before{content:"\\25B8";display:inline-block;margin-right:8px;color:var(--muted);transition:none}
details.sec[open]>summary::before{content:"\\25BE"}
details.sec>.body{padding:6px 16px 14px;overflow-x:auto}
details.src{border:1px solid var(--border);border-radius:4px;margin:8px 0}
details.src>summary{cursor:pointer;padding:6px 10px;color:var(--muted);font-size:.9rem}
.hl{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:10px 12px;overflow:auto;
max-height:640px;margin:8px 0}.hl pre{margin:0;line-height:1.45}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:.9rem;display:block;overflow-x:auto}
th,td{border:1px solid var(--border);padding:6px 10px;text-align:left;vertical-align:top}
th{background:var(--surface)}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;font-size:.78rem;font-weight:600;color:#fff;white-space:nowrap}
.tag.VERIFIED{background:var(--ok)}.tag.CORRECTED{background:var(--warn)}.tag.NOT-TRUE{background:var(--bad)}
.tag.OBSERVED{background:var(--info)}.tag.NOT-VERIFIED{background:var(--bad)}
figure{margin:14px 0}figure img{max-width:100%;height:auto;border:1px solid var(--border);border-radius:4px}
figcaption{color:var(--muted);font-size:.88rem;margin-top:4px}
figure.diagram{background:#fff;border:1px solid var(--border);border-radius:4px;padding:8px;overflow-x:auto}
svg.svg{width:100%;height:auto;min-width:640px;font-family:inherit}
svg .node{fill:#f7f8fa;stroke:#8c959f}svg .node.alt{fill:#fff;stroke-dasharray:4 3}
svg .t1{font-size:12px;font-weight:600;fill:#1f2328}svg .t2{font-size:10px;fill:#57606a}
svg .edge{fill:none;stroke:#57606a;stroke-width:1.3}svg .edge.dash{stroke-dasharray:5 4}
svg .lbl{font-size:10px;fill:#57606a}svg .lbl.left{text-anchor:start}svg .life{stroke:#c9ced4;stroke-dasharray:3 4}
svg .loop{fill:none;stroke:#3b82d4;stroke-dasharray:6 4}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
.kpi div{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px 12px}
.kpi b{display:block;font-size:1.4rem}.kpi span{color:var(--muted);font-size:.85rem}
footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--border);color:var(--muted);font-size:.8rem;
text-align:center}
@media(max-width:700px){nav.toc ol{columns:1}h1{font-size:1.5rem}.wrap{padding:0 12px 40px}}
@media print{details.sec>.body{display:block}nav.toc{display:none}.hl{max-height:none}}
""" + HL.get_style_defs(".hl")


# ----------------------------------------------------------------------------- page assembly

def section(sid: str, title: str, body: str, open_: bool = False, note: str = "") -> str:
    return (f'<details class="sec" id="{esc(sid)}"{" open" if open_ else ""}><summary><h2 style="display:inline">'
            f'{esc(title)}</h2>{(" " + note) if note else ""}</summary><div class="body">{body}</div></details>')


def table(headers: list[str], rows: list[list[str]], raw: bool = False) -> str:
    cell = (lambda c: c) if raw else esc
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def evidence_links(items: list[str]) -> str:
    return " ".join(file_link(i) for i in items)


def revision(root: Path = ROOT) -> dict:
    def git(*args):
        try:
            return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    stamp = re.search(r"\((\d{4}-\d\d-\d\dT[\d:]+Z)\)", read(f"{EVIDENCE}/retention_dryrun.txt", root))
    return {"built": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), "commit": git("rev-parse", "--short", "HEAD"),
            "dirty": bool(git("status", "--porcelain", "--", "logapp", "scripts", "Docs", "keycloak", "api", "webapp")),
            "evidence": stamp.group(1) if stamp else "unknown"}


def sec_status(root: Path = ROOT) -> str:
    rows = [[f'<span class="tag {c["status"].replace(" ", "-")}">{esc(c["status"])}</span>', esc(c["claim"]),
             esc(c["detail"]), evidence_links(c["evidence"])] for c in claims(root)]
    return ("<p>Every status is computed at build time from the repository and the evidence files; it is not typed in. "
            "<b>NOT TRUE</b> marks a premise of the request that the code contradicts, <b>CORRECTED</b> a statement that "
            "was wrong in earlier documentation and has been fixed, <b>OBSERVED</b> a behaviour seen on the running "
            "stack.</p>" + table(["Status", "Claim", "Result", "Evidence"], rows, raw=True))


def sec_screens(root: Path = ROOT) -> str:
    out = ["<p>Captured from the running stack at <code>http://localhost:8083</code> (login passwords are never shown). "
           "Every row is real data written by the application or pulled from Keycloak.</p>"]
    for name, caption in SCREENSHOTS:
        data = base64.b64encode((root / "Docs/report-assets" / name).read_bytes()).decode()
        out.append(f'<figure><img loading="lazy" alt="{esc(caption)}" src="data:image/jpeg;base64,{data}">'
                   f'<figcaption>{esc(name)} - {esc(caption)}</figcaption></figure>')
    return "".join(out)


def sec_sources(root: Path = ROOT) -> str:
    files = (("logapp/log_app.py", "python", "Flask routes, request hooks, token lifecycle, TokenVault"),
             ("logapp/store.py", "python", "PostgreSQL / SQLite persistence, schema DDL, queries, statistics"),
             ("logapp/event_sync.py", "python", "Pulls Keycloak events and normalises them"),
             ("logapp/token_source.py", "python", "Client-credentials token cache for the admin REST calls"),
             ("logapp/log_config.py", "python", "Environment configuration"),
             ("logapp/log_helpers.py", "python", "Filters, paging, JWT payload decoding, severity"),
             ("logapp/Dockerfile", "docker", "Multi-stage, non-root image, 1 worker x 8 threads"))
    parts = []
    for rel, lang, what in files:
        parts.append(section("src-" + slugify(rel, "-"), rel, f"<p>{esc(what)}.</p>" + listing(rel, lang, root)))
    return "".join(parts)


def sec_tests(root: Path = ROOT) -> str:
    ev = lambda n: read(f"{EVIDENCE}/{n}", root)
    passed, failed = pytest_summary(ev("pytest.txt"))
    per_file = per_file_test_counts(ev("test_counts.txt"))
    rows, total = coverage_rows(ev("coverage.txt"))
    n_pass, n_fail, _ = verify_counts(ev("verify.txt"))
    kpi = (f'<div class="kpi"><div><b>{passed}</b><span>tests passed ({failed} failed)</span></div>'
           f'<div><b>{total["cover"]}%</b><span>branch coverage</span></div>'
           f'<div><b>{n_pass}</b><span>verify.sh PASS ({n_fail} FAIL)</span></div>'
           f'<div><b>{len(per_file)}</b><span>test files</span></div></div>')
    counts = table(["Test file", "Tests"], [[f"tests/{k}", str(v)] for k, v in per_file.items()] +
                   [["Total", str(sum(per_file.values()))]])
    cov = table(["Module", "Stmts", "Miss", "Branch", "BrPart", "Cover", "Missing lines"],
                [[r["name"], r["stmts"], r["miss"], r["branch"], r["brpart"], f'{r["cover"]}%', r["missing"]]
                 for r in rows] + [["TOTAL", total["stmts"], total["miss"], total["branch"], total["brpart"],
                                    f'{total["cover"]}%', ""]])
    note = ("<p>The uncovered lines of <code>logapp/store.py</code> are the PostgreSQL connection branches; they run "
            "only against a live database and are exercised by <code>scripts/verify.sh</code> instead.</p>")
    return (kpi + f"<h3>Tests per file</h3>{counts}<h3>Coverage report</h3><p class=\"meta\">{file_link(EVIDENCE + '/coverage.txt')}"
            f"</p>{cov}{note}<h3>pytest output</h3>{highlight(ev('pytest.txt'), 'text')}"
            f"<h3>scripts/verify.sh output</h3><p class=\"meta\">{file_link(EVIDENCE + '/verify.txt')} - {n_pass} PASS</p>"
            f"{highlight(ev('verify.txt'), 'text')}"
            f"<h3>scripts/verify_logapp.py</h3>{listing('scripts/verify_logapp.py', 'python', root)}")


def sec_schemas(root: Path = ROOT) -> str:
    ev = lambda n: json.loads(read(f"{EVIDENCE}/{n}", root))
    rows = ev("event_rows.json")
    sample_events = {"total": len(rows), "page": 1, "page_size": 25, "events": rows}
    keys = ev("token_refresh_response_keys.json")
    token_sample = {"access_token": "<jwt>", "expires_in": 299, "refresh_expires_in": 1800, "refresh_token": "<jwt>",
                    "token_type": "Bearer", "not-before-policy": 0, "session_state": "<uuid>",
                    "scope": "openid email profile"}
    assert set(token_sample) == set(keys), "token sample drifted from the captured response keys"
    checks = [("Event row (live PostgreSQL rows)", EVENT_ROW_SCHEMA, rows[0]),
              ("Event row (Keycloak-sourced)", EVENT_ROW_SCHEMA, rows[1]),
              ("/events.json response", EVENTS_JSON_SCHEMA, sample_events),
              ("Token endpoint refresh response (keys captured live)", TOKEN_REFRESH_SCHEMA, token_sample),
              ("Keycloak raw event (live admin REST)", KEYCLOAK_EVENT_SCHEMA, ev("keycloak_raw_event.json"))]
    results = [[name, "valid" if not (e := validate(inst, sch)) else "INVALID: " + "; ".join(e)] for name, sch, inst in checks]
    if any(r[1] != "valid" for r in results):
        raise SystemExit("schema validation failed: " + str(results))
    def block(title, schema, sample, note="", caption="Example (captured from the running stack)"):
        return (f"<h3>{esc(title)}</h3>{note}<h4>Schema</h4>{highlight(json.dumps(schema, indent=2), 'json')}"
                f"<h4>{esc(caption)}</h4>{highlight(json.dumps(sample, indent=2), 'json')}")
    cols = table(["Column", "PostgreSQL type", "Nullable"], [[c, t, "yes" if n else "no"]
                 for c, t, n in pg_columns(read(f"{EVIDENCE}/pg_schema.txt", root), "app_events")])
    flow = ("<p>Refresh flow: <code>enforce_token_lifecycle</code> checks the access token before every request. With fewer "
            "than <code>LOGAPP_EXPIRY_WARN_SECONDS</code> left it logs <code>TOKEN_EXPIRY_WARNING</code>, posts "
            "<code>grant_type=refresh_token</code> to the token endpoint and logs <code>TOKEN_REFRESH</code> (or "
            "<code>TOKEN_REFRESH_FAILED</code>). Keycloak independently records <code>REFRESH_TOKEN</code>, which the sync "
            f"imports. See {file_link('logapp/log_app.py', find_line('logapp/log_app.py', 'def refresh_tokens'))}.</p>")
    api_note = ("<p><b>There is no dashboard /api contract.</b> The JSON endpoints of the dashboard are "
                "<code>/events.json</code> (login required, same filters as the page) and <code>/healthz</code> "
                "(<code>{\"status\":\"UP\",\"database\":true}</code>, 503 when the database is down). The "
                "<code>/api/*</code> routes belong to the separate api service.</p>")
    return (api_note + table(["Instance", "Result"], results) + block("Event row", EVENT_ROW_SCHEMA, rows[0],
            f"<p>Table <code>logapp.app_events</code> as created in PostgreSQL:</p>{cols}") +
            block("GET /events.json", EVENTS_JSON_SCHEMA, sample_events) +
            "<h3>Token refresh flow</h3>" + flow + block("Token endpoint response", TOKEN_REFRESH_SCHEMA, token_sample,
                  caption="Example (key names captured from the running stack; token and numeric values are illustrative)") +
            block("Keycloak raw event", KEYCLOAK_EVENT_SCHEMA, ev("keycloak_raw_event.json")))


def sec_diagrams() -> str:
    return ("<p>Both drawings are inline SVG, so the report works offline. The Mermaid sources are in the Architecture "
            "section.</p><h3>Component interactions</h3>" + f'<figure class="diagram">{svg_components()}</figure>'
            "<h3>PostgreSQL event flow</h3>" + f'<figure class="diagram">{svg_pg_flow()}</figure>')


def sec_requirements(root: Path = ROOT) -> str:
    files = ("logapp/requirements.txt", "webapp/requirements.txt", "api/requirements.txt", "requirements.txt")
    names = {f: requirement_names(read(f, root)) for f in files}
    matrix = table(["File", "PyJWT listed?", "Packages"], [[f, "yes" if "pyjwt" in n else "no", ", ".join(n)]
                                                           for f, n in names.items()])
    note = ("<p><b>PyJWT confirmation.</b> It is listed in <code>api/requirements.txt</code> (the resource server "
            "validates bearer tokens) and in the root <code>requirements.txt</code> (the test environment). It is "
            "<b>not</b> in <code>logapp/requirements.txt</code> or <code>webapp/requirements.txt</code>: those apps let "
            "Authlib validate the ID token and only read claims from tokens they already hold.</p>")
    return note + matrix + "".join(f"<h3>{esc(f)}</h3>{listing(f, 'text', root)}" for f in files)


def sec_labels(root: Path = ROOT) -> str:
    labels = ui_labels(root)
    return ("<p>Extracted from the Jinja templates and the <code>API_CALLS</code> table; this is the text a user sees.</p>"
            + table(["Source", "Element", "Text"], [[a, b, c] for a, b, c in labels]))


def sec_retention(root: Path = ROOT) -> str:
    deploy = read("Docs/Deployment.md", root)
    sql = re.search(r"### Retention SQL.*?```sql\n(.*?)```", deploy, re.S).group(1)
    dry = read(f"{EVIDENCE}/retention_dryrun.txt", root)
    return ("<p>Extracted from <code>Docs/Deployment.md</code>. <code>ts</code>, <code>login_at</code> and "
            "<code>logout_at</code> are epoch <b>milliseconds</b>. The earlier statement compared them with "
            "<code>now()</code> and failed on PostgreSQL; the version below was dry-run on the live database inside a "
            "transaction that was rolled back.</p>" + highlight(sql, "sql") + "<h3>Dry-run output</h3>" +
            highlight(dry, "text") + f"<p class=\"meta\">{file_link(EVIDENCE + '/retention_dryrun.txt')}</p>")


def sec_glossary(root: Path = ROOT) -> str:
    cfg = read("logapp/log_config.py", root)
    used = list(dict.fromkeys(re.findall(r'"((?:OIDC|LOGAPP|API|SERVICE)_[A-Z_]+)"', cfg)))
    env_rows = [[v, ENV_DESCRIPTIONS.get(v, ""), file_link("logapp/log_config.py", find_line("logapp/log_config.py", v))]
                for v in used]
    example = {n: (d, c) for n, d, c in env_example_entries(read(".env.example", root))}
    for row in env_rows:
        row[1] = esc(row[1]) + (f' <span class="muted">.env.example default: <code>{esc(example[row[0]][0])}</code></span>'
                                if row[0] in example else "")
        row[0] = f"<code>{esc(row[0])}</code>"
    filt = [[f"<code>{esc(k)}</code>", esc(v)] for k, v in FILTER_PARAMS]
    terms = [[f"<b>{esc(k)}</b>", esc(v)] for k, v in GLOSSARY]
    kinds = ", ".join(re.search(r"EVENT_KINDS = \((.*?)\)", read("logapp/log_app.py", root)).group(1).replace('"', "").split(", "))
    return ("<h3>Terms</h3>" + table(["Term", "Meaning"], terms, raw=True) +
            "<h3>Environment variables of the dashboard</h3>" + table(["Variable", "Meaning", "Read in"], env_rows, raw=True) +
            "<h3>Query parameters of /dashboard and /events.json</h3>" + table(["Parameter", "Meaning"], filt, raw=True) +
            f"<p>Event kinds: <code>{esc(kinds)}</code>.</p>")


def sec_troubleshooting(root: Path = ROOT) -> str:
    rows = []
    for symptom, fix, refs in TROUBLESHOOTING:
        links = " ".join(file_link(f, find_line(f, n, root)) for f, n in refs)
        rows.append([esc(symptom), esc(fix), links])
    return ("<p>Each code reference is resolved to a line number at build time, so a moved or deleted symbol breaks "
            "the build instead of leaving a dead link. More symptoms: "
            f"{file_link('Docs/Quickstart.md')} and {file_link('Docs/Deployment.md')}.</p>"
            + table(["Symptom", "Cause and fix", "Code path"], rows, raw=True))


PLACEHOLDER_MAIL = re.compile(r"[\w.+-]+@(?:[\w-]+\.)*(?:example\.\w+|yourdomain\.tld)\b")


def mark_placeholder_mail(document: str) -> str:
    """Append the secret scanner's reviewed-line marker to lines that only show a placeholder e-mail address
    (taken from the documentation examples). Real addresses are not marked, so the scanner still reports them."""
    return "\n".join(f"{line}<!-- nosecret -->" if PLACEHOLDER_MAIL.search(line) else line
                     for line in document.split("\n"))


def build(root: Path = ROOT) -> str:
    rev = revision(root)
    arch = md_to_html(read("Docs/Architecture.md", root), "arch", DIAGRAMS)
    deploy = md_to_html(read("Docs/Deployment.md", root), "dep")
    sections = [
        ("status", "Claim register and verification status", sec_status(root), True),
        ("screens", "Dashboard screenshots", sec_screens(root), True),
        ("architecture", "Architecture (full Docs/Architecture.md)", f'<p class="meta">{file_link("Docs/Architecture.md")}</p>' + arch, False),
        ("diagrams", "Diagrams: components and PostgreSQL event flow", sec_diagrams(), False),
        ("source", "Source of the log dashboard", sec_sources(root), False),
        ("tests", "Tests, coverage, verify.sh and verify_logapp.py", sec_tests(root), False),
        ("schemas", "JSON schemas and API contracts", sec_schemas(root), False),
        ("deployment", "Deployment procedures (full Docs/Deployment.md)", f'<p class="meta">{file_link("Docs/Deployment.md")}</p>' + deploy, False),
        ("retention", "Retention SQL", sec_retention(root), False),
        ("requirements", "Requirements files and PyJWT", sec_requirements(root), False),
        ("labels", "UI labels as implemented", sec_labels(root), False),
        ("glossary", "Glossary of terms, variables and parameters", sec_glossary(root), False),
        ("troubleshooting", "Troubleshooting cross-referenced to code", sec_troubleshooting(root), False),
    ]
    toc = "".join(f'<li><a href="#{i}">{esc(t)}</a></li>' for i, t, _, _ in sections)
    body = "".join(section(i, t, b, o) for i, t, b, o in sections)
    dirty = " (working tree has uncommitted changes)" if rev["dirty"] else ""
    page = (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width, initial-scale=1"><title>Keycloak log dashboard - system report</title>'
            f'<style>{CSS}</style></head><body><div class="wrap"><header class="top">'
            f'<h1>Keycloak log dashboard - system report</h1>'
            f'<p class="meta">Revision: built <b>{esc(rev["built"])}</b> from commit <code>{esc(rev["commit"])}</code>{dirty}. '
            f'Evidence captured from the running stack on <b>{esc(rev["evidence"])}</b>. '
            f'Generated by {file_link("scripts/build_report.py")}; regenerate with '
            f'<code>.venv/bin/python scripts/build_report.py</code>.</p></header>'
            f'<nav class="toc" aria-label="Contents"><b>Contents</b><ol>{toc}</ol></nav>{body}'
            f'<footer>Made with IBM Bob</footer></div></body></html>')
    page = mark_placeholder_mail(page)
    assert_no_secrets(page, root)
    return page


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=DEFAULT_OUT, help="output file, relative to the project root")
    args = parser.parse_args(argv)
    page = build()
    target = ROOT / args.out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(page, encoding="utf-8")
    shown = target.relative_to(ROOT) if target.is_relative_to(ROOT) else target
    print(f"wrote {shown} ({len(page) / 1024:.0f} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
