"""Unit tests for scripts/build_report.py: parsers, schema checker, secret guard, claim register and a full build."""
import json
import re
from pathlib import Path

import pytest

import build_report as br


def text_of(markup: str) -> str:
    """Visible text of highlighted markup (Pygments splits every token into its own span)."""
    import html
    return html.unescape(re.sub(r"<[^>]+>", "", markup))

ROOT = Path(__file__).resolve().parents[1]


# ----------------------------------------------------------------------------- evidence parsers

def test_pytest_summary_reads_last_line():
    assert br.pytest_summary("....\n213 passed in 0.75s\n") == (213, 0)
    assert br.pytest_summary("2 failed, 5 passed in 1s") == (5, 2)
    assert br.pytest_summary("nothing here") == (0, 0)


def test_per_file_test_counts():
    text = "  14 Devs/x/tests/test_a.py\n   7 Devs/x/tests/test_b.py\nnoise\n"
    assert br.per_file_test_counts(text) == {"test_a.py": 14, "test_b.py": 7}


def test_coverage_rows_and_total():
    text = ("Name Stmts Miss Branch BrPart Cover Missing\n"
            "logapp/store.py   157  10  40  2  94%   73-74, 83-85\n"
            "logapp/log_config.py  49  0  6  0  100%\n"
            "TOTAL  206  10  46  2  95%\n")
    rows, total = br.coverage_rows(text)
    assert [r["name"] for r in rows] == ["logapp/store.py", "logapp/log_config.py"]
    assert rows[0]["missing"] == "73-74, 83-85" and rows[1]["cover"] == 100
    assert total["stmts"] == 206 and total["cover"] == 95


def test_verify_counts():
    assert br.verify_counts("PASS  a\nPASS  b\nFAIL  c\n") == (2, 1, False)
    assert br.verify_counts("PASS  a\n\nVERIFY OK\n") == (1, 0, True)


def test_pg_columns_filters_by_table():
    text = (" app_events | id | bigint | NO | \n app_events | ip | text | YES | \n sync_state | name | text | NO | \n")
    assert br.pg_columns(text, "app_events") == [("id", "bigint", False), ("ip", "text", True)]
    assert br.pg_columns(text, "missing") == []


def test_requirement_names_strips_extras_pins_and_comments():
    text = "PyJWT[crypto]==2.15.1  # tokens\nFlask>=3\n\n# comment\npsycopg[binary]==3.3\nSome_Pkg~=1.0\n"
    assert br.requirement_names(text) == ["pyjwt", "flask", "psycopg", "some-pkg"]


def test_env_example_entries_attach_the_comment_above():
    text = "# --- group ---\n# Port of x.\nPORT=8083\nPLAIN=1\n# Many\n# lines\nQUOTED=\"a b\"\n"
    assert br.env_example_entries(text) == [("PORT", "8083", "Port of x."), ("PLAIN", "1", ""),
                                            ("QUOTED", "a b", "Many lines")]


# ----------------------------------------------------------------------------- secret guard

ENV = 'KC_PASSWORD=supersecret1\nKEYCLOAK_VERSION=26.8.2\nSOME_SECRET="quoted-secret"\nSHORT_PASSWORD=abc\nPORT=8083\n'  # nosecret: fake fixture


def test_secret_values_only_picks_secret_like_names_and_long_values():
    assert br.secret_values(ENV) == ["supersecret1", "quoted-secret"]


def test_keycloak_version_is_not_treated_as_a_secret():
    assert "26.8.2" not in br.secret_values(ENV)


def test_assert_no_secrets_fails_when_a_value_leaks(tmp_path):
    (tmp_path / ".env").write_text(ENV)
    br.assert_no_secrets("harmless page with 26.8.2", tmp_path)
    with pytest.raises(SystemExit) as exc:
        br.assert_no_secrets("page that contains supersecret1", tmp_path)
    assert "supersecret1" not in str(exc.value)


def test_assert_no_secrets_ignores_missing_env(tmp_path):
    br.assert_no_secrets("anything", tmp_path)


# ----------------------------------------------------------------------------- schema checker

def test_validate_accepts_and_rejects():
    schema = {"type": "object", "additionalProperties": False, "required": ["a"],
              "properties": {"a": {"type": "integer"}, "b": {"type": ["string", "null"]},
                             "c": {"type": "string", "enum": ["x", "y"]}}}
    assert br.validate({"a": 1, "b": None, "c": "x"}, schema) == []
    assert any("missing required 'a'" in e for e in br.validate({}, schema))
    assert any("unexpected 'z'" in e for e in br.validate({"a": 1, "z": 1}, schema))
    assert any("expected integer" in e for e in br.validate({"a": "1"}, schema))
    assert any("expected integer" in e for e in br.validate({"a": True}, schema))
    assert any("not in" in e for e in br.validate({"a": 1, "c": "q"}, schema))


def test_validate_const_arrays_and_refs():
    schema = {"type": "object", "properties": {"k": {"const": 1}, "xs": {"type": "array", "items": {"$ref": "#/$defs/i"}}},
              "$defs": {"i": {"type": "integer"}}}
    assert br.validate({"k": 1, "xs": [1, 2]}, schema) == []
    assert br.validate({"k": 2}, schema)
    assert br.validate({"xs": [1, "no"]}, schema)


def test_real_evidence_validates_against_the_contracts():
    ev = ROOT / br.EVIDENCE
    rows = json.loads((ev / "event_rows.json").read_text())
    assert all(br.validate(r, br.EVENT_ROW_SCHEMA) == [] for r in rows)
    assert br.validate({"total": 2, "page": 1, "page_size": 25, "events": rows}, br.EVENTS_JSON_SCHEMA) == []
    assert br.validate(json.loads((ev / "keycloak_raw_event.json").read_text()), br.KEYCLOAK_EVENT_SCHEMA) == []


def test_event_schema_rejects_unknown_source_and_extra_column():
    row = {"id": 1, "ts": 1, "source": "other", "kind": "auth", "event_type": "X", "dedupe_key": None}
    assert br.validate(row, br.EVENT_ROW_SCHEMA)
    assert br.validate({**row, "source": "app", "surprise": 1}, br.EVENT_ROW_SCHEMA)


def test_event_schema_matches_the_columns_of_the_store():
    import store
    assert set(br.EVENT_ROW_SCHEMA["properties"]) == set(store._COLUMNS) | {"id"}


# ----------------------------------------------------------------------------- source and markdown helpers

def test_find_line_and_file_link():
    line = br.find_line("logapp/log_app.py", "class TokenVault")
    assert line > 1
    link = br.file_link("logapp/log_app.py", line)
    assert f'href="../logapp/log_app.py#L{line}"' in link
    with pytest.raises(LookupError):
        br.find_line("logapp/log_app.py", "no such text anywhere 9f3a")


def test_listing_contains_the_file_verbatim_and_is_highlighted():
    html_out = br.listing("scripts/verify_logapp.py", "python")
    assert "scripts/verify_logapp.py" in html_out and 'class="hl"' in html_out
    assert "def check(" in text_of(html_out)
    assert (ROOT / "scripts/verify_logapp.py").read_text().rstrip() in text_of(html_out)


def test_highlight_falls_back_to_text_for_unknown_language():
    assert "plain" in br.highlight("plain", "no-such-lexer-xyz")


def test_md_to_html_highlights_code_and_prefixes_anchors():
    md = "# Title\n\n## Sub part\n\nSee [sub](#sub-part).\n\n```python\nx = 1\n```\n"
    out = br.md_to_html(md, "pre")
    assert 'id="pre-title"' in out and 'id="pre-sub-part"' in out  # toc ids carry the section prefix
    assert 'id="title"' not in out and 'href="#pre-sub-part"' in out
    assert 'class="hl"' in out and "<h3" in out and "<h4" in out


def test_md_to_html_mermaid_uses_registered_svg_or_notes_its_absence():
    md = "```mermaid\nflowchart TB\n  A-->B\n```\n\n```mermaid\nsequenceDiagram\n  participant Z\n```\n"
    out = br.md_to_html(md, "m", {"participant Z": "<svg>drawn</svg>"})
    assert out.count("<svg>drawn</svg>") == 1
    assert "no static drawing" in out and out.count("Mermaid source") == 2


def test_svg_diagrams_are_well_formed_and_self_contained():
    import xml.dom.minidom as minidom
    for svg in (br.svg_components(), br.svg_pg_flow()):
        minidom.parseString(svg)
        assert "http://" not in svg.replace("http://www.w3.org/2000/svg", "")
    assert "PostgreSQL" in br.svg_pg_flow() and "Keycloak" in br.svg_components()


# ----------------------------------------------------------------------------- claims and labels

def test_claims_have_the_expected_statuses():
    by_claim = {c["claim"]: c for c in br.claims()}
    assert by_claim["All unit tests pass"]["status"] == "VERIFIED"
    assert by_claim["scripts/verify.sh passes end to end"]["status"] == "VERIFIED"
    assert by_claim["PyJWT is listed in the requirements of logapp and webapp"]["status"] == "NOT TRUE"
    assert by_claim["The dashboard exposes an /api contract"]["status"] == "NOT TRUE"
    assert by_claim["The retention SQL is deployed as currently documented"]["status"] == "CORRECTED"
    assert by_claim["Keycloak events have no id"]["status"] == "CORRECTED"
    assert not [c for c in by_claim.values() if c["status"] == "NOT VERIFIED"]
    assert all(c["evidence"] for c in by_claim.values())


def test_claims_report_not_verified_when_evidence_is_missing_or_wrong(tmp_path):
    for rel in ("logapp", "webapp", "api", "Docs/report-assets/evidence", "keycloak/realm"):
        (tmp_path / rel).mkdir(parents=True, exist_ok=True)
    for rel in ("logapp/requirements.txt", "webapp/requirements.txt", "api/requirements.txt", "requirements.txt",
                ".env.example", "Docs/Deployment.md"):
        (tmp_path / rel).write_text("flask\n")
    (tmp_path / "logapp/log_app.py").write_text("")
    (tmp_path / "keycloak/realm/demo-realm.json").write_text('{"enabledEventTypes": []}')
    ev = tmp_path / "Docs/report-assets/evidence"
    (ev / "pytest.txt").write_text("1 failed, 2 passed in 1s\n")
    (ev / "test_counts.txt").write_text("  3 x/tests/test_a.py\n")
    (ev / "coverage.txt").write_text("TOTAL 10 5 2 1 50%\n")
    (ev / "verify.txt").write_text("PASS a\nFAIL b\n")
    (ev / "containers.txt").write_text("a (unhealthy)\n")
    (ev / "retention_dryrun.txt").write_text("nothing\n")
    (ev / "pg_schema.txt").write_text("")
    (ev / "keycloak_raw_event.json").write_text('{"id": "short", "type": "LOGIN"}')
    statuses = {c["claim"]: c["status"] for c in br.claims(tmp_path)}
    assert statuses["All unit tests pass"] == "NOT VERIFIED"
    assert statuses["Branch coverage of the project code"] == "NOT VERIFIED"
    assert statuses["scripts/verify.sh passes end to end"] == "NOT VERIFIED"
    assert statuses["All five containers are healthy"] == "NOT VERIFIED"
    assert statuses["The retention SQL is deployed as currently documented"] == "NOT VERIFIED"
    assert statuses["Keycloak events have no id"] == "NOT VERIFIED"


def test_ui_labels_are_extracted_from_templates_and_api_calls():
    labels = {(page, kind, text) for page, kind, text in br.ui_labels()}
    assert ("dashboard.html", "label", "Origin") in labels
    assert ("dashboard.html", "label", "Live (5 s)") in labels
    assert ("dashboard.html", "button", "Apply") in labels
    assert ("admin.html", "tile", "Active sessions") in labels
    assert ("admin.html", "button", "Sync now") in labels
    assert ("log_app.py", "API_CALLS[me]", "Who am I?") in labels
    assert ("dashboard.html", "link", "Older »") in labels


# ----------------------------------------------------------------------------- full build

@pytest.fixture(scope="module")
def page():
    return br.build()


def test_build_is_self_contained(page):
    assert page.startswith("<!DOCTYPE html>") and "<script" not in page
    assert not re.search(r'(?:src|poster|action)="(?:https?:)?//', page)
    assert not re.search(r"@import|url\(\s*https?", page)
    assert page.count("data:image/jpeg;base64,") == 4


def test_build_has_every_requested_section(page):
    for sid in ("status", "screens", "architecture", "diagrams", "source", "tests", "schemas", "deployment",
                "retention", "requirements", "labels", "glossary", "troubleshooting"):
        assert f'id="{sid}"' in page
    assert page.count("<details") >= 20 and "Revision: built" in page and "Made with IBM Bob" in page


def test_build_internal_anchors_resolve_and_linked_files_exist(page):
    ids = set(re.findall(r'id="([^"]+)"', page))
    assert {h for h in re.findall(r'href="#([^"]+)"', page) if h not in ids} == set()
    for href in re.findall(r'href="\.\./([^"#]+)', page):
        assert (ROOT / href).exists(), href


def test_build_embeds_numbers_from_the_evidence_not_literals(page):
    passed, _ = br.pytest_summary((ROOT / br.EVIDENCE / "pytest.txt").read_text())
    assert f"{passed} passed" in page
    assert "def main(" in text_of(page) and "verify_logapp.py" in page


def test_build_states_the_false_premises_honestly(page):
    assert "NOT TRUE" in page and "There is no dashboard /api contract" in page
    assert "<b>not</b> in <code>logapp/requirements.txt</code>" in page
    assert "LOGAPP_DATABASE_URL" in page and "bigint &lt; timestamp with time zone" in page


def test_build_never_contains_env_secrets(page):
    env = ROOT / ".env"
    if env.exists():
        assert not [v for v in br.secret_values(env.read_text()) if v in page]


def test_main_writes_the_report(tmp_path, capsys):
    out = tmp_path / "r.html"
    assert br.main(["--out", str(out)]) == 0
    assert "wrote" in capsys.readouterr().out and out.read_text().startswith("<!DOCTYPE html>")


def test_placeholder_mail_is_marked_but_real_mail_is_not():
    real = "someone@" + "corp.internal"  # built at run time: a fake address, not a literal one
    doc = f"ACME_EMAIL=you@yourdomain.tld\ncontact: admin@example.com\nreal: {real}"
    marked = br.mark_placeholder_mail(doc).split("\n")
    assert marked[0].endswith("<!-- nosecret -->") and marked[1].endswith("<!-- nosecret -->")
    assert marked[2] == f"real: {real}"
