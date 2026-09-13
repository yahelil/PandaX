"""Regulatory-shape tests: Annex VII/V completeness, VEX honesty, Art.14 timing.

These are the tests that matter for the product claim. Getting a technical file
wrong is how a compliance vendor mis-sells compliance, so the structure of the
output is asserted, not eyeballed.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from pandax.context import RunContext
from pandax.feeds import severity_from_vector
from pandax.stages import clock, dossier, triage

# --- Annex VII / Annex V ----------------------------------------------------

ANNEX_VII_ITEMS = ["1", "2", "3", "4", "5", "6", "7", "8"]
ANNEX_V_ITEMS = ["1", "2", "3", "4", "5", "6", "7", "8"]


def test_annex_vii_has_all_eight_items(ctx: RunContext):
    data = dossier.build_dossier(ctx)
    assert [s["item"] for s in data["annex_vii"]] == ANNEX_VII_ITEMS


def test_annex_v_has_all_eight_items(ctx: RunContext):
    data = dossier.build_dossier(ctx)
    assert [e["ref"] for e in data["annex_v"]] == ANNEX_V_ITEMS


def test_annex_vii_item_1_covers_all_four_subparagraphs(ctx: RunContext):
    data = dossier.build_dossier(ctx)
    item1 = next(s for s in data["annex_vii"] if s["item"] == "1")
    assert [e["ref"] for e in item1["entries"]] == ["1(a)", "1(b)", "1(c)", "1(d)"]


def test_every_entry_declares_its_provenance(ctx: RunContext):
    data = dossier.build_dossier(ctx)
    allowed = {dossier.DERIVED, dossier.ATTESTED, dossier.REQUIRED}
    entries = [e for s in data["annex_vii"] for e in s["entries"]] + data["annex_v"]
    assert entries
    assert all(e["status"] in allowed for e in entries)


def test_underivable_fields_are_flagged_not_invented(ctx: RunContext):
    """Photographs and Annex II user instructions cannot come from a build."""
    data = dossier.build_dossier(ctx)
    item1 = next(s for s in data["annex_vii"] if s["item"] == "1")
    for ref in ("1(c)", "1(d)"):
        entry = next(e for e in item1["entries"] if e["ref"] == ref)
        assert entry["status"] == dossier.REQUIRED
        assert entry["value"] == dossier.NEEDS_INPUT


def test_missing_manufacturer_metadata_becomes_required_input(run_dir, ledger):
    """With no product.yaml, nothing is fabricated - it is all marked required."""
    bare = RunContext(
        artifact=run_dir, run_dir=run_dir, run_id="run-test", ledger=ledger, product={}
    )
    (run_dir / "findings.cdx-vex.json").write_text("{}", encoding="utf-8")
    data = dossier.build_dossier(bare)
    assert data["summary"]["attested"] == 0
    assert data["summary"]["required_input"] > 0
    for entry in data["annex_v"]:
        assert dossier.NEEDS_INPUT in entry["value"] or entry["status"] != dossier.REQUIRED


def test_declaration_is_blocked_while_actively_exploited(ctx: RunContext):
    """Annex I Part I(2)(a): no known exploitable vulnerabilities."""
    data = dossier.build_dossier(ctx)
    statement = next(e for e in data["annex_v"] if e["ref"] == "5")
    assert statement["status"] == dossier.REQUIRED
    assert "CANNOT BE DECLARED" in statement["value"]


def test_declaration_is_allowed_once_nothing_is_exploited(ctx: RunContext):
    for finding in ctx.findings:
        finding.kev = False
    data = dossier.build_dossier(ctx)
    statement = next(e for e in data["annex_v"] if e["ref"] == "5")
    assert statement["status"] == dossier.DERIVED
    assert "in conformity with Regulation (EU) 2024/2847" in statement["value"]


# --- CycloneDX VEX ----------------------------------------------------------


def test_vex_is_cyclonedx_16_and_keeps_kev_separate_from_reachability(ctx: RunContext):
    vex = triage.build_vex(ctx)
    assert vex["bomFormat"] == "CycloneDX" and vex["specVersion"] == "1.6"
    states = {v["id"]: v["analysis"]["state"] for v in vex["vulnerabilities"]}
    assert states["CVE-2021-44228"] == "in_triage"
    assert states["CVE-2020-28500"] == "in_triage"


def test_vex_never_claims_not_affected(ctx: RunContext):
    """No reachability analysis is performed, so no suppression may be asserted."""
    vex = triage.build_vex(ctx)
    assert all(
        v["analysis"]["state"] != "not_affected" for v in vex["vulnerabilities"]
    )


def test_vex_points_at_real_sbom_bom_refs(ctx: RunContext):
    vex = triage.build_vex(ctx)
    known = {c["bom_ref"] for c in ctx.components}
    for entry in vex["vulnerabilities"]:
        assert entry["affects"][0]["ref"] in known


def test_vex_carries_cvss_and_epss_ratings(ctx: RunContext):
    vex = triage.build_vex(ctx)
    log4j = next(v for v in vex["vulnerabilities"] if v["id"] == "CVE-2021-44228")
    methods = {r["method"] for r in log4j["ratings"]}
    assert "CVSSv31" in methods and "other" in methods


# --- Article 14 -------------------------------------------------------------


def test_article_14_deadlines_match_the_statute():
    aware = dt.datetime(2026, 9, 6, 12, 0, tzinfo=dt.timezone.utc)
    due = clock.deadlines(aware)
    assert due["early_warning"] == "2026-09-07T12:00:00Z"  # 24h, Art.14(2)(a)
    assert due["notification"] == "2026-09-09T12:00:00Z"  # 72h, Art.14(2)(b)
    assert "final_report" not in due  # runs from confirmed measure availability


def test_clock_only_arms_for_actively_exploited(ctx: RunContext):
    for finding in ctx.findings:
        finding.kev = False
    list(clock.run(ctx))
    assert ctx.incidents == []
    assert not (ctx.run_dir / "incidents.json").exists()


def test_clock_writes_three_filings_per_incident(ctx: RunContext):
    list(clock.run(ctx))
    assert len(ctx.incidents) == 1
    target = ctx.run_dir / "filings" / "CVE-2021-44228"
    assert {p.name for p in target.iterdir()} == {
        "early_warning.json",
        "notification.json",
        "final_report.json",
    }


@pytest.mark.parametrize(
    "filing,article,required",
    [
        (
            "early_warning",
            "Art.14(2)(a)",
            [
                "actively_exploited_vulnerability",
                "member_states_made_available",
                "product",
            ],
        ),
        (
            "notification",
            "Art.14(2)(b)",
            [
                "product_general_information",
                "general_nature_of_vulnerability",
                "general_nature_of_exploit",
                "corrective_or_mitigating_measures_taken",
                "measures_users_can_take",
                "sensitivity_of_information",
            ],
        ),
        (
            "final_report",
            "Art.14(2)(c)",
            [
                "vulnerability_description_severity_impact",
                "malicious_actor_information",
                "security_update_details",
            ],
        ),
    ],
)
def test_filings_carry_every_field_the_article_requires(
    ctx: RunContext, filing: str, article: str, required: list[str]
):
    list(clock.run(ctx))
    path = ctx.run_dir / "filings" / "CVE-2021-44228" / f"{filing}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["article_ref"] == article
    assert list(payload["article_14_fields"]) == required
    # Every field must name the sub-paragraph that requires it.
    assert all("article_ref" in field for field in payload["article_14_fields"].values())


def test_early_warning_reports_the_member_states(ctx: RunContext):
    list(clock.run(ctx))
    payload = json.loads(
        (ctx.run_dir / "filings" / "CVE-2021-44228" / "early_warning.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["article_14_fields"]["member_states_made_available"]["value"] == ["NL", "DE"]
    assert payload["coordinating_csirt_member_state"] == "NL"  # Art.14(7)


def test_final_report_uses_srp_fields_and_does_not_invent_its_deadline(ctx: RunContext):
    list(clock.run(ctx))
    payload = json.loads(
        (ctx.run_dir / "filings" / "CVE-2021-44228" / "final_report.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["due_by"] is None
    assert payload["submission_status"].startswith("INCOMPLETE DRAFT")
    assert payload["fields"]["notification_level"]["value"] == "Final"
    assert payload["fields"]["date_time_corrective_or_mitigating_measure_available"][
        "value"
    ] == "MANUFACTURER INPUT REQUIRED"
    assert {"full_description_severity", "full_description_impact"} <= set(payload["fields"])


# --- severity banding -------------------------------------------------------


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CRITICAL"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "LOW"),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N", "MEDIUM"),
        ("", "UNKNOWN"),
    ],
)
def test_severity_banding(vector: str, expected: str):
    assert severity_from_vector(vector) == expected


# --- declaration of conformity, Article 28 ----------------------------------


def test_declaration_carries_the_regulation_publication_reference(ctx: RunContext):
    """Art.28(3) identifies Union acts 'including their publication references'."""
    data = dossier.build_dossier(ctx)
    ref = data["regulation_reference"]
    assert "2024/2847" in ref["title"]
    assert ref["oj"] == "OJ L, 2024/2847, 20.11.2024"
    assert ref["eli"] == "http://data.europa.eu/eli/reg/2024/2847/oj"


def test_ce_marking_block_is_present_and_never_drawn(ctx: RunContext):
    """Art.30(1): for software the CE marking goes on the declaration.

    The graphic form is prescribed by Annex II to Regulation (EC) No 765/2008,
    so the tool must not synthesise one - it reserves the space instead.
    """
    data = dossier.build_dossier(ctx)
    ce = data["ce_marking"]
    assert ce["applies"] is True
    assert "765/2008" in ce["form"]
    assert "5 mm" in ce["placement"]
    assert ce["artwork"] == ""  # nothing invented when none is supplied


def test_retention_statement_matches_annex_viii(ctx: RunContext):
    """Annex VIII Part I(4.2): 10 years or the support period, whichever longer."""
    statement = dossier.build_dossier(ctx)["retention"]["statement"]
    assert "10 years" in statement and "whichever is longer" in statement


def test_annex_v_item_8_is_additional_information_not_the_signature(ctx: RunContext):
    """Annex V item 8 is 'Additional information:'; the signature block follows it."""
    data = dossier.build_dossier(ctx)
    item8 = next(e for e in data["annex_v"] if e["ref"] == "8")
    assert "Signed for and on behalf of" not in item8["value"]
    assert "Support period" in item8["value"]


def test_simplified_declaration_needs_the_full_text_address(ctx: RunContext):
    """Art.13(20): the simplified declaration must carry the exact address."""
    data = dossier.build_dossier(ctx)
    assert data["doc_url"] == "https://example.invalid/doc"

    ctx.product["vulnerability_handling"]["declaration_url"] = ""
    assert dossier.build_dossier(ctx)["doc_url"] == ""
