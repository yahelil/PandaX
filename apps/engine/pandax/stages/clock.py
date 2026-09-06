"""S5 CLOCK - CRA Article 14 reporting deadlines and ENISA filing drafts.

The blueprint proposed a Temporal.io cluster here. A durable workflow engine to
track three timestamps per incident is not a viability question - it is an
operational choice for later. What *is* a viability question is whether the
filing content can be produced correctly and automatically, so that is what
this stage does.

Every field below carries an `article_ref` naming the sub-paragraph of
Regulation (EU) 2024/2847 that requires it. Article 14(2), verbatim:

  (a) early warning, within 24 hours of becoming aware, indicating where
      applicable the Member States in which the product has been made available;
  (b) vulnerability notification, within 72 hours, providing general information
      about the product, the general nature of the exploit and of the
      vulnerability, corrective or mitigating measures taken, measures users can
      take, and how sensitive the manufacturer considers the information;
  (c) final report, no later than 14 days after a corrective or mitigating
      measure is available, including (i) a description of the vulnerability
      including severity and impact, (ii) where available, information about any
      malicious actor exploiting it, and (iii) details about the security update
      or other corrective measures.

The notifications are generated, not submitted: the ENISA single reporting
platform (Article 16) does not go live until 11 September 2026.
"""

from __future__ import annotations

import datetime as dt
import json

from .. import events as ev
from ..context import Finding, RunContext
from ..evidence import sha256_file

STAGE = "S5 CLOCK"

EARLY_WARNING_HOURS = 24
NOTIFICATION_HOURS = 72
FINAL_REPORT_DAYS = 14


def _iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _short(iso: str) -> str:
    """2026-09-07T16:20:27Z -> 07 Sep 16:20, so the table fits a terminal."""
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime(
        "%d %b %H:%M"
    )


def deadlines(aware_at: dt.datetime) -> dict[str, str]:
    """The three statutory deadlines from the moment of awareness."""
    return {
        "early_warning": _iso(aware_at + dt.timedelta(hours=EARLY_WARNING_HOURS)),
        "notification": _iso(aware_at + dt.timedelta(hours=NOTIFICATION_HOURS)),
        "final_report": _iso(aware_at + dt.timedelta(days=FINAL_REPORT_DAYS)),
    }


def _early_warning(finding: Finding, ctx: RunContext, aware_at: dt.datetime) -> dict:
    handling = ctx.product.get("vulnerability_handling", {})
    return {
        "filing_type": "early_warning",
        "article_ref": "Art.14(2)(a)",
        "deadline_hours": EARLY_WARNING_HOURS,
        "aware_at": _iso(aware_at),
        "due_by": deadlines(aware_at)["early_warning"],
        "fields": {
            "actively_exploited_vulnerability": {
                "article_ref": "Art.14(1)",
                "value": finding.cve,
                "basis": (
                    "Listed in the CISA Known Exploited Vulnerabilities catalogue"
                    f" since {finding.kev_date_added}."
                ),
            },
            "member_states_made_available": {
                "article_ref": "Art.14(2)(a)",
                "value": handling.get("markets_available", []),
            },
            "product": {
                "article_ref": "Art.14(2)(a)",
                "value": _product_identity(ctx),
            },
        },
    }


def _notification(finding: Finding, ctx: RunContext, aware_at: dt.datetime) -> dict:
    handling = ctx.product.get("vulnerability_handling", {})
    corrective = (
        f"Upgrade {finding.component} to {finding.fixed_version} or later."
        if finding.fixed_version
        else "MANUFACTURER INPUT REQUIRED - no fixed version published upstream."
    )
    return {
        "filing_type": "vulnerability_notification",
        "article_ref": "Art.14(2)(b)",
        "deadline_hours": NOTIFICATION_HOURS,
        "aware_at": _iso(aware_at),
        "due_by": deadlines(aware_at)["notification"],
        "fields": {
            "product_general_information": {
                "article_ref": "Art.14(2)(b)",
                "value": _product_identity(ctx),
            },
            "general_nature_of_vulnerability": {
                "article_ref": "Art.14(2)(b)",
                "value": finding.summary
                or "MANUFACTURER INPUT REQUIRED - no advisory summary available.",
                "cvss_vector": finding.cvss_vector,
                "severity": finding.severity,
            },
            "general_nature_of_exploit": {
                "article_ref": "Art.14(2)(b)",
                "value": finding.kev_action
                or "MANUFACTURER INPUT REQUIRED - describe observed exploitation.",
                "epss_probability": round(finding.epss, 6),
            },
            "corrective_or_mitigating_measures_taken": {
                "article_ref": "Art.14(2)(b)",
                "value": "MANUFACTURER INPUT REQUIRED - confirm measures deployed.",
                "suggested": corrective,
            },
            "measures_users_can_take": {
                "article_ref": "Art.14(2)(b)",
                "value": corrective,
                "update_mechanism": handling.get("secure_update_mechanism", ""),
            },
            "sensitivity_of_information": {
                "article_ref": "Art.14(2)(b)",
                "value": "MANUFACTURER INPUT REQUIRED - TLP marking.",
            },
        },
    }


def _final_report(finding: Finding, ctx: RunContext, aware_at: dt.datetime) -> dict:
    return {
        "filing_type": "final_report",
        "article_ref": "Art.14(2)(c)",
        "deadline_days": FINAL_REPORT_DAYS,
        "deadline_basis": (
            "Art.14(2)(c): no later than 14 days after a corrective or mitigating "
            "measure is available. A fixed upstream version is already published, "
            "so the clock is measured from the moment of awareness."
            if finding.fixed_version
            else "Art.14(2)(c): clock starts once a corrective measure is available; "
            "no upstream fix is published yet, so this date is provisional."
        ),
        "aware_at": _iso(aware_at),
        "due_by": deadlines(aware_at)["final_report"],
        "fields": {
            "vulnerability_description_severity_impact": {
                "article_ref": "Art.14(2)(c)(i)",
                "value": finding.summary,
                "severity": finding.severity,
                "cvss_vector": finding.cvss_vector,
                "impact": "MANUFACTURER INPUT REQUIRED - product-specific impact.",
            },
            "malicious_actor_information": {
                "article_ref": "Art.14(2)(c)(ii)",
                "value": "Not available to the manufacturer. See CISA KEV entry.",
                "kev_date_added": finding.kev_date_added,
            },
            "security_update_details": {
                "article_ref": "Art.14(2)(c)(iii)",
                "value": (
                    f"Upgrade {finding.component} {finding.version} -> "
                    f"{finding.fixed_version}."
                    if finding.fixed_version
                    else "MANUFACTURER INPUT REQUIRED - no upstream fix published."
                ),
            },
        },
    }


def _product_identity(ctx: RunContext) -> dict:
    product = ctx.product.get("product", {})
    manufacturer = ctx.product.get("manufacturer", {})
    return {
        "name": product.get("name", ""),
        "version": product.get("version", ""),
        "unique_id": product.get("unique_id", ""),
        "manufacturer": manufacturer.get("legal_name", ""),
    }


def run(ctx: RunContext) -> ev.Stream:
    yield ev.start(STAGE, "CRA Article 14 statutory clock")

    hits = ctx.kev_findings
    if not hits:
        yield ev.log(
            STAGE,
            "no actively exploited vulnerabilities - Article 14 not triggered",
            ev.GOOD,
        )
        yield ev.done(STAGE, "no reporting obligation")
        return

    manufacturer = ctx.product.get("manufacturer", {})
    csirt_ms = manufacturer.get("main_establishment_ms", "")
    yield ev.log(
        STAGE,
        f"coordinating CSIRT: {csirt_ms or 'UNKNOWN'} (Art.14(7), main establishment)",
    )

    aware_at = dt.datetime.now(dt.timezone.utc)
    filings_dir = ctx.path("filings")
    filings_dir.mkdir(parents=True, exist_ok=True)

    outputs = []
    incidents = []
    clock_rows: list[list[str]] = []
    for finding in sorted(hits, key=lambda f: -f.epss):
        due = deadlines(aware_at)
        incident = {
            "incident_id": f"{ctx.run_id}-{finding.cve}",
            "cve": finding.cve,
            "component": f"{finding.component} {finding.version}",
            "purl": finding.purl,
            "aware_at": _iso(aware_at),
            "trigger": "CISA KEV listing (actively exploited)",
            "kev_date_added": finding.kev_date_added,
            "epss": round(finding.epss, 6),
            "coordinating_csirt_member_state": csirt_ms,
            "submission_route": (
                "ENISA single reporting platform (Art.16). No public API; the "
                "platform is not operational until 11 Sept 2026. Filings below "
                "are generated for human sign-off, not submitted."
            ),
            "deadlines": due,
            "status": "early_warning_pending",
        }
        incidents.append(incident)

        target = filings_dir / finding.cve.replace("/", "_")
        target.mkdir(parents=True, exist_ok=True)
        for name, builder in (
            ("early_warning", _early_warning),
            ("notification", _notification),
            ("final_report", _final_report),
        ):
            path = target / f"{name}.json"
            payload = builder(finding, ctx, aware_at)
            payload["incident_id"] = incident["incident_id"]
            payload["coordinating_csirt_member_state"] = csirt_ms
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            outputs.append(path)

        clock_rows.append(
            [finding.cve] + [_short(due[k]) for k in
                             ("early_warning", "notification", "final_report")]
        )

    yield ev.alert(
        STAGE,
        f">> {len(incidents)} statutory clock(s) started - deadlines are UTC",
    )
    yield ev.table(
        STAGE,
        "Article 14 deadlines",
        ["CVE ID", "24h warning (a)", "72h notice (b)", "14d final (c)"],
        clock_rows,
        ev.ALERT_LVL,
    )

    incidents_path = ctx.path("incidents.json")
    incidents_path.write_text(json.dumps(incidents, indent=2), encoding="utf-8")
    outputs.append(incidents_path)
    ctx.incidents = incidents

    yield ev.metric(STAGE, "incidents opened", len(incidents))
    yield ev.metric(STAGE, "filing drafts", len(outputs) - 1)
    yield ev.artifact(
        STAGE, ctx.ledger.rel(incidents_path), sha256_file(incidents_path)
    )

    ctx.ledger.append(
        stage="S5_CLOCK",
        tool="pandax.article14",
        tool_version="0.1.0",
        inputs=[ctx.ledger.ref(ctx.path("findings.cdx-vex.json"))],
        outputs=[ctx.ledger.ref(p) for p in outputs],
        params={
            "early_warning_hours": EARLY_WARNING_HOURS,
            "notification_hours": NOTIFICATION_HOURS,
            "final_report_days": FINAL_REPORT_DAYS,
            "regulation": "(EU) 2024/2847 Art.14(2)",
        },
    )
    yield ev.done(
        STAGE, f"{len(incidents)} incident clock(s) armed", ev.ALERT_LVL
    )
