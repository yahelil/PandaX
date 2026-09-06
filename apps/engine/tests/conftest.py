from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from pandax.context import Finding, RunContext
from pandax.evidence import Ledger

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    target = tmp_path / "run-test"
    target.mkdir()
    return target


@pytest.fixture
def ledger(run_dir: Path) -> Ledger:
    return Ledger(run_dir)


@pytest.fixture
def product() -> dict:
    return {
        "product": {
            "name": "SmartHub SH-100",
            "type": "Smart home hub",
            "version": "2.3.1",
            "unique_id": "PDX-SH100-EU",
            "intended_purpose": "Residential smart-home gateway.",
            "risk_tier": "default",
            "conformity_route": "Module A",
            "support_period_months": 60,
            "support_period_rationale": "Five years.",
        },
        "manufacturer": {
            "legal_name": "PandaX Devices B.V.",
            "address": "Keizersgracht 1, Amsterdam",
            "main_establishment_ms": "NL",
            "signatory_name": "A. Bakker",
            "signatory_function": "Head of Product Security",
            "place_of_issue": "Amsterdam",
        },
        "vulnerability_handling": {
            "cvd_policy_url": "https://example.invalid/cvd",
            "contact_address": "security@example.invalid",
            "security_txt_url": "https://example.invalid/.well-known/security.txt",
            "secure_update_mechanism": "Signed dual-bank OTA.",
            "markets_available": ["NL", "DE"],
        },
    }


@pytest.fixture
def ctx(run_dir: Path, ledger: Ledger, product: dict) -> RunContext:
    context = RunContext(
        artifact=Path("artifact.zip"),
        run_dir=run_dir,
        run_id="run-test",
        ledger=ledger,
        product=product,
    )
    context.components = [
        {
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "name": "log4j-core",
            "version": "2.14.1",
            "type": "library",
            "bom_ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?id=a",
        },
        {
            "purl": "pkg:npm/lodash@4.17.15",
            "name": "lodash",
            "version": "4.17.15",
            "type": "library",
            "bom_ref": "pkg:npm/lodash@4.17.15?id=b",
        },
    ]
    context.findings = [
        Finding(
            cve="CVE-2021-44228",
            osv_id="GHSA-jfh8-c2jp-5v3q",
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            component="log4j-core",
            version="2.14.1",
            summary="Remote code injection in Log4j",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            severity="CRITICAL",
            fixed_version="2.15.0",
            kev=True,
            kev_date_added="2021-12-10",
            kev_action="Apply updates.",
            epss=0.99999,
            bom_ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?id=a",
        ),
        Finding(
            cve="CVE-2020-28500",
            osv_id="GHSA-29mw-wpgm-hmr9",
            purl="pkg:npm/lodash@4.17.15",
            component="lodash",
            version="4.17.15",
            summary="ReDoS in lodash",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            severity="MEDIUM",
            fixed_version="4.17.21",
            epss=0.012,
            bom_ref="pkg:npm/lodash@4.17.15?id=b",
        ),
    ]
    (run_dir / "findings.cdx-vex.json").write_text("{}", encoding="utf-8")
    return context


@pytest.fixture
def make_zip():
    """Build a zip from an explicit {arcname: content} map.

    Uses writestr directly so traversal names like "../evil" survive into the
    archive - zipfile.write() would normalise them away.
    """

    def build(path: Path, entries: dict[str, bytes]) -> Path:
        with zipfile.ZipFile(path, "w") as zf:
            for name, blob in entries.items():
                zf.writestr(name, blob)
        return path

    return build
