"""Evaluate the engine against real, third-party artifacts.

The demo fixture is circular: its components were chosen *because* they carry
known-exploited CVEs, so detecting them proves little. This harness scans
artifacts nobody here assembled, and checks the results three ways:

  1. Ground truth   - CVEs the vendor's own advisories say affect this release,
                      and CVEs that must NOT appear (fixed before it shipped).
  2. Differential   - the same product, an old release and a late one. A real
                      scanner shows the old one is worse; a broken one does not.
  3. Independent    - Grype, a separate scanner with a separate database
                      (Anchore's, built from NVD/GitHub feeds) run over the same
                      artifact. Agreement is evidence; disagreement is a lead.

Everything is digest-pinned, so a rerun scans identical bytes.

    uv run python tools/evaluate.py            # scan + compare
    uv run python tools/evaluate.py --report   # print the last results
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "workspace" / "tools"
CORPUS = ROOT / "evaluation" / "corpus"
RESULTS = ROOT / "evaluation" / "results"

GRYPE_VERSION = "0.118.0"
GRYPE_BUILDS = {
    ("Windows", "AMD64"): (
        f"grype_{GRYPE_VERSION}_windows_amd64.zip",
        "82fb07f246e61526e8f2bf187fc6bb29ed23c7450cda6e9d1868a60fb942fc98",
        "grype.exe",
    ),
    ("Linux", "x86_64"): (
        f"grype_{GRYPE_VERSION}_linux_amd64.tar.gz",
        "1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2",
        "grype",
    ),
    ("Darwin", "arm64"): (
        f"grype_{GRYPE_VERSION}_darwin_arm64.tar.gz",
        "938f050bb5076c8aa761867b39843abad2414dfe4cc82b7d36886e634f49c640",
        "grype",
    ),
}


@dataclass
class Target:
    """A real third-party artifact with vendor-published expectations."""

    name: str
    url: str
    sha256: str
    note: str
    # CVEs the vendor's advisories say affect this release. Detecting these is
    # the test; each carries the advisory that is the source of truth.
    must_find: dict[str, str] = field(default_factory=dict)
    # CVEs fixed *before* this release shipped. Reporting one is a false
    # positive, which matters as much as a miss.
    must_not_find: dict[str, str] = field(default_factory=dict)


# Three targets chosen so that detection must follow the artifact's actual
# contents. The first two are the SAME product at the SAME version, packaged
# differently: a scanner that guesses from name and version cannot tell them
# apart, and will fail one of them.
TARGETS = [
    Target(
        name="struts-2.5.12-full",
        url="https://archive.apache.org/dist/struts/2.5.12/struts-2.5.12-lib.zip",
        sha256="c75922069cf0ec83723a2c678552c4098361179181b03c1fbb7855a852547884",
        note="Struts 2.5.12 full distribution, 93 jars - includes the REST plugin",
        must_find={
            "CVE-2017-9805": "S2-052, REST plugin RCE (KEV) - struts2-rest-plugin IS bundled here",
            "CVE-2018-11776": "S2-057, namespace RCE (KEV) - affects struts2-core 2.5.12",
        },
    ),
    Target(
        name="struts-2.5.12-min",
        url="https://archive.apache.org/dist/struts/2.5.12/struts-2.5.12-min-lib.zip",
        sha256="80c9d177e866f4138de9278a36bf9da9dabdb8e313e526aa3e864c2068157600",
        note="Struts 2.5.12 minimum libs, 8 jars - same version, no REST plugin",
        must_find={
            "CVE-2018-11776": "S2-057 - struts2-core is present, so this must still fire",
        },
        must_not_find={
            "CVE-2017-9805": "S2-052 - struts2-rest-plugin is NOT in this package, so "
            "reporting it would be a false positive",
        },
    ),
    Target(
        name="struts-2.5.33-min",
        url="https://archive.apache.org/dist/struts/2.5.33/struts-2.5.33-min-lib.zip",
        sha256="5dde2aa5a9f93e73fe9f8105d1902a2da277f19695c8093b6e97450d53c42b4e",
        note="Struts 2.5.33 (Dec 2023), last of the 2.5 line - the differential control",
        must_not_find={
            "CVE-2017-9805": "S2-052, fixed in 2.5.13 - six years before this release",
            "CVE-2018-11776": "S2-057, fixed in 2.5.17 - five years before this release",
        },
    ),
]


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def fetch(url: str, expect: str, dest: Path) -> str:
    """Download unless already present and matching. Returns the digest."""
    if dest.exists():
        digest = sha256_bytes(dest.read_bytes())
        if not expect or digest == expect:
            return digest
    print(f"  downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "pandax-eval"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        blob = resp.read()
    digest = sha256_bytes(blob)
    if expect and digest != expect:
        raise SystemExit(
            f"digest mismatch for {url}\n  expected {expect}\n  got      {digest}"
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(blob)
    print(f"    {len(blob):,} bytes  sha256:{digest[:16]}...")
    return digest


def install_grype() -> Path:
    import platform
    import stat
    import tarfile
    import io

    key = (platform.system(), platform.machine())
    if key not in GRYPE_BUILDS:
        raise SystemExit(f"no pinned grype build for {key}")
    asset, digest, binname = GRYPE_BUILDS[key]
    dest = TOOLS / binname
    if dest.exists():
        return dest
    url = f"https://github.com/anchore/grype/releases/download/v{GRYPE_VERSION}/{asset}"
    print(f"  downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "pandax-eval"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        blob = resp.read()
    got = sha256_bytes(blob)
    if got != digest:
        raise SystemExit(f"grype digest mismatch: expected {digest}, got {got}")
    TOOLS.mkdir(parents=True, exist_ok=True)
    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf, open(dest, "wb") as out:
            shutil.copyfileobj(zf.open(binname), out)
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            member = tf.extractfile(binname)
            if member is None:
                raise SystemExit(f"{binname} missing from {asset}")
            with open(dest, "wb") as out:
                shutil.copyfileobj(member, out)
    dest.chmod(dest.stat().st_mode | stat.S_IEXEC)
    print(f"    grype v{GRYPE_VERSION} installed, sha256 verified")
    return dest


def run_pandax(artifact: Path, out_base: Path) -> dict:
    """Scan with the engine under test and return its findings."""
    from pandax import events as ev
    from pandax import pipeline

    summary: dict = {}
    for event in pipeline.run(artifact, out_base=out_base):
        if event.kind == ev.RUN_DONE:
            summary = dict(event.data)
    run_dir = Path(summary["run_dir"])
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    sbom = json.loads((run_dir / "sbom.cdx.json").read_text(encoding="utf-8"))
    return {
        "run_dir": str(run_dir),
        "components": [c["purl"] for c in sbom.get("components", []) if c.get("purl")],
        "cves": sorted({f["cve"] for f in findings}),
        "kev": sorted({f["cve"] for f in findings if f["kev"]}),
    }


def run_grype(grype: Path, artifact: Path, out: Path) -> dict:
    """Scan the same artifact with an independent tool and database."""
    proc = subprocess.run(
        [str(grype), f"file:{artifact}", "-o", "json", "-q"],
        capture_output=True,
        text=True,
        encoding="utf-8",      # Windows would otherwise decode as cp1252 and fail
        errors="replace",
        timeout=1800,
    )
    if not proc.stdout:
        return {"error": (proc.stderr or "no output")[:400], "cves": [], "components": []}
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()[:400], "cves": [], "components": []}
    data = json.loads(proc.stdout)
    out.write_text(proc.stdout, encoding="utf-8")
    cves = set()
    for match in data.get("matches", []):
        vid = match.get("vulnerability", {}).get("id", "")
        if vid.startswith("CVE-"):
            cves.add(vid)
        for related in match.get("relatedVulnerabilities", []) or []:
            rid = related.get("id", "")
            if rid.startswith("CVE-"):
                cves.add(rid)
    return {
        "cves": sorted(cves),
        "components": sorted(
            {
                a.get("artifact", {}).get("purl", "")
                for a in data.get("matches", [])
                if a.get("artifact", {}).get("purl")
            }
        ),
    }


def evaluate() -> int:
    CORPUS.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)

    print("\nPandaX evaluation - third-party artifacts, independent cross-check")
    print("=" * 76)
    grype = install_grype()

    report = {"targets": []}
    for target in TARGETS:
        print(f"\n### {target.name} - {target.note}")
        artifact = CORPUS / Path(target.url).name
        digest = fetch(target.url, target.sha256, artifact)

        print("  scanning with pandax ...")
        mine = run_pandax(artifact, RESULTS / target.name)
        print(f"    {len(mine['components'])} components, {len(mine['cves'])} CVEs, "
              f"{len(mine['kev'])} KEV")

        print("  scanning with grype (independent DB) ...")
        theirs = run_grype(grype, artifact, RESULTS / f"{target.name}.grype.json")
        if theirs.get("error"):
            print(f"    grype failed: {theirs['error']}")
        else:
            print(f"    {len(theirs['components'])} components, {len(theirs['cves'])} CVEs")

        mine_set, theirs_set = set(mine["cves"]), set(theirs["cves"])
        report["targets"].append(
            {
                "name": target.name,
                "note": target.note,
                "artifact": artifact.name,
                "sha256": digest,
                "pandax": mine,
                "grype": theirs,
                "must_find": {
                    cve: {"found": cve in mine_set, "source": why}
                    for cve, why in target.must_find.items()
                },
                "must_not_find": {
                    cve: {"absent": cve not in mine_set, "source": why}
                    for cve, why in target.must_not_find.items()
                },
                "agreement": {
                    "both": sorted(mine_set & theirs_set),
                    "pandax_only": sorted(mine_set - theirs_set),
                    "grype_only": sorted(theirs_set - mine_set),
                },
            }
        )

    (RESULTS / "evaluation.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print_report(report)
    return 0 if verdict(report) else 1


def verdict(report: dict) -> bool:
    for t in report["targets"]:
        if not all(v["found"] for v in t["must_find"].values()):
            return False
        if not all(v["absent"] for v in t["must_not_find"].values()):
            return False
    return True


def print_report(report: dict) -> None:
    print("\n" + "=" * 76)
    print("RESULTS")
    print("=" * 76)

    for t in report["targets"]:
        mine, theirs = t["pandax"], t["grype"]
        print(f"\n{t['name']}  ({t['note']})")
        print(f"  artifact sha256 {t['sha256'][:32]}...")
        # NB: grype's JSON reports only the artifacts it matched, not its full
        # catalogue, so its component count is not comparable to pandax's SBOM.
        print(f"  pandax : {len(mine['components']):>4} components catalogued  "
              f"{len(mine['cves']):>4} findings  {len(mine['kev']):>3} KEV")
        print(f"  grype  : {len(theirs.get('components', [])):>4} components matched   "
              f"{len(theirs.get('cves', [])):>4} findings")

        for cve, r in t["must_find"].items():
            mark = "PASS" if r["found"] else "FAIL"
            print(f"    [{mark}] must find    {cve}  ({r['source']})")
        for cve, r in t["must_not_find"].items():
            mark = "PASS" if r["absent"] else "FAIL"
            print(f"    [{mark}] must NOT find {cve}  ({r['source']})")

        # Compare CVE identifiers only. Advisories that carry no CVE id yet
        # (GHSA-*, PYSEC-*) are real findings, but grype indexes by CVE, so
        # counting them as disagreements would understate the agreement.
        mine = {c for c in mine["cves"] if c.startswith("CVE-")}
        theirs_cves = {c for c in theirs.get("cves", []) if c.startswith("CVE-")}
        both, only_mine, only_theirs = (
            mine & theirs_cves,
            mine - theirs_cves,
            theirs_cves - mine,
        )
        total = len(mine | theirs_cves)
        if total:
            print(f"    agreement with grype: {len(both)}/{total} CVEs "
                  f"({100 * len(both) // total}%)  "
                  f"pandax-only {sorted(only_mine) or 0}  "
                  f"grype-only {sorted(only_theirs) or 0}")
        no_cve = [c for c in t["pandax"]["cves"] if not c.startswith("CVE-")]
        if no_cve:
            print(f"    plus {len(no_cve)} advisories with no CVE assigned yet: "
                  f"{', '.join(no_cve[:3])}")

    print("\ndifferential (pandax):")
    for t in report["targets"]:
        print(f"    {t['name']:24} {len(t['pandax']['cves']):>4} CVEs  "
              f"{len(t['pandax']['kev']):>2} KEV  "
              f"{len(t['pandax']['components']):>3} components")

    print("\n" + ("ALL GROUND-TRUTH CHECKS PASSED" if verdict(report)
                  else "GROUND-TRUTH CHECKS FAILED"))
    print()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", action="store_true", help="print last results")
    args = parser.parse_args()
    if args.report:
        path = RESULTS / "evaluation.json"
        if not path.exists():
            raise SystemExit("no results yet - run without --report first")
        print_report(json.loads(path.read_text(encoding="utf-8")))
        return 0
    return evaluate()


if __name__ == "__main__":
    sys.exit(main())
