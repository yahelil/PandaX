"""Vulnerability intelligence sources, with an on-disk cache.

Three feeds, each chosen for a distinct job and each verified reachable
without an API key:

  OSV.dev   deterministic PURL -> vulnerability matching, batched
  CISA KEV  "actively exploited" - the fact that starts the Article 14 clock
  EPSS      probability of exploitation in the next 30 days, for ranking

NVD was dropped: it needs an API key, is rate-limited, and OSV already
aggregates the same advisories with better package-level precision.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterable

import httpx

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"

OSV_BATCH_SIZE = 100
KEV_MAX_AGE_SECONDS = 6 * 3600
TIMEOUT = httpx.Timeout(60.0, connect=20.0)


class FeedError(Exception):
    """Raised when a vulnerability feed cannot be reached or parsed."""


class Feeds:
    """Feed client. Caches vulnerability details so reruns are fast and offline-ish."""

    def __init__(self, cache_dir: Path, offline: bool = False):
        self.cache_dir = Path(cache_dir)
        self.vuln_cache = self.cache_dir / "osv"
        self.vuln_cache.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self._client: httpx.Client | None = None
        self.last_epss_status = "unknown"
        self.last_epss_errors: list[str] = []

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=TIMEOUT, headers={"User-Agent": "pandax-poc/0.1"}
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # --- OSV ---------------------------------------------------------------

    def query_purls(self, purls: Iterable[str]) -> dict[str, list[str]]:
        """Map each PURL to the OSV vulnerability ids affecting it."""
        purls = list(purls)
        result: dict[str, list[str]] = {p: [] for p in purls}
        for start in range(0, len(purls), OSV_BATCH_SIZE):
            chunk = purls[start : start + OSV_BATCH_SIZE]
            payload = {"queries": [{"package": {"purl": p}} for p in chunk]}
            try:
                resp = self.client.post(OSV_BATCH_URL, json=payload)
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                raise FeedError(f"OSV querybatch failed: {exc}") from exc
            try:
                results = resp.json().get("results", [])
                if not isinstance(results, list) or len(results) != len(chunk):
                    raise ValueError("response did not contain one result per query")
                for purl, entry in zip(chunk, results):
                    vulns = entry.get("vulns", [])
                    if not isinstance(vulns, list):
                        raise ValueError("vulns must be a list")
                    result[purl] = [v["id"] for v in vulns]
            except (KeyError, TypeError, ValueError) as exc:
                raise FeedError(f"OSV querybatch returned malformed results: {exc}") from exc
        return result

    def vuln_detail(self, osv_id: str) -> dict[str, Any]:
        """Fetch one OSV advisory, cached on disk by id."""
        cached = self.vuln_cache / f"{osv_id}.json"
        if cached.exists():
            return json.loads(cached.read_text(encoding="utf-8"))
        if self.offline:
            raise FeedError(f"{osv_id} not cached and feeds are offline")
        try:
            resp = self.client.get(OSV_VULN_URL.format(id=osv_id))
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise FeedError(f"OSV detail {osv_id} failed: {exc}") from exc
        data = resp.json()
        cached.write_text(json.dumps(data), encoding="utf-8")
        return data

    # --- CISA KEV ----------------------------------------------------------

    def kev(self) -> dict[str, dict[str, Any]]:
        """CISA Known Exploited Vulnerabilities, keyed by CVE id."""
        cached = self.cache_dir / "kev.json"
        fresh = (
            cached.exists()
            and (time.time() - cached.stat().st_mtime) < KEV_MAX_AGE_SECONDS
        )
        if not fresh and not self.offline:
            try:
                resp = self.client.get(KEV_URL)
                resp.raise_for_status()
                cached.write_text(json.dumps(resp.json()), encoding="utf-8")
            except httpx.HTTPError as exc:
                if not cached.exists():
                    raise FeedError(f"CISA KEV fetch failed: {exc}") from exc
        if not cached.exists():
            raise FeedError("CISA KEV feed unavailable and not cached")
        data = json.loads(cached.read_text(encoding="utf-8"))
        return {v["cveID"]: v for v in data.get("vulnerabilities", [])}

    def kev_released(self) -> str:
        cached = self.cache_dir / "kev.json"
        if not cached.exists():
            return "unknown"
        return json.loads(cached.read_text(encoding="utf-8")).get("dateReleased", "")

    # --- EPSS --------------------------------------------------------------

    def epss(self, cves: Iterable[str]) -> dict[str, float]:
        """Exploit Prediction Scoring System values, best effort."""
        cves = [c for c in cves if c.startswith("CVE-")]
        scores: dict[str, float] = {}
        self.last_epss_errors = []
        if not cves:
            self.last_epss_status = "unscanned"
            return scores
        if self.offline:
            self.last_epss_status = "unscanned"
            return scores
        self.last_epss_status = "completed"
        for start in range(0, len(cves), 100):
            chunk = cves[start : start + 100]
            try:
                resp = self.client.get(EPSS_URL, params={"cve": ",".join(chunk)})
                resp.raise_for_status()
                for row in resp.json().get("data", []):
                    scores[row["cve"]] = float(row.get("epss", 0.0))
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                # EPSS is enrichment, not a gate: a miss must not fail a scan.
                self.last_epss_status = "failed"
                self.last_epss_errors.append(str(exc))
                continue
        return scores


def severity_from_vector(vector: str) -> str:
    """Coarse severity band from a CVSS v3 base score embedded in a vector.

    OSV gives the vector, not the score. Rather than pull in a CVSS library for
    one number, findings are banded by the fields that dominate the base score.
    """
    if not vector:
        return "UNKNOWN"
    parts = dict(
        piece.split(":", 1) for piece in vector.split("/") if ":" in piece
    )
    impacts = [parts.get(k, "N") for k in ("C", "I", "A")]
    high = impacts.count("H")
    network = parts.get("AV") == "N"
    low_complexity = parts.get("AC") == "L"
    no_privileges = parts.get("PR") == "N"
    no_interaction = parts.get("UI") == "N"

    if high == 3 and network and low_complexity and no_privileges:
        return "CRITICAL"
    if high >= 2 and network:
        return "HIGH"
    if high >= 1 and network and no_interaction:
        return "HIGH"
    if high >= 1:
        return "MEDIUM"
    return "LOW"
