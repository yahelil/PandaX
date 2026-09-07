from __future__ import annotations

import threading

from pandax.feeds import Feeds as BaseFeeds
from pandax.stages import match


def test_match_resolves_advisories_concurrently(ctx):
    advisory_ids = ["GHSA-test-0001", "GHSA-test-0002"]
    barrier = threading.Barrier(len(advisory_ids))
    lock = threading.Lock()
    active = 0
    peak_active = 0

    class Feeds(BaseFeeds):
        def __init__(self):
            pass

        def query_purls(self, purls):
            return {purl: advisory_ids for purl in purls}

        def vuln_detail(self, osv_id):
            nonlocal active, peak_active
            with lock:
                active += 1
                peak_active = max(peak_active, active)
            try:
                barrier.wait(timeout=0.5)
                return {"id": osv_id, "aliases": ["CVE-2026-0001"]}
            finally:
                with lock:
                    active -= 1

    list(match.run(ctx, Feeds()))

    assert peak_active > 1


def test_fixed_version_does_not_match_purl_prefix():
    advisory = {
        "affected": [
            {
                "package": {"purl": "pkg:npm/foo"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"fixed": "9.9.9"}]}
                ],
            }
        ]
    }

    assert match._fixed_version(advisory, "pkg:npm/foobar@1.0.0") == ""
