from __future__ import annotations

import json
import os
import time

import httpx
import pytest

from pandax.feeds import (
    KEV_MAX_AGE_SECONDS,
    OSV_DETAIL_MAX_AGE_SECONDS,
    FeedError,
    Feeds,
)


class FailingClient:
    def get(self, url, **kwargs):
        raise httpx.ConnectError("offline", request=httpx.Request("GET", url))


def _make_stale(path, age):
    timestamp = time.time() - age - 60
    os.utime(path, (timestamp, timestamp))


def test_online_osv_detail_refresh_does_not_hide_behind_stale_cache(tmp_path):
    feeds = Feeds(tmp_path)
    cached = tmp_path / "osv" / "CVE-2026-1000.json"
    cached.write_text('{"id":"old"}', encoding="utf-8")
    _make_stale(cached, OSV_DETAIL_MAX_AGE_SECONDS)
    feeds._client = FailingClient()

    with pytest.raises(FeedError, match="OSV detail"):
        feeds.vuln_detail("CVE-2026-1000")


def test_online_kev_refresh_does_not_report_stale_cache_as_current(tmp_path):
    feeds = Feeds(tmp_path)
    cached = tmp_path / "kev.json"
    cached.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    _make_stale(cached, KEV_MAX_AGE_SECONDS)
    feeds._client = FailingClient()

    with pytest.raises(FeedError, match="CISA KEV fetch failed"):
        feeds.kev()


def test_explicit_offline_mode_can_use_stale_cached_sources(tmp_path):
    feeds = Feeds(tmp_path, offline=True)
    osv = tmp_path / "osv" / "CVE-2026-1000.json"
    osv.write_text('{"id":"cached"}', encoding="utf-8")
    kev = tmp_path / "kev.json"
    kev.write_text(
        json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-1000"}]}),
        encoding="utf-8",
    )
    _make_stale(osv, OSV_DETAIL_MAX_AGE_SECONDS)
    _make_stale(kev, KEV_MAX_AGE_SECONDS)

    assert feeds.vuln_detail("CVE-2026-1000")["id"] == "cached"
    assert "CVE-2026-1000" in feeds.kev()
