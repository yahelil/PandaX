from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import cryptography
import pytest

from pandax.case_snapshot import snapshot_bytes
from pandax.evidence import (
    Ledger,
    load_or_create_key,
    verify_bundle as product_verify_bundle,
    write_manifest,
    write_public_key,
)
from pandax_verifier.verification import verify_bundle
from test_case_fields import ready_case
from test_case_review import IDENTITY
from test_case_service import service


def _make_product_bundle(tmp_path: Path) -> tuple[Path, Path]:
    run = tmp_path / "engine-run"
    run.mkdir()
    evidence = run / "evidence.json"
    evidence.write_text('{"source":"PandaX engine"}', encoding="utf-8")
    ledger = Ledger(run)
    ledger.append("TEST", "pandax", "0.1.0", [], [ledger.ref(evidence)])
    key = load_or_create_key(tmp_path / "installation-private.pem")
    write_manifest(
        run,
        run.name,
        {"name": "Device", "version": "1"},
        {"pandax": "0.1.0"},
        ledger,
        key,
    )
    trusted = tmp_path / "installation-public.pem"
    write_public_key(key, trusted)
    return run, trusted


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("changed", "invalid"),
        ("deleted", "incomplete"),
        ("unexpected", "invalid"),
    ],
)
def test_product_and_external_verifiers_agree_on_scan_bundle(
    tmp_path, mutation, expected
):
    run, trusted = _make_product_bundle(tmp_path)

    product = product_verify_bundle(run, trusted)
    external = verify_bundle(run, trusted)

    assert product.status == external.status == "trusted"
    assert product.integrity_ok == external.integrity_ok is True
    assert product.signature_valid == external.signature_valid is True
    assert product.bundle_key_fingerprint == external.bundle_key_fingerprint

    if mutation == "changed":
        (run / "evidence.json").write_text("tampered", encoding="utf-8")
    elif mutation == "deleted":
        (run / "evidence.json").unlink()
    else:
        (run / "injected.txt").write_text("not sealed", encoding="utf-8")
    assert product_verify_bundle(run, trusted).status == expected
    assert verify_bundle(run, trusted).status == expected


def test_external_verifier_accepts_real_case_snapshot(service, tmp_path):
    case = ready_case(service, "vulnerability", "notification")
    body = {
        "request_id": "external-verifier-snapshot",
        "expected_version": case["version"],
        **IDENTITY,
        "revision": case["report"]["revision"],
    }
    case = service.execute("snapshot", body, case["id"])
    saved = case["snapshots"][-1]
    archive = tmp_path / "case-snapshot.zip"
    archive.write_bytes(snapshot_bytes(service, case["id"], saved["id"]))
    signing_key = load_or_create_key(tmp_path / "data" / "installation-signing-key.pem")
    trusted = tmp_path / "case-public.pem"
    write_public_key(signing_key, trusted)

    result = verify_bundle(archive, trusted)

    assert result.status == "trusted"
    assert result.integrity_ok and result.signature_valid


def test_verifier_source_has_no_product_or_network_imports():
    source_root = Path(__file__).resolve().parents[1] / "src" / "pandax_verifier"
    forbidden = {"pandax", "httpx", "requests", "socket", "urllib"}
    imported: set[str] = set()
    for source in source_root.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])

    assert imported.isdisjoint(forbidden)


def test_cli_runs_when_product_package_is_not_importable(tmp_path):
    run, trusted = _make_product_bundle(tmp_path)
    verifier_source = Path(__file__).resolve().parents[1] / "src"
    site_packages = Path(cryptography.__file__).resolve().parents[1]
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join([str(verifier_source), str(site_packages)]),
        "PYTHONNOUSERSITE": "1",
    }
    script = (
        "import importlib.util,sys; "
        "assert importlib.util.find_spec('pandax') is None; "
        "from pandax_verifier.cli import main; "
        f"sys.exit(main([{str(run)!r}, '--trusted-key', {str(trusted)!r}, '--json']))"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert '"status": "trusted"' in completed.stdout
