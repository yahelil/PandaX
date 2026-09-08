"""Firmware boundaries, transport, root selection, and existing ingest integration."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from pandax import firmware as fw
from pandax.firmware_worker import select_root
from pandax.native import inventory
from pandax.stages import ingest


def transport(path, entries=None, status="completed"):
    report = {"status": status, "reason": "test extraction outcome", "unblob_version": "26.6.4",
              "handler": "squashfs_v4_le", "root": "firmware.bin_extract", "links": []}
    files = entries if entries is not None else [("root/etc/openwrt_release", b"DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='23.05.5'"),
        ("root/usr/lib/opkg/status", b"Package: busybox\nVersion: 1.36.1-r2\nStatus: install ok installed\n")]
    report.update(file_count=len(files), uncompressed_bytes=sum(len(data) for _, data in files))
    files = [(fw.REPORT, json.dumps(report).encode()), (fw.RAW_REPORT, b"[]")] + files
    with tarfile.open(path, "w") as tf:
        for name, content in files:
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            tf.addfile(entry, io.BytesIO(content))


def fake_docker(monkeypatch, status="completed"):
    monkeypatch.setattr(fw.shutil, "which", lambda _: "docker")
    def run(docker, src, archive, log, limits):
        transport(archive, status=status)
        log.write_text("extractor diagnostic", encoding="utf-8")
    monkeypatch.setattr(fw, "_run_container", run)


def test_limits_are_read_per_job_and_validated(monkeypatch):
    assert fw.Limits.from_env() == fw.Limits()
    monkeypatch.setenv("PANDAX_FIRMWARE_MAX_FILES", "17")
    assert fw.Limits.from_env().max_files == 17
    for bad in ("0", "-1", "a", "1.5"):
        monkeypatch.setenv("PANDAX_FIRMWARE_MAX_FILES", bad)
        with pytest.raises(fw.FirmwareError, match="positive integer"):
            fw.Limits.from_env()


def test_oversized_input_is_rejected_before_copy_or_docker(tmp_path, ctx, monkeypatch):
    ctx.artifact = tmp_path / "firmware.bin"
    ctx.artifact.write_bytes(b"large input")
    monkeypatch.setenv("PANDAX_FIRMWARE_MAX_INPUT_BYTES", "3")
    with pytest.raises(ingest.UnsafeArtifact, match="max_input_bytes"):
        list(ingest.run(ctx))
    assert not (ctx.run_dir / "input/firmware.bin").exists()
    assert ctx.extracted_dir is None
    assert json.loads(ctx.path(fw.REPORT).read_text())["status"] == "failed"


def test_no_docker_has_actionable_diagnostic(tmp_path, monkeypatch):
    monkeypatch.setattr(fw.shutil, "which", lambda _: None)
    src = tmp_path / "firmware.bin"
    src.write_bytes(b"hsqs")
    with pytest.raises(fw.FirmwareError, match="Docker Desktop"):
        fw.extract(src, tmp_path / "extracted")
    report = json.loads((tmp_path / fw.REPORT).read_text())
    assert report["source_sha256"] == fw.sha256_file(src)
    assert report["status"] != "completed"


def test_ingestion_preserves_contract_inventory_and_provenance(tmp_path, ctx, monkeypatch):
    fake_docker(monkeypatch)
    ctx.artifact = tmp_path / "firmware.bin"
    ctx.artifact.write_bytes(b"hsqs")
    list(ingest.run(ctx))
    assert ctx.extracted_dir == ctx.run_dir / "extracted"
    assert inventory(ctx.extracted_dir)["components"][0]["name"] == "busybox"
    assert ctx.tool_versions["unblob"] == "26.6.4"
    report = json.loads(ctx.path(fw.REPORT).read_text())
    assert report["status"] == "completed"
    assert report["source_sha256"] == fw.sha256_file(ctx.artifact)
    outputs = {o["path"] for o in ctx.ledger.records[-1]["outputs"]}
    assert {fw.REPORT, fw.RAW_REPORT, fw.LOG, "ingest_tree.json"} <= outputs
    tree = json.loads(ctx.path("ingest_tree.json").read_text())
    assert tree["file_count"] == 2
    assert "etc/openwrt_release" in tree["files"]


@pytest.mark.parametrize("status", ["partial", "encrypted", "unsupported", "failed"])
def test_incomplete_extraction_never_reaches_inventory(tmp_path, ctx, monkeypatch, status):
    fake_docker(monkeypatch, status)
    ctx.artifact = tmp_path / "firmware.bin"
    ctx.artifact.write_bytes(b"hsqs")
    with pytest.raises(ingest.UnsafeArtifact):
        list(ingest.run(ctx))
    assert ctx.extracted_dir is None
    assert not list((ctx.run_dir / "extracted").iterdir())
    assert json.loads(ctx.path(fw.REPORT).read_text())["status"] == status
    assert ctx.path(fw.RAW_REPORT).exists()
    assert not list(ctx.run_dir.glob(".firmware-*"))


@pytest.mark.parametrize("name", ["root/../escape", "root/C:/escape", "root/a\\escape",
                                    "root//absolute", "root/NUL", "root/file:stream"])
def test_host_refuses_unsafe_paths(tmp_path, name):
    archive = tmp_path / "transport.tar"
    transport(archive, [(name, b"bad")])
    with pytest.raises(fw.FirmwareError):
        fw._receive(archive, tmp_path / "root", tmp_path, fw.Limits())


def test_host_refuses_links_and_case_collisions(tmp_path):
    archive = tmp_path / "transport.tar"
    with tarfile.open(archive, "w") as tf:
        entry = tarfile.TarInfo("root/escape")
        entry.type = tarfile.SYMTYPE
        entry.linkname = "../../outside"
        tf.addfile(entry)
    with pytest.raises(fw.FirmwareError, match="invalid entry"):
        fw._receive(archive, tmp_path / "root", tmp_path, fw.Limits())
    transport(archive, [("root/Etc/a", b"a"), ("root/etc/b", b"b")])
    with pytest.raises(fw.FirmwareError, match="case-colliding"):
        fw._receive(archive, tmp_path / "root", tmp_path, fw.Limits())


@pytest.mark.parametrize("limits", [fw.Limits(max_output_bytes=2), fw.Limits(max_files=1)])
def test_host_enforces_output_limits(tmp_path, limits):
    archive = tmp_path / "transport.tar"
    transport(archive)
    with pytest.raises(fw.FirmwareError, match="limits|too many"):
        fw._receive(archive, tmp_path / "root", tmp_path, limits)


def test_container_command_has_isolation_and_configured_limits(tmp_path):
    src = tmp_path / "folder, with spaces" / "firmware.bin"
    cmd = fw.command("docker", src, "job", fw.Limits(max_output_bytes=10000, max_files=25))
    for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--pull=never",
                 "--security-opt=no-new-privileges", "--user=1000:1000"):
        assert flag in cmd
    assert any("size=10000,nr_inodes=26" in arg and "noexec" in arg for arg in cmd)
    assert sum(arg.endswith(",readonly") for arg in cmd) == 2
    assert fw.IMAGE in cmd
    assert "folder, with spaces" in cmd[cmd.index("--mount") + 1]


def test_timeout_removes_container_not_just_client(tmp_path, monkeypatch):
    calls = []
    class Process:
        returncode = None
        def poll(self): return self.returncode
        def kill(self): self.returncode = -1
        def wait(self, **kwargs): return self.returncode
    proc = Process()
    monkeypatch.setattr(fw.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(fw.subprocess, "run", lambda args, **k: calls.append(args))
    clock = iter([0, 2])
    monkeypatch.setattr(fw.time, "monotonic", lambda: next(clock))
    with pytest.raises(fw.FirmwareError, match="timeout"):
        fw._run_container("docker", tmp_path / "input", tmp_path / "out.tar",
                          tmp_path / "log", fw.Limits(timeout_seconds=1))
    assert calls[0][:3] == ["docker", "rm", "-f"]
    assert proc.returncode == -1


def test_worker_child_logs_cannot_corrupt_binary_transport():
    worker = Path(fw.__file__).with_name("firmware_worker.py")
    script = """
import importlib.metadata, os, runpy, sys, types
importlib.metadata.version = lambda _: '26.6.4'
def process_file(*args):
    os.write(1, b'extractor child log\\n')
    return types.SimpleNamespace(to_json=lambda: '[]')
processing = types.ModuleType('unblob.processing')
processing.ExtractionConfig = lambda **kwargs: None
processing.process_file = process_file
sys.modules['unblob'] = types.ModuleType('unblob')
sys.modules['unblob.processing'] = processing
handlers = types.ModuleType('unblob.handlers')
handlers.BUILTIN_HANDLERS = []
sys.modules['unblob.handlers'] = handlers
models = types.ModuleType('unblob.models')
models.HandlerType = types.SimpleNamespace(FILESYSTEM='filesystem')
sys.modules['unblob.models'] = models
runpy.run_path(sys.argv[1], run_name='__main__')
"""
    result = subprocess.run([sys.executable, "-c", script, str(worker)],
                            check=True, capture_output=True, timeout=15)
    assert b"extractor child log" in result.stderr
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tf:
        assert json.load(tf.extractfile(fw.REPORT))["status"] == "unsupported"
        assert json.load(tf.extractfile(fw.RAW_REPORT)) == []


def root_reports(work, count=1):
    results = []
    for i in range(count):
        root = work / f"root{i}"
        root.mkdir(exist_ok=True)
        results.append({"task": {"path": "/input/firmware.bin", "depth": 0},
            "reports": [{"__typename__": "ChunkReport", "id": str(i),
                         "handler_name": "ubifs", "extraction_reports": [], "is_encrypted": False}],
            "subtasks": [{"blob_id": str(i), "path": str(root), "depth": 1}]})
    return results


@pytest.mark.parametrize("count,status", [(0, "unsupported"), (1, "completed"), (2, "unsupported")])
def test_one_filesystem_root_only(tmp_path, count, status):
    report, root = select_root(root_reports(tmp_path, count), tmp_path)
    assert report["status"] == status
    assert (root is not None) == (count == 1)


def test_inventory_subdirectories_are_not_extra_filesystem_roots(tmp_path):
    results = root_reports(tmp_path)
    child = tmp_path / "root0/etc"
    child.mkdir()
    results.append({"task": {"path": str(child.parent), "depth": 1}, "reports": [],
                    "subtasks": [{"blob_id": "0", "path": str(child), "depth": 1}]})
    report, root = select_root(results, tmp_path)
    assert report["status"] == "completed"
    assert root == child.parent


def test_other_filesystem_is_not_silently_ignored(tmp_path):
    results = root_reports(tmp_path)
    results[0]["reports"].append({"__typename__": "ChunkReport", "id": "other",
                                   "handler_name": "extfs", "extraction_reports": []})
    report, root = select_root(results, tmp_path, {"ubifs", "extfs"})
    assert report["status"] == "unsupported"
    assert root is None


@pytest.mark.parametrize("problem,status", [
    ({"__typename__": "ExtractCommandFailedReport", "severity": "WARNING"}, "partial"),
    ({"__typename__": "PathTraversalProblem"}, "partial"),
    ({"__typename__": "ChunkReport", "is_encrypted": True}, "encrypted"),
    ({"__typename__": "UnknownChunkReport"}, "partial"),
])
def test_worker_fails_closed_even_when_extractor_exit_was_zero(tmp_path, problem, status):
    results = root_reports(tmp_path)
    results[0]["reports"].append(problem)
    report, root = select_root(results, tmp_path)
    assert report["status"] == status
    assert root is None
