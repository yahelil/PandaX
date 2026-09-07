from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pandax import cli, pipeline


runner = CliRunner()


def test_scan_sbom_command_forwards_options(monkeypatch, tmp_path: Path):
    source = tmp_path / "bom.json"
    source.write_text("{}", encoding="utf-8")
    out = tmp_path / "results"
    captured = {}
    stream = iter(())

    def run_sbom(path, out_base=None, offline=False):
        captured.update(path=path, out=out_base, offline=offline)
        return stream

    def render(source_path, received_stream, quiet, input_label="artifact", subtitle=""):
        captured.update(
            source=source_path,
            stream=received_stream,
            quiet=quiet,
            input_label=input_label,
            subtitle=subtitle,
        )

    monkeypatch.setattr(pipeline, "run_sbom", run_sbom)
    monkeypatch.setattr(cli, "_render_pipeline", render)

    result = runner.invoke(
        cli.app,
        ["scan-sbom", str(source), "--out", str(out), "--offline", "--quiet"],
    )

    assert result.exit_code == 0
    assert captured["path"] == source
    assert captured["out"] == out
    assert captured["offline"] is True
    assert captured["quiet"] is True
    assert captured["input_label"] == "SBOM"


def test_scan_sbom_missing_file_exits_with_pipeline_error(tmp_path: Path):
    result = runner.invoke(cli.app, ["scan-sbom", str(tmp_path / "missing.json")])
    assert result.exit_code == 1
    assert "SBOM not found" in result.stdout
