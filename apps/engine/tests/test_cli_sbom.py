from __future__ import annotations

from pathlib import Path

from click import unstyle
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

    def render(
        source_path,
        received_stream,
        quiet,
        input_label="artifact",
        subtitle="",
        json_output=None,
        sarif_output=None,
    ):
        captured.update(
            source=source_path,
            stream=received_stream,
            quiet=quiet,
            input_label=input_label,
            subtitle=subtitle,
            json_output=json_output,
            sarif_output=sarif_output,
        )

    monkeypatch.setattr(pipeline, "run_sbom", run_sbom)
    monkeypatch.setattr(cli, "_render_pipeline", render)

    result = runner.invoke(
        cli.app,
        [
            "scan-sbom",
            str(source),
            "--out",
            str(out),
            "--offline",
            "--quiet",
            "--json-output",
            str(tmp_path / "summary.json"),
            "--sarif-output",
            str(tmp_path / "pandax.sarif"),
        ],
    )

    assert result.exit_code == 0
    assert captured["path"] == source
    assert captured["out"] == out
    assert captured["offline"] is True
    assert captured["quiet"] is True
    assert captured["input_label"] == "SBOM"
    assert captured["json_output"] == tmp_path / "summary.json"
    assert captured["sarif_output"] == tmp_path / "pandax.sarif"


def test_version_is_available_without_running_pipeline():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "Actis by PandaX 0.1.0"


def test_help_uses_public_brand_and_command_name():
    result = runner.invoke(cli.app, ["--help"], prog_name="actis")
    help_text = unstyle(result.stdout)
    assert result.exit_code == 0
    assert "Actis by PandaX" in help_text
    assert "Usage: actis" in help_text
    assert "Usage: pandax" not in help_text
    assert "Run PandaX" not in help_text


def test_scan_sbom_missing_file_exits_with_pipeline_error(tmp_path: Path):
    result = runner.invoke(cli.app, ["scan-sbom", str(tmp_path / "missing.json")])
    assert result.exit_code == 1
    assert "SBOM not found" in result.stdout
