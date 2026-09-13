"""Install pinned veraPDF locally. Requires Java; never runs during a scan."""

from __future__ import annotations

import io
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from bootstrap import TOOLS, fetch

VERSION = "1.30.2"
URL = f"https://software.verapdf.org/releases/1.30/verapdf-greenfield-{VERSION}-installer.zip"
SHA256 = "6cc6341cb1af644044054b81f00a6590a7918abb18f762243de115258bcad838"


def main() -> None:
    java = shutil.which("java")
    if not java:
        raise SystemExit("Install Java and add it to PATH before installing veraPDF")
    target = (TOOLS / "verapdf").resolve()
    if target.exists():
        raise SystemExit(f"{target} already exists; move it aside before reinstalling")
    blob = fetch(URL, SHA256)
    with tempfile.TemporaryDirectory(prefix="pandax-verapdf-") as directory:
        temp = Path(directory)
        jar = temp / "installer.jar"
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            jar.write_bytes(archive.read(
                f"verapdf-greenfield-{VERSION}/verapdf-izpack-installer-{VERSION}.jar"))
        root = ET.Element("AutomatedInstallation", langpack="eng")
        prefix = "com.izforge.izpack.panels."
        ET.SubElement(root, prefix + "htmlhello.HTMLHelloPanel", id="welcome")
        panel = ET.SubElement(root, prefix + "target.TargetPanel", id="install_dir")
        ET.SubElement(panel, "installpath").text = str(target)
        panel = ET.SubElement(root, prefix + "packs.PacksPanel", id="sdk_pack_select")
        for index, name, selected in (
            (0, "veraPDF GUI", "true"),
            (1, "veraPDF Mac and *nix Scripts", "true"),
            (2, "veraPDF Validation model", "false"),
            (3, "veraPDF Documentation", "false"),
            (4, "veraPDF Sample Plugins", "false"),
        ):
            ET.SubElement(panel, "pack", index=str(index), name=name, selected=selected)
        ET.SubElement(root, prefix + "install.InstallPanel", id="install")
        ET.SubElement(root, prefix + "finish.FinishPanel", id="finish")
        config = temp / "auto-install.xml"
        ET.ElementTree(root).write(config, encoding="utf-8", xml_declaration=True)
        subprocess.run([java, "-jar", str(jar), str(config)], check=True, timeout=180)
    cli = target / "bin" / f"cli-{VERSION}.jar"
    version = subprocess.run([java, "-jar", str(cli), "--version"], check=True,
                             capture_output=True, text=True, timeout=60)
    if not version.stdout.splitlines() or version.stdout.splitlines()[0] != f"veraPDF {VERSION}":
        raise SystemExit(f"Unexpected installed veraPDF version: {version.stdout}")
    print(version.stdout)
    print(f"Installed veraPDF {VERSION} in {target}")
    print("For preflight, add that directory to PATH or use --verapdf with its launcher.")


if __name__ == "__main__":
    main()
