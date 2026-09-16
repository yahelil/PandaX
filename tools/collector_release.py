"""Package and verify the Windows Collector with a detached Ed25519 seal."""

from __future__ import annotations

import argparse
import hashlib
import os
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def package(directory: Path, output: Path) -> None:
    directory = directory.resolve(strict=True)
    if not (directory / "actis-collector.exe").is_file() or not (directory / "syft.exe").is_file():
        raise ValueError("Windows Collector and pinned Syft must both be in the release")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(directory.rglob("*")):
            if file.is_file():
                archive.write(file, file.relative_to(directory.parent).as_posix())


def sign(output: Path) -> None:
    pem = os.environ.get("COLLECTOR_RELEASE_SIGNING_KEY_PEM")
    if not pem:
        raise ValueError("COLLECTOR_RELEASE_SIGNING_KEY_PEM is required to publish a signed release")
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("release signing key must be Ed25519")
    checksum = output.with_name(output.name + ".sha256")
    checksum.write_text(f"{_digest(output)}  {output.name}\n", encoding="ascii")
    output.with_name(output.name + ".sha256.sig").write_text(key.sign(checksum.read_bytes()).hex() + "\n", encoding="ascii")
    output.with_name(output.name + ".release-pubkey.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def verify(output: Path, trusted_public_key: Path) -> bool:
    checksum = output.with_name(output.name + ".sha256")
    signature = output.with_name(output.name + ".sha256.sig")
    key = serialization.load_pem_public_key(trusted_public_key.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("trusted release public key must be Ed25519")
    key.verify(bytes.fromhex(signature.read_text(encoding="ascii").strip()), checksum.read_bytes())
    expected, filename = checksum.read_text(encoding="ascii").strip().split("  ", 1)
    return filename == output.name and expected == _digest(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("package")
    make.add_argument("directory", type=Path)
    make.add_argument("output", type=Path)
    check = commands.add_parser("verify")
    check.add_argument("output", type=Path)
    check.add_argument("trusted_public_key", type=Path)
    args = parser.parse_args()
    if args.command == "package":
        package(args.directory, args.output)
        sign(args.output)
    elif not verify(args.output, args.trusted_public_key):
        raise SystemExit("release checksum mismatch")


if __name__ == "__main__":
    main()
