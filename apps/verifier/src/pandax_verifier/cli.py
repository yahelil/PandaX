from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .verification import TrustedKeyConfigurationError, verify_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pandax-verify",
        description="Check a PandaX evidence folder or ZIP without connecting to PandaX.",
    )
    parser.add_argument("bundle", type=Path, help="Evidence folder or ZIP file")
    trust = parser.add_mutually_exclusive_group()
    trust.add_argument(
        "--trusted-key",
        type=Path,
        help="Public key received separately from the evidence",
    )
    trust.add_argument(
        "--inspect-only",
        action="store_true",
        help="Check integrity without claiming that the signer is trusted",
    )
    parser.add_argument(
        "--json", action="store_true", help="Print a machine-readable result"
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _print_human(result: object) -> None:
    data = result.as_dict()  # type: ignore[attr-defined]
    headings = {
        "trusted": "TRUSTED",
        "untrusted": "INTACT, TRUST NOT ESTABLISHED",
        "invalid": "INVALID OR TAMPERED",
        "incomplete": "INCOMPLETE",
    }
    print(headings[data["status"]])
    print(data["reason"])
    print()
    for check in data["checks"]:
        mark = "PASS" if check["ok"] else "FAIL"
        print(f"[{mark}] {check['name']}: {check['detail']}")
    if data["bundle_key_fingerprint"]:
        print(f"\nBundle key fingerprint:  {data['bundle_key_fingerprint']}")
    if data["trusted_key_fingerprint"]:
        print(f"Trusted key fingerprint: {data['trusted_key_fingerprint']}")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify_bundle(args.bundle, trusted_key=args.trusted_key)
    except TrustedKeyConfigurationError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "schema": "pandax/verification-result/v1",
                        "error": "trusted_key_configuration",
                        "reason": str(exc),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        else:
            print(f"Trusted key configuration error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
    else:
        _print_human(result)

    if result.ok:
        return 0
    if args.inspect_only and result.integrity_ok and result.signature_valid:
        return 0
    return 1


def entrypoint() -> None:
    raise SystemExit(main())

