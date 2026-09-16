# Actis Evidence Verifier

This is a small, independent program for checking evidence produced by Actis by
PandaX. It does not need an Actis account, a running Actis server, or an internet
connection. A customer, auditor, insurer, lawyer, or regulator can run it on a
copied evidence folder or ZIP file.

The verifier answers three separate questions:

1. **Is the evidence intact?** It checks that files and the recorded history
   have not been added, removed, reordered, or changed.
2. **Does the bundle's signature work?** It checks the signature using the
   public key included for inspection inside the bundle.
3. **Is the signer trusted?** It checks the same signature using a public key
   that the receiver obtained separately from the evidence.

The third check matters because an attacker could alter evidence and place a
new key and signature beside it. A key delivered separately gives the receiver
an independent reference for the expected Actis installation.

## Install

From this directory, install the application with Python 3.10 or newer:

```text
python -m pip install .
```

The only runtime dependency is the widely used `cryptography` package. The
verifier never imports the PandaX product and never makes a network request.

## Verify with an approved public key

The organization that operates the PandaX installation provides the public key
through a channel separate from the evidence bundle. Save it in a protected
configuration location, confirm its displayed fingerprint with the provider,
and run:

```text
actis-verify evidence.zip --trusted-key actis-public.pem
```

After key rotation, verify against a separately distributed versioned registry:

```powershell
actis-verify evidence.zip --trusted-key-registry actis-signing-keys.json
```

Active and historical versions can establish trust. Revoked versions remain
identifiable but return an untrusted result.

A successful result says `TRUSTED` and exits with code 0.

## Inspect older evidence without a trusted key

```text
actis-verify evidence.zip --inspect-only
```

This can confirm that the bundle is internally intact, but it clearly reports
that signer trust was not established. A successful inspection exits with code
0 only because the user explicitly selected inspection mode.

## Machine-readable result

```text
actis-verify evidence.zip --trusted-key actis-public.pem --json
```

Verification output uses the schema `actis/verification-result/v1` and includes the
overall status, integrity and signature results, signer trust, key
fingerprints, a plain-language reason, and every individual check. A trusted-key
configuration error uses `actis/verifier-error/v1`.

Exit codes are:

- `0`: trusted, or an intact bundle in explicit inspection mode
- `1`: untrusted, invalid, incomplete, or unsupported evidence
- `2`: invalid command options or an unusable trusted-key configuration

The frozen bundle contract, schemas, migration policy, and public-safe fixtures
are in [`docs/evidence-format-v1.md`](../../docs/evidence-format-v1.md).

## Safety limits

ZIP files are read directly and are never extracted. The verifier rejects
encrypted entries, symbolic links, absolute or parent-directory paths,
duplicate names, case-colliding names, more than 20,000 files, more than 512 MiB
of uncompressed content, and paths deeper than 24 levels.

