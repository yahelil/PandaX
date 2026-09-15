# Trusted evidence verification

An evidence bundle contains a public key so its internal signature can be
inspected. That bundled key is not trusted by itself: anyone able to replace a
bundle could also replace the key inside it.

PandaX establishes trust by checking the signature against a public key obtained
separately. The operator of the PandaX installation provides that key. This is
PandaX's operations/security team for a hosted installation, or the customer's
authorised IT/security administrator for a self-hosted installation. Ordinary
report reviewers and evidence recipients do not select trust keys.

## Provisioning

1. Set `PANDAX_SIGNING_KEY` to the private Ed25519 key used by the installation.
   If it is omitted, local development uses `~/.pandax/dev_signing_key.pem`.
2. Export only the public half:

   ```powershell
   actis key export-public C:\onboarding\actis-public.pem
   ```

3. Record the printed SHA-256 fingerprint in the customer onboarding record.
4. Deliver the public key separately from evidence, using the authenticated
   administration or configuration channel for that deployment.
5. Have the receiving administrator confirm the fingerprint through a second
   trusted channel.
6. Configure the verifier:

   ```powershell
   $env:PANDAX_TRUSTED_KEY = "C:\secure-config\actis-public.pem"
   actis verify C:\evidence\run-example
   ```

The public key is not secret, but its origin must be authenticated. Do not use a
key merely because it arrived in the same email, ZIP, or download as the evidence.
PandaX does not fetch trust keys from arbitrary URLs or accept one inside an
evidence bundle as authoritative.

## Customer-controlled organization keys

Hosted Actis keeps the private Ed25519 key in the customer's environment. Create
an organization-scoped proof of possession locally:

```powershell
actis key enrollment-proof org-acme release-signing --signing-key C:\secure\customer.pem
```

An organization administrator submits the resulting JSON to
`POST /v1/organizations/{organization_id}/trust-keys`. The server stores only
the public key, fingerprint, proof result, version, and audit history. Registering
a new key with the same name rotates the active key; old bundles remain
verifiable only when their signed manifest time precedes that rotation. Revoking
a key immediately makes every bundle signed by it untrusted.

`POST /v1/organizations/{organization_id}/trust-verifications` accepts an
evidence ZIP and reports its policy, registry source, Ed25519 algorithm,
verification time, key name/version/status, integrity result, and trust decision.
ZIP paths and expansion limits are checked before verification. Enrollment,
rotation, revocation, and verification are tenant-scoped audit events.

## Results

- `trusted`: the evidence is intact and the external trusted key verifies its
  signature.
- `untrusted`: internal checks pass, but no trusted key was configured or the
  bundle was signed by another key.
- `invalid`: evidence, history, or signature content no longer matches.
- `incomplete`: required evidence or signature files are missing or malformed.

For historical review without an available trusted key, use
`actis verify RUN --inspect-only`. This can confirm internal integrity, but the
result explicitly does not establish signer trust.

The server reads the public key path from `PANDAX_TRUSTED_KEY`. Its
`/api/verify/{run_id}` response separates `integrity_ok`, `signature_valid`, and
`signer_trust`; `ok` is true only for a fully `trusted` result. A malformed
configured key is an installation error and returns HTTP 503.

## Independent verifier for recipients

Auditors and other recipients do not need to install or trust the PandaX
product. The separate application in `apps/verifier` reads an evidence folder
or ZIP directly, works offline, and does not import PandaX code:

```powershell
cd apps\verifier
python -m pip install .
actis-verify C:\evidence\case-snapshot.zip --trusted-key C:\secure-config\actis-public.pem
```

For machine-readable output, add `--json`. For historical evidence where no
separately delivered key is available, use `--inspect-only`; this may confirm
internal integrity but never labels the signer trusted.

The standalone verifier independently checks the manifest, every listed file,
unexpected files, ledger file digest, record count and order, hash-chain links,
chain head, stage outputs, bundled signature, and separately trusted signature.
ZIP files are read without extraction and are rejected when their names or
declared sizes could make them unsafe. See
[`apps/verifier/README.md`](../apps/verifier/README.md) for distribution,
plain-language results, and exit codes.

The organization registry supports independently versioned key names, rotation,
and revocation. Managed KMS/HSM custody and identity-backed/eIDAS seals remain
separate production work; customer private keys are never sent to PandaX.
