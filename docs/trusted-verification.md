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
   pandax key export-public C:\onboarding\pandax-public.pem
   ```

3. Record the printed SHA-256 fingerprint in the customer onboarding record.
4. Deliver the public key separately from evidence, using the authenticated
   administration or configuration channel for that deployment.
5. Have the receiving administrator confirm the fingerprint through a second
   trusted channel.
6. Configure the verifier:

   ```powershell
   $env:PANDAX_TRUSTED_KEY = "C:\secure-config\pandax-public.pem"
   pandax verify C:\evidence\run-example
   ```

The public key is not secret, but its origin must be authenticated. Do not use a
key merely because it arrived in the same email, ZIP, or download as the evidence.
PandaX does not fetch trust keys from arbitrary URLs or accept one inside an
evidence bundle as authoritative.

## Results

- `trusted`: the evidence is intact and the external trusted key verifies its
  signature.
- `untrusted`: internal checks pass, but no trusted key was configured or the
  bundle was signed by another key.
- `invalid`: evidence, history, or signature content no longer matches.
- `incomplete`: required evidence or signature files are missing or malformed.

For historical review without an available trusted key, use
`pandax verify RUN --inspect-only`. This can confirm internal integrity, but the
result explicitly does not establish signer trust.

The server reads the public key path from `PANDAX_TRUSTED_KEY`. Its
`/api/verify/{run_id}` response separates `integrity_ok`, `signature_valid`, and
`signer_trust`; `ok` is true only for a fully `trusted` result. A malformed
configured key is an installation error and returns HTTP 503.

This first version supports one active key per installation. Rotation, revoked
keys, multiple simultaneous keys, and identity-backed/eIDAS seals are separate
future work.
