# Windows x64 Collector beta

`actis-collector` collects an authorized product input locally and exports a
minimized, Ed25519-signed `actis/manifest/v1` ZIP. The first release supports
directories, ZIP/TAR archives, CycloneDX 1.2/1.6 JSON, and SPDX 2.2/2.3 JSON.
It does not extract container images or SquashFS/UBIFS firmware. macOS and Linux
packages are later work.

## Generate an SBOM locally

Download the verified Windows bundle from the
[latest Collector release](https://github.com/yahelil/PandaX/releases/latest/download/actis-collector-windows-x64.zip),
verify it as described below, and run:

```powershell
.\actis-collector\actis-collector.exe sbom C:\path\to\product `
  --output .\bom.cdx.json
```

`sbom` needs no account, product ID, signing key, token, or network connection.
It accepts a directory, ZIP/TAR archive, or existing CycloneDX/SPDX JSON. The
bundled, pinned Syft build inventories directories and archives locally with
update checks disabled. The command writes a privacy-minimized CycloneDX 1.6
document atomically and prints its SHA-256, exact component coverage, tool
versions, limitations, and `uploaded: false`.

Only component type, name, version, package URL, and an opaque generated BOM
reference are retained. Source contents, source paths, source filenames,
Syft evidence, credentials, and working files are omitted. The user can inspect
`bom.cdx.json` and explicitly upload it later. Nothing is sent automatically.
Inputs with no versioned package URL fail rather than producing a misleading
empty inventory.

Uploading a raw source ZIP remains a separate, explicit hosted-analysis option.
That option sends the archive to Actis; use `sbom` when source must remain local.

## Create a signed Collector package

Before collection, an organization administrator with recent MFA must enroll
the **public** Ed25519 key in the organization trust registry using the
five-minute, one-use challenge at `POST /trust-keys/challenges`, then sign its
proof locally and submit `POST /trust-keys`. The private key stays on the
customer machine. `actis-collector` requires `--signing-key` on every collection
and has no development-key fallback.

```powershell
actis-collector collect .\product.zip --output .\release-evidence.zip `
  --organization-id ORG_ID --product-id PRODUCT_ID --release-id RELEASE_ID `
  --signing-key C:\secure\customer-ed25519.pem
```

`collect` is the offline and CI-safe default. It prints the exact seven ZIP
entries and a coverage summary. The package contains a projected CycloneDX 1.6
component inventory, coverage/extraction summary, limitations, tool/rules IDs,
ledger, manifest, signature, and public inspection key. It omits raw sources,
extracted files, working files, source paths, and private keys. A component with
no versioned purl makes the coverage **inconclusive**; an empty or unsupported
inventory fails locally. Inventory completion is not a vulnerability or CRA
clean result.

```powershell
$env:PANDAX_ACCESS_TOKEN = '<short-lived token after MFA login>'
actis-collector run .\product.zip --output .\release-evidence.zip `
  --organization-id ORG_ID --product-id PRODUCT_ID --release-id RELEASE_ID `
  --signing-key C:\secure\customer-ed25519.pem --base-url https://BETA_HOST
```

`run` collects and signs locally, displays the exact upload package, then asks
for approval before sending it. `upload .\release-evidence.zip --base-url ...`
does the same for an existing package. The token can come from
`PANDAX_ACCESS_TOKEN` or a hidden prompt; it is never saved or printed. A
noninteractive upload requires the explicit `--approve-upload` option. Retries
use the package SHA-256 as the default idempotency key. Raw-artifact upload is
outside this Collector release.

Verify a copied ZIP with a public key obtained separately from the customer or
the authenticated registry:

```powershell
actis-verify .\release-evidence.zip --trusted-key .\enrolled-public-key.pem
```

The hosted endpoint checks integrity, signature validity, and active
organization-key trust separately. Revoked keys cannot sign new uploads; old
signed jobs remain readable. Historical unsigned `actis.collector/v1` jobs are
readable, while new unsigned Collector uploads are rejected in staging, beta,
and production. The private-beta pilot still requires the approval recorded in
[private-beta-scope.md](private-beta-scope.md).

## Verify and install a Windows release

Each Windows build publishes `actis-collector-windows-x64.zip`, its `.sha256`
file, a detached `.sha256.sig`, and the release public key. Obtain the expected
release-key fingerprint through a separately authenticated PandaX channel;
files downloaded together do not establish publisher identity by themselves.
From a source checkout, verify the checksum and signature before extraction:

```powershell
uv run python tools/collector_release.py verify `
  .\actis-collector-windows-x64.zip `
  .\trusted-collector-release-public-key.pem
Expand-Archive .\actis-collector-windows-x64.zip .\actis-collector
.\actis-collector\actis-collector\actis-collector.exe --help
```

The release ZIP contains the pinned `syft.exe`. Native Windows Authenticode
signing is not part of the current beta promise.
