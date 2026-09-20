"""Populate the connected sample workspace from explicitly illustrative SBOMs.

Dry-run by default. Re-running --apply reuses the sample release and analysis job.
"""

import argparse
import hashlib
import json
import os
import time
import uuid
from datetime import date
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = {
    "ACM-HUB-110": ("Home Hub", "home-hub.cdx.json"),
    "ACM-CAM-200": ("Smart Camera", "smart-camera.cdx.json"),
    "ACM-LOCK-140": ("Smart Lock", "smart-lock.cdx.json"),
    "ACM-THERM-300": ("Thermostat", "thermostat.cdx.json"),
    "ACM-EDGE-520": ("Edge Gateway", "edge-gateway.cdx.json"),
}
VERSION = "1.0.0-sample"
NOTICE = "Illustrative sample product and dependency inventory; not a measured shipping-product SBOM or manufacturer attestation."


class Api:
    def __init__(self, url: str, organization: str, token: str):
        self.base = f"{url.rstrip('/')}/v1/organizations/{quote(organization, safe='')}"
        self.token = token

    def call(self, method: str, path: str, data: dict | bytes | None = None,
             extra_headers: dict[str, str] | None = None):
        headers = {"Authorization": f"Bearer {self.token}", "User-Agent": "curl/8.0"}
        if extra_headers:
            headers.update(extra_headers)
        body = None
        if isinstance(data, dict):
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(data, bytes):
            body = data
        request = Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=25) as response:
                content = response.read()
                return json.loads(content) if content else None
        except HTTPError as error:
            detail = error.read(500).decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path}: HTTP {error.code}: {detail}") from error


def sbom_bytes(filename: str) -> bytes:
    content = (ROOT / "fixtures" / "connected-samples" / filename).read_bytes()
    data = json.loads(content)
    assert data["bomFormat"] == "CycloneDX"
    assert {item["value"] for item in data["metadata"]["properties"] if item["name"] == "actis:sample"} == {"true"}
    assert all(component.get("purl") for component in data["components"])
    return content


def upload(api: Api, product_id: str, release_id: str, filename: str):
    content = sbom_bytes(filename)
    boundary = f"actis-{uuid.uuid4().hex}"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"sbom\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/json\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    key = "connected-sample-" + hashlib.sha256(content).hexdigest()[:24]
    path = f"/products/{quote(product_id)}/releases/{quote(release_id)}/analysis-jobs"
    return api.call("POST", path, body, {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Idempotency-Key": key,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--organization", required=True)
    parser.add_argument("--token", help="API token; alternatively set ACTIS_SAMPLE_TOKEN")
    parser.add_argument("--only", choices=tuple(SAMPLES), help="Seed one product first")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    token = args.token or os.environ.get("ACTIS_SAMPLE_TOKEN", "")
    if not token:
        parser.error("Set ACTIS_SAMPLE_TOKEN to an authorized API token")
    api = Api(args.api_url, args.organization, token)

    products = api.call("GET", "/products")
    selected = []
    for identifier, (name, filename) in SAMPLES.items():
        if args.only and args.only != identifier:
            continue
        matches = [item for item in products if item["identifier"] == identifier]
        if len(matches) != 1 or matches[0]["name"] not in {name, f"Sample {name}"}:
            raise RuntimeError(f"Expected one untouched or sample product: {identifier}")
        product = matches[0]
        releases = api.call("GET", f"/products/{quote(product['id'])}/releases")
        if any(item["version"] != VERSION for item in releases):
            raise RuntimeError(f"Refusing to change product with non-sample release: {identifier}")
        sbom_bytes(filename)
        selected.append((product, releases, name, filename))

    for product, releases, name, filename in selected:
        print(f"{product['identifier']}: {len(releases)} sample release(s); evidence {filename}")
    if not args.apply:
        print("Dry run only; pass --apply to update the connected workspace.")
        return

    for product, releases, name, filename in selected:
        product_path = f"/products/{quote(product['id'])}"
        sample_name = f"Sample {name}"
        if product["name"] != sample_name or NOTICE not in product["description"]:
            api.call("PATCH", product_path, {
                "name": sample_name,
                "manufacturer": "Example Manufacturer (sample)",
                "description": NOTICE,
            })
        release = next((item for item in releases if item["version"] == VERSION), None)
        if release is None:
            release = api.call("POST", product_path + "/releases", {
                "version": VERSION,
                "channel": "stable",
                "status": "draft",
                "release_date": date.today().isoformat(),
                "support_start": product["support_start"],
                "support_end": product["support_end"],
            })
        job_path = product_path + f"/releases/{quote(release['id'])}/analysis-jobs"
        existing = api.call("GET", job_path)
        if any(item["status"] in {"failed", "unsupported"} for item in existing):
            raise RuntimeError(f"Existing sample analysis failed for {sample_name}; inspect before retrying")
        job = existing[0] if existing else upload(api, product["id"], release["id"], filename)
        if job["status"] == "queued":
            job = api.call("POST", job_path + f"/{quote(job['id'])}/run")
        print(f"{sample_name}: analysis {job['id']} ({job['status']})")
        deadline = time.monotonic() + 240
        while job["status"] in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(5)
            job = api.call("GET", job_path + f"/{quote(job['id'])}")
        if job["status"] != "completed":
            raise RuntimeError(f"Sample analysis did not complete for {sample_name}: {job['status']}")

        # Also repairs an earlier completed job whose automatic projection failed.
        api.call("POST", job_path + f"/{quote(job['id'])}/enroll")
        findings = api.call("GET", "/findings?view=all")
        documents = api.call("GET", "/documents")
        finding_count = sum(item["release_id"] == release["id"] for item in findings)
        document_count = sum(item["release_id"] == release["id"] for item in documents)
        if finding_count < 1 or document_count < 3:
            raise RuntimeError(
                f"Incomplete enrollment for {sample_name}: {finding_count} findings, {document_count} documents"
            )
        print(f"{sample_name}: {finding_count} findings, {document_count} documents")
    print("Connected sample products and evidence enrolled.")


if __name__ == "__main__":
    main()
