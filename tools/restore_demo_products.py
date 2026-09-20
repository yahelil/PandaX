"""Restore the five dashboard sample products to an API portfolio once.

Set ACTIS_API_TOKEN, then pass the API origin and organization. Omit --apply to
preview; existing identifiers are skipped. No releases or findings are seeded.
"""

import argparse
import json
import os
from datetime import date
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


PRODUCTS = (
    ("Smart Camera", "ACM-CAM-200", "Acme Devices GmbH", "Indoor connected security camera with encrypted cloud recording.", "important_i", "2031-06-30"),
    ("Home Hub", "ACM-HUB-110", "Acme Devices GmbH", "Residential gateway coordinating local sensors and cloud services.", "critical", "2030-12-31"),
    ("Smart Lock", "ACM-LOCK-140", "Acme Devices GmbH", "Connected access-control lock for residential and small commercial use.", "important_ii", "2032-03-31"),
    ("Thermostat", "ACM-THERM-300", "Acme Devices GmbH", "Wi-Fi thermostat with local scheduling and mobile application control.", "default", "2029-08-31"),
    ("Edge Gateway", "ACM-EDGE-520", "Acme Industrial Systems BV", "Industrial protocol gateway connecting field devices to managed cloud services.", "important_ii", "2033-01-31"),
)


def request(url: str, token: str, method: str = "GET", payload: dict | None = None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=body, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        **({"Content-Type": "application/json"} if body is not None else {}),
    })
    try:
        with urlopen(req, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        raise RuntimeError(f"{method} {url}: HTTP {error.code}: {error.read().decode(errors='replace')}") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    token = os.environ.get("ACTIS_API_TOKEN")
    if not token:
        parser.error("ACTIS_API_TOKEN is required")
    url = f"{args.api_url.rstrip('/')}/v1/organizations/{quote(args.organization_id, safe='')}/products"
    current = request(url, token)
    by_identifier = {item["identifier"]: item for item in current}
    missing = [product for product in PRODUCTS if product[1] not in by_identifier]
    print(f"Current products: {len(current)}; missing samples: {len(missing)}")
    for name, identifier, manufacturer, description, cra_class, support_end in missing:
        if not args.apply:
            print(f"Would create: {name} ({identifier})")
            continue
        created = request(url, token, "POST", {
            "name": name,
            "identifier": identifier,
            "manufacturer": manufacturer,
            "description": description,
            "cra_class": cra_class,
            "classification_status": "review_required",
            "support_start": date.today().isoformat(),
            "support_end": support_end,
        })
        print(f"Created: {created['name']} ({created['id']})")
    if args.apply:
        after = request(url, token)
        remaining = [product[1] for product in PRODUCTS if product[1] not in {item["identifier"] for item in after}]
        if remaining:
            raise RuntimeError(f"Missing after restore: {', '.join(remaining)}")
        print(f"Verified: all five sample products present; total products: {len(after)}")


if __name__ == "__main__":
    main()
