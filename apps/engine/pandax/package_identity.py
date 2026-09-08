"""Resolve known publisher binaries by SHA-256, independently of CVE expectations.

Syft derives incorrect Maven coordinates for Tomcat's OSGi-only Catalina JARs.
These pins were verified against Maven Central; no filename/version guessing.
Unknown bytes retain Syft's identity. This is bounded identity coverage, not a
general Maven resolver, and contains no vulnerability verdicts.
"""
import json
from pathlib import Path

from .evidence import sha256_file

IDENTITIES = json.loads((Path(__file__).parent / 'data/package-identities.json').read_text())


def enrich(sbom: dict, root: Path) -> int:
    root = root.resolve()
    resolved = 0
    for component in sbom.get('components', []):
        properties = component.get('properties', [])
        locations = [p['value'] for p in properties
                     if p['name'].startswith('syft:location:') and p['name'].endswith(':path')]
        for location in locations:
            # Syft uses a leading slash for paths relative to its scan root.
            path = (root / location.replace('\\', '/').lstrip('/')).resolve()
            if not path.is_relative_to(root) or path.suffix.lower() != '.jar' or not path.is_file():
                continue
            digest = sha256_file(path)
            identity = IDENTITIES.get(digest)
            if identity is None:
                continue
            component.setdefault('properties', []).extend([
                {'name': 'pandax:original-purl', 'value': component.get('purl', '')},
                {'name': 'pandax:identity-sha256', 'value': digest},
                {'name': 'pandax:identity-source', 'value': identity['url']},
            ])
            component.update({k: identity[k] for k in ('name', 'version', 'purl')})
            # Preserve bom-ref so existing dependency and VEX links remain valid.
            resolved += 1
            break
    return resolved
