from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_free_isolated_non_root_deployment_config():
    services = yaml.safe_load((ROOT / "render.yaml").read_text())["services"]

    assert [(service["name"], service["envVars"][0]["value"]) for service in services] == [
        ("actis-api-staging", "staging"),
    ]
    assert all(service["plan"] == "free" for service in services)
    assert all(service["region"] == "frankfurt" for service in services)
    assert all(service["healthCheckPath"] == "/health/ready" for service in services)
    assert all("maxShutdownDelaySeconds" not in service for service in services)
    assert all(
        item.get("sync") is False
        for service in services
        for item in service["envVars"]
        if item["key"].endswith(("URL", "KEY", "B64", "ID", "VERSION", "ISSUER", "URI", "ORIGINS"))
        and "value" not in item
    )

    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "USER 10001:10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "alembic upgrade head" in dockerfile
