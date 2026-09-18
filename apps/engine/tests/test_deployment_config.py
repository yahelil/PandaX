from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]
SECRET_KEYS = {
    "PANDAX_DATABASE_URL",
    "PANDAX_STORAGE_URL",
    "PANDAX_STORAGE_SECRET_KEY",
    "PANDAX_SIGNING_KEY_B64",
    "PANDAX_SIGNING_KEY_REGISTRY_B64",
    "PANDAX_OIDC_ISSUER",
    "PANDAX_OIDC_AUDIENCE",
    "PANDAX_OIDC_JWKS_URI",
    "PANDAX_CORS_ORIGINS",
}


def test_render_blueprint_defines_isolated_free_services():
    services = yaml.safe_load((ROOT / "render.yaml").read_text())["services"]

    assert [service["name"] for service in services] == [
        "actis-api-staging",
        "actis-api-beta",
    ]
    assert [service["envVars"][0] for service in services] == [
        {"key": "PANDAX_ENVIRONMENT", "value": "staging"},
        {"key": "PANDAX_ENVIRONMENT", "value": "beta"},
    ]

    for service in services:
        assert service["runtime"] == "docker"
        assert service["plan"] == "free"
        assert service["region"] == "frankfurt"
        assert service["healthCheckPath"] == "/health/live"
        assert service["autoDeployTrigger"] == "off"
        assert "disk" not in service


def test_render_blueprint_prompts_for_each_environment_secret():
    services = yaml.safe_load((ROOT / "render.yaml").read_text())["services"]

    for service in services:
        env = {item["key"]: item for item in service["envVars"]}
        assert env.keys() >= SECRET_KEYS | {"PANDAX_SCHEDULER_SECRET"}
        assert all(env[key] == {"key": key, "sync": False} for key in SECRET_KEYS)
        assert env["PANDAX_SCHEDULER_SECRET"] == {
            "key": "PANDAX_SCHEDULER_SECRET",
            "generateValue": True,
        }
