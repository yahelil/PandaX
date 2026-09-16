from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from pandax.release_monitoring_scheduler_api import (
    create_release_monitoring_scheduler_router,
)


SECRET = "s" * 32


class Repository:
    def __init__(self):
        self.claims = ["first", "second"]
        self.limit = None

    def claim_due(self, *, limit):
        self.limit = limit
        return self.claims

    def run(self, claim, runner):
        runner(claim)
        return SimpleNamespace(consecutive_failures=int(claim == "second"))


def client(repository=None, *, capacity=True):
    repository = repository or Repository()
    app = FastAPI()
    app.include_router(
        create_release_monitoring_scheduler_router(
            lambda: repository,
            lambda claim: claim,
            lambda: capacity,
            lambda: SECRET,
        )
    )
    return TestClient(app), repository


def test_scheduler_requires_the_exact_bearer_secret():
    api, _ = client()

    assert api.post("/internal/jobs/release-monitoring").status_code == 401
    assert api.post(
        "/internal/jobs/release-monitoring",
        headers={"authorization": "Bearer wrong"},
    ).status_code == 401


def test_scheduler_runs_one_bounded_batch_and_returns_only_counts():
    api, repository = client()

    response = api.post(
        "/internal/jobs/release-monitoring",
        headers={"authorization": f"Bearer {SECRET}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "completed",
        "claimed": 2,
        "succeeded": 1,
        "failed": 1,
    }
    assert repository.limit == 25


def test_scheduler_stops_when_database_capacity_is_restricted():
    api, repository = client(capacity=False)

    response = api.post(
        "/internal/jobs/release-monitoring",
        headers={"authorization": f"Bearer {SECRET}"},
    )

    assert response.json() == {
        "status": "capacity_restricted",
        "claimed": 0,
        "succeeded": 0,
        "failed": 0,
    }
    assert repository.limit is None
