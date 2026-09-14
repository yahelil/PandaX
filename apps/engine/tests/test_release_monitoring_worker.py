from pandax.release_monitoring_worker import ReleaseMonitoringLoop


class FakeRepository:
    def __init__(self, claims=(), error: Exception | None = None):
        self.claims = list(claims)
        self.error = error
        self.runs = []

    def claim_due(self, *, limit):
        if self.error:
            raise self.error
        return self.claims[:limit]

    def run(self, claim, runner):
        self.runs.append((claim, runner(claim)))


def test_run_once_claims_bounded_batch_and_executes_runner():
    repository = FakeRepository(["first", "second", "third"])
    loop = ReleaseMonitoringLoop(
        lambda: repository,
        lambda claim: f"observed:{claim}",
        batch_size=2,
    )

    assert loop.run_once() == 2
    assert repository.runs == [
        ("first", "observed:first"),
        ("second", "observed:second"),
    ]
    assert loop.last_error is None


def test_run_once_contains_repository_failure_for_next_tick():
    repository = FakeRepository(error=RuntimeError("database unavailable"))
    loop = ReleaseMonitoringLoop(lambda: repository, lambda claim: claim)

    assert loop.run_once() == 0
    assert loop.last_error == "database unavailable"
