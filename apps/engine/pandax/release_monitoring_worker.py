"""Small scheduler around the release-monitoring repository seam."""

from __future__ import annotations

import threading
from collections.abc import Callable

from .release_monitoring import (
    ReleaseMonitoringRepository,
    ReleaseMonitoringRunner,
)


class ReleaseMonitoringLoop:
    """Claim due checks periodically without coupling scheduling to matching."""

    def __init__(
        self,
        repository_factory: Callable[[], ReleaseMonitoringRepository],
        runner: ReleaseMonitoringRunner,
        *,
        interval_seconds: float = 60.0,
        batch_size: int = 25,
    ) -> None:
        self.repository_factory = repository_factory
        self.runner = runner
        self.interval_seconds = max(1.0, interval_seconds)
        self.batch_size = max(1, batch_size)
        self.last_error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_forever,
            name="actis-release-monitoring",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval_seconds + 1.0)

    def run_once(self) -> int:
        try:
            repository = self.repository_factory()
            claims = repository.claim_due(limit=self.batch_size)
            for claim in claims:
                repository.run(claim, self.runner)
            self.last_error = None
            return len(claims)
        except Exception as exc:
            self.last_error = str(exc)
            return 0

    def _run_forever(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.run_once()
