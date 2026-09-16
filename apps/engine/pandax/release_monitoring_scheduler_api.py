"""Authenticated machine endpoint for scheduled release monitoring."""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from .release_monitoring import ReleaseMonitoringRepository, ReleaseMonitoringRunner


class ScheduledMonitoringResult(BaseModel):
    status: str
    claimed: int
    succeeded: int
    failed: int


def scheduler_secret() -> str:
    value = os.environ.get("PANDAX_SCHEDULER_SECRET", "")
    if len(value) < 32:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "release monitoring scheduler is not configured",
        )
    return value


def create_release_monitoring_scheduler_router(
    repository_dependency: Callable[[], ReleaseMonitoringRepository],
    runner: ReleaseMonitoringRunner,
    growth_allowed: Callable[[], bool],
    secret_dependency: Callable[[], str] = scheduler_secret,
) -> APIRouter:
    router = APIRouter(tags=["internal-jobs"])

    @router.post(
        "/internal/jobs/release-monitoring",
        response_model=ScheduledMonitoringResult,
        include_in_schema=False,
    )
    def run_due_monitoring(
        repository: ReleaseMonitoringRepository = Depends(repository_dependency),
        expected_secret: str = Depends(secret_dependency),
        authorization: str | None = Header(default=None),
    ) -> ScheduledMonitoringResult:
        supplied = ""
        if authorization:
            scheme, separator, token = authorization.partition(" ")
            if separator and scheme.casefold() == "bearer":
                supplied = token
        if not supplied or not secrets.compare_digest(supplied, expected_secret):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "invalid scheduler credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not growth_allowed():
            return ScheduledMonitoringResult(
                status="capacity_restricted", claimed=0, succeeded=0, failed=0
            )

        claims = repository.claim_due(limit=25)
        succeeded = 0
        failed = 0
        for claim in claims:
            record = repository.run(claim, runner)
            if record.consecutive_failures:
                failed += 1
            else:
                succeeded += 1
        return ScheduledMonitoringResult(
            status="completed",
            claimed=len(claims),
            succeeded=succeeded,
            failed=failed,
        )

    return router
