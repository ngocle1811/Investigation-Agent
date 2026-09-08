"""Liveness and dependency health endpoints."""

from typing import Literal

from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from investigation_agent.storage import database, vector

router = APIRouter(tags=["health"])


class DependencyStatus(BaseModel):
    """Connectivity state for one backing service."""

    status: Literal["ok", "unavailable"]
    detail: str


class HealthResponse(BaseModel):
    """Application and backing-service health state."""

    status: Literal["ok", "degraded"]
    service: str
    dependencies: dict[str, DependencyStatus]


@router.get("/health/live")
async def liveness() -> dict[str, str]:
    """Return process liveness without contacting dependencies."""

    return {"status": "ok", "service": "investigation-agent-api"}


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Return readiness information for PostgreSQL and Qdrant."""

    db_ok, db_detail = await run_in_threadpool(database.check_database)
    qdrant_ok, qdrant_detail = await run_in_threadpool(vector.check_qdrant)
    dependencies = {
        "postgres": DependencyStatus(status="ok" if db_ok else "unavailable", detail=db_detail),
        "qdrant": DependencyStatus(
            status="ok" if qdrant_ok else "unavailable", detail=qdrant_detail
        ),
    }
    return HealthResponse(
        status="ok" if db_ok and qdrant_ok else "degraded",
        service="investigation-agent-api",
        dependencies=dependencies,
    )
