"""FastAPI application entry point."""

import logging

from fastapi import FastAPI

from investigation_agent import __version__
from investigation_agent.api.routes.health import router as health_router
from investigation_agent.common.config import get_settings
from investigation_agent.common.logging import configure_logging

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    description="Evidence-grounded SOC incident investigation API",
    version=__version__,
)
app.include_router(health_router)


@app.get("/", tags=["meta"])
async def root() -> dict[str, str]:
    """Return a small service discovery payload."""

    return {
        "service": "investigation-agent-api",
        "version": __version__,
        "docs": "/docs",
    }


logger.info("api_configured", extra={"app_env": settings.app_env})
