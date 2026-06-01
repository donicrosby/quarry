"""FastAPI application factory for Quarry server."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter

from quarry.config import QuarrySettings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Manage Temporal client lifecycle."""
    settings = QuarrySettings()
    client = await Client.connect(
        settings.temporal_address,
        data_converter=pydantic_data_converter,
    )
    app.state.settings = settings
    app.state.temporal_client = client
    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(title="Quarry API", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:*", "http://127.0.0.1:*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    from quarry_server.routers import health
    from quarry_server.routers.scans import router as scans_router

    app.include_router(health.router)
    app.include_router(scans_router)
    return app
