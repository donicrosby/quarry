"""Health check router."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/healthz")
async def health_check() -> dict[str, str]:
    """Return health status."""
    return {"status": "ok"}
