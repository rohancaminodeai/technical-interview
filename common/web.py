"""Shared web/HTTP wiring for the FastAPI services.

Only the demo CORS toggle lives here for now. It is opt-in via the
CORS_ALLOW_ORIGINS env var (see common/config.py): when unset the middleware is
never installed, so production and the unit/e2e suites are byte-for-byte
unchanged. The demo UI sets it to the static page's origin.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from common.config import CORS_ALLOW_ORIGINS


def maybe_enable_cors(app: FastAPI) -> None:
    """Allow the configured browser origins to call this service (demo only).

    No cookies are used (the token rides in the Authorization header), so
    allow_credentials stays off and explicit origins are safe.
    """
    if not CORS_ALLOW_ORIGINS:
        return
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(CORS_ALLOW_ORIGINS),
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
