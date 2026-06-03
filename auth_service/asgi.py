"""ASGI entrypoint for the auth service: `uvicorn auth_service.asgi:app`.

Builds the app from on-disk keys + IdP DB. Kept separate from app.py so unit
tests can import the create_app factory without touching the filesystem.
"""
from auth_service.app import build_default_app

app = build_default_app()
