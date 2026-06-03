"""ASGI entrypoint for a tenant service: `uvicorn tenant_service.asgi:app`.

One image, parametrized by env: TENANT_ID picks which tenant this process is,
and the JWKS is read from the shared keys volume (offline validation — no call
to the auth service on the request path).
"""
import json
import os

from common.config import DATA_DIR, JWKS_PATH
from tenant_service.app import create_app

TENANT_ID = os.environ["TENANT_ID"]

app = create_app(
    tenant_id=TENANT_ID,
    jwks=json.loads(JWKS_PATH.read_text()),
    db_path=str(DATA_DIR / f"{TENANT_ID}.sqlite"),
)
