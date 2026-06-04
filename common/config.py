"""Shared constants for the prototype.

These are the values pinned in SPEC.md (§3). Centralised here so the auth service,
tenant services, and tests all agree. Paths are overridable via environment variables
so Docker containers can point at mounted volumes.
"""
import os
from pathlib import Path

# --- repo layout -----------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = Path(os.environ.get("KEYS_DIR", ROOT / "keys"))
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))

PRIVATE_KEY_PATH = KEYS_DIR / "private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public.pem"
JWKS_PATH = KEYS_DIR / "jwks.json"

# --- token contract (SPEC.md §3) -------------------------------------------
ISSUER = os.environ.get("JWT_ISSUER", "https://auth.platform.local")
AUDIENCE = os.environ.get("JWT_AUDIENCE", "platform-tenants")
ALGORITHM = "RS256"            # never anything else; verifiers pin to ["RS256"]
TOKEN_TTL_SECONDS = int(os.environ.get("JWT_TTL_SECONDS", "900"))   # 15 min
CLOCK_SKEW_LEEWAY_SECONDS = 60

# --- prototype tenants -----------------------------------------------------
KNOWN_TENANTS = ("tenant_a", "tenant_b")

# --- demo UI (CORS) --------------------------------------------------------
# Comma-separated origins allowed to call the services from a browser.
# Empty (the default) => no CORS middleware is installed, so production and the
# unit/e2e suites behave exactly as before.
CORS_ALLOW_ORIGINS = tuple(
    o.strip() for o in os.environ.get("CORS_ALLOW_ORIGINS", "").split(",") if o.strip()
)
