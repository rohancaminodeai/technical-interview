"""Generate the IdP's RSA keypair and publish a JWKS document.

The private key signs tokens (lives only in the auth service — KMS in production).
The public key is published via JWKS so tenants can verify offline (SPEC.md §4.2).

Usage:
    python keys/gen_keys.py [--force]

Idempotent: refuses to overwrite an existing private key unless --force is given,
so re-running in a seeded environment won't silently rotate the key.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Allow running as `python keys/gen_keys.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.config import (  # noqa: E402
    ALGORITHM,
    JWKS_PATH,
    KEYS_DIR,
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH,
)


def _b64url_uint(value: int) -> str:
    """Encode an unsigned int as base64url with no padding (JWK n/e format)."""
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def compute_kid(public_key: rsa.RSAPublicKey) -> str:
    """Deterministic key id = first 16 hex chars of SHA-256 over the DER public key.

    Deterministic so the JWKS `kid` matches the token header `kid` for the same key.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


def build_jwks(public_key: rsa.RSAPublicKey, kid: str) -> dict:
    numbers = public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": ALGORITHM,
                "kid": kid,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }


def generate(force: bool = False) -> str:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() and not force:
        print(f"private key already exists at {PRIVATE_KEY_PATH} (use --force to rotate)")
        # Still (re)publish JWKS from the existing public key so the set is consistent.
        public_key = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
        kid = compute_kid(public_key)
        JWKS_PATH.write_text(json.dumps(build_jwks(public_key, kid), indent=2))
        return kid

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    PRIVATE_KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    PUBLIC_KEY_PATH.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    kid = compute_kid(public_key)
    JWKS_PATH.write_text(json.dumps(build_jwks(public_key, kid), indent=2))

    print(f"wrote {PRIVATE_KEY_PATH}")
    print(f"wrote {PUBLIC_KEY_PATH}")
    print(f"wrote {JWKS_PATH} (kid={kid})")
    return kid


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate IdP RSA keypair + JWKS")
    parser.add_argument("--force", action="store_true", help="overwrite existing keys")
    args = parser.parse_args()
    generate(force=args.force)
