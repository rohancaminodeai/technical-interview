"""Unit-test fixtures: an ephemeral RSA keypair + JWKS.

Generated in-process so unit tests never depend on `keys/` having been
populated on disk. Reuses the production helpers from keys/gen_keys.py so the
test JWKS is built exactly the way the real one is.
"""
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from keys.gen_keys import build_jwks, compute_kid


@pytest.fixture(scope="session")
def keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = compute_kid(public_key)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return SimpleNamespace(
        private_pem=private_pem,
        public_pem=public_pem,
        public_key=public_key,
        kid=kid,
        jwks=build_jwks(public_key, kid),
    )


@pytest.fixture(scope="session")
def other_keypair():
    """A second, unrelated keypair — for forged-signature tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return SimpleNamespace(private_pem=private_pem)
