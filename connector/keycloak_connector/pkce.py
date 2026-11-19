"""PKCE (RFC 7636) and random-value helpers. Standard library only."""
from __future__ import annotations

import base64
import hashlib
import secrets


def random_token(nbytes: int = 32) -> str:
    """URL-safe random string used for ``state`` and ``nonce`` (unguessable, single use)."""
    return secrets.token_urlsafe(nbytes)


def generate_verifier() -> str:
    """A fresh PKCE ``code_verifier`` (64 URL-safe characters, within the 43-128 range of the RFC)."""
    return secrets.token_urlsafe(48)


def challenge_s256(verifier: str) -> str:
    """``BASE64URL(SHA256(verifier))`` without padding: the ``code_challenge`` for method ``S256``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def half_hash(value: str, alg: str = "RS256") -> str:
    """Left half of the hash of ``value``, base64url encoded: the form of ``at_hash`` in ID tokens.

    The hash function follows the signing algorithm (``RS256`` -> SHA-256, ``RS384`` -> SHA-384 ...).
    """
    bits = alg[-3:]
    hasher = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}.get(bits, hashlib.sha256)
    digest = hasher(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")
