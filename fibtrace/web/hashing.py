"""
Password hashing for fibtrace web users (ported from netlapse).

Stdlib-only (``hashlib.scrypt``) — no bcrypt/argon2/passlib dependency. scrypt
is memory-hard, which is the property that matters against GPU/ASIC cracking.

Hashes are stored as a single self-describing string so parameters can be
upgraded over time without a schema change and old hashes still verify:

    scrypt$<N>$<r>$<p>$<b64salt>$<b64hash>

Only ``verify_password`` is needed to check a login; ``needs_rehash`` lets the
caller transparently upgrade a user's stored hash to current parameters on
their next successful login.
"""

import base64
import hashlib
import hmac
import os

# Current parameters. N must be a power of two. 16384/8/1 ≈ 16 MiB, ~130ms.
_N = 16384
_R = 8
_P = 1
_DKLEN = 32
_SALT_BYTES = 16
_MAXMEM = 64 * 1024 * 1024  # headroom above the ~16 MiB scrypt needs

_PREFIX = "scrypt"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def hash_password(password: str) -> str:
    """Hash a plaintext password into the self-describing scrypt format."""
    if not password:
        raise ValueError("password must not be empty")
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN, maxmem=_MAXMEM,
    )
    return f"{_PREFIX}${_N}${_R}${_P}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a plaintext password against a stored hash."""
    try:
        prefix, n, r, p, b64salt, b64hash = stored.split("$")
        if prefix != _PREFIX:
            return False
        n, r, p = int(n), int(r), int(p)
        salt = _b64d(b64salt)
        expected = _b64d(b64hash)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt, n=n, r=r, p=p, dklen=len(expected), maxmem=_MAXMEM,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, base64.binascii.Error):
        return False


def needs_rehash(stored: str) -> bool:
    """True if a stored hash was made with parameters weaker than current."""
    try:
        prefix, n, r, p, _, _ = stored.split("$")
        if prefix != _PREFIX:
            return True
        return (int(n), int(r), int(p)) != (_N, _R, _P)
    except (ValueError, TypeError):
        return True