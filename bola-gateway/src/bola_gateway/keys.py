"""
Per-project keys: each project's HUUID secret is derived from one master key with
HKDF-SHA256 (RFC 5869), so the secret of a project never needs storing and never
leaves the services that mint and validate.
"""

import hashlib
import hmac
from uuid import UUID

HASH = hashlib.sha256
KEY_BYTES = 32
INFO_PREFIX = b"huuid-project:"
SALT = b"bola-gateway"
FIRST_BLOCK = b"\x01"


def hkdf_sha256(master: bytes, info: bytes, length: int = KEY_BYTES) -> bytes:
    """HKDF extract and expand; one block is enough for a 32-byte key."""
    if length > HASH().digest_size:
        raise ValueError("Only single-block outputs are needed here")
    pseudo_random_key = hmac.new(SALT, master, HASH).digest()
    return hmac.new(pseudo_random_key, info + FIRST_BLOCK, HASH).digest()[:length]


def project_key(master: bytes, project_id: UUID) -> bytes:
    return hkdf_sha256(master, INFO_PREFIX + str(project_id).encode())
