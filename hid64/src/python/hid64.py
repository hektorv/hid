import hmac
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_key(master_key: bytes, context_id: str) -> bytes:
    """Derive a per-tenant or per-context 32-byte key from a master key via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context_id.encode("utf-8"),
    ).derive(master_key)


def get_prefix32(root_id: str, parent_id: str, secret: bytes) -> int:
    """32-bit HMAC-SHA256 prefix bound to (root_id, parent_id).

    `root_id` must be authenticated externally before calling.
    """
    context = f"{root_id}:{parent_id}".encode("utf-8")
    digest = hmac.new(secret, context, hashlib.sha256).digest()
    return int.from_bytes(digest[:4], "big")


def generate_hid64(root_id: str, parent_id: str, secret: bytes) -> int:
    prefix = get_prefix32(root_id, parent_id, secret)
    suffix = int.from_bytes(os.urandom(4), "big")
    return (prefix << 32) | suffix


def validate_hid64(root_id: str, parent_id: str, child_id: int, secret: bytes) -> bool:
    return (child_id >> 32) == get_prefix32(root_id, parent_id, secret)
