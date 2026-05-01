import hmac
import hashlib
import os
from uuid import UUID, RFC_4122

def hmac_prefix(parent_id: str, secret: bytes, length: int = 3) -> bytes:
    """Derive HMAC-SHA256 prefix (truncated to `length`)."""
    return hmac.new(secret, parent_id.encode('utf-8'), hashlib.sha256).digest()[:length]

def generate_huuid(parent_id: str, secret: bytes, prefix_len: int = 3) -> UUID:
    """Generate a hierarchical UUID (HUUID) from a parent_id and secret key."""
    if not (1 <= prefix_len <= 6):
        raise ValueError("Prefix length must be between 1 and 6 bytes")

    prefix = hmac_prefix(parent_id, secret, prefix_len)
    suffix = os.urandom(6 - prefix_len)  # 6 bytes total for node

    # UUIDv8: version (bits 12–15 = 1000) and variant (bits 6–7 = 10)
    time_low = os.urandom(4)
    time_mid = os.urandom(2)

    rand_12 = int.from_bytes(os.urandom(2), "big") & 0x0FFF
    time_hi_and_version = (0x8 << 12) | rand_12  # Set version 8
    time_hi_and_version_bytes = time_hi_and_version.to_bytes(2, "big")

    clock_seq_hi = (0b10 << 6) | (os.urandom(1)[0] & 0x3F)
    clock_seq_low = os.urandom(1)

    node = prefix + suffix  # 6 bytes

    uuid_bytes = (
        time_low +                  # 4 bytes
        time_mid +                  # 2 bytes
        time_hi_and_version_bytes + # 2 bytes
        bytes([clock_seq_hi]) +     # 1 byte
        clock_seq_low +             # 1 byte
        node                        # 6 bytes
    )
    return UUID(bytes=uuid_bytes)

def validate_huuid(parent_id: str, uuid_obj: UUID, secret: bytes, prefix_len: int = 3) -> bool:
    """Validate that a UUID matches the HUUID derived from parent_id."""
    if uuid_obj.version != 8:
        return False
    if uuid_obj.variant != RFC_4122:
        return False

    expected_prefix = hmac_prefix(parent_id, secret, prefix_len)
    node = uuid_obj.bytes[-6:]
    return node.startswith(expected_prefix)
