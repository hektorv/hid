"""Settings shared by the backend, the validator and the attack script, from the environment."""

import os
from dataclasses import dataclass
from enum import StrEnum

# HUUID v1 reference default: a 3-byte (24-bit) tag.
DEFAULT_PREFIX_BYTES = 3
DEFAULT_PROTECTED_PREFIX = "/projects"


class Mode(StrEnum):
    """Enforce rejects what fails validation; observe lets it through and records it."""

    ENFORCE = "enforce"
    OBSERVE = "observe"


@dataclass(frozen=True)
class Settings:
    master_key: bytes
    token_key: bytes
    prefix_bytes: int = DEFAULT_PREFIX_BYTES
    mode: Mode = Mode.ENFORCE
    protected_prefix: str = DEFAULT_PROTECTED_PREFIX


def _required(name: str) -> bytes:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not set; generate one with `python -m bola_gateway.secrets`")
    return value.encode()


def from_environment() -> Settings:
    return Settings(
        master_key=_required("MASTER_KEY"),
        token_key=_required("TOKEN_KEY"),
        prefix_bytes=int(os.environ.get("PREFIX_BYTES", DEFAULT_PREFIX_BYTES)),
        mode=Mode(os.environ.get("MODE", Mode.ENFORCE)),
        protected_prefix=os.environ.get("PROTECTED_PREFIX", DEFAULT_PROTECTED_PREFIX),
    )
