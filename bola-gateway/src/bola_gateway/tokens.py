"""
Access tokens: who the caller is and which projects (chain roots) they may use.
Signed with HS256; the backend issues them, the validator only verifies them.
"""

import time
from dataclasses import dataclass
from uuid import UUID

import jwt

ALGORITHM = "HS256"
LIFETIME_SECONDS = 3600
REQUIRED_CLAIMS = ["sub", "projects", "exp"]


class InvalidTokenError(Exception):
    pass


@dataclass(frozen=True)
class Claims:
    subject: str
    projects: frozenset[UUID]


def issue(key: bytes, subject: str, projects: list[UUID]) -> str:
    payload = {
        "sub": subject,
        "projects": [str(p) for p in projects],
        "exp": int(time.time()) + LIFETIME_SECONDS,
    }
    return jwt.encode(payload, key, algorithm=ALGORITHM)


def verify(key: bytes, token: str) -> Claims:
    try:
        payload = jwt.decode(
            token, key, algorithms=[ALGORITHM], options={"require": REQUIRED_CLAIMS}
        )
        return Claims(str(payload["sub"]), frozenset(UUID(p) for p in payload["projects"]))
    except (jwt.InvalidTokenError, ValueError, TypeError) as error:
        raise InvalidTokenError from error
