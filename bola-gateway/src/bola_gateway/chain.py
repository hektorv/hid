"""
The check the perimeter makes on every request: does the chain of identifiers in
the URL belong to the caller?

The identifiers of a nested REST path, read in order, form a chain: the first is
a project (a root the token lists), each next one an HUUID minted under the one
before. One HMAC per link decides it, with no database. A path the validator could
read differently from the backend (encoded characters, dot segments, empty
segments) is refused rather than guessed: the proxy forwards it as sent.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from http import HTTPStatus
from itertools import pairwise
from uuid import UUID

from huuid import validate_huuid

from bola_gateway.keys import project_key
from bola_gateway.tokens import Claims

SEPARATOR = "/"
QUERY = "?"
# Characters and segments that let two parsers read one path two ways.
AMBIGUOUS_MARKERS = ("%", "\\", ";")
DOT_SEGMENTS = frozenset({".", ".."})


class Verdict(StrEnum):
    ALLOWED = "allowed"
    UNPROTECTED = "unprotected"
    UNAUTHENTICATED = "unauthenticated"
    AMBIGUOUS_PATH = "ambiguous-path"
    FOREIGN_ROOT = "foreign-root"
    BROKEN_CHAIN = "broken-chain"


# What the perimeter answers for each verdict when it enforces.
STATUS: dict[Verdict, HTTPStatus] = {
    Verdict.ALLOWED: HTTPStatus.NO_CONTENT,
    Verdict.UNPROTECTED: HTTPStatus.NO_CONTENT,
    Verdict.UNAUTHENTICATED: HTTPStatus.UNAUTHORIZED,
    Verdict.AMBIGUOUS_PATH: HTTPStatus.FORBIDDEN,
    Verdict.FOREIGN_ROOT: HTTPStatus.FORBIDDEN,
    Verdict.BROKEN_CHAIN: HTTPStatus.FORBIDDEN,
}


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    # How many links were checked with an HMAC (the cost the thesis measures).
    links: int = 0

    @property
    def allowed(self) -> bool:
        return STATUS[self.verdict] == HTTPStatus.NO_CONTENT


def _as_uuid(segment: str) -> UUID | None:
    try:
        return UUID(segment)
    except ValueError:
        return None


def path_of(uri: str) -> str:
    return uri.split(QUERY, 1)[0]


def is_ambiguous(path: str) -> bool:
    segments = path.split(SEPARATOR)[1:]
    return (
        any(marker in path for marker in AMBIGUOUS_MARKERS)
        or any(segment in DOT_SEGMENTS for segment in segments)
        or "" in segments[:-1]
    )


def chain_in(path: str) -> list[UUID]:
    """The identifiers of the path, root first: every segment that is a UUID."""
    return [found for segment in path.split(SEPARATOR) if (found := _as_uuid(segment))]


@dataclass(frozen=True)
class ChainCheck:
    master_key: bytes
    prefix_bytes: int
    protected_prefix: str

    def decide(self, uri: str, claims: Claims | None) -> Decision:
        path = path_of(uri)
        if not path.startswith(self.protected_prefix):
            return Decision(Verdict.UNPROTECTED)
        if is_ambiguous(path):
            return Decision(Verdict.AMBIGUOUS_PATH)
        if claims is None:
            return Decision(Verdict.UNAUTHENTICATED)
        chain = chain_in(path)
        if not chain:
            return Decision(Verdict.ALLOWED)
        root, *descendants = chain
        if root not in claims.projects:
            return Decision(Verdict.FOREIGN_ROOT)
        return self._links(root, chain, len(descendants))

    def _links(self, root: UUID, chain: Sequence[UUID], count: int) -> Decision:
        key = project_key(self.master_key, root)
        for checked, (parent, child) in enumerate(pairwise(chain), 1):
            if not validate_huuid(str(parent), child, key, self.prefix_bytes):
                return Decision(Verdict.BROKEN_CHAIN, checked)
        return Decision(Verdict.ALLOWED, count)
