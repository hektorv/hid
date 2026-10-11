"""The chain check: one HMAC per link, no database, and no guessing about paths."""

import secrets
import uuid

import pytest
from huuid import generate_huuid

from bola_gateway.chain import ChainCheck, Verdict, chain_in, is_ambiguous
from bola_gateway.keys import project_key
from bola_gateway.tokens import Claims

MASTER = secrets.token_bytes(32)
PREFIX_BYTES = 3
CHECK = ChainCheck(MASTER, PREFIX_BYTES, "/projects")


def chain_of(project: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    key = project_key(MASTER, project)
    iteration = generate_huuid(str(project), key, PREFIX_BYTES)
    return iteration, generate_huuid(str(iteration), key, PREFIX_BYTES)


ALICE_PROJECT, BOB_PROJECT = uuid.uuid4(), uuid.uuid4()
ALICE_ITERATION, ALICE_TASK = chain_of(ALICE_PROJECT)
BOB_ITERATION, BOB_TASK = chain_of(BOB_PROJECT)
BOB = Claims("bob", frozenset({BOB_PROJECT}))


def path(project: uuid.UUID, iteration: uuid.UUID, task: uuid.UUID) -> str:
    return f"/projects/{project}/iterations/{iteration}/tasks/{task}"


def test_the_callers_own_chain_passes_with_one_hmac_per_link() -> None:
    decision = CHECK.decide(path(BOB_PROJECT, BOB_ITERATION, BOB_TASK) + "?expand=1", BOB)
    assert (decision.verdict, decision.links, decision.allowed) == (Verdict.ALLOWED, 2, True)


@pytest.mark.parametrize(
    ("uri", "verdict"),
    [
        (path(ALICE_PROJECT, ALICE_ITERATION, ALICE_TASK), Verdict.FOREIGN_ROOT),
        (path(BOB_PROJECT, ALICE_ITERATION, ALICE_TASK), Verdict.BROKEN_CHAIN),
        (path(BOB_PROJECT, BOB_ITERATION, ALICE_TASK), Verdict.BROKEN_CHAIN),
        (path(BOB_PROJECT, BOB_ITERATION, uuid.uuid4()), Verdict.BROKEN_CHAIN),
    ],
    ids=["foreign root", "foreign child", "foreign leaf", "invented leaf"],
)
def test_chains_that_are_not_the_callers_are_refused(uri: str, verdict: Verdict) -> None:
    decision = CHECK.decide(uri, BOB)
    assert (decision.verdict, decision.allowed) == (verdict, False)


def test_a_broken_link_stops_the_check_where_it_breaks() -> None:
    assert CHECK.decide(path(BOB_PROJECT, ALICE_ITERATION, ALICE_TASK), BOB).links == 1


@pytest.mark.parametrize(
    "uri",
    [
        f"/projects/{BOB_PROJECT}/iterations/%2e%2e/{ALICE_ITERATION}",
        f"/projects/{BOB_PROJECT}/iterations/../{ALICE_ITERATION}",
        f"/projects/{BOB_PROJECT}//iterations/{BOB_ITERATION}",
        f"/projects/{BOB_PROJECT};x/iterations/{BOB_ITERATION}",
        f"/projects/{BOB_PROJECT}/iterations\\{ALICE_ITERATION}",
    ],
    ids=["encoded dots", "dot segment", "empty segment", "matrix parameter", "backslash"],
)
def test_paths_two_parsers_could_read_differently_are_refused(uri: str) -> None:
    assert is_ambiguous(uri)
    assert CHECK.decide(uri, BOB).verdict == Verdict.AMBIGUOUS_PATH


def test_without_a_token_protected_paths_are_unauthenticated() -> None:
    assert CHECK.decide(f"/projects/{BOB_PROJECT}", None).verdict == Verdict.UNAUTHENTICATED


def test_paths_outside_the_hierarchy_are_left_to_the_backend() -> None:
    assert CHECK.decide("/auth/token", None).verdict == Verdict.UNPROTECTED


def test_the_chain_is_every_uuid_segment_root_first() -> None:
    uri = path(BOB_PROJECT, BOB_ITERATION, BOB_TASK)
    assert chain_in(uri) == [BOB_PROJECT, BOB_ITERATION, BOB_TASK]
