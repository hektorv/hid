"""
The perimeter end to end, in process: the backend lets BOLA through, the validator
stops it before the backend is asked, and observe mode only records it.
"""

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from bola_gateway.settings import Mode, Settings
from bola_gateway.validator import ORIGINAL_URI, VERDICT_HEADER
from bola_gateway.validator import create_app as create_validator
from tests.conftest import Owner, ask


def gateway(validator: TestClient, backend: TestClient, uri: str, owner: Owner) -> int:
    """What Nginx does: ask the validator, forward only on a 2xx answer."""
    allowed = ask(validator, uri, owner.headers)
    if allowed >= 300:
        return allowed
    status: int = backend.get(uri, headers=owner.headers).status_code
    return status


def attacks(alice: Owner, bob: Owner) -> dict[str, str]:
    return {
        "foreign project": f"/projects/{alice.project}",
        "foreign chain": f"/projects/{alice.project}/iterations/{alice.iteration}",
        "own project, foreign iteration": f"/projects/{bob.project}/iterations/{alice.iteration}",
        "own chain, foreign task": (
            f"/projects/{bob.project}/iterations/{bob.iteration}/tasks/{alice.task}"
        ),
    }


def test_the_backend_alone_serves_every_attack(
    backend: TestClient, alice: Owner, bob: Owner
) -> None:
    served = {
        name: backend.get(uri, headers=bob.headers) for name, uri in attacks(alice, bob).items()
    }
    assert {name: r.status_code for name, r in served.items()} == dict.fromkeys(served, 200)
    leaked = served["own chain, foreign task"].json()
    assert (leaked["id"], leaked["parent"]) == (alice.task, alice.iteration)


def test_the_perimeter_stops_every_attack_and_serves_the_owner(
    backend: TestClient, validator: TestClient, alice: Owner, bob: Owner
) -> None:
    statuses = {
        name: gateway(validator, backend, uri, bob) for name, uri in attacks(alice, bob).items()
    }
    assert statuses == dict.fromkeys(statuses, 403)
    assert gateway(validator, backend, alice.task_path, alice) == 200
    assert gateway(validator, backend, bob.task_path, bob) == 200


def test_writing_into_a_foreign_chain_is_stopped(
    validator: TestClient, alice: Owner, bob: Owner
) -> None:
    injection = f"/projects/{bob.project}/iterations/{alice.iteration}/tasks"
    assert ask(validator, injection, bob.headers) == 403


def test_a_missing_or_forged_token_is_unauthenticated(validator: TestClient, bob: Owner) -> None:
    forged = {"Authorization": "Bearer not.a.token"}
    assert ask(validator, bob.task_path) == 401
    assert ask(validator, bob.task_path, forged) == 401


@pytest.fixture
def observer(settings: Settings) -> Iterator[TestClient]:
    observing = Settings(settings.master_key, settings.token_key, mode=Mode.OBSERVE)
    with TestClient(create_validator(observing)) as client:
        yield client


def test_observe_mode_lets_everything_through_and_names_the_verdict(
    observer: TestClient, alice: Owner, bob: Owner
) -> None:
    foreign = f"/projects/{bob.project}/iterations/{alice.iteration}"
    response = observer.get("/validate", headers={ORIGINAL_URI: foreign, **bob.headers})
    assert (response.status_code, response.headers[VERDICT_HEADER]) == (204, "broken-chain")
