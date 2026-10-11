"""A backend and a validator sharing keys, and two users each with a project chain."""

import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from bola_gateway.backend import create_app as create_backend
from bola_gateway.settings import Mode, Settings
from bola_gateway.validator import ORIGINAL_URI
from bola_gateway.validator import create_app as create_validator


def make_settings(mode: Mode = Mode.ENFORCE) -> Settings:
    return Settings(
        master_key=secrets.token_bytes(32), token_key=secrets.token_bytes(32), mode=mode
    )


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def backend(settings: Settings, tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_backend(settings, str(tmp_path / "backend.db"))) as client:
        yield client


@pytest.fixture
def validator(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_validator(settings)) as client:
        yield client


@dataclass(frozen=True)
class Owner:
    """A user with one project, one iteration in it and one task in that."""

    headers: dict[str, str]
    project: str
    iteration: str
    task: str

    @property
    def task_path(self) -> str:
        return f"/projects/{self.project}/iterations/{self.iteration}/tasks/{self.task}"


def token(backend: TestClient, username: str) -> dict[str, str]:
    issued = backend.post("/auth/token", json={"username": username}).json()
    return {"Authorization": f"Bearer {issued['access_token']}"}


def make_owner(backend: TestClient, username: str) -> Owner:
    headers = token(backend, username)
    project = backend.post("/projects", headers=headers, json={"name": username}).json()["id"]
    headers = token(backend, username)
    iteration = backend.post(
        f"/projects/{project}/iterations", headers=headers, json={"name": "I1"}
    ).json()["id"]
    task = backend.post(
        f"/projects/{project}/iterations/{iteration}/tasks", headers=headers, json={"title": "T"}
    ).json()["id"]
    return Owner(headers, project, iteration, task)


@pytest.fixture
def alice(backend: TestClient) -> Owner:
    return make_owner(backend, "alice")


@pytest.fixture
def bob(backend: TestClient) -> Owner:
    return make_owner(backend, "bob")


def ask(validator: TestClient, uri: str, headers: dict[str, str] | None = None) -> int:
    """What Nginx's auth_request subrequest gets back for a URI."""
    response = validator.get("/validate", headers={ORIGINAL_URI: uri, **(headers or {})})
    status: int = response.status_code
    return status
