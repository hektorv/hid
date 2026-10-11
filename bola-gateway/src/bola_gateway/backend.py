"""
A deliberately vulnerable API with nested resources:

    /projects/{project_id}/iterations/{iteration_id}/tasks/{task_id}

It authenticates every request (a valid token is required) but never checks that
the resource belongs to the caller: each handler looks up the last identifier of
the path alone. That is the textbook BOLA (OWASP API1:2023) the perimeter has to
stop without any change to this code.

It mints identifiers as HUUIDs: a project ID is random, an iteration's is minted
under its project and a task's under its iteration, with the project's key.

Every request it serves is logged, so the experiment can count what reached it.
"""

import json
import logging
import os
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from uuid import UUID

from huuid import generate_huuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from bola_gateway import tokens
from bola_gateway.keys import project_key
from bola_gateway.settings import Settings, from_environment

DEFAULT_DATABASE = "bola-backend.db"
BEARER = "Bearer "
SCHEMA = """
CREATE TABLE IF NOT EXISTS projects
    (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS iterations
    (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tasks
    (id TEXT PRIMARY KEY, iteration_id TEXT NOT NULL, title TEXT NOT NULL);
"""

logger = logging.getLogger("bola_gateway.backend")


class Unauthenticated(Exception):
    pass


def create_app(settings: Settings | None = None, database: str | None = None) -> Starlette:
    config = settings or from_environment()
    path = database or os.environ.get("DATABASE", DEFAULT_DATABASE)

    @contextmanager
    def connect() -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(path)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    with connect() as connection:
        connection.executescript(SCHEMA)

    def caller(request: Request) -> tokens.Claims:
        authorization = request.headers.get("Authorization", "")
        try:
            return tokens.verify(config.token_key, authorization.removeprefix(BEARER))
        except tokens.InvalidTokenError as error:
            raise Unauthenticated from error

    def served(request: Request, status: HTTPStatus) -> None:
        logger.info(
            json.dumps({"method": request.method, "path": request.url.path, "status": status})
        )

    def one(request: Request, query: str, key: str) -> Response:
        """The vulnerability: fetch by the last identifier only, whoever asks."""
        caller(request)
        with connect() as connection:
            row = connection.execute(query, (request.path_params[key],)).fetchone()
        status = HTTPStatus.OK if row else HTTPStatus.NOT_FOUND
        served(request, status)
        return JSONResponse(row and dict(zip(("id", "parent", "name"), row, strict=True)), status)

    async def issue_token(request: Request) -> Response:
        """Lab sign-in: the token lists the projects the user owns now."""
        username = str((await request.json())["username"])
        with connect() as connection:
            owned = connection.execute("SELECT id FROM projects WHERE owner = ?", (username,))
            projects = [UUID(row[0]) for row in owned.fetchall()]
        return JSONResponse({"access_token": tokens.issue(config.token_key, username, projects)})

    async def create_project(request: Request) -> Response:
        owner = caller(request).subject
        project_id = uuid.uuid4()
        with connect() as connection:
            connection.execute(
                "INSERT INTO projects VALUES (?, ?, ?)",
                (str(project_id), owner, str((await request.json())["name"])),
            )
        served(request, HTTPStatus.CREATED)
        return JSONResponse({"id": str(project_id)}, HTTPStatus.CREATED)

    async def create_iteration(request: Request) -> Response:
        caller(request)
        project_id = UUID(request.path_params["project_id"])
        key = project_key(config.master_key, project_id)
        iteration_id = generate_huuid(str(project_id), key, config.prefix_bytes)
        with connect() as connection:
            connection.execute(
                "INSERT INTO iterations VALUES (?, ?, ?)",
                (str(iteration_id), str(project_id), str((await request.json())["name"])),
            )
        served(request, HTTPStatus.CREATED)
        return JSONResponse({"id": str(iteration_id)}, HTTPStatus.CREATED)

    async def create_task(request: Request) -> Response:
        caller(request)
        key = project_key(config.master_key, UUID(request.path_params["project_id"]))
        iteration_id = request.path_params["iteration_id"]
        task_id = generate_huuid(iteration_id, key, config.prefix_bytes)
        with connect() as connection:
            connection.execute(
                "INSERT INTO tasks VALUES (?, ?, ?)",
                (str(task_id), iteration_id, str((await request.json())["title"])),
            )
        served(request, HTTPStatus.CREATED)
        return JSONResponse({"id": str(task_id)}, HTTPStatus.CREATED)

    async def get_project(request: Request) -> Response:
        return one(request, "SELECT id, owner, name FROM projects WHERE id = ?", "project_id")

    async def get_iteration(request: Request) -> Response:
        query = "SELECT id, project_id, name FROM iterations WHERE id = ?"
        return one(request, query, "iteration_id")

    async def get_task(request: Request) -> Response:
        return one(request, "SELECT id, iteration_id, title FROM tasks WHERE id = ?", "task_id")

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def unauthenticated(request: Request, exc: Exception) -> Response:
        return JSONResponse({"detail": "A valid token is required"}, HTTPStatus.UNAUTHORIZED)

    project = "/projects/{project_id}"
    iteration = project + "/iterations/{iteration_id}"
    routes = [
        Route("/health", health),
        Route("/auth/token", issue_token, methods=["POST"]),
        Route("/projects", create_project, methods=["POST"]),
        Route(project, get_project),
        Route(project + "/iterations", create_iteration, methods=["POST"]),
        Route(iteration, get_iteration),
        Route(iteration + "/tasks", create_task, methods=["POST"]),
        Route(iteration + "/tasks/{task_id}", get_task),
    ]
    return Starlette(routes=routes, exception_handlers={Unauthenticated: unauthenticated})


def app() -> Starlette:
    """Factory for uvicorn: `uvicorn --factory bola_gateway.backend:app`."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    return create_app()
