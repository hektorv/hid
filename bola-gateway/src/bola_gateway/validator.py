"""
The validator Nginx consults before forwarding a request (`auth_request`).

Nginx sends a body-less subrequest carrying the original URI and the caller's
Authorization header. A 2xx answer lets the request through; 401 or 403 stops it
at the perimeter, before the backend or its database see it. In observe mode
everything passes and the verdict is only recorded, so the same deployment
serves as baseline and as treatment.

Every decision is logged as one JSON line with the time it took, for the
measurements.
"""

import json
import logging
import time
from collections.abc import Callable
from http import HTTPStatus

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from bola_gateway import tokens
from bola_gateway.chain import STATUS, ChainCheck, Decision
from bola_gateway.settings import Mode, Settings, from_environment

ORIGINAL_URI = "X-Original-URI"
ORIGINAL_METHOD = "X-Original-Method"
VERDICT_HEADER = "X-Bola-Verdict"
BEARER = "Bearer "
NANOSECONDS_PER_MICROSECOND = 1_000

logger = logging.getLogger("bola_gateway.validator")

# How each mode turns a decision into the answer Nginx acts on.
ANSWERS: dict[Mode, Callable[[Decision], HTTPStatus]] = {
    Mode.ENFORCE: lambda decision: STATUS[decision.verdict],
    Mode.OBSERVE: lambda decision: HTTPStatus.NO_CONTENT,
}


def _claims(request: Request, settings: Settings) -> tokens.Claims | None:
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith(BEARER):
        return None
    try:
        return tokens.verify(settings.token_key, authorization.removeprefix(BEARER))
    except tokens.InvalidTokenError:
        return None


def create_app(settings: Settings | None = None) -> Starlette:
    config = settings or from_environment()
    check = ChainCheck(config.master_key, config.prefix_bytes, config.protected_prefix)
    answer = ANSWERS[config.mode]

    async def validate(request: Request) -> Response:
        started = time.perf_counter_ns()
        uri = request.headers.get(ORIGINAL_URI, "")
        claims = _claims(request, config)
        decision = check.decide(uri, claims)
        status = answer(decision)
        elapsed = (time.perf_counter_ns() - started) // NANOSECONDS_PER_MICROSECOND
        logger.info(
            json.dumps(
                {
                    "mode": config.mode,
                    "method": request.headers.get(ORIGINAL_METHOD, ""),
                    "uri": uri,
                    "subject": claims.subject if claims else None,
                    "verdict": decision.verdict,
                    "links": decision.links,
                    "status": status,
                    "micros": elapsed,
                }
            )
        )
        return Response(status_code=status, headers={VERDICT_HEADER: decision.verdict})

    return Starlette(routes=[Route("/validate", validate)])


def app() -> Starlette:
    """Factory for uvicorn: `uvicorn --factory bola_gateway.validator:app`."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    return create_app()
