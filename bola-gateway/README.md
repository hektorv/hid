# bola-gateway

A perimeter against BOLA (OWASP API1:2023) for APIs with nested resources, built
from a standard reverse proxy and the HUUID reference implementation, with no
change to the API it protects.

```
client ──▶ Nginx ──auth_request──▶ validator (Python + huuid)
             │                      does the chain in the URL belong to the caller?
             └──▶ backend, untouched (only when the validator answered 2xx)
```

The identifiers of a nested path, read in order, form a chain:
`/projects/{p}/iterations/{i}/tasks/{t}`. The project is a root the caller's
token lists; each next identifier is an HUUID minted under the one before with
the project's key (HKDF of a master key). The validator checks one HMAC per link
and needs no database. A request that fails is answered 401 or 403 by Nginx and
never reaches the backend.

The backend is deliberately vulnerable: it requires a valid token but looks up
the last identifier of the path alone, whoever asks. It is the baseline.

## Pieces

| Path | What |
|---|---|
| `src/bola_gateway/chain.py` | The decision: root in the token, every link an HUUID child, ambiguous paths refused |
| `src/bola_gateway/validator.py` | The service Nginx consults; modes `enforce` and `observe`; one JSON log line per decision with its time |
| `src/bola_gateway/backend.py` | The vulnerable API; logs every request it serves |
| `src/bola_gateway/attack.py` | The experiment: Bob against Alice's data, backend alone vs. through the gateway, and latency |
| `nginx/nginx.conf` | `auth_request` on `/projects`, the verdict in the access log and in `X-Bola-Verdict` |
| `tests/` | The chain check, the validator and the whole path in process |

## Run

```sh
cd bola-gateway
python3.12 -m venv .venv && .venv/bin/pip install -e ../huuid -e ".[dev]"
.venv/bin/pytest

.venv/bin/python -m bola_gateway.secrets > .env      # never committed
docker compose up --build -d                          # GATEWAY_PORT, BACKEND_PORT, MODE, PREFIX_BYTES
.venv/bin/python -m bola_gateway.attack --gateway http://localhost:8080 --backend http://localhost:8081
```

`MODE=observe` lets every request through and only records the verdict, so the
same deployment gives the baseline and the treatment. `PREFIX_BYTES` sets the
HUUID tag length (3, the v1 default, is 24 bits).

## A first run (2026-10-10, development laptop, Docker)

| attack (Bob on Alice's data) | backend alone | through the gateway |
|---|---|---|
| foreign project | 200 | 403 |
| foreign chain | 200 | 403 |
| own project, foreign iteration | 200 | 403 |
| own chain, foreign task | 200 | 403 |
| own chain, invented task | 404 | 403 |
| write into a foreign iteration | 201 | 403 |
| encoded dot segments | 404 | 403 |

None of the blocked requests reached the backend (its log counts only the setup,
the direct attacks and the legitimate requests). For 300 legitimate reads of a
three-level resource: median 1.58 ms alone, 2.41 ms through the gateway; the
validator's own decision took a median of 207 µs, the rest is the extra hop of
the subrequest. One run, one machine: an indication, not a measurement.

## What it does not cover

- Same-parent access between users of one project: that is authorization of
  actions, not structure, and stays with the application.
- HUUID v1's known limits apply as they are (the tag depends on the parent only;
  24-bit tags by default): the gateway evaluates the reference implementation,
  it does not change it.
- Paths that two parsers could read differently (encoded characters, dot or
  empty segments, `;`, `\`) are refused rather than interpreted, because Nginx
  forwards the URI as the client sent it.
