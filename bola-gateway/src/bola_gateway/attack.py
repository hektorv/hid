"""
The experiment against a running lab: Bob, a legitimate user with his own project,
tries to reach Alice's resources, first on the backend directly (the baseline)
and then through the gateway. Then legitimate requests measure what the gateway
costs.

    python -m bola_gateway.attack --gateway http://localhost:8080 \\
        --backend http://localhost:8081 --requests 300
"""

import argparse
import statistics
import time
import uuid
from dataclasses import dataclass

import httpx

MILLISECONDS = 1_000
QUANTILES = 20
P95_CUT = 18  # statistics.quantiles(n=20) gives 19 cut points; the 19th is the 95th percentile


@dataclass(frozen=True)
class Owner:
    headers: dict[str, str]
    project: str
    iteration: str
    task: str


@dataclass(frozen=True)
class Attack:
    name: str
    method: str
    path: str


def sign_in(client: httpx.Client, username: str) -> dict[str, str]:
    issued = client.post("/auth/token", json={"username": username}).raise_for_status().json()
    return {"Authorization": f"Bearer {issued['access_token']}"}


def make_owner(client: httpx.Client, username: str) -> Owner:
    headers = sign_in(client, username)
    project = client.post("/projects", headers=headers, json={"name": username}).json()["id"]
    headers = sign_in(client, username)
    iterations = f"/projects/{project}/iterations"
    iteration = client.post(iterations, headers=headers, json={"name": "I1"}).json()["id"]
    tasks = f"{iterations}/{iteration}/tasks"
    task = client.post(tasks, headers=headers, json={"title": "secret"}).json()["id"]
    return Owner(headers, project, iteration, task)


def attacks(alice: Owner, bob: Owner) -> list[Attack]:
    own = f"/projects/{bob.project}/iterations/{bob.iteration}"
    return [
        Attack("foreign project", "GET", f"/projects/{alice.project}"),
        Attack("foreign chain", "GET", f"/projects/{alice.project}/iterations/{alice.iteration}"),
        Attack(
            "own project, foreign iteration",
            "GET",
            f"/projects/{bob.project}/iterations/{alice.iteration}",
        ),
        Attack("own chain, foreign task", "GET", f"{own}/tasks/{alice.task}"),
        Attack("own chain, invented task", "GET", f"{own}/tasks/{uuid.uuid4()}"),
        Attack(
            "write into a foreign iteration",
            "POST",
            f"/projects/{bob.project}/iterations/{alice.iteration}/tasks",
        ),
        Attack(
            "encoded dot segments",
            "GET",
            f"/projects/{bob.project}/iterations/%2e%2e/{alice.iteration}",
        ),
    ]


def run_attacks(base: str, bob: Owner, plan: list[Attack]) -> list[tuple[str, int]]:
    with httpx.Client(base_url=base) as client:
        return [
            (
                attack.name,
                client.request(
                    attack.method, attack.path, headers=bob.headers, json={"title": "injected"}
                ).status_code,
            )
            for attack in plan
        ]


def latencies(base: str, owner: Owner, count: int) -> list[float]:
    path = f"/projects/{owner.project}/iterations/{owner.iteration}/tasks/{owner.task}"
    timings = []
    with httpx.Client(base_url=base) as client:
        client.get(path, headers=owner.headers)  # warm the connections
        for _ in range(count):
            started = time.perf_counter()
            client.get(path, headers=owner.headers).raise_for_status()
            timings.append((time.perf_counter() - started) * MILLISECONDS)
    return timings


def summary(timings: list[float]) -> str:
    p95 = statistics.quantiles(timings, n=QUANTILES)[P95_CUT]
    return f"median {statistics.median(timings):.2f} ms, p95 {p95:.2f} ms"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--gateway", default="http://localhost:8080")
    parser.add_argument("--backend", default="http://localhost:8081")
    parser.add_argument("--requests", type=int, default=300)
    options = parser.parse_args()

    with httpx.Client(base_url=options.backend) as client:
        alice, bob = make_owner(client, "alice"), make_owner(client, "bob")
    plan = attacks(alice, bob)
    direct = run_attacks(options.backend, bob, plan)
    guarded = run_attacks(options.gateway, bob, plan)

    print("| attack (Bob on Alice's data) | backend alone | through the gateway |")
    print("|---|---|---|")
    for (name, alone), (_, through) in zip(direct, guarded, strict=True):
        print(f"| {name} | {alone} | {through} |")
    print()
    print(f"Legitimate requests ({options.requests}, Alice reading her own task):")
    print(f"- backend alone:       {summary(latencies(options.backend, alice, options.requests))}")
    print(f"- through the gateway: {summary(latencies(options.gateway, alice, options.requests))}")


if __name__ == "__main__":
    main()
