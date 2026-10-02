"""Closed-loop load test against the LOCAL compose stack (`make up`). Dev fixtures only.

Each stage runs N concurrent virtual users for D seconds; each user fires requests
back to back. Prints one JSON line per stage: throughput, latency percentiles, codes.

    STAGES=10,50,100 DURATION=15 uv run python tools/load/load.py staff_case_list

Scenarios: api_readyz, web_intake_page, staff_case_list, staff_case_detail,
public_submit (creates real cases: reset with `make clean && make up`).

The staff scenarios use one account, so after rate_limit_staff_per_user (default 600
requests a minute) they get 429 by design: that is the per-user limit working, not a fault.
"""

import asyncio
import json
import os
import statistics
import sys
import time
import uuid
from collections import Counter
from pathlib import Path

import httpx

API = "http://localhost:8000"
WEB = "http://localhost:3000"
KC = "http://localhost:8080/realms/idprivacy/protocol/openid-connect/token"
BFF = "dev-bff-shared-secret-change-me-0123456789"  # compose dev default
STAGES = [int(x) for x in os.environ.get("STAGES", "10,50,100,200").split(",")]
DURATION = float(os.environ.get("DURATION", "20"))


REALM = Path(__file__).resolve().parents[2] / "infra/compose/keycloak/idprivacy-realm.json"


def password() -> str:
    """The dev password lives only in the realm fixture."""
    return str(json.loads(REALM.read_text())["users"][0]["credentials"][0]["value"])


def token(user: str) -> str:
    r = httpx.post(
        KC,
        data={
            "grant_type": "password",
            "client_id": "idprivacy-dev-cli",
            "username": user,
            "password": password(),
        },
    )
    r.raise_for_status()
    return r.json()["access_token"]


def scenario(name: str):
    if name == "api_readyz":
        return lambda c, i: c.get(f"{API}/readyz")
    if name == "web_intake_page":
        return lambda c, i: c.get(f"{WEB}/r/acme")
    if name in ("staff_case_list", "staff_case_detail"):
        hdr = {"Authorization": f"Bearer {token('analyst@acme.example.test')}"}
        if name == "staff_case_list":
            return lambda c, i: c.get(f"{API}/v1/cases?limit=25", headers=hdr)
        ids = [x["id"] for x in httpx.get(f"{API}/v1/cases?limit=25", headers=hdr).json()["items"]]
        return lambda c, i: c.get(f"{API}/v1/cases/{ids[i % len(ids)]}", headers=hdr)
    if name == "public_submit":

        def submit(c, i):
            n = uuid.uuid4().int
            ip = f"10.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"
            body = {
                "intakeSlug": "acme",
                "rights": ["ERASURE"],
                "fullName": "Load Test",
                "contact": {"channel": "EMAIL", "value": f"load{n % 10**12}@example.in"},
                "consentToProcess": True,
            }
            return c.post(
                f"{API}/v1/public/requests",
                json=body,
                headers={"X-Internal-Auth": BFF, "X-Client-IP": ip},
            )

        return submit
    raise SystemExit(f"unknown scenario {name}")


async def stage(fire, users: int) -> dict:
    lat: list[float] = []
    codes: Counter = Counter()
    deadline = time.perf_counter() + DURATION
    limits = httpx.Limits(max_connections=users, max_keepalive_connections=users)
    async with httpx.AsyncClient(timeout=30, limits=limits) as c:

        async def vu(k: int) -> None:
            i = k
            while time.perf_counter() < deadline:
                t0 = time.perf_counter()
                try:
                    r = await fire(c, i)
                    codes[r.status_code] += 1
                except httpx.HTTPError as e:
                    codes[type(e).__name__] += 1
                lat.append((time.perf_counter() - t0) * 1000)
                i += users

        t0 = time.perf_counter()
        await asyncio.gather(*(vu(k) for k in range(users)))
        elapsed = time.perf_counter() - t0
    q = statistics.quantiles(lat, n=100) if len(lat) > 1 else [lat[0]] * 99
    ok = sum(v for k, v in codes.items() if isinstance(k, int) and k < 400)
    return {
        "users": users,
        "requests": len(lat),
        "rps": round(len(lat) / elapsed, 1),
        "p50": round(q[49], 1),
        "p95": round(q[94], 1),
        "p99": round(q[98], 1),
        "max": round(max(lat), 1),
        "error_pct": round(100 * (1 - ok / len(lat)), 2),
        "codes": dict(codes),
    }


async def main(name: str) -> None:
    fire = scenario(name)
    for users in STAGES:
        res = await stage(fire, users)
        print(json.dumps({"scenario": name, **res}), flush=True)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
