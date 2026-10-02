"""The API under concurrent staff load, served by a real uvicorn server.

Regression: staff routes held a pooled DB connection across separate threadpool hops
(dependency, then handler). With the default 40 worker threads and a 10-connection
pool, ~50 concurrent staff requests deadlocked the API at 0% CPU, and it stayed wedged
after the load stopped (CSO finding 27c0d030f50e, found by /benchmark on 2026-10-02).
"""

import socket
import threading
import time
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa

from idprivacy.main import create_app
from idprivacy.platform.storage import MemoryBlobStore
from tests.conftest import bearer, make_settings

CONCURRENCY = 80  # comfortably above 40 threads + 10 connections
TIMEOUT = 15.0  # a deadlocked request hangs for the 30 s pool timeout or longer


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def live_api(migrated_db: None, rsa_key: rsa.RSAPrivateKey) -> Iterator[str]:
    app = create_app(
        make_settings(),
        key_resolver=lambda _token: rsa_key.public_key(),
        readiness_probes={},
        blob_store=MemoryBlobStore(),
    )
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


def test_concurrent_staff_reads_complete_and_the_api_stays_healthy(
    live_api: str,
    make_tenant,
    provision_user,
    make_token,  # type: ignore[no-untyped-def]
) -> None:
    _, subject = provision_user(make_tenant(), ["AUDITOR"])  # least-privileged reader
    headers = bearer(make_token(subject))

    def read(_: int) -> int | str:
        try:
            return httpx.get(f"{live_api}/v1/cases", headers=headers, timeout=TIMEOUT).status_code
        except httpx.TimeoutException:
            return "timeout"

    started = time.monotonic()
    with ThreadPoolExecutor(CONCURRENCY) as pool:
        outcomes = Counter(pool.map(read, range(CONCURRENCY * 3)))
    elapsed = time.monotonic() - started

    # Every request must finish: served (200) or shed fast (503), never hung.
    assert set(outcomes) <= {200, 503}, f"{dict(outcomes)} in {elapsed:.1f}s"
    assert outcomes[200] > 0
    # And the API answers immediately afterwards (no lingering wedge).
    after = httpx.get(f"{live_api}/v1/cases", headers=headers, timeout=5.0)
    assert after.status_code == 200


@pytest.mark.anyio
async def test_requests_over_the_admission_limit_wait_then_get_503() -> None:
    import anyio

    from idprivacy.platform.http import AdmissionLimitMiddleware

    release = anyio.Event()

    async def slow_app(scope, receive, send):  # type: ignore[no-untyped-def]
        await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = AdmissionLimitMiddleware(slow_app, limit=1, timeout=0.2)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        results: dict[str, httpx.Response] = {}

        async def call(name: str) -> None:
            results[name] = await c.get("/")

        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "first")  # takes the only slot
            await anyio.sleep(0.05)
            tg.start_soon(call, "second")  # waits 0.2 s, then is shed
            await anyio.sleep(0.4)
            release.set()
    assert results["first"].status_code == 200
    assert results["second"].status_code == 503
    assert results["second"].headers["retry-after"] == "1"
