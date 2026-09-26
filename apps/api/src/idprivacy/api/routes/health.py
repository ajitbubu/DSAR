from typing import Any

from fastapi import APIRouter, Depends, Request, Response, status

from idprivacy.platform.auth.deps import Public

router = APIRouter(tags=["ops"])


@router.get("/healthz", dependencies=[Depends(Public())])
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", dependencies=[Depends(Public())])
def readyz(request: Request, response: Response) -> dict[str, Any]:
    checks: dict[str, str] = {}
    state = request.app.state
    for name, probe in state.readiness_probes.items():
        try:
            probe()
            checks[name] = "ok"
        except Exception:  # details go to logs, never to the client
            state.log.warning("readiness_probe_failed", probe=name, exc_info=True)
            checks[name] = "fail"
    ok = all(v == "ok" for v in checks.values())
    if not ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if ok else "degraded", "checks": checks}
