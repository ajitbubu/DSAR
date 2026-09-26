"""Placeholder service. Discovery and action endpoints arrive in M3."""

from fastapi import FastAPI

app = FastAPI(title="ID-PRIVACY mock connectors", docs_url=None, redoc_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
