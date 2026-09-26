"""contracts/openapi.json must match the app's schema (ADR-0001). Regenerate: `make contracts`."""

import json
from pathlib import Path

from idprivacy.main import create_app
from tests.conftest import make_settings

CONTRACT = Path(__file__).resolve().parents[3] / "contracts" / "openapi.json"


def test_openapi_contract_is_up_to_date() -> None:
    app = create_app(make_settings(), key_resolver=lambda _t: None, readiness_probes={})
    assert CONTRACT.exists(), "run `make contracts`"
    assert json.loads(CONTRACT.read_text()) == app.openapi(), "contract drift: run `make contracts`"
