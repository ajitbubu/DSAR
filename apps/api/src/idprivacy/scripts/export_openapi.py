"""Write the app's OpenAPI schema to contracts/openapi.json (checked by tests/test_contracts.py)."""

import json
import sys
from pathlib import Path

from idprivacy.config import Settings
from idprivacy.main import create_app


def main() -> None:
    settings = Settings(
        env="test",
        database_url_app="postgresql+psycopg://unused@localhost/unused",
        oidc_issuer="https://idp.invalid",
        oidc_jwks_url="https://idp.invalid/jwks",
        local_master_key="ZGV2LW9ubHktbWFzdGVyLWtleS0zMi1ieXRlcyEhISE=",
    )
    app = create_app(settings, key_resolver=lambda _t: None, readiness_probes={})
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "contracts/openapi.json")
    out.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
