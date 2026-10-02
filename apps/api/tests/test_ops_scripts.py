"""Smoke tests for the scheduled ops scripts: each main() runs against the test database.

The services they call are tested elsewhere; these pin the wiring the jobs depend on in
production (tenant listing as the migrator, per-tenant sessions, settings, output).
"""

from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, text

from idprivacy.platform.crypto import VaultTransitKeyProvider
from idprivacy.platform.storage import MemoryBlobStore
from idprivacy.scripts import minimise_closed, purge_reports, vault_provision
from tests import test_closure
from tests.conftest import MIGRATOR_URL, make_settings
from tests.test_crypto import FakeTransit

closed = test_closure.closed


@pytest.fixture
def script_env(monkeypatch: pytest.MonkeyPatch) -> MemoryBlobStore:
    monkeypatch.setenv("IDP_DATABASE_URL_MIGRATOR", MIGRATOR_URL)
    store = MemoryBlobStore()
    for mod in (minimise_closed, purge_reports):
        build = mod.build_services
        monkeypatch.setattr(mod, "get_settings", make_settings)
        monkeypatch.setattr(mod, "build_services", lambda s, _b=build: _b(s, blob_store=store))
    return store


def test_minimise_closed_shreds_a_case_past_its_grace_period(
    script_env: MemoryBlobStore,
    closed: dict[str, Any],
    migrator_engine: Engine,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rid = closed["rid"]
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE privacy_request SET closed_at = closed_at - interval '31 days' "
                "WHERE id = :r"
            ),
            {"r": rid},
        )
    minimise_closed.main()
    assert capsys.readouterr().out.startswith("minimised ")
    with migrator_engine.connect() as conn:
        minimised_at = conn.execute(
            text("SELECT minimised_at FROM privacy_request WHERE id = :r"), {"r": rid}
        ).scalar()
    assert minimised_at is not None


def test_purge_reports_runs_across_tenants(
    script_env: MemoryBlobStore, capsys: pytest.CaptureFixture[str]
) -> None:
    purge_reports.main()
    assert capsys.readouterr().out.startswith("purged ")


def test_vault_provision_refuses_without_the_vault_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(vault_provision, "get_settings", make_settings)  # local provider
    with pytest.raises(SystemExit, match="nothing to provision"):
        vault_provision.main()


def test_vault_provision_creates_both_keys_for_every_tenant(
    monkeypatch: pytest.MonkeyPatch,
    make_tenant,  # type: ignore[no-untyped-def]
    capsys: pytest.CaptureFixture[str],
) -> None:
    tenant = make_tenant()
    fake = FakeTransit()
    client = httpx.Client(base_url="http://vault", transport=httpx.MockTransport(fake))
    keys = VaultTransitKeyProvider("http://vault", "tok", client=client)
    monkeypatch.setenv("IDP_DATABASE_URL_MIGRATOR", MIGRATOR_URL)
    monkeypatch.setattr(vault_provision, "get_settings", make_settings)
    monkeypatch.setattr(vault_provision, "build_keys", lambda _s: keys)
    vault_provision.main()
    assert {f"idp-kek-{tenant}", f"idp-bidx-{tenant}"} <= set(fake.keys)
    assert capsys.readouterr().out.startswith("provisioned keys for ")
