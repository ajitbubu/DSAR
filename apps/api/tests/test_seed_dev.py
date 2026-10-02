"""Dev seed configuration."""

import json
from pathlib import Path

from idprivacy.scripts.seed_dev import DEV_PACKS

MANIFEST = Path(__file__).resolve().parents[3] / "packages/policy-packs/manifest.json"


# Regression: ISSUE-001 — dev seed pinned DPDP 1.1.0 after 1.2.0 shipped, and every
# `make up` downgraded the dev tenants, so new cases never got the 1.2.0 rules
# Found by /qa on 2026-10-02
# Report: .gstack/qa-reports/run-20261002T184419Z/qa-report-dsar-2026-10-02.md
def test_dev_tenants_enable_the_latest_published_pack() -> None:
    latest: dict[str, tuple[int, ...]] = {}
    for p in json.loads(MANIFEST.read_text(encoding="utf-8"))["packs"]:
        version = tuple(int(n) for n in p["version"].split("."))
        latest[p["code"]] = max(latest.get(p["code"], version), version)
    for code, version in DEV_PACKS:
        assert tuple(int(n) for n in version.split(".")) == latest[code], code
