"""Architecture rules (M2 acceptance): no regulation-specific branches in platform code.

Regulation behaviour lives in policy packs. Source code must stay regulation-agnostic,
so adding GDPR later is a new pack, not edits to handlers (ADR-0005).
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SOURCE_ROOTS = [REPO / "apps/api/src/idprivacy", REPO / "apps/worker/src/idprivacy_worker"]
# Dev seed data may name the pack a dev tenant enables; it's configuration, not logic.
ALLOWED = {REPO / "apps/api/src/idprivacy/scripts/seed_dev.py"}
REGULATIONS = re.compile(r"\b(DPDP|GDPR|UK[_ -]?GDPR|CCPA|CPRA|LGPD|PDPA)\b", re.IGNORECASE)


def test_no_regulation_names_in_platform_code() -> None:
    offenders = []
    for root in SOURCE_ROOTS:
        for path in root.rglob("*.py"):
            if path in ALLOWED:
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if REGULATIONS.search(line):
                    offenders.append(f"{path.relative_to(REPO)}:{n}: {line.strip()}")
    assert offenders == [], "regulation-specific code outside policy packs:\n" + "\n".join(
        offenders
    )


def test_rule_detects_violations(tmp_path: Path) -> None:
    """Guard against the regex silently matching nothing."""
    assert REGULATIONS.search('if pack.code == "DPDP":')
    assert REGULATIONS.search("# handle gdpr article 17")
    assert not REGULATIONS.search("policy_pack.code")
