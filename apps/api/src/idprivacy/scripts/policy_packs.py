"""Policy-pack tooling.

pin <pack.yaml>   Validate a pack and record its hash in manifest.json (authoring step)
publish           Verify every pinned pack and publish new versions to the DB (migrator)
schema            Write the generated JSON Schema for pack authors
"""

import json
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from idprivacy.domain.policy.loader import MANIFEST, canonical_hash, load_all, parse, read_yaml
from idprivacy.domain.policy.model import PolicyPack
from idprivacy.domain.policy.registry import publish

ROOT = Path(
    os.environ.get(
        "IDP_POLICY_PACKS_DIR", Path(__file__).resolve().parents[5] / "packages" / "policy-packs"
    )
)
SCHEMA = ROOT / "schema" / "policy-pack.schema.json"


def pin(path: Path) -> None:
    content = read_yaml(path)
    pack = parse(content)
    manifest_path = ROOT / MANIFEST
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"packs": []}
    entry = {
        "code": pack.code,
        "version": pack.version,
        "path": str(path.resolve().relative_to(ROOT.resolve())),
        "sha256": canonical_hash(content),
    }
    manifest["packs"] = [
        p for p in manifest["packs"] if (p["code"], p["version"]) != (pack.code, pack.version)
    ] + [entry]
    manifest["packs"].sort(key=lambda p: (p["code"], p["version"]))
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"pinned {pack.ref} {entry['sha256']}")  # noqa: T201


def publish_all() -> None:
    engine = create_engine(os.environ["IDP_DATABASE_URL_MIGRATOR"])
    loaded = load_all(ROOT)
    with Session(engine) as session, session.begin():
        for item in loaded:
            publish(session, item)
    print("published:", ", ".join(i.pack.ref for i in loaded))  # noqa: T201


def schema_json() -> str:
    return json.dumps(PolicyPack.model_json_schema(by_alias=True), indent=2, sort_keys=True) + "\n"


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "pin" and len(sys.argv) == 3:
        pin(Path(sys.argv[2]))
    elif cmd == "publish":
        publish_all()
    elif cmd == "schema":
        SCHEMA.write_text(schema_json())
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
