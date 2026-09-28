"""Load, validate and integrity-check policy packs.

Integrity layers (threat model T-22):
1. The repo manifest pins each pack's SHA-256. A pack file that doesn't match is refused.
2. Publishing to the DB refuses a different hash for an existing code@version.
3. The DB blocks edits by trigger, and the registry re-hashes every pack it loads.

The hash is taken over canonical JSON of the parsed pack. That makes it stable across
YAML formatting and identical for the file and the JSONB copy in the DB.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from idprivacy.domain.policy.model import PolicyPack

MANIFEST = "manifest.json"


class PackValidationError(ValueError):
    pass


class PackIntegrityError(ValueError):
    pass


def canonical_hash(content: dict[str, Any]) -> str:
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def parse(content: dict[str, Any]) -> PolicyPack:
    try:
        return PolicyPack.model_validate(content)
    except ValidationError as exc:
        raise PackValidationError(str(exc)) from exc


def read_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PackValidationError(f"{path}: pack must be a mapping")
    # Round-trip through JSON so the content is exactly what JSONB will store.
    return json.loads(json.dumps(data))  # type: ignore[no-any-return]


@dataclass(frozen=True)
class PinnedPack:
    code: str
    version: str
    path: Path
    sha256: str


def read_manifest(root: Path) -> list[PinnedPack]:
    data = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    return [
        PinnedPack(p["code"], p["version"], root / p["path"], p["sha256"]) for p in data["packs"]
    ]


@dataclass(frozen=True)
class LoadedPack:
    pack: PolicyPack
    content: dict[str, Any]
    sha256: str


def load_pinned(pin: PinnedPack) -> LoadedPack:
    content = read_yaml(pin.path)
    digest = canonical_hash(content)
    if digest != pin.sha256:
        raise PackIntegrityError(
            f"{pin.code}@{pin.version}: content hash {digest[:12]}… does not match the "
            f"manifest pin {pin.sha256[:12]}…"
        )
    pack = parse(content)
    if (pack.code, pack.version) != (pin.code, pin.version):
        raise PackIntegrityError(
            f"{pin.path}: declares {pack.ref}, manifest says {pin.code}@{pin.version}"
        )
    return LoadedPack(pack, content, digest)


def load_all(root: Path) -> list[LoadedPack]:
    return [load_pinned(pin) for pin in read_manifest(root)]
