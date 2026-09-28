"""Resolve credential references (``scheme:name``) to secret values (open decision D-5).

Only ``env:`` exists today and is refused outside local/test by ``Settings``. A
production backend (Vault, a cloud secret manager) plugs in here. Values are never
logged or stored in the DB.
"""

import os


class SecretNotFound(LookupError):
    pass


def resolve(ref: str) -> str:
    scheme, _, name = ref.partition(":")
    if scheme != "env" or not name:
        raise SecretNotFound(f"unsupported secret reference scheme {scheme!r}")
    value = os.environ.get(name)
    if not value:
        raise SecretNotFound(f"secret {name} is not set")
    return value
