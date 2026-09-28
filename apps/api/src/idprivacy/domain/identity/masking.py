"""Masking for identifiers shown to staff or written into evidence."""


def mask(kind: str, value: str) -> str:
    if kind == "EMAIL":
        local, _, domain = value.partition("@")
        return f"{local[:1]}•••@{domain[:1]}•••.{domain.rsplit('.', 1)[-1]}"
    if kind == "PHONE":
        return f"{value[:3]}•••••{value[-3:]}"
    return f"{'•' * max(len(value) - 2, 1)}{value[-2:]}"
