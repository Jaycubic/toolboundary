from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "<redacted>"

_SENSITIVE = re.compile(
    r"(pass(word)?|pwd|secret|token|api[_-]?key|access[_-]?key|auth(?!or)|bearer|jwt|"
    r"credential|private[_-]?key|cookie|session)",
    re.IGNORECASE,
)
_BEARER_VALUE = re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_MAX_DEPTH = 20


def _is_sensitive(name: object, extra_names: frozenset[str]) -> bool:
    return isinstance(name, str) and (name in extra_names or bool(_SENSITIVE.search(name)))


def redact_structure(
    value: Any,
    *,
    extra_names: frozenset[str] = frozenset(),
    _depth: int = 0,
) -> Any:
    """Return a copy of ``value`` with sensitive keys and bearer strings removed."""
    if _depth >= _MAX_DEPTH:
        return REDACTED
    if isinstance(value, str):
        return _BEARER_VALUE.sub(REDACTED, value)
    if isinstance(value, Mapping):
        return {
            key: REDACTED
            if _is_sensitive(key, extra_names)
            else redact_structure(item, extra_names=extra_names, _depth=_depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        items = [
            redact_structure(item, extra_names=extra_names, _depth=_depth + 1) for item in value
        ]
        return tuple(items) if isinstance(value, tuple) else items
    return value


def redact_args(
    arguments: dict[str, Any],
    *,
    extra_names: frozenset[str] = frozenset(),
    max_len: int = 200,
    log_values: bool = True,
) -> dict[str, str]:
    """Prepare call arguments for audit metadata without exposing known secrets."""
    redacted: dict[str, str] = {}
    for name, value in arguments.items():
        if _is_sensitive(name, extra_names):
            redacted[name] = REDACTED
        elif not log_values:
            redacted[name] = f"<{type(value).__name__}>"
        else:
            try:
                rendered = repr(redact_structure(value, extra_names=extra_names))
            except Exception:  # noqa: BLE001
                rendered = "<unrepresentable>"
            redacted[name] = (
                rendered if len(rendered) <= max_len else rendered[:max_len] + "...(truncated)"
            )
    return redacted
