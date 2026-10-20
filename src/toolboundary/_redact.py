from __future__ import annotations

import re
from typing import Any

_SENSITIVE = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|credential|"
    r"private[_-]?key|cookie|session)",
    re.IGNORECASE,
)


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
        if name in extra_names or _SENSITIVE.search(name):
            redacted[name] = "<redacted>"
        elif not log_values:
            redacted[name] = f"<{type(value).__name__}>"
        else:
            try:
                rendered = repr(value)
            except Exception:  # noqa: BLE001
                rendered = "<unrepresentable>"
            redacted[name] = (
                rendered if len(rendered) <= max_len else rendered[:max_len] + "...(truncated)"
            )
    return redacted
