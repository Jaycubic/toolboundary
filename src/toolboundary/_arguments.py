"""Normalize a tool call's arguments so policy sees what the tool will receive."""

from __future__ import annotations

import inspect
from typing import Any, Callable


def normalize_call_arguments(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Map positional and keyword arguments onto ``func``'s parameter names.

    Values collected by ``**kwargs`` are expanded to the top level, so a policy
    looking up ``amount`` finds it however the caller supplied it. Raises
    ``TypeError`` if the arguments cannot be bound, before the tool can run.
    """
    signature = inspect.signature(func)
    bound = signature.bind_partial(*args, **kwargs)
    bound.apply_defaults()
    arguments = dict(bound.arguments)

    for name, parameter in signature.parameters.items():
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            for key, value in arguments.pop(name, {}).items():
                arguments.setdefault(key, value)

    return arguments
