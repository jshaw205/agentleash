"""Wildcard matching for IAM actions, resources and ARNs."""

from __future__ import annotations

import re
from functools import lru_cache

from agentleash.iam.tristate import Tri

_VARIABLE = re.compile(r"\$\{[^}]*\}")


@lru_cache(maxsize=4096)
def _compile(pattern: str, case_sensitive: bool) -> re.Pattern[str]:
    parts = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    return re.compile("".join(parts), 0 if case_sensitive else re.IGNORECASE | re.DOTALL)


def wildcard_match(pattern: str, value: str, case_sensitive: bool = True) -> bool:
    return _compile(pattern, case_sensitive).fullmatch(value) is not None


def match_action(pattern: str, action: str) -> bool:
    """IAM action names match case-insensitively."""
    return wildcard_match(pattern, action, case_sensitive=False)


def match_resource(pattern: str, resource: str) -> Tri:
    """Match a resource ARN against a policy pattern.

    Policy variables such as ``${aws:username}`` depend on the request, so a
    pattern containing one matches as UNKNOWN when it would match with the
    variable treated as a wildcard.
    """
    if "${" not in pattern:
        return Tri.TRUE if wildcard_match(pattern, resource) else Tri.FALSE
    loose = _VARIABLE.sub("*", pattern)
    return Tri.UNKNOWN if wildcard_match(loose, resource) else Tri.FALSE


def arn_account(arn: str) -> str | None:
    """The account ID field of an ARN, or None when the ARN has none (S3 buckets)."""
    parts = arn.split(":", 5)
    if len(parts) < 6 or not parts[4]:
        return None
    return parts[4]
