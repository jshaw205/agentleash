"""Wildcard matching for IAM actions, resources and ARNs."""

from __future__ import annotations

import re
from functools import cache, lru_cache

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


def globs_overlap(a: str, b: str) -> bool:
    """True if some string matches both glob patterns (``*`` and ``?``)."""

    @cache
    def ov(i: int, j: int) -> bool:
        if i == len(a) and j == len(b):
            return True
        if i < len(a) and a[i] == "*":
            return ov(i + 1, j) or (j < len(b) and ov(i, j + 1))
        if j < len(b) and b[j] == "*":
            return ov(i, j + 1) or (i < len(a) and ov(i + 1, j))
        if i == len(a) or j == len(b):
            return False
        if a[i] == "?" or b[j] == "?" or a[i] == b[j]:
            return ov(i + 1, j + 1)
        return False

    return ov(0, 0)


def match_resource(pattern: str, resource: str, mode: str = "exact") -> Tri:
    """Match a resource against a policy pattern.

    ``mode`` is ``exact`` for a concrete ARN. When the resource is itself a
    pattern standing for a set of resources (``arn:aws:s3:::bucket/*``):
    ``overlap`` asks whether the policy pattern covers some of them, and
    ``contains`` whether it covers all of them. Containment is approximate: a
    ``?`` in the policy pattern is taken to cover a ``*`` in the resource.

    Policy variables such as ``${aws:username}`` depend on the request, so a
    pattern containing one matches as UNKNOWN when it would match with the
    variable treated as a wildcard.
    """
    has_variable = "${" in pattern
    if has_variable:
        pattern = _VARIABLE.sub("*", pattern)
    if mode == "overlap":
        hit = globs_overlap(pattern, resource)
    else:
        hit = wildcard_match(pattern, resource)
    if not hit:
        return Tri.FALSE
    return Tri.UNKNOWN if has_variable else Tri.TRUE


def arn_account(arn: str) -> str | None:
    """The account ID field of an ARN, or None when the ARN has none (S3 buckets)."""
    parts = arn.split(":", 5)
    if len(parts) < 6 or not parts[4]:
        return None
    return parts[4]
