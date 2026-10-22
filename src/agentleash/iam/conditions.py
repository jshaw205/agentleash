"""IAM condition evaluation against partially known request context.

The context maps a condition key (case-insensitive) to its values. A key that is
missing from the context is unknown; a key mapped to ``None`` is known to be
absent from the request. Anything unknown makes the result UNKNOWN rather than
guessing, and the key is reported back so a finding can name it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from agentleash.iam.matching import wildcard_match
from agentleash.iam.tristate import Tri, all_of, any_of

Context = Mapping[str, Sequence[str] | None]


@dataclass
class ConditionResult:
    value: Tri
    unresolved_keys: set[str] = field(default_factory=set)


def _as_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, bool):
        return ["true" if value else "false"]
    return [str(value)]


def _compare(base: str, policy_value: str, actual: str) -> bool | None:
    """Positive comparison for one operator family. None means not evaluable."""
    if base in ("StringEquals", "ArnEquals"):
        return policy_value == actual
    if base == "StringEqualsIgnoreCase":
        return policy_value.lower() == actual.lower()
    if base in ("StringLike", "ArnLike"):
        return wildcard_match(policy_value, actual)
    if base == "Bool":
        return policy_value.lower() == actual.lower()
    if base.startswith("Numeric"):
        try:
            p, a = float(policy_value), float(actual)
        except ValueError:
            return None
        return {
            "NumericEquals": a == p,
            "NumericLessThan": a < p,
            "NumericLessThanEquals": a <= p,
            "NumericGreaterThan": a > p,
            "NumericGreaterThanEquals": a >= p,
        }.get(base)
    if base == "IpAddress":
        try:
            return ipaddress.ip_address(actual) in ipaddress.ip_network(policy_value, strict=False)
        except ValueError:
            return None
    return None


_NEGATED = {
    "StringNotEquals": "StringEquals",
    "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
    "StringNotLike": "StringLike",
    "ArnNotEquals": "ArnEquals",
    "ArnNotLike": "ArnLike",
    "NumericNotEquals": "NumericEquals",
    "NotIpAddress": "IpAddress",
}


def _evaluate_key(operator: str, key: str, policy_values: list[str], context: Context) -> Tri:
    qualifier = None
    if ":" in operator:
        qualifier, operator = operator.split(":", 1)
    if_exists = operator.endswith("IfExists")
    if if_exists:
        operator = operator[: -len("IfExists")]

    lookup = {k.lower(): v for k, v in context.items()}
    known = key.lower() in lookup
    actual = lookup.get(key.lower())

    if operator == "Null":
        if not known:
            return Tri.UNKNOWN
        wants_absent = any(v.lower() == "true" for v in policy_values)
        return Tri.TRUE if (actual is None) == wants_absent else Tri.FALSE

    if not known:
        return Tri.UNKNOWN
    if actual is None:
        # Key absent from the request: IfExists passes, negated operators pass,
        # ForAllValues over an empty set passes, everything else fails.
        if if_exists or operator in _NEGATED or qualifier == "ForAllValues":
            return Tri.TRUE
        return Tri.FALSE

    negated = operator in _NEGATED
    base = _NEGATED.get(operator, operator)

    def matches(value: str) -> Tri:
        results = [_compare(base, p, value) for p in policy_values]
        if any(r is True for r in results):
            return Tri.TRUE
        if any(r is None for r in results):
            return Tri.UNKNOWN
        return Tri.FALSE

    per_value = [matches(v) for v in actual]
    if qualifier == "ForAllValues":
        positive = all_of(*per_value)
    else:
        positive = any_of(*per_value)
    return ~positive if negated else positive


def evaluate_conditions(block: Mapping | None, context: Context) -> ConditionResult:
    """Evaluate a statement's Condition block. All operators and keys are ANDed."""
    if not block:
        return ConditionResult(Tri.TRUE)
    results = []
    unresolved: set[str] = set()
    for operator, keys in block.items():
        for key, values in keys.items():
            r = _evaluate_key(operator, key, _as_list(values), context)
            if r is Tri.UNKNOWN:
                unresolved.add(key)
            results.append(r)
    return ConditionResult(all_of(*results), unresolved)
