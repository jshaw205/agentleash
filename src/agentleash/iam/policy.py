"""Policy documents and statement matching."""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from agentleash.iam.conditions import Context, evaluate_conditions
from agentleash.iam.matching import match_action, match_resource
from agentleash.iam.tristate import Tri, all_of, any_of


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_document(document: str | Mapping[str, Any]) -> dict[str, Any]:
    """Accept a policy as a dict, a JSON string, or URL-encoded JSON (as IAM returns it)."""
    if isinstance(document, Mapping):
        return dict(document)
    text = document
    if text.lstrip().startswith("%7B") or text.lstrip().startswith("%7b"):
        text = urllib.parse.unquote(text)
    return json.loads(text)


@dataclass(frozen=True)
class PrincipalRef:
    """Who is asking, as a resource policy's Principal element sees it."""

    arn: str
    account_id: str
    # For an assumed-role session, the role it came from also matches.
    role_arn: str | None = None


@dataclass
class StatementHit:
    source: str
    sid: str | None
    effect: str
    value: Tri
    unresolved_keys: set[str] = field(default_factory=set)
    via_account: bool = False


def _principal_matches(stmt: Mapping, who: PrincipalRef) -> tuple[Tri, bool]:
    """Return (matches, matched_only_via_account_root)."""
    if "Principal" not in stmt and "NotPrincipal" not in stmt:
        return Tri.TRUE, False
    element = stmt.get("Principal", stmt.get("NotPrincipal"))
    negate = "NotPrincipal" in stmt

    direct = False
    via_account = False
    if element == "*":
        direct = True
    else:
        for value in _as_list(element.get("AWS") if isinstance(element, Mapping) else None):
            if value == "*" or value in (who.arn, who.role_arn):
                direct = True
            elif value in (who.account_id, f"arn:aws:iam::{who.account_id}:root"):
                via_account = True
    matched = direct or via_account
    if negate:
        return (Tri.FALSE if matched else Tri.TRUE), False
    return (Tri.TRUE if matched else Tri.FALSE), (via_account and not direct)


def evaluate_statement(
    stmt: Mapping,
    action: str,
    resource: str,
    context: Context,
    who: PrincipalRef | None = None,
    source: str = "",
    resource_is_pattern: bool = False,
) -> StatementHit:
    effect = stmt.get("Effect", "Allow")
    # For a set of resources, an Allow counts if it covers some of them and a
    # Deny only if it covers all of them, so a partial deny never hides a path.
    if not resource_is_pattern:
        in_mode = out_mode = "exact"
    elif effect == "Allow":
        in_mode, out_mode = "overlap", "contains"
    else:
        in_mode, out_mode = "contains", "overlap"

    if "NotAction" in stmt:
        action_ok = not any(match_action(p, action) for p in _as_list(stmt["NotAction"]))
    else:
        action_ok = any(match_action(p, action) for p in _as_list(stmt.get("Action")))
    if not action_ok:
        return StatementHit(source, stmt.get("Sid"), effect, Tri.FALSE)

    if "NotResource" in stmt:
        resource_ok = ~any_of(
            *(match_resource(p, resource, out_mode) for p in _as_list(stmt["NotResource"]))
        )
    elif "Resource" in stmt:
        resource_ok = any_of(
            *(match_resource(p, resource, in_mode) for p in _as_list(stmt["Resource"]))
        )
    else:
        resource_ok = Tri.TRUE  # trust policies and some resource policies omit it

    via_account = False
    principal_ok = Tri.TRUE
    if who is not None:
        principal_ok, via_account = _principal_matches(stmt, who)

    cond = evaluate_conditions(stmt.get("Condition"), context)
    value = all_of(resource_ok, principal_ok, cond.value)
    return StatementHit(
        source,
        stmt.get("Sid"),
        effect,
        value,
        cond.unresolved_keys if value is not Tri.FALSE else set(),
        via_account,
    )


@dataclass
class PolicySetResult:
    allow: Tri
    deny: Tri
    hits: list[StatementHit]


def evaluate_policies(
    policies: list[tuple[str, Mapping]],
    action: str,
    resource: str,
    context: Context,
    who: PrincipalRef | None = None,
    allow_via_account: bool = True,
    resource_is_pattern: bool = False,
) -> PolicySetResult:
    """Evaluate a set of (source label, document) pairs.

    ``allow_via_account=False`` ignores Allow statements that match the caller
    only through its account root, which is how a same-account resource policy
    delegates to identity policies rather than granting on its own.
    """
    hits: list[StatementHit] = []
    for source, document in policies:
        for stmt in _as_list(document.get("Statement")):
            hit = evaluate_statement(
                stmt, action, resource, context, who, source, resource_is_pattern
            )
            if hit.value is not Tri.FALSE:
                hits.append(hit)
    allows = [
        h.value for h in hits if h.effect == "Allow" and (allow_via_account or not h.via_account)
    ]
    denies = [h.value for h in hits if h.effect == "Deny"]
    return PolicySetResult(any_of(*allows), any_of(*denies), hits)
