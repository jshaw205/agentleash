"""Combine identity, resource, boundary and organisation policies into one decision.

This follows AWS's documented evaluation logic for an IAM role making a request:

1. An explicit Deny in any applicable policy wins.
2. SCPs (principal's account), RCPs (resource's account), the permissions
   boundary and any session policy each act as a ceiling that must also allow.
3. Within one account, an allow in the identity policies or a resource policy
   that names the role directly is enough. A resource policy that only names the
   account root delegates to identity policies instead of granting on its own.
4. Across accounts, both the identity policies and the resource policy must allow.
5. Some resources only honour their own policy: a KMS key policy and a role's
   trust policy must allow the caller, directly or by delegating to its account.

Boundaries are applied to resource-policy grants too, since for role sessions a
resource policy that names the role ARN is limited by the boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentleash.iam.conditions import Context
from agentleash.iam.matching import arn_account, match_action
from agentleash.iam.policy import PolicySetResult, PrincipalRef, StatementHit, evaluate_policies
from agentleash.iam.principals import Principal
from agentleash.iam.tristate import Tri, all_of, any_of

# Actions whose resource policy must allow the caller for the request to succeed.
RESOURCE_POLICY_REQUIRED = ("kms:*", "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:TagSession")

PolicyList = Sequence[tuple[str, Mapping[str, Any]]]


class Decision(Enum):
    ALLOWED = "allowed"
    CONDITIONAL = "conditional"
    NOT_ALLOWED = "not_allowed"  # implicit deny: nothing grants it
    DENIED = "denied"  # explicit deny


@dataclass
class Request:
    action: str
    resource: str
    # Extra known condition keys. aws:PrincipalArn, aws:PrincipalAccount and the
    # role's aws:PrincipalTag/* keys are filled in automatically.
    context: Mapping[str, Sequence[str] | None] = field(default_factory=dict)
    resource_account: str | None = None


@dataclass
class Result:
    decision: Decision
    allowing: list[StatementHit] = field(default_factory=list)
    denying: list[StatementHit] = field(default_factory=list)
    unresolved_keys: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOWED


def _context_for(principal: Principal, request: Request) -> dict[str, Sequence[str] | None]:
    ctx: dict[str, Sequence[str] | None] = {
        "aws:PrincipalArn": [principal.arn],
        "aws:PrincipalAccount": [principal.account_id],
        "aws:PrincipalType": ["AssumedRole"],
    }
    for key, value in principal.tags.items():
        ctx[f"aws:PrincipalTag/{key}"] = [value]
    ctx.update(request.context)
    return ctx


def _ceiling(layers: Sequence[PolicyList] | None, request: Request, ctx: Context) -> list[PolicySetResult]:
    if not layers:
        return []
    return [evaluate_policies(list(layer), request.action, request.resource, ctx) for layer in layers]


def evaluate(
    principal: Principal,
    request: Request,
    resource_policy: Mapping[str, Any] | None = None,
    scps: Sequence[PolicyList] | None = None,
    rcps: Sequence[PolicyList] | None = None,
    session_policies: PolicyList | None = None,
) -> Result:
    """Decide whether ``principal`` may perform ``request``.

    ``scps`` and ``rcps`` are lists of layers (root, each OU, the account), each
    layer a list of policies; every layer must allow. Pass None when they are not
    known, which treats them as allowing everything.
    """
    ctx = _context_for(principal, request)
    action, resource = request.action, request.resource
    who = PrincipalRef(principal.arn, principal.account_id)
    resource_account = request.resource_account or arn_account(resource) or principal.account_id
    same_account = resource_account == principal.account_id
    notes: list[str] = []

    identity = evaluate_policies(principal.identity_policies, action, resource, ctx)
    identity_allow = identity.allow
    if principal.missing_policies:
        identity_allow = any_of(identity_allow, Tri.UNKNOWN)
        notes.append("policies not in snapshot: " + ", ".join(principal.missing_policies))

    if resource_policy:
        rp_any = evaluate_policies([("resource-policy", resource_policy)], action, resource, ctx, who)
        rp_direct = evaluate_policies(
            [("resource-policy", resource_policy)], action, resource, ctx, who, allow_via_account=False
        )
    else:
        rp_any = rp_direct = PolicySetResult(Tri.FALSE, Tri.FALSE, [])

    boundary = (
        evaluate_policies([principal.boundary], action, resource, ctx) if principal.boundary else None
    )
    session = evaluate_policies(list(session_policies), action, resource, ctx) if session_policies else None
    scp_layers = _ceiling(scps, request, ctx)
    rcp_layers = _ceiling(rcps, request, ctx)

    all_sets = [identity, rp_any, *scp_layers, *rcp_layers]
    if boundary:
        all_sets.append(boundary)
    if session:
        all_sets.append(session)
    deny = any_of(*(s.deny for s in all_sets))

    needs_rp = any(match_action(p, action) for p in RESOURCE_POLICY_REQUIRED)
    if needs_rp:
        if same_account:
            grant = any_of(rp_direct.allow, all_of(rp_any.allow, identity_allow))
        else:
            grant = all_of(rp_any.allow, identity_allow)
    elif same_account:
        grant = any_of(identity_allow, rp_direct.allow)
    else:
        grant = all_of(identity_allow, rp_any.allow)

    ceilings = [s.allow for s in scp_layers + rcp_layers]
    if boundary:
        ceilings.append(boundary.allow)
    if session:
        ceilings.append(session.allow)
    allowed = all_of(grant, *ceilings)

    hits = [h for s in all_sets for h in s.hits]
    allowing = [h for h in hits if h.effect == "Allow"]
    denying = [h for h in hits if h.effect == "Deny"]
    unresolved = set().union(*(h.unresolved_keys for h in hits)) if hits else set()

    if deny is Tri.TRUE:
        decision = Decision.DENIED
    elif allowed is Tri.FALSE:
        decision = Decision.NOT_ALLOWED
    elif allowed is Tri.TRUE and deny is Tri.FALSE:
        decision = Decision.ALLOWED
    else:
        decision = Decision.CONDITIONAL
    return Result(decision, allowing, denying, unresolved, notes)


def can_assume(caller: Principal, target: Principal, **kwargs) -> Result:
    """Can ``caller`` call sts:AssumeRole on ``target``? Checks identity and trust policy."""
    return evaluate(
        caller,
        Request("sts:AssumeRole", target.arn),
        resource_policy=target.trust_policy,
        **kwargs,
    )
