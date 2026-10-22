"""IAM roles as the evaluator sees them, built from GetAccountAuthorizationDetails."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from agentleash.iam.matching import arn_account
from agentleash.iam.policy import parse_document


@dataclass
class Principal:
    arn: str
    account_id: str
    name: str
    # (source label, document) pairs: inline and attached managed policies.
    identity_policies: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    boundary: tuple[str, dict[str, Any]] | None = None
    trust_policy: dict[str, Any] | None = None
    tags: dict[str, str] = field(default_factory=dict)
    # Policy ARNs referenced by the role but missing from the snapshot. Their
    # contents are unknown, so any decision that could hinge on them is conditional.
    missing_policies: list[str] = field(default_factory=list)


def _default_version(policy: Mapping[str, Any]) -> dict[str, Any] | None:
    for version in policy.get("PolicyVersionList", []):
        if version.get("IsDefaultVersion"):
            return parse_document(version["Document"])
    return None


def load_roles(details: Mapping[str, Any]) -> dict[str, Principal]:
    """Build Principals for every role in an authorisation-details dump, keyed by ARN."""
    managed: dict[str, dict[str, Any]] = {}
    for policy in details.get("Policies", []):
        doc = _default_version(policy)
        if doc is not None:
            managed[policy["Arn"]] = doc

    roles: dict[str, Principal] = {}
    for role in details.get("RoleDetailList", []):
        arn = role["Arn"]
        p = Principal(
            arn=arn,
            account_id=arn_account(arn) or "",
            name=role.get("RoleName", arn.rsplit("/", 1)[-1]),
            trust_policy=parse_document(role["AssumeRolePolicyDocument"])
            if role.get("AssumeRolePolicyDocument")
            else None,
            tags={t["Key"]: t["Value"] for t in role.get("Tags", [])},
        )
        for inline in role.get("RolePolicyList", []):
            p.identity_policies.append(
                (f"{arn}#inline/{inline['PolicyName']}", parse_document(inline["PolicyDocument"]))
            )
        for attached in role.get("AttachedManagedPolicies", []):
            policy_arn = attached["PolicyArn"]
            if policy_arn in managed:
                p.identity_policies.append((policy_arn, managed[policy_arn]))
            else:
                p.missing_policies.append(policy_arn)
        boundary_arn = (role.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
        if boundary_arn:
            if boundary_arn in managed:
                p.boundary = (boundary_arn, managed[boundary_arn])
            else:
                p.missing_policies.append(boundary_arn)
                p.boundary = (boundary_arn, {"Statement": []})
        roles[arn] = p
    return roles
