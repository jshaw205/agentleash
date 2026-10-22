"""The snapshot: everything agentleash collected from one account.

A live scan builds a Snapshot in memory and analyses it straight away. Saving it
(``--save-snapshot``) is optional and mainly for tests, CI and sharing results.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


class SnapshotError(ValueError):
    """Raised when a snapshot file is missing required fields or has the wrong version."""


@dataclass
class ActionGroup:
    name: str
    executor_lambda_arn: str | None = None
    return_control: bool = False
    # Function or OpenAPI schema, as returned by GetAgentActionGroup.
    function_schema: dict[str, Any] | None = None
    api_schema: dict[str, Any] | None = None
    state: str = "ENABLED"


@dataclass
class Agent:
    agent_id: str
    name: str
    region: str
    service_role_arn: str
    aliases: list[str] = field(default_factory=list)
    action_groups: list[ActionGroup] = field(default_factory=list)
    knowledge_base_ids: list[str] = field(default_factory=list)
    collaborator_agent_ids: list[str] = field(default_factory=list)
    user_input_enabled: bool = True
    code_interpreter_enabled: bool = False
    guardrail_id: str | None = None


@dataclass
class KnowledgeBase:
    knowledge_base_id: str
    name: str
    region: str
    role_arn: str
    # S3 data source bucket ARNs: anyone who can write here can inject.
    data_source_bucket_arns: list[str] = field(default_factory=list)


@dataclass
class LambdaFunction:
    arn: str
    role_arn: str
    region: str
    # Names only: values are dropped at collection time.
    environment_variable_names: list[str] = field(default_factory=list)
    resource_policy: dict[str, Any] | None = None
    in_vpc: bool = False


@dataclass
class Snapshot:
    account_id: str
    regions: list[str]
    collected_at: str
    agents: list[Agent] = field(default_factory=list)
    knowledge_bases: list[KnowledgeBase] = field(default_factory=list)
    lambda_functions: list[LambdaFunction] = field(default_factory=list)
    # Raw output of iam:GetAccountAuthorizationDetails, pages merged.
    iam: dict[str, Any] = field(default_factory=dict)
    # Resource ARN -> policy document.
    resource_policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Organisation SCPs and RCPs, if collected.
    organization_policies: list[dict[str, Any]] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Snapshot:
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise SnapshotError(f"unsupported schema_version {version!r}; expected {SCHEMA_VERSION}")
        for key in ("account_id", "regions", "collected_at"):
            if key not in data:
                raise SnapshotError(f"snapshot is missing required field {key!r}")
        agents = [
            Agent(**{**a, "action_groups": [ActionGroup(**g) for g in a.get("action_groups", [])]})
            for a in data.get("agents", [])
        ]
        return cls(
            account_id=data["account_id"],
            regions=list(data["regions"]),
            collected_at=data["collected_at"],
            agents=agents,
            knowledge_bases=[KnowledgeBase(**kb) for kb in data.get("knowledge_bases", [])],
            lambda_functions=[LambdaFunction(**fn) for fn in data.get("lambda_functions", [])],
            iam=data.get("iam", {}),
            resource_policies=data.get("resource_policies", {}),
            organization_policies=data.get("organization_policies", []),
        )


def load(path: str | Path) -> Snapshot:
    with open(path, encoding="utf-8") as fh:
        return Snapshot.from_dict(json.load(fh))


def save(snapshot: Snapshot, path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snapshot.to_dict(), fh, indent=2, sort_keys=True)
        fh.write("\n")
