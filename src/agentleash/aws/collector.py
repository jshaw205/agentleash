"""Collect a Snapshot from a live account using only allowlisted read-only calls."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from agentleash.aws.client import OperationNotAllowed, ReadOnlySession
from agentleash.snapshot import ActionGroup, Agent, KnowledgeBase, LambdaFunction, Snapshot

log = logging.getLogger(__name__)

# Error codes that mean "nothing here" rather than a problem worth reporting.
_ABSENT = {
    "NoSuchBucketPolicy",
    "ResourceNotFoundException",
    "NoSuchEntity",
}


class Collector:
    def __init__(self, session: ReadOnlySession):
        self.s = session
        self.warnings: list[str] = []

    # -- helpers -----------------------------------------------------------

    def _call(
        self, service: str, operation: str, region: str | None = None, **params
    ) -> dict | None:
        try:
            return self.s.call(service, operation, region=region, **params)
        except OperationNotAllowed:
            raise
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            if code not in _ABSENT:
                self._warn(service, operation, region, code or str(err))
        except BotoCoreError as err:
            self._warn(service, operation, region, type(err).__name__)
        return None

    def _pages(
        self, service: str, operation: str, region: str | None = None, **params
    ) -> Iterable[dict]:
        try:
            yield from self.s.paginate(service, operation, region=region, **params)
        except OperationNotAllowed:
            raise
        except ClientError as err:
            self._warn(
                service, operation, region, err.response.get("Error", {}).get("Code", str(err))
            )
        except BotoCoreError as err:
            self._warn(service, operation, region, type(err).__name__)

    def _warn(self, service: str, operation: str, region: str | None, reason: str) -> None:
        where = f" in {region}" if region else ""
        message = f"{service}:{operation}{where} failed: {reason}"
        log.warning(message)
        self.warnings.append(message)

    # -- collection --------------------------------------------------------

    def collect(self, regions: list[str] | None = None) -> Snapshot:
        identity = self._call("sts", "GetCallerIdentity") or {}
        account = identity.get("Account", "")
        if not regions:
            found = self._call("ec2", "DescribeRegions") or {}
            regions = sorted(r["RegionName"] for r in found.get("Regions", []))

        snap = Snapshot(
            account_id=account,
            regions=list(regions),
            collected_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        snap.iam = self._iam()

        lambda_arns: set[str] = set()
        for region in regions:
            for agent in self._agents(region):
                snap.agents.append(agent)
                lambda_arns.update(
                    g.executor_lambda_arn for g in agent.action_groups if g.executor_lambda_arn
                )
            kb_ids = {kb for a in snap.agents if a.region == region for kb in a.knowledge_base_ids}
            snap.knowledge_bases.extend(self._knowledge_bases(region, kb_ids))

        for arn in sorted(lambda_arns):
            fn = self._lambda(arn)
            if fn:
                snap.lambda_functions.append(fn)

        self._resource_policies(snap, regions)
        snap.warnings = self.warnings
        return snap

    def _iam(self) -> dict[str, Any]:
        merged: dict[str, list] = {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }
        for page in self._pages("iam", "GetAccountAuthorizationDetails"):
            for key, items in merged.items():
                items.extend(page.get(key, []))
        return merged

    def _agents(self, region: str) -> Iterable[Agent]:
        for page in self._pages("bedrock-agent", "ListAgents", region=region):
            for summary in page.get("agentSummaries", []):
                agent_id = summary["agentId"]
                detail = (
                    self._call("bedrock-agent", "GetAgent", region=region, agentId=agent_id) or {}
                ).get("agent", {})
                aliases: dict[str, list[str]] = {}
                for alias_page in self._pages(
                    "bedrock-agent", "ListAgentAliases", region=region, agentId=agent_id
                ):
                    for alias in alias_page.get("agentAliasSummaries", []):
                        for route in alias.get("routingConfiguration", []):
                            aliases.setdefault(route["agentVersion"], []).append(
                                alias["agentAliasName"]
                            )
                for version in ["DRAFT", *sorted(v for v in aliases if v != "DRAFT")]:
                    yield self._agent_version(
                        region, agent_id, version, detail, aliases.get(version, [])
                    )

    def _agent_version(
        self, region: str, agent_id: str, version: str, detail: dict, aliases: list[str]
    ) -> Agent:
        ids = {"agentId": agent_id, "agentVersion": version}
        agent = Agent(
            agent_id=agent_id,
            name=detail.get("agentName", agent_id),
            region=region,
            service_role_arn=detail.get("agentResourceRoleArn", ""),
            version=version,
            aliases=aliases,
            guardrail_id=(detail.get("guardrailConfiguration") or {}).get("guardrailIdentifier"),
            # User input is on unless the agent explicitly disables it; the
            # invoker's prompt is always attacker-reachable in this model anyway.
            user_input_enabled=True,
        )
        for page in self._pages("bedrock-agent", "ListAgentActionGroups", region=region, **ids):
            for summary in page.get("actionGroupSummaries", []):
                got = self._call(
                    "bedrock-agent",
                    "GetAgentActionGroup",
                    region=region,
                    actionGroupId=summary["actionGroupId"],
                    **ids,
                )
                group = (got or {}).get("agentActionGroup", {})
                signature = group.get("parentActionGroupSignature")
                if signature == "AMAZON.CodeInterpreter":
                    agent.code_interpreter_enabled = group.get("actionGroupState") != "DISABLED"
                    continue
                if signature == "AMAZON.UserInput":
                    agent.user_input_enabled = group.get("actionGroupState") != "DISABLED"
                    continue
                executor = group.get("actionGroupExecutor") or {}
                api_schema = group.get("apiSchema")
                agent.action_groups.append(
                    ActionGroup(
                        name=group.get("actionGroupName", summary.get("actionGroupName", "")),
                        executor_lambda_arn=executor.get("lambda"),
                        return_control=executor.get("customControl") == "RETURN_CONTROL",
                        function_schema=group.get("functionSchema"),
                        api_schema=api_schema if isinstance(api_schema, dict) else None,
                        state=group.get("actionGroupState", "ENABLED"),
                    )
                )
        for page in self._pages("bedrock-agent", "ListAgentKnowledgeBases", region=region, **ids):
            for kb in page.get("agentKnowledgeBaseSummaries", []):
                if kb.get("knowledgeBaseState") != "DISABLED":
                    agent.knowledge_base_ids.append(kb["knowledgeBaseId"])
        for page in self._pages("bedrock-agent", "ListAgentCollaborators", region=region, **ids):
            for collab in page.get("agentCollaboratorSummaries", []):
                alias_arn = (collab.get("agentDescriptor") or {}).get("aliasArn", "")
                # arn:aws:bedrock:<region>:<account>:agent-alias/<agentId>/<aliasId>
                parts = alias_arn.split("/")
                if len(parts) >= 3:
                    agent.collaborator_agent_ids.append(parts[1])
        return agent

    def _knowledge_bases(self, region: str, kb_ids: set[str]) -> Iterable[KnowledgeBase]:
        for kb_id in sorted(kb_ids):
            got = (
                self._call(
                    "bedrock-agent", "GetKnowledgeBase", region=region, knowledgeBaseId=kb_id
                )
                or {}
            ).get("knowledgeBase", {})
            kb = KnowledgeBase(
                knowledge_base_id=kb_id,
                name=got.get("name", kb_id),
                region=region,
                role_arn=got.get("roleArn", ""),
            )
            for page in self._pages(
                "bedrock-agent", "ListDataSources", region=region, knowledgeBaseId=kb_id
            ):
                for ds in page.get("dataSourceSummaries", []):
                    detail = (
                        self._call(
                            "bedrock-agent",
                            "GetDataSource",
                            region=region,
                            knowledgeBaseId=kb_id,
                            dataSourceId=ds["dataSourceId"],
                        )
                        or {}
                    ).get("dataSource", {})
                    config = detail.get("dataSourceConfiguration") or {}
                    kb.data_source_types.append(config.get("type", "UNKNOWN"))
                    bucket = (config.get("s3Configuration") or {}).get("bucketArn")
                    if bucket:
                        kb.data_source_bucket_arns.append(bucket)
            yield kb

    def _lambda(self, arn: str) -> LambdaFunction | None:
        region = arn.split(":")[3]
        config = self._call("lambda", "GetFunctionConfiguration", region=region, FunctionName=arn)
        if not config:
            return None
        policy = self._call("lambda", "GetPolicy", region=region, FunctionName=arn)
        return LambdaFunction(
            arn=arn,
            role_arn=config.get("Role", ""),
            region=region,
            # Values are deliberately dropped here and never stored or logged.
            environment_variable_names=sorted(
                ((config.get("Environment") or {}).get("Variables") or {}).keys()
            ),
            resource_policy=json.loads(policy["Policy"])
            if policy and policy.get("Policy")
            else None,
            in_vpc=bool((config.get("VpcConfig") or {}).get("VpcId")),
        )

    def _resource_policies(self, snap: Snapshot, regions: list[str]) -> None:
        inv: dict[str, list[str]] = {
            "s3_buckets": [],
            "secrets": [],
            "kms_keys": [],
            "sqs_queues": [],
            "sns_topics": [],
        }
        policies = snap.resource_policies

        for page in self._pages("s3", "ListBuckets"):
            for bucket in page.get("Buckets", []):
                name = bucket["Name"]
                inv["s3_buckets"].append(name)
                got = self._call("s3", "GetBucketPolicy", Bucket=name)
                if got and got.get("Policy"):
                    policies[f"arn:aws:s3:::{name}"] = json.loads(got["Policy"])

        for region in regions:
            for page in self._pages("secretsmanager", "ListSecrets", region=region):
                for secret in page.get("SecretList", []):
                    arn = secret["ARN"]
                    inv["secrets"].append(arn)
                    got = self._call(
                        "secretsmanager", "GetResourcePolicy", region=region, SecretId=arn
                    )
                    if got and got.get("ResourcePolicy"):
                        policies[arn] = json.loads(got["ResourcePolicy"])
            for page in self._pages("kms", "ListKeys", region=region):
                for key in page.get("Keys", []):
                    arn = key["KeyArn"]
                    inv["kms_keys"].append(arn)
                    got = self._call(
                        "kms", "GetKeyPolicy", region=region, KeyId=arn, PolicyName="default"
                    )
                    if got and got.get("Policy"):
                        policies[arn] = json.loads(got["Policy"])
            for page in self._pages("sqs", "ListQueues", region=region):
                for url in page.get("QueueUrls", []):
                    got = self._call(
                        "sqs",
                        "GetQueueAttributes",
                        region=region,
                        QueueUrl=url,
                        AttributeNames=["QueueArn", "Policy"],
                    )
                    attrs = (got or {}).get("Attributes", {})
                    if attrs.get("QueueArn"):
                        inv["sqs_queues"].append(attrs["QueueArn"])
                        if attrs.get("Policy"):
                            policies[attrs["QueueArn"]] = json.loads(attrs["Policy"])
            for page in self._pages("sns", "ListTopics", region=region):
                for topic in page.get("Topics", []):
                    arn = topic["TopicArn"]
                    inv["sns_topics"].append(arn)
                    got = self._call("sns", "GetTopicAttributes", region=region, TopicArn=arn)
                    policy = (got or {}).get("Attributes", {}).get("Policy")
                    if policy:
                        policies[arn] = json.loads(policy)
        snap.inventory = inv


def collect(session: ReadOnlySession, regions: list[str] | None = None) -> Snapshot:
    return Collector(session).collect(regions)
