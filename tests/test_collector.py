import json

import pytest
from botocore.exceptions import ClientError

from agentleash.aws.allowlist import is_allowed
from agentleash.aws.collector import collect

ACCT = "111122223333"
FN = f"arn:aws:lambda:eu-west-2:{ACCT}:function:lookup-ticket"


class FakeSession:
    """Stands in for ReadOnlySession, with canned responses and the same allowlist check."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def _respond(self, service, operation, params):
        assert is_allowed(service, operation), f"{service}:{operation} not allowlisted"
        self.calls.append((service, operation, params))
        handler = self.responses.get((service, operation), {})
        value = handler(params) if callable(handler) else handler
        if isinstance(value, Exception):
            raise value
        return value

    def call(self, service, operation, region=None, **params):
        return self._respond(service, operation, params)

    def paginate(self, service, operation, region=None, **params):
        value = self._respond(service, operation, params)
        yield from (value if isinstance(value, list) else [value])


def denied(operation):
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, operation)


@pytest.fixture
def responses():
    return {
        ("sts", "GetCallerIdentity"): {"Account": ACCT},
        ("iam", "GetAccountAuthorizationDetails"): [
            {"RoleDetailList": [{"RoleName": "a", "Arn": f"arn:aws:iam::{ACCT}:role/a"}]},
            {"RoleDetailList": [{"RoleName": "b", "Arn": f"arn:aws:iam::{ACCT}:role/b"}]},
        ],
        ("bedrock-agent", "ListAgents"): {"agentSummaries": [{"agentId": "AG1"}]},
        ("bedrock-agent", "GetAgent"): {
            "agent": {
                "agentName": "support",
                "agentResourceRoleArn": f"arn:aws:iam::{ACCT}:role/svc",
            }
        },
        ("bedrock-agent", "ListAgentAliases"): {
            "agentAliasSummaries": [
                {"agentAliasName": "prod", "routingConfiguration": [{"agentVersion": "3"}]}
            ]
        },
        ("bedrock-agent", "ListAgentActionGroups"): {
            "actionGroupSummaries": [{"actionGroupId": "G1"}, {"actionGroupId": "G2"}]
        },
        ("bedrock-agent", "GetAgentActionGroup"): lambda p: {
            "agentActionGroup": {
                "G1": {"actionGroupName": "TicketOps", "actionGroupExecutor": {"lambda": FN}},
                "G2": {
                    "actionGroupName": "ci",
                    "parentActionGroupSignature": "AMAZON.CodeInterpreter",
                },
            }[p["actionGroupId"]]
        },
        ("bedrock-agent", "ListAgentKnowledgeBases"): {
            "agentKnowledgeBaseSummaries": [
                {"knowledgeBaseId": "KB1", "knowledgeBaseState": "ENABLED"}
            ]
        },
        ("bedrock-agent", "ListAgentCollaborators"): {"agentCollaboratorSummaries": []},
        ("bedrock-agent", "GetKnowledgeBase"): {"knowledgeBase": {"name": "docs", "roleArn": "r"}},
        ("bedrock-agent", "ListDataSources"): {"dataSourceSummaries": [{"dataSourceId": "DS1"}]},
        ("bedrock-agent", "GetDataSource"): {
            "dataSource": {
                "dataSourceConfiguration": {
                    "type": "S3",
                    "s3Configuration": {"bucketArn": "arn:aws:s3:::docs"},
                }
            }
        },
        ("lambda", "GetFunctionConfiguration"): {
            "Role": f"arn:aws:iam::{ACCT}:role/tool",
            "Environment": {"Variables": {"DB_PASSWORD": "hunter2"}},
        },
        ("lambda", "GetPolicy"): ClientError(
            {"Error": {"Code": "ResourceNotFoundException"}}, "GetPolicy"
        ),
        ("s3", "ListBuckets"): {"Buckets": [{"Name": "docs"}]},
        ("s3", "GetBucketPolicy"): {"Policy": json.dumps({"Statement": []})},
        ("secretsmanager", "ListSecrets"): denied("ListSecrets"),
        ("kms", "ListKeys"): {"Keys": []},
        ("sqs", "ListQueues"): {},
        ("sns", "ListTopics"): {"Topics": []},
    }


def test_collects_agents_iam_and_resources(responses):
    snap = collect(FakeSession(responses), ["eu-west-2"])
    assert snap.account_id == ACCT
    assert [r["RoleName"] for r in snap.iam["RoleDetailList"]] == ["a", "b"], "IAM pages are merged"
    assert [(a.version, a.aliases) for a in snap.agents] == [("DRAFT", []), ("3", ["prod"])]
    agent = snap.agents[0]
    assert [g.name for g in agent.action_groups] == ["TicketOps"]
    assert agent.code_interpreter_enabled
    assert snap.knowledge_bases[0].data_source_bucket_arns == ["arn:aws:s3:::docs"]
    assert snap.lambda_functions[0].resource_policy is None
    assert snap.inventory["s3_buckets"] == ["docs"]
    assert "arn:aws:s3:::docs" in snap.resource_policies


def test_environment_variable_values_are_never_kept(responses):
    snap = collect(FakeSession(responses), ["eu-west-2"])
    assert snap.lambda_functions[0].environment_variable_names == ["DB_PASSWORD"]
    assert "hunter2" not in json.dumps(snap.to_dict())


def test_access_denied_becomes_a_warning_not_a_crash(responses):
    snap = collect(FakeSession(responses), ["eu-west-2"])
    assert any("secretsmanager:ListSecrets" in w for w in snap.warnings)
    assert not any("GetPolicy" in w for w in snap.warnings), (
        "missing Lambda policy is not a warning"
    )


def test_regions_are_discovered_when_not_given(responses):
    responses[("ec2", "DescribeRegions")] = {
        "Regions": [{"RegionName": "eu-west-2"}, {"RegionName": "eu-west-1"}]
    }
    assert collect(FakeSession(responses)).regions == ["eu-west-1", "eu-west-2"]
