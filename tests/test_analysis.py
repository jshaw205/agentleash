import copy
import json
from pathlib import Path

from agentleash.analysis import analyse
from agentleash.analysis.impacts import Severity
from agentleash.iam import Decision
from agentleash.report import to_json, to_markdown
from agentleash.snapshot import Snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-basic.json"
ACCT = "111122223333"


def base() -> dict:
    return json.loads(FIXTURE.read_text())


def add_tool(data: dict, agent: int, name: str, role: str, statements: list, **group) -> None:
    fn = f"arn:aws:lambda:eu-west-2:{ACCT}:function:{name}"
    data["agents"][agent]["action_groups"].append(
        {"name": name, "executor_lambda_arn": fn, **group}
    )
    data["lambda_functions"].append(
        {"arn": fn, "role_arn": f"arn:aws:iam::{ACCT}:role/{role}", "region": "eu-west-2"}
    )
    data["iam"]["RoleDetailList"].append(
        {
            "RoleName": role,
            "Arn": f"arn:aws:iam::{ACCT}:role/{role}",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
            "RolePolicyList": [{"PolicyName": "tool", "PolicyDocument": {"Statement": statements}}],
            "AttachedManagedPolicies": [],
        }
    )


def by_impact(result, key):
    return [f for f in result.findings if f.impact.key == key]


def test_fixture_finds_assume_role_chain_to_customer_exports():
    result = analyse(Snapshot.from_dict(base()))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.impact.key == "data_read"
    assert f.severity is Severity.HIGH
    assert f.decision is Decision.ALLOWED
    assert f.resources == ["s3://customer-exports"]
    assert [h.kind for h in f.hops] == ["source", "tool", "role", "assume"]
    assert "trust-policy" in f.hops[-1].evidence


def test_max_hops_zero_stops_at_the_tool_role():
    assert analyse(Snapshot.from_dict(base()), max_hops=0).findings == []


def test_escalation_write_exfil_and_kb_poisoning():
    data = base()
    add_tool(
        data,
        0,
        "deploy",
        "deploy-tool-role",
        [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole", "lambda:CreateFunction"],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"},
        ],
    )
    result = analyse(Snapshot.from_dict(data))

    esc = by_impact(result, "priv_esc")
    assert esc and esc[0].severity is Severity.CRITICAL
    assert "pass a role to a new Lambda function" in esc[0].resources
    assert result.findings[0].impact.key == "priv_esc", "critical findings sort first"

    poison = by_impact(result, "kb_poison")
    assert poison and poison[0].resources == ["s3://support-docs-ingest"]
    assert by_impact(result, "exfil")

    read = by_impact(result, "data_read")[0]
    assert any("s3:PutObject" in channel for channel in read.indirect_exfil)


def test_unknown_condition_lowers_severity():
    data = base()
    add_tool(
        data,
        0,
        "secrets",
        "secrets-tool-role",
        [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            }
        ],
    )
    f = by_impact(analyse(Snapshot.from_dict(data)), "secret_read")[0]
    assert f.decision is Decision.CONDITIONAL
    assert f.severity is Severity.MEDIUM
    assert f.unresolved_keys == ["aws:SourceIp"]


def test_prefix_scoped_grant_is_found_and_partial_deny_does_not_hide_it():
    data = base()
    add_tool(
        data,
        0,
        "reports",
        "reports-tool-role",
        [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::customer-exports/reports/*",
            },
            {
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::customer-exports/private/*",
            },
        ],
    )
    findings = [
        f for f in by_impact(analyse(Snapshot.from_dict(data)), "data_read") if f.tool == "reports"
    ]
    assert findings and findings[0].decision is Decision.ALLOWED


def test_collaborator_tools_are_reachable_from_supervisor():
    data = base()
    collaborator = copy.deepcopy(data["agents"][0])
    collaborator.update(agent_id="AGENT00002", name="billing-agent", action_groups=[], aliases=[])
    data["agents"].append(collaborator)
    data["agents"][0]["action_groups"] = []
    data["agents"][0]["collaborator_agent_ids"] = ["AGENT00002"]
    add_tool(
        data,
        1,
        "refund",
        "refund-tool-role",
        [{"Effect": "Allow", "Action": "dynamodb:Scan", "Resource": "*"}],
    )
    result = analyse(Snapshot.from_dict(data))
    supervisor = [f for f in result.findings if f.agent == "support-agent"]
    assert supervisor and "via collaborator billing-agent" in supervisor[0].hops[1].label


def test_observations_for_return_control_and_web_sources():
    data = base()
    data["agents"][0]["action_groups"].append({"name": "Approve", "return_control": True})
    data["knowledge_bases"][0]["data_source_types"] = ["WEB"]
    texts = " ".join(o.text for o in analyse(Snapshot.from_dict(data)).observations)
    assert "returns control" in texts
    assert "web content" in texts


def test_reports_render():
    result = analyse(Snapshot.from_dict(base()))
    doc = to_json(result)
    assert doc["summary"]["high"] == 1
    assert doc["findings"][0]["decision"] == "allowed"
    md = to_markdown(result)
    assert "## HIGH: Read data via support-agent / TicketOps" in md
