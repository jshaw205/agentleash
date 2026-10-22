"""The catalogue of impacts agentleash checks each reachable role for.

Each probe is one action against one resource, or against a pattern standing
for a set of resources (every object in a bucket, every parameter in a region).
Probes are built from the snapshot's inventory, so findings name real resources.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from agentleash.snapshot import Snapshot


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def lower(self) -> Severity:
        return Severity(max(self.value - 1, Severity.LOW.value))


@dataclass(frozen=True)
class ImpactClass:
    key: str
    title: str
    severity: Severity
    # Reads only hurt if the result can get back to the attacker.
    needs_exfil: bool


SECRET_READ = ImpactClass("secret_read", "Read secrets", Severity.HIGH, True)
DATA_READ = ImpactClass("data_read", "Read data", Severity.HIGH, True)
DATA_WRITE = ImpactClass("data_write", "Modify or delete data", Severity.HIGH, False)
KB_POISON = ImpactClass("kb_poison", "Poison a knowledge base", Severity.HIGH, False)
DECRYPT = ImpactClass("decrypt", "Decrypt with KMS keys", Severity.MEDIUM, True)
PRIV_ESC = ImpactClass("priv_esc", "Escalate privileges", Severity.CRITICAL, False)
AGENT_TAMPER = ImpactClass(
    "agent_tamper", "Rewrite agents or their tools", Severity.CRITICAL, False
)
EXFIL = ImpactClass("exfil", "Send data out of the account", Severity.MEDIUM, False)


@dataclass(frozen=True)
class Probe:
    impact: ImpactClass
    action: str
    resource: str
    is_pattern: bool = False
    resource_account: str | None = None
    # A resource policy to evaluate with; defaults to the snapshot's for resource.
    policy_key: str | None = None
    # Use an attacker-owned resource that allows everyone (exfiltration probes).
    attacker_owned: bool = False
    label: str = ""


# A stand-in account for resources the attacker owns. Its policies allow anyone.
ATTACKER_ACCOUNT = "000000000000"
ATTACKER_POLICY = {
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]
}

# Each escalation is a set of actions that must all be allowed, on resource patterns.
ESCALATIONS: list[tuple[str, list[tuple[str, str]]]] = [
    ("create a new default version of a managed policy", [("iam:CreatePolicyVersion", "policy/*")]),
    ("attach a managed policy to a role", [("iam:AttachRolePolicy", "role/*")]),
    ("put an inline policy on a role", [("iam:PutRolePolicy", "role/*")]),
    ("rewrite a role's trust policy", [("iam:UpdateAssumeRolePolicy", "role/*")]),
    ("create access keys for a user", [("iam:CreateAccessKey", "user/*")]),
    ("attach a managed policy to a user", [("iam:AttachUserPolicy", "user/*")]),
    (
        "pass a role to a new Lambda function",
        [("iam:PassRole", "role/*"), ("lambda:CreateFunction", "function:*")],
    ),
]


def probes(snap: Snapshot) -> list[Probe]:
    acct = snap.account_id
    inv = snap.inventory
    out: list[Probe] = []

    kb_buckets = {arn for kb in snap.knowledge_bases for arn in kb.data_source_bucket_arns}
    for name in inv.get("s3_buckets", []):
        bucket_arn = f"arn:aws:s3:::{name}"
        objects = f"{bucket_arn}/*"
        common = {"resource_account": acct, "policy_key": bucket_arn, "is_pattern": True}
        out.append(Probe(DATA_READ, "s3:GetObject", objects, label=f"s3://{name}", **common))
        write_impact = KB_POISON if bucket_arn in kb_buckets else DATA_WRITE
        out.append(Probe(write_impact, "s3:PutObject", objects, label=f"s3://{name}", **common))
        out.append(Probe(DATA_WRITE, "s3:DeleteObject", objects, label=f"s3://{name}", **common))

    for arn in inv.get("secrets", []):
        out.append(
            Probe(SECRET_READ, "secretsmanager:GetSecretValue", arn, label=arn.split(":")[-1])
        )
    for arn in inv.get("kms_keys", []):
        out.append(Probe(DECRYPT, "kms:Decrypt", arn, label=arn.split("/")[-1]))

    for region in snap.regions:
        out.append(
            Probe(
                SECRET_READ,
                "ssm:GetParameter",
                f"arn:aws:ssm:{region}:{acct}:parameter/*",
                is_pattern=True,
                label=f"SSM parameters in {region}",
            )
        )
        out.append(
            Probe(
                DATA_READ,
                "dynamodb:Scan",
                f"arn:aws:dynamodb:{region}:{acct}:table/*",
                is_pattern=True,
                label=f"DynamoDB tables in {region}",
            )
        )
        for action in ("bedrock:UpdateAgentActionGroup", "bedrock:UpdateAgent"):
            out.append(
                Probe(
                    AGENT_TAMPER,
                    action,
                    f"arn:aws:bedrock:{region}:{acct}:agent/*",
                    is_pattern=True,
                    label=f"Bedrock agents in {region}",
                )
            )
        out.append(
            Probe(
                AGENT_TAMPER,
                "lambda:UpdateFunctionCode",
                f"arn:aws:lambda:{region}:{acct}:function:*",
                is_pattern=True,
                label=f"Lambda functions in {region}",
            )
        )

    # Exfiltration to resources the attacker owns in another account.
    region = snap.regions[0] if snap.regions else "us-east-1"
    for action, resource in [
        ("s3:PutObject", "arn:aws:s3:::attacker-bucket/*"),
        ("sqs:SendMessage", f"arn:aws:sqs:{region}:{ATTACKER_ACCOUNT}:attacker-queue"),
        ("sns:Publish", f"arn:aws:sns:{region}:{ATTACKER_ACCOUNT}:attacker-topic"),
        ("lambda:InvokeFunction", f"arn:aws:lambda:{region}:{ATTACKER_ACCOUNT}:function:attacker"),
    ]:
        out.append(
            Probe(
                EXFIL,
                action,
                resource,
                is_pattern=True,
                resource_account=ATTACKER_ACCOUNT,
                attacker_owned=True,
                label=f"{action} to another account",
            )
        )
    return out
