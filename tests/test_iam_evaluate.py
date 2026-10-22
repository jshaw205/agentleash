from pathlib import Path

from agentleash import snapshot
from agentleash.iam import Decision, Principal, Request, can_assume, evaluate, load_roles
from agentleash.iam.matching import match_action, match_resource
from agentleash.iam.tristate import Tri

ACCOUNT = "111122223333"
OTHER = "444455556666"
FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-basic.json"


def role(name="app", statements=(), account=ACCOUNT, **kwargs) -> Principal:
    arn = f"arn:aws:iam::{account}:role/{name}"
    return Principal(
        arn=arn,
        account_id=account,
        name=name,
        identity_policies=[("inline", {"Statement": list(statements)})],
        **kwargs,
    )


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def deny(action, resource="*", **extra):
    return {"Effect": "Deny", "Action": action, "Resource": resource, **extra}


BUCKET_OBJ = "arn:aws:s3:::customer-exports/report.csv"


def test_matching_rules():
    assert match_action("s3:Get*", "S3:GetObject")
    assert not match_action("s3:Get*", "s3:PutObject")
    assert match_action("iam:?etRole", "iam:GetRole")
    assert match_resource("arn:aws:s3:::customer-*/*", BUCKET_OBJ) is Tri.TRUE
    assert match_resource("arn:aws:s3:::Customer-*/*", BUCKET_OBJ) is Tri.FALSE
    assert match_resource("arn:aws:s3:::home/${aws:username}/*", "arn:aws:s3:::home/bob/x") is Tri.UNKNOWN


def test_identity_allow_and_implicit_deny():
    p = role(statements=[allow("s3:GetObject", "arn:aws:s3:::customer-exports/*")])
    assert evaluate(p, Request("s3:GetObject", BUCKET_OBJ)).decision is Decision.ALLOWED
    assert evaluate(p, Request("s3:PutObject", BUCKET_OBJ)).decision is Decision.NOT_ALLOWED


def test_explicit_deny_wins():
    p = role(statements=[allow("s3:*"), deny("s3:GetObject", "arn:aws:s3:::customer-exports/*")])
    result = evaluate(p, Request("s3:GetObject", BUCKET_OBJ))
    assert result.decision is Decision.DENIED
    assert result.denying


def test_not_action_deny():
    guardrail = {"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*"}
    p = role(statements=[allow("*"), guardrail])
    assert evaluate(p, Request("s3:GetObject", BUCKET_OBJ)).allowed
    assert evaluate(p, Request("iam:CreateUser", "*")).decision is Decision.DENIED


def test_unknown_condition_makes_allow_conditional():
    p = role(statements=[allow("s3:GetObject", Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})])
    result = evaluate(p, Request("s3:GetObject", BUCKET_OBJ))
    assert result.decision is Decision.CONDITIONAL
    assert result.unresolved_keys == {"aws:SourceIp"}


def test_unknown_deny_condition_makes_allow_conditional():
    p = role(
        statements=[
            allow("s3:GetObject"),
            deny("s3:*", Condition={"StringNotEquals": {"aws:SourceVpce": "vpce-1"}}),
        ]
    )
    assert evaluate(p, Request("s3:GetObject", BUCKET_OBJ)).decision is Decision.CONDITIONAL


def test_principal_tags_are_known():
    p = role(
        statements=[allow("s3:GetObject", Condition={"StringEquals": {"aws:PrincipalTag/team": "data"}})],
        tags={"team": "data"},
    )
    assert evaluate(p, Request("s3:GetObject", BUCKET_OBJ)).allowed


def test_permissions_boundary_caps_identity():
    p = role(
        statements=[allow("*")],
        boundary=("boundary", {"Statement": [allow("s3:*")]}),
    )
    assert evaluate(p, Request("s3:GetObject", BUCKET_OBJ)).allowed
    assert evaluate(p, Request("iam:CreateUser", "*")).decision is Decision.NOT_ALLOWED


def test_scp_layers_must_all_allow_and_can_deny():
    p = role(statements=[allow("*")])
    full = [("FullAWSAccess", {"Statement": [allow("*")]})]
    no_iam = [("DenyIam", {"Statement": [allow("*"), deny("iam:*")]})]
    s3_only = [("S3Only", {"Statement": [allow("s3:*")]})]
    assert evaluate(p, Request("iam:CreateUser", "*"), scps=[full, no_iam]).decision is Decision.DENIED
    assert evaluate(p, Request("ec2:RunInstances", "*"), scps=[full, s3_only]).decision is Decision.NOT_ALLOWED
    assert evaluate(p, Request("s3:GetObject", BUCKET_OBJ), scps=[full, s3_only]).allowed


def test_same_account_resource_policy_naming_role_is_enough():
    p = role(statements=[])
    bucket_policy = {"Statement": [allow("s3:GetObject", "arn:aws:s3:::customer-exports/*", Principal={"AWS": p.arn})]}
    assert evaluate(p, Request("s3:GetObject", BUCKET_OBJ), resource_policy=bucket_policy).allowed


def test_resource_policy_naming_account_root_delegates_to_identity():
    p = role(statements=[])
    key = f"arn:aws:kms:eu-west-2:{ACCOUNT}:key/abc"
    key_policy = {"Statement": [allow("kms:*", Principal={"AWS": f"arn:aws:iam::{ACCOUNT}:root"})]}
    assert evaluate(p, Request("kms:Decrypt", key), resource_policy=key_policy).decision is Decision.NOT_ALLOWED
    p2 = role(statements=[allow("kms:Decrypt")])
    assert evaluate(p2, Request("kms:Decrypt", key), resource_policy=key_policy).allowed


def test_kms_needs_key_policy_even_with_identity_allow():
    p = role(statements=[allow("kms:Decrypt")])
    key = f"arn:aws:kms:eu-west-2:{ACCOUNT}:key/abc"
    assert evaluate(p, Request("kms:Decrypt", key)).decision is Decision.NOT_ALLOWED


def test_cross_account_needs_both_sides():
    p = role(statements=[allow("sqs:SendMessage")])
    queue = f"arn:aws:sqs:eu-west-2:{OTHER}:inbox"
    open_policy = {"Statement": [allow("sqs:SendMessage", queue, Principal={"AWS": ACCOUNT})]}
    assert evaluate(p, Request("sqs:SendMessage", queue)).decision is Decision.NOT_ALLOWED
    assert evaluate(p, Request("sqs:SendMessage", queue), resource_policy=open_policy).allowed
    no_identity = role(statements=[])
    assert (
        evaluate(no_identity, Request("sqs:SendMessage", queue), resource_policy=open_policy).decision
        is Decision.NOT_ALLOWED
    )


def test_missing_managed_policy_makes_result_conditional():
    p = role(statements=[], missing_policies=["arn:aws:iam::aws:policy/ReadOnlyAccess"])
    result = evaluate(p, Request("s3:GetObject", BUCKET_OBJ))
    assert result.decision is Decision.CONDITIONAL
    assert result.notes


def test_fixture_assume_role_chain():
    roles = load_roles(snapshot.load(FIXTURE).iam)
    tool = roles[f"arn:aws:iam::{ACCOUNT}:role/support-tool-role"]
    reader = roles[f"arn:aws:iam::{ACCOUNT}:role/data-reader"]

    assert can_assume(tool, reader).allowed
    assert evaluate(reader, Request("s3:GetObject", BUCKET_OBJ)).allowed
    assert evaluate(tool, Request("s3:GetObject", BUCKET_OBJ)).decision is Decision.NOT_ALLOWED
    # The tool role trusts only lambda.amazonaws.com, so the reader cannot assume it back.
    assert can_assume(reader, tool).decision is Decision.NOT_ALLOWED


def test_url_encoded_documents_are_parsed():
    details = {
        "RoleDetailList": [
            {
                "RoleName": "r",
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/r",
                "AssumeRolePolicyDocument": "%7B%22Statement%22%3A%20%5B%5D%7D",
                "RolePolicyList": [],
                "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/Managed"}],
            }
        ],
        "Policies": [
            {
                "Arn": "arn:aws:iam::aws:policy/Managed",
                "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": {"Statement": [allow("s3:ListAllMyBuckets")]}}
                ],
            }
        ],
    }
    r = load_roles(details)[f"arn:aws:iam::{ACCOUNT}:role/r"]
    assert r.trust_policy == {"Statement": []}
    assert evaluate(r, Request("s3:ListAllMyBuckets", "*")).allowed
