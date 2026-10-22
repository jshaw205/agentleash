import json
from pathlib import Path

from agentleash.aws.allowlist import (
    ALLOWED_OPERATIONS,
    BANNED_OPERATIONS,
    READ_ONLY_PREFIXES,
    is_allowed,
    required_iam_actions,
)

POLICY = Path(__file__).parent.parent / "policy" / "agentleash-read-only.json"


def test_every_allowed_operation_is_read_only():
    for service, operation in ALLOWED_OPERATIONS:
        assert operation.startswith(READ_ONLY_PREFIXES), f"{service}:{operation}"


def test_no_banned_operation_is_allowlisted():
    assert not set(ALLOWED_OPERATIONS) & BANNED_OPERATIONS


def test_every_iam_action_is_read_only():
    for action in required_iam_actions():
        _, name = action.split(":", 1)
        assert name.startswith(READ_ONLY_PREFIXES), action


def test_writes_and_secret_reads_are_refused():
    assert not is_allowed("iam", "CreateRole")
    assert not is_allowed("bedrock-agent", "UpdateAgent")
    assert not is_allowed("secretsmanager", "GetSecretValue")
    assert not is_allowed("s3", "GetObject")


def test_shipped_policy_grants_exactly_the_allowlist():
    policy = json.loads(POLICY.read_text())
    statements = policy["Statement"]
    assert all(s["Effect"] == "Allow" for s in statements)
    granted = {a for s in statements for a in s["Action"]}
    assert granted == required_iam_actions()
    assert not any("*" in a for a in granted), "policy must not use action wildcards"
