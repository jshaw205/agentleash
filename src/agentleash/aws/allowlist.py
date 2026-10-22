"""The fixed list of AWS operations agentleash is allowed to call.

Each entry maps a (boto3 service, API operation) pair to the IAM action that
authorises it. The shipped least-privilege policy in ``policy/`` must grant
exactly these IAM actions, and a test enforces that.

Adding an operation here is a security-relevant change: it must be a
read-only ``List*``, ``Get*`` or ``Describe*`` call, and it must never return
secret material (for example ``secretsmanager:GetSecretValue`` is banned).
"""

from types import MappingProxyType

READ_ONLY_PREFIXES = ("List", "Get", "Describe")

# Operations that are read-only in name but return secret material.
BANNED_OPERATIONS = frozenset(
    {
        ("secretsmanager", "GetSecretValue"),
        ("secretsmanager", "BatchGetSecretValue"),
        ("ssm", "GetParameter"),
        ("ssm", "GetParameters"),
        ("ssm", "GetParametersByPath"),
        ("s3", "GetObject"),
        ("lambda", "GetFunction"),  # returns a presigned URL to the code package
        ("kms", "GetParametersForImport"),
        ("iam", "GetCredentialReport"),
    }
)

# (service, operation) -> IAM action. None means no IAM permission is needed.
_ALLOWED = {
    # Identity of the caller, for the report header.
    ("sts", "GetCallerIdentity"): None,
    # Region discovery.
    ("ec2", "DescribeRegions"): "ec2:DescribeRegions",
    # Bedrock Agents.
    ("bedrock-agent", "ListAgents"): "bedrock:ListAgents",
    ("bedrock-agent", "GetAgent"): "bedrock:GetAgent",
    ("bedrock-agent", "ListAgentAliases"): "bedrock:ListAgentAliases",
    ("bedrock-agent", "ListAgentVersions"): "bedrock:ListAgentVersions",
    ("bedrock-agent", "ListAgentActionGroups"): "bedrock:ListAgentActionGroups",
    ("bedrock-agent", "GetAgentActionGroup"): "bedrock:GetAgentActionGroup",
    ("bedrock-agent", "ListAgentKnowledgeBases"): "bedrock:ListAgentKnowledgeBases",
    ("bedrock-agent", "ListAgentCollaborators"): "bedrock:ListAgentCollaborators",
    ("bedrock-agent", "GetKnowledgeBase"): "bedrock:GetKnowledgeBase",
    ("bedrock-agent", "ListDataSources"): "bedrock:ListDataSources",
    ("bedrock-agent", "GetDataSource"): "bedrock:GetDataSource",
    ("bedrock", "GetGuardrail"): "bedrock:GetGuardrail",
    # IAM: every role, policy, trust policy and boundary in one paginated call.
    ("iam", "GetAccountAuthorizationDetails"): "iam:GetAccountAuthorizationDetails",
    # Lambda action group executors.
    ("lambda", "ListFunctions"): "lambda:ListFunctions",
    ("lambda", "GetFunctionConfiguration"): "lambda:GetFunctionConfiguration",
    ("lambda", "GetPolicy"): "lambda:GetPolicy",
    # Resource policies on likely targets.
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets",
    ("s3", "GetBucketPolicy"): "s3:GetBucketPolicy",
    ("kms", "ListKeys"): "kms:ListKeys",
    ("kms", "GetKeyPolicy"): "kms:GetKeyPolicy",
    ("secretsmanager", "ListSecrets"): "secretsmanager:ListSecrets",
    ("secretsmanager", "GetResourcePolicy"): "secretsmanager:GetResourcePolicy",
    ("sqs", "ListQueues"): "sqs:ListQueues",
    ("sqs", "GetQueueAttributes"): "sqs:GetQueueAttributes",
    ("sns", "ListTopics"): "sns:ListTopics",
    ("sns", "GetTopicAttributes"): "sns:GetTopicAttributes",
    # Organisation ceilings (optional; only works from the management account
    # or a delegated administrator).
    ("organizations", "ListPolicies"): "organizations:ListPolicies",
    ("organizations", "DescribePolicy"): "organizations:DescribePolicy",
    ("organizations", "ListTargetsForPolicy"): "organizations:ListTargetsForPolicy",
}

ALLOWED_OPERATIONS = MappingProxyType(_ALLOWED)


def is_allowed(service: str, operation: str) -> bool:
    """Return True only for allowlisted, read-only, non-banned operations."""
    return (
        (service, operation) in ALLOWED_OPERATIONS
        and (service, operation) not in BANNED_OPERATIONS
        and operation.startswith(READ_ONLY_PREFIXES)
    )


def required_iam_actions() -> set[str]:
    """The IAM actions the shipped read-only policy must grant."""
    return {action for action in ALLOWED_OPERATIONS.values() if action is not None}
