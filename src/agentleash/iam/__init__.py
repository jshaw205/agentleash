"""Static evaluation of AWS IAM policies.

The evaluator answers "can this principal perform this action on this
resource?" from the documents in a snapshot, without calling AWS. Each answer is
one of four decisions, and anything that depends on request-time context the
snapshot cannot know (a source IP, an external ID, a tag that was not collected)
comes back as ``CONDITIONAL`` with the unresolved condition keys named.
"""

from agentleash.iam.evaluate import Decision, Request, Result, can_assume, evaluate
from agentleash.iam.principals import Principal, load_roles

__all__ = [
    "Decision",
    "Principal",
    "Request",
    "Result",
    "can_assume",
    "evaluate",
    "load_roles",
]
