# Vulnerable-by-design demo agent

A small, deliberately weak Bedrock agent for testing agentleash against a real account.

> **Warning:** deploy this only into an empty sandbox account, and run `terraform destroy` when
> you are done. Every resource it creates is tagged
> `Warning = deliberately-vulnerable-do-not-use-in-production`.

## What it creates

| Resource | Purpose |
| --- | --- |
| Bedrock agent `support-agent`, alias `prod` | A support assistant with one tool |
| Action group `TicketOps` → Lambda `lookup-ticket` | Reads any S3 object the agent asks for |
| Role `support-tool-role` | The tool's execution role, with three deliberate flaws |
| Role `data-reader` | Can read `customer-exports`; trusts the whole account |
| Buckets `tickets` and `customer-exports` | Synthetic data only |

There is no knowledge base, KMS key or Secrets Manager secret, because those cost money even
when idle.

## Cost

Deploying and scanning are effectively free. Nothing here has an hourly charge: S3 storage is a
few bytes, and Lambda and the agent cost nothing unless invoked. agentleash itself never invokes the
model. If you chat to the agent, Claude 3 Haiku costs fractions of a penny per message.

## Account setup (once)

1. Create a new AWS account. Turn on MFA for the root user, then stop using root.
2. **Billing → Budgets → Create budget → Zero spend budget**, with your email address.
3. **IAM Identity Center** → enable it in eu-west-2 → create a user for yourself.
4. Create two permission sets and assign both to your user on the account:
   - `DemoDeployer`: AWS managed `AdministratorAccess`. Use it only to deploy and destroy.
   - `AgentleashReadOnly`: an inline policy with the contents of
     [`../policy/agentleash-read-only.json`](../policy/agentleash-read-only.json).
5. **Bedrock console (eu-west-2) → Model access** → make sure Claude 3 Haiku is enabled.

On your machine, install AWS CLI v2, Terraform 1.5 or later, Python 3.12 and pipx, then run
`aws configure sso` twice to create a profile for each permission set, for example
`agentleash-deploy` and `agentleash-scan`.

## Run it

```
aws sso login --profile agentleash-deploy
cd demo
terraform init
terraform apply -var region=eu-west-2        # with AWS_PROFILE=agentleash-deploy

pipx install git+https://github.com/jshaw205/agentleash
aws sso login --profile agentleash-scan
agentleash scan --profile agentleash-scan --region eu-west-2

terraform destroy                            # with AWS_PROFILE=agentleash-deploy
```

## Expected findings

| Severity | Finding |
| --- | --- |
| High | Read data: `TicketOps` → `support-tool-role` → `sts:AssumeRole` `data-reader` → `customer-exports` |
| High | Read data: `TicketOps` → `support-tool-role` → `tickets` |
| High | Modify or delete data: `s3:PutObject` on both buckets, from `support-tool-role` |
| Medium | Send data out of the account: `s3:PutObject` to a bucket in another account |

The read findings should also list `s3:PutObject from support-tool-role` as an exfiltration route
for injections that arrive through tool output rather than the user's prompt.

## Optional: try a real injection

In the Bedrock console, open the agent's test window and ask it to look up the ticket at bucket
`<prefix>-customer-exports`, key `exports/customers.csv`. The tool role cannot read that bucket
directly, so the call fails. That shows why the AssumeRole path matters: an attacker would need
the Lambda code to assume `data-reader`. agentleash reports the role's reach, not the current
code's behaviour, because code changes and roles tend to outlive it.
