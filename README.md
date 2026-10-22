# agentleash

**If your AI agent is prompt-injected, what can the attacker reach in your AWS account?**

agentleash reads your Amazon Bedrock agents, the tools (action groups) behind them, the Lambda
functions and IAM roles those tools run as, and the resource policies on what those roles can
touch. It then prints every attack path from attacker-controlled text to an impact, for example:

```
HIGH  support-agent / prod alias
  user prompt
  -> tool lookup_ticket (action group TicketOps)
  -> runs as role support-tool-role
  -> sts:AssumeRole data-reader (trust: account root; identity: Allow *)
  -> s3:GetObject on customer-exports
  -> exfil: agent reply to user
```

It assumes the model is fully compromised: the agent will call any tool it has, with any
arguments the tool schema allows. The result is a worst-case blast radius you can use to scope
IAM, not a guess about whether a given injection would work.

> **Status:** pre-alpha. The read-only AWS layer, snapshot format and CLI skeleton are in place;
> the IAM evaluator and path analysis are under way. See [the roadmap](#roadmap).

## Read-only by design

agentleash only ever makes read-only AWS calls, and you can check that for yourself:

- Every AWS call goes through one module with a fixed allowlist of `List*`, `Get*` and
  `Describe*` operations ([`src/agentleash/aws/allowlist.py`](src/agentleash/aws/allowlist.py)).
  A botocore hook refuses anything else before a request is signed.
- [`policy/agentleash-read-only.json`](policy/agentleash-read-only.json) grants exactly those
  actions and nothing more. Run under it, agentleash cannot change your account even if it has a
  bug. A test keeps the policy and the allowlist in step.
- It never reads secret material: no `secretsmanager:GetSecretValue`, no `s3:GetObject`, and
  Lambda environment variable values are dropped as soon as they are fetched.

## Usage

```
pipx install agentleash
aws sso login --profile audit
agentleash scan --profile audit --region eu-west-2
```

agentleash uses the standard AWS credential chain, so profiles, SSO and environment variables all
work. Without `--region` it scans every enabled region.

Optional: `--save-snapshot scan.json` keeps what was collected, and
`--from-snapshot scan.json` re-analyses it without calling AWS.

## Roadmap

1. Skeleton: CLI, snapshot schema, read-only AWS layer, fixtures. *(this release)*
2. IAM evaluator: identity and resource policies, explicit deny, permission boundaries, wildcard
   expansion, allowed / denied / conditional results.
3. First usable release: Bedrock Agents collector, attack-path graph, JSON and Markdown reports.
4. `sts:AssumeRole` chains, privilege-escalation edges, SCPs and RCPs.

Later: Amazon Bedrock AgentCore, least-privilege policies per tool from CloudTrail, a
vulnerable-by-design demo agent, SARIF output.

## Development

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest          # sockets are disabled: tests can never reach AWS
```

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

agentleash is an independent project and is not affiliated with or endorsed by Amazon Web
Services.
