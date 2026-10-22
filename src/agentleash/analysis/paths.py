"""Build the attack graph and turn its paths into findings.

The model, from the design: the agent is assumed fully compromised, so it will
call any tool it has with any arguments. A tool backed by Lambda can do whatever
its execution role allows, and from that role whatever any role it can assume
allows, transitively. Each impact reachable that way is a finding.
"""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Iterable
from dataclasses import dataclass, field

import networkx as nx

from agentleash.analysis.impacts import (
    ATTACKER_POLICY,
    ESCALATIONS,
    EXFIL,
    PRIV_ESC,
    ImpactClass,
    Probe,
    Severity,
    probes,
)
from agentleash.iam import Decision, Principal, Request, can_assume, evaluate, load_roles
from agentleash.iam.evaluate import Result
from agentleash.snapshot import Agent, Snapshot

DEFAULT_MAX_HOPS = 4
_REACHABLE = (Decision.ALLOWED, Decision.CONDITIONAL)


@dataclass
class Hop:
    kind: str  # source, tool, role, assume
    label: str
    evidence: str = ""


@dataclass
class Finding:
    id: str
    severity: Severity
    decision: Decision
    impact: ImpactClass
    agent: str
    agent_id: str
    agent_version: str
    aliases: list[str]
    region: str
    tool: str
    hops: list[Hop]
    actions: list[str]
    resources: list[str]
    evidence: list[str] = field(default_factory=list)
    unresolved_keys: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Ways data could leave the account if the attacker is not the person
    # reading the agent's reply (injection via a document or tool output).
    indirect_exfil: list[str] = field(default_factory=list)


@dataclass
class Observation:
    agent: str
    region: str
    text: str


@dataclass
class AnalysisResult:
    account_id: str
    findings: list[Finding]
    observations: list[Observation]
    agents_analysed: int
    roles_analysed: int


@dataclass
class _Tool:
    name: str
    role_arn: str
    lambda_arn: str
    via: str = ""  # collaborator agent name, when reached through one


def _trusts_aws_principals(role: Principal) -> bool:
    for stmt in (role.trust_policy or {}).get("Statement", []):
        principal = stmt.get("Principal", stmt.get("NotPrincipal"))
        if principal == "*" or (isinstance(principal, dict) and "AWS" in principal):
            return True
    return False


def _sources(result: Result) -> list[str]:
    seen: list[str] = []
    for hit in result.allowing:
        label = hit.source + (f" (Sid {hit.sid})" if hit.sid else "")
        if label not in seen:
            seen.append(label)
    return seen


class _Analyser:
    def __init__(self, snap: Snapshot, max_hops: int):
        self.snap = snap
        self.max_hops = max_hops
        self.roles = load_roles(snap.iam)
        self.lambdas = {fn.arn: fn for fn in snap.lambda_functions}
        self.probes = probes(snap)
        self._graph: nx.DiGraph | None = None
        self._probe_cache: dict[tuple[str, Probe], Result] = {}

    # -- graph -------------------------------------------------------------

    @property
    def graph(self) -> nx.DiGraph:
        if self._graph is None:
            g = nx.DiGraph()
            g.add_nodes_from(self.roles)
            targets = [r for r in self.roles.values() if _trusts_aws_principals(r)]
            for caller in self.roles.values():
                for target in targets:
                    if target.arn == caller.arn:
                        continue
                    result = can_assume(caller, target)
                    if result.decision in _REACHABLE:
                        g.add_edge(caller.arn, target.arn, result=result)
            self._graph = g
        return self._graph

    def chains(self, start: str) -> dict[str, list[str]]:
        if start not in self.graph:
            return {start: [start]}
        return nx.single_source_shortest_path(self.graph, start, cutoff=self.max_hops)

    # -- probes ------------------------------------------------------------

    def _check(self, principal: Principal, probe: Probe) -> Result:
        key = (principal.arn, probe)
        if key not in self._probe_cache:
            policy = (
                ATTACKER_POLICY
                if probe.attacker_owned
                else self.snap.resource_policies.get(probe.policy_key or probe.resource)
            )
            self._probe_cache[key] = evaluate(
                principal,
                Request(
                    probe.action,
                    probe.resource,
                    resource_account=probe.resource_account,
                    resource_is_pattern=probe.is_pattern,
                ),
                resource_policy=policy,
            )
        return self._probe_cache[key]

    def _escalations(self, principal: Principal) -> Iterable[tuple[str, list[str], Result]]:
        acct = self.snap.account_id
        for title, steps in ESCALATIONS:
            results = []
            for action, suffix in steps:
                if action.startswith("lambda:"):
                    resource = f"arn:aws:lambda:*:{acct}:{suffix}"
                else:
                    resource = f"arn:aws:iam::{acct}:{suffix}"
                results.append(
                    evaluate(principal, Request(action, resource, resource_is_pattern=True))
                )
            decisions = [r.decision for r in results]
            if all(d in _REACHABLE for d in decisions):
                worst = results[0]
                for r in results:
                    if r.decision is Decision.CONDITIONAL:
                        worst = r
                yield title, [a for a, _ in steps], worst

    # -- agents ------------------------------------------------------------

    def _tools(self, agent: Agent, seen: set[str] | None = None) -> list[_Tool]:
        seen = seen or {agent.agent_id}
        tools = []
        for group in agent.action_groups:
            if group.state == "DISABLED" or not group.executor_lambda_arn:
                continue
            fn = self.lambdas.get(group.executor_lambda_arn)
            if fn and fn.role_arn:
                tools.append(_Tool(group.name, fn.role_arn, fn.arn))
        for collab_id in agent.collaborator_agent_ids:
            if collab_id in seen:
                continue
            seen.add(collab_id)
            for other in self.snap.agents:
                if other.agent_id == collab_id and other.version == "DRAFT":
                    for t in self._tools(other, seen):
                        tools.append(_Tool(t.name, t.role_arn, t.lambda_arn, via=other.name))
        return tools

    def observations(self, agent: Agent) -> list[Observation]:
        out = []
        for group in agent.action_groups:
            if group.return_control and group.state != "DISABLED":
                out.append(
                    Observation(
                        agent.name,
                        agent.region,
                        f"Tool {group.name} returns control to your application, which runs it "
                        "outside AWS's view. Check that code by hand.",
                    )
                )
            elif group.executor_lambda_arn and group.executor_lambda_arn not in self.lambdas:
                out.append(
                    Observation(
                        agent.name,
                        agent.region,
                        f"Tool {group.name} uses {group.executor_lambda_arn}, which could not be read.",
                    )
                )
        if agent.code_interpreter_enabled:
            out.append(
                Observation(
                    agent.name,
                    agent.region,
                    "Code interpreter is enabled: an injected agent can run arbitrary code in its sandbox.",
                )
            )
        for kb in self.snap.knowledge_bases:
            if kb.knowledge_base_id in agent.knowledge_base_ids and "WEB" in kb.data_source_types:
                out.append(
                    Observation(
                        agent.name,
                        agent.region,
                        f"Knowledge base {kb.name} ingests web content: anyone who can edit those "
                        "pages can inject instructions.",
                    )
                )
        return out

    def analyse(self) -> AnalysisResult:
        findings: dict[tuple, Finding] = {}
        observations: list[Observation] = []
        for agent in self.snap.agents:
            observations.extend(self.observations(agent))
            agent_findings: list[Finding] = []
            exfil: set[str] = set()
            for tool in self._tools(agent):
                for target, chain in self.chains(tool.role_arn).items():
                    principal = self.roles.get(target)
                    if principal is None:
                        continue
                    hops = self._hops(agent, tool, chain)
                    chain_conditional = self._chain_conditional(chain)
                    for probe in self.probes:
                        result = self._check(principal, probe)
                        if result.decision not in _REACHABLE:
                            continue
                        if probe.impact is EXFIL:
                            exfil.add(f"{probe.action} from {principal.name}")
                        self._add(
                            findings,
                            agent_findings,
                            agent,
                            tool,
                            chain,
                            hops,
                            probe.impact,
                            probe.action,
                            probe.label,
                            result,
                            chain_conditional,
                        )
                    for title, actions, result in self._escalations(principal):
                        self._add(
                            findings,
                            agent_findings,
                            agent,
                            tool,
                            chain,
                            hops,
                            PRIV_ESC,
                            " + ".join(actions),
                            title,
                            result,
                            chain_conditional,
                        )
            for f in agent_findings:
                f.indirect_exfil = sorted(exfil)
        ordered = sorted(
            findings.values(),
            key=lambda f: (
                -f.severity,
                f.decision is not Decision.ALLOWED,
                f.agent,
                f.tool,
                f.impact.key,
            ),
        )
        return AnalysisResult(
            self.snap.account_id, ordered, observations, len(self.snap.agents), len(self.roles)
        )

    def _chain_conditional(self, chain: list[str]) -> bool:
        return any(
            self.graph.edges[a, b]["result"].decision is Decision.CONDITIONAL
            for a, b in itertools.pairwise(chain)
        )

    def _hops(self, agent: Agent, tool: _Tool, chain: list[str]) -> list[Hop]:
        hops = [
            Hop(
                "source",
                "Attacker-controlled text: the user's prompt, a retrieved document or a tool result",
            )
        ]
        via = f" via collaborator {tool.via}" if tool.via else ""
        hops.append(Hop("tool", f"tool {tool.name}{via}", tool.lambda_arn))
        hops.append(
            Hop(
                "role",
                f"runs as {self.roles[chain[0]].name if chain[0] in self.roles else chain[0]}",
                chain[0],
            )
        )
        for a, b in itertools.pairwise(chain):
            result = self.graph.edges[a, b]["result"]
            hops.append(
                Hop(
                    "assume",
                    f"sts:AssumeRole into {self.roles[b].name}",
                    "; ".join(_sources(result)) or b,
                )
            )
        return hops

    def _add(
        self,
        findings: dict[tuple, Finding],
        agent_findings: list[Finding],
        agent: Agent,
        tool: _Tool,
        chain: list[str],
        hops: list[Hop],
        impact: ImpactClass,
        action: str,
        resource_label: str,
        result: Result,
        chain_conditional: bool,
    ) -> None:
        key = (agent.agent_id, agent.version, tool.name, tuple(chain), impact.key)
        conditional = chain_conditional or result.decision is Decision.CONDITIONAL
        f = findings.get(key)
        if f is None:
            digest = hashlib.sha256("|".join(map(str, key)).encode()).hexdigest()[:10]
            f = Finding(
                id=f"AL-{digest}",
                severity=impact.severity,
                decision=Decision.CONDITIONAL,
                impact=impact,
                agent=agent.name,
                agent_id=agent.agent_id,
                agent_version=agent.version,
                aliases=list(agent.aliases),
                region=agent.region,
                tool=tool.name,
                hops=hops,
                actions=[],
                resources=[],
            )
            findings[key] = f
            agent_findings.append(f)
        if not conditional:
            f.decision = Decision.ALLOWED
        if action not in f.actions:
            f.actions.append(action)
        if resource_label not in f.resources:
            f.resources.append(resource_label)
        for src in _sources(result):
            if src not in f.evidence:
                f.evidence.append(src)
        f.unresolved_keys = sorted(set(f.unresolved_keys) | result.unresolved_keys)
        for note in result.notes:
            if note not in f.notes:
                f.notes.append(note)
        f.severity = impact.severity if f.decision is Decision.ALLOWED else impact.severity.lower()


def analyse(snap: Snapshot, max_hops: int = DEFAULT_MAX_HOPS) -> AnalysisResult:
    return _Analyser(snap, max_hops).analyse()
