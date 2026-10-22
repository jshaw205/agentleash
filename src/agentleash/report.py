"""Write analysis results as findings.json and report.md."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentleash import __version__
from agentleash.analysis.paths import AnalysisResult, Finding
from agentleash.iam import Decision

_MAX_LISTED = 10


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "severity": f.severity.name,
        "decision": f.decision.value,
        "impact": {"key": f.impact.key, "title": f.impact.title},
        "agent": {
            "name": f.agent,
            "id": f.agent_id,
            "version": f.agent_version,
            "aliases": f.aliases,
            "region": f.region,
        },
        "tool": f.tool,
        "hops": [{"kind": h.kind, "label": h.label, "evidence": h.evidence} for h in f.hops],
        "actions": f.actions,
        "resources": f.resources,
        "evidence": f.evidence,
        "unresolved_condition_keys": f.unresolved_keys,
        "notes": f.notes,
        "indirect_exfil": f.indirect_exfil,
    }


def to_json(result: AnalysisResult) -> dict[str, Any]:
    return {
        "tool": "agentleash",
        "version": __version__,
        "account_id": result.account_id,
        "summary": summary(result),
        "findings": [finding_to_dict(f) for f in result.findings],
        "observations": [
            {"agent": o.agent, "region": o.region, "text": o.text} for o in result.observations
        ],
    }


def summary(result: AnalysisResult) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in result.findings:
        counts[f.severity.name] += 1
    return {
        "agents": result.agents_analysed,
        "roles": result.roles_analysed,
        "findings": len(result.findings),
        **{k.lower(): v for k, v in counts.items()},
    }


def _listed(items: list[str]) -> str:
    shown = ", ".join(f"`{i}`" for i in items[:_MAX_LISTED])
    if len(items) > _MAX_LISTED:
        shown += f" and {len(items) - _MAX_LISTED} more"
    return shown


def to_markdown(result: AnalysisResult) -> str:
    s = summary(result)
    lines = [
        f"# agentleash report for account {result.account_id}",
        "",
        (
            f"agentleash {__version__} analysed {s['agents']} agent version(s) and {s['roles']} IAM role(s), "
            "assuming each agent is fully prompt-injected."
        ),
        "",
        "| Severity | Findings |",
        "| --- | --- |",
    ]
    for level in ("critical", "high", "medium", "low"):
        lines.append(f"| {level.capitalize()} | {s[level]} |")
    lines.append("")

    if not result.findings:
        lines += ["No attack paths found.", ""]
    for f in result.findings:
        alias = f" (aliases: {', '.join(f.aliases)})" if f.aliases else ""
        qualifier = "" if f.decision is Decision.ALLOWED else ", conditional"
        lines += [
            f"## {f.severity.name}{qualifier}: {f.impact.title} via {f.agent} / {f.tool}",
            "",
            f"`{f.id}` · agent `{f.agent_id}` version {f.agent_version}{alias} in {f.region}",
            "",
            "```",
        ]
        lines += [("  -> " if i else "  ") + h.label for i, h in enumerate(f.hops)]
        lines += [
            f"  -> {', '.join(f.actions)} on {', '.join(f.resources[:3])}"
            + (f" and {len(f.resources) - 3} more" if len(f.resources) > 3 else ""),
            "```",
            "",
        ]
        lines.append(f"- **Resources:** {_listed(f.resources)}")
        if f.evidence:
            lines.append(f"- **Granted by:** {_listed(f.evidence)}")
        for h in f.hops:
            if h.kind == "assume":
                lines.append(f"- **{h.label}:** allowed by {h.evidence}")
        if f.unresolved_keys:
            lines.append(
                f"- **Conditional on:** {_listed(f.unresolved_keys)}, which agentleash cannot resolve statically."
            )
        for note in f.notes:
            lines.append(f"- **Note:** {note}")
        if f.impact.needs_exfil:
            if f.indirect_exfil:
                lines.append(
                    "- **If the injection comes from a document or tool output**, data could leave via "
                    + _listed(f.indirect_exfil)
                    + "."
                )
            else:
                lines.append(
                    "- **If the injection comes from a document or tool output**, no outbound channel was found, "
                    "so the result only reaches whoever reads the agent's reply."
                )
        lines.append("")

    if result.observations:
        lines += ["## Other observations", ""]
        for o in result.observations:
            lines.append(f"- **{o.agent}** ({o.region}): {o.text}")
        lines.append("")
    return "\n".join(lines)


def write(result: AnalysisResult, output_dir: str | Path) -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "findings.json"
    md_path = out / "report.md"
    json_path.write_text(json.dumps(to_json(result), indent=2) + "\n", encoding="utf-8")
    md_path.write_text(to_markdown(result), encoding="utf-8")
    return json_path, md_path
