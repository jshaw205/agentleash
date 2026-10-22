"""Command-line entry point: ``agentleash scan``."""

from __future__ import annotations

import argparse
import logging
import sys

from agentleash import __version__, report, snapshot
from agentleash.analysis import analyse
from agentleash.analysis.paths import DEFAULT_MAX_HOPS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentleash",
        description="Show what a prompt-injected AI agent could reach in your AWS account.",
    )
    parser.add_argument("--version", action="version", version=f"agentleash {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan an account using read-only AWS calls")
    scan.add_argument(
        "--profile", help="AWS profile name (defaults to the standard credential chain)"
    )
    scan.add_argument(
        "--region",
        action="append",
        dest="regions",
        help="region to scan; repeat for several (default: every enabled region)",
    )
    scan.add_argument("--output-dir", default="agentleash-out", help="where to write the report")
    scan.add_argument("--save-snapshot", metavar="PATH", help="also save what was collected")
    scan.add_argument(
        "--from-snapshot",
        metavar="PATH",
        help="analyse a saved snapshot instead of calling AWS",
    )
    scan.add_argument(
        "--max-hops",
        type=int,
        default=DEFAULT_MAX_HOPS,
        help=f"longest sts:AssumeRole chain to follow (default {DEFAULT_MAX_HOPS})",
    )
    scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="exit with status 1 if any finding is at or above this severity",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="warning: %(message)s")

    if args.command != "scan":
        return 1

    if args.from_snapshot:
        snap = snapshot.load(args.from_snapshot)
    else:
        from agentleash.aws.client import ReadOnlySession
        from agentleash.aws.collector import collect

        session = ReadOnlySession(profile=args.profile, region=(args.regions or [None])[0])
        snap = collect(session, args.regions)
        if args.save_snapshot:
            snapshot.save(snap, args.save_snapshot)
            print(f"Saved snapshot to {args.save_snapshot}")

    result = analyse(snap, max_hops=args.max_hops)
    json_path, md_path = report.write(result, args.output_dir)
    s = report.summary(result)
    print(
        f"Account {snap.account_id}: {s['agents']} agent version(s), {s['findings']} finding(s) "
        f"({s['critical']} critical, {s['high']} high, {s['medium']} medium, {s['low']} low)."
    )
    print(f"Report: {md_path}\nFindings: {json_path}")
    if snap.warnings:
        print(
            f"{len(snap.warnings)} call(s) failed during collection; see findings for gaps.",
            file=sys.stderr,
        )

    if args.fail_on:
        threshold = {"low": 1, "medium": 2, "high": 3, "critical": 4}[args.fail_on]
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0
