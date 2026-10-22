"""Command-line entry point: ``agentleash scan``."""

from __future__ import annotations

import argparse
import sys

from agentleash import __version__, snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentleash",
        description="Show what a prompt-injected AI agent could reach in your AWS account.",
    )
    parser.add_argument("--version", action="version", version=f"agentleash {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan an account using read-only AWS calls")
    scan.add_argument("--profile", help="AWS profile name (defaults to the standard credential chain)")
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        if args.from_snapshot:
            snap = snapshot.load(args.from_snapshot)
            print(
                f"Loaded snapshot for account {snap.account_id}: "
                f"{len(snap.agents)} agent(s) across {len(snap.regions)} region(s)."
            )
            print("Analysis is not implemented yet (milestone 3).", file=sys.stderr)
            return 2
        print("Live scanning is not implemented yet (milestone 3).", file=sys.stderr)
        return 2

    return 1
