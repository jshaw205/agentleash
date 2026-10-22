from pathlib import Path

import pytest

from agentleash import snapshot
from agentleash.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-basic.json"


def test_fixture_round_trips(tmp_path):
    snap = snapshot.load(FIXTURE)
    assert snap.account_id == "111122223333"
    assert snap.agents[0].action_groups[0].name == "TicketOps"

    out = tmp_path / "copy.json"
    snapshot.save(snap, out)
    assert snapshot.load(out) == snap


def test_wrong_schema_version_is_rejected():
    with pytest.raises(snapshot.SnapshotError):
        snapshot.Snapshot.from_dict({"schema_version": 99})


def test_cli_scans_snapshot_and_writes_reports(tmp_path, capsys):
    out = tmp_path / "out"
    assert main(["scan", "--from-snapshot", str(FIXTURE), "--output-dir", str(out)]) == 0
    assert "Account 111122223333" in capsys.readouterr().out
    assert (out / "findings.json").exists()
    assert "customer-exports" in (out / "report.md").read_text()


def test_cli_fail_on(tmp_path):
    args = ["scan", "--from-snapshot", str(FIXTURE), "--output-dir", str(tmp_path)]
    assert main([*args, "--fail-on", "high"]) == 1
    assert main([*args, "--fail-on", "critical"]) == 0
