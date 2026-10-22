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


def test_cli_loads_snapshot(capsys):
    assert main(["scan", "--from-snapshot", str(FIXTURE)]) == 2
    assert "account 111122223333" in capsys.readouterr().out
