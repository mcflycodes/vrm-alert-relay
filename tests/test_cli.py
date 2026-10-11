import json
import runpy
from importlib.metadata import entry_points, version

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vrm_alert_relay import __version__
from vrm_alert_relay.cli import PROG, main


def test_version_matches_package_metadata() -> None:
    assert __version__ == version("vrm-alert-relay")


def test_version_flag_prints_version_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert captured.out == f"{PROG} {__version__}\n"
    assert captured.err == ""


def test_default_run_logs_one_dry_run_json_line(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0

    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "placeholder"
    assert record["level"] == "info"
    assert record["dry_run"] is True
    assert record["version"] == __version__
    assert "dry-run" in record["message"]


@given(suffix=st.text(alphabet=st.characters(categories=["Ll", "Nd"]), min_size=1, max_size=20))
def test_unknown_options_are_rejected_without_running(suffix: str) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([f"--unknown-{suffix}"])

    assert excinfo.value.code == 2


def test_console_script_points_at_main() -> None:
    (script,) = entry_points(group="console_scripts", name=PROG)

    assert script.value == "vrm_alert_relay.cli:main"


def test_module_entry_point_runs_placeholder(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["vrm_alert_relay"])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("vrm_alert_relay", run_name="__main__")

    assert excinfo.value.code == 0
    assert json.loads(capsys.readouterr().err)["dry_run"] is True
