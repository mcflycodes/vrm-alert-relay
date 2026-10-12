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


def test_no_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "a command is required" in captured.err
    assert captured.err.startswith("usage: vrm-alert-relay")


def test_help_names_the_project_as_unofficial(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])

    out = " ".join(capsys.readouterr().out.split())
    assert "Unofficial" in out
    assert "Not affiliated with or endorsed by Victron Energy" in out
    for command in ("run", "check-config", "test-notification"):
        assert command in out


@given(suffix=st.text(alphabet=st.characters(categories=["Ll", "Nd"]), min_size=1, max_size=20))
def test_unknown_options_are_rejected_without_running(suffix: str) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([f"--unknown-{suffix}"])

    assert excinfo.value.code == 2


def test_test_notification_requires_a_recipient() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["test-notification"])

    assert excinfo.value.code == 2


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["run", "--log-level", "loud"])

    assert excinfo.value.code == 2


def test_invalid_log_level_in_the_environment_is_rejected(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("VRM_ALERT_RELAY_LOG_LEVEL", "chatty")

    with pytest.raises(SystemExit) as excinfo:
        main(["run"])

    assert excinfo.value.code == 2
    assert "VRM_ALERT_RELAY_LOG_LEVEL" in capsys.readouterr().err


def test_console_script_points_at_main() -> None:
    (script,) = entry_points(group="console_scripts", name=PROG)

    assert script.value == "vrm_alert_relay.cli:main"


def test_module_entry_point_runs_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["vrm_alert_relay", "--version"])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("vrm_alert_relay", run_name="__main__")

    assert excinfo.value.code == 0
    assert capsys.readouterr().out == f"{PROG} {__version__}\n"
