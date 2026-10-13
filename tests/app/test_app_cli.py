"""The command line against the mocked VRM and VoIP.ms APIs. All data is fictitious."""

from __future__ import annotations

import json
import os
import signal
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from app_helpers import OWNER_PHONE, SECRETS, VOIPMS_HOST, freezer_rule

from vrm_alert_relay.app import CONFIG_ENV, STATE_DIR_ENV, ExitCode, open_runtime
from vrm_alert_relay.app.service import TEST_MESSAGE
from vrm_alert_relay.cli import main

if TYPE_CHECKING:
    from app_helpers import Harness


def real_time(harness: Harness) -> None:
    """The CLI runs on the system clock, so VRM records must carry real times."""
    harness.vrm.now = lambda: datetime.now(UTC)


def records(text: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in text.splitlines() if line.startswith("{")]


def events(text: str) -> list[object]:
    return [record.get("event") for record in records(text)]


def run_args(harness: Harness, *extra: str) -> list[str]:
    return [
        "run",
        "--config",
        str(harness.config_path),
        "--state-dir",
        str(harness.state_dir),
        *extra,
    ]


def test_run_once_starts_in_dry_run_and_stops_cleanly(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config(sending=False)
    real_time(harness)
    harness.vrm.set("tsT", 20, -20)

    assert main(run_args(harness, "--once")) == ExitCode.OK

    out = capsys.readouterr().out
    started = next(r for r in records(out) if r.get("event") == "service.started")
    assert started["dry_run"] is True
    assert started["live_providers"] == []
    assert events(out)[-2:] == ["service.stopping", "service.stopped"]
    assert "relay.cycle" in events(out)
    assert len(harness.vrm.requests) == 1
    assert not any(secret in out for secret in SECRETS)


def test_run_reads_its_paths_from_the_environment(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config(sending=False)
    real_time(harness)
    monkeypatch.setenv(CONFIG_ENV, str(harness.config_path))
    monkeypatch.setenv(STATE_DIR_ENV, str(harness.state_dir))
    monkeypatch.setenv("VRM_ALERT_RELAY_LOG_LEVEL", "warning")

    assert main(["run", "--once"]) == ExitCode.OK

    out = capsys.readouterr().out
    assert "service.started" not in events(out)  # an info record, below WARNING
    assert (harness.state_dir / "relay-state.sqlite3").exists()


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_a_stop_signal_finishes_the_cycle_and_closes_state(
    harness: Harness, capsys: pytest.CaptureFixture[str], signum: signal.Signals
) -> None:
    harness.write_config()
    real_time(harness)
    harness.vrm.set("tsT", 20, -10)
    previous = signal.getsignal(signum)
    harness.vrm.on_request = lambda: os.kill(os.getpid(), signum)

    assert main(run_args(harness)) == ExitCode.OK

    out = capsys.readouterr().out
    assert events(out)[-3:] == ["service.stopping", "service.stopped", "service.signal"]
    signal_record = records(out)[-1]
    assert signal_record["signal"] == signum.name
    # The cycle that was running finished: its alert went out.
    assert len(harness.voipms.sent()) == 1
    assert signal.getsignal(signum) is previous
    # The state directory was released.
    open_runtime(harness.config_path, harness.state_dir).close()


def test_run_with_an_unusable_configuration_exits_3(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(run_args(harness)) == ExitCode.CONFIG

    captured = capsys.readouterr()
    assert captured.err == (
        "vrm-alert-relay: cannot start:\n  - configuration file: does not exist\n"
    )
    assert "service.startup_failed" in events(captured.out)


def test_run_while_another_relay_holds_the_state_exits_4(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config()
    with harness.service():
        assert main(run_args(harness, "--once")) == ExitCode.STATE_LOCKED

    assert "another relay process is using it" in capsys.readouterr().err
    assert harness.vrm.requests == []


def test_run_serves_the_health_endpoint_when_enabled(
    harness: Harness, capsys: pytest.CaptureFixture[str], free_port: int
) -> None:
    harness.write_config(health={"enabled": True, "port": free_port})
    real_time(harness)

    assert main(run_args(harness, "--once")) == ExitCode.OK

    listening = next(
        r for r in records(capsys.readouterr().out) if r.get("event") == "health.listening"
    )
    assert listening["bind"] == "127.0.0.1"
    assert listening["port"] == free_port


# check-config ---------------------------------------------------------------


def test_check_config_reports_a_ready_configuration(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config()

    assert main(["check-config", "--config", str(harness.config_path)]) == ExitCode.OK

    out = capsys.readouterr().out
    assert out.startswith("result: ready: the configuration and its secret files are valid\n")
    assert "live recipients: owner_sms, partner_sms\n" in out
    assert "dry-run recipients: audit\n" in out
    assert "system recipients: owner_sms\n" in out
    assert "live providers: voipms\n" in out


def test_check_config_structure_only_reads_no_secrets(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config()
    for secret in (harness.root / "secrets").iterdir():
        secret.unlink()

    code = main(["check-config", "--structure-only", "--config", str(harness.config_path)])

    assert code == ExitCode.OK
    out = capsys.readouterr().out
    assert out.startswith("result: valid structure: secret files were not read\n")
    assert "notes:\n  - structure-only check" in out


def test_check_config_lists_problems_and_exits_3(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config()
    (harness.root / "secrets" / "vrm_token").unlink()

    assert main(["check-config", "--config", str(harness.config_path)]) == ExitCode.CONFIG

    out = capsys.readouterr().out
    assert out.startswith("result: problems found\nproblems:\n  - vrm.token_file: ")


def test_check_config_of_an_unreadable_file_shows_no_summary(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["check-config", "--config", str(harness.root / "missing.yaml")])

    assert code == ExitCode.CONFIG
    assert capsys.readouterr().out == (
        "result: problems found\nproblems:\n  - configuration file: does not exist\n"
    )


def test_check_config_warns_that_empty_system_recipients_only_log(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config(system=[])

    assert main(["check-config", "--config", str(harness.config_path)]) == ExitCode.OK

    out = capsys.readouterr().out
    assert "system problems (monitoring degraded or restored" in out
    assert "will only be logged\n" in out
    assert "system recipients: none (system notifications are only logged)\n" in out


def test_check_config_masks_phone_shaped_recipient_names(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config(
        recipients={
            "owner_sms": {"provider": "voipms", "phone": "+1 202 555 0142"},
            "r2025550123": {"provider": "voipms", "phone": "+1 202 555 0123"},
        },
    )
    config = json.loads(harness.config_path.read_text())
    config["rules"][0]["recipients"] = ["r2025550123"]
    del config["system_recipients"]
    harness.config_path.write_text(json.dumps(config))

    assert main(["check-config", "--config", str(harness.config_path)]) == ExitCode.OK

    out = capsys.readouterr().out
    assert "2025550123" not in out
    assert "live recipients: owner_sms, [#1]\n" in out
    assert "system recipients: [#1] (default: every recipient used by a rule)\n" in out
    assert "recipients.owner_sms: not used by any rule" in out


# test-notification -----------------------------------------------------------


def notify(harness: Harness, recipient: str = "owner_sms") -> int:
    return main(
        [
            "test-notification",
            "--config",
            str(harness.config_path),
            "--state-dir",
            str(harness.state_dir),
            "--recipient",
            recipient,
        ]
    )


def test_test_notification_delivers_one_message_live(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config()

    assert notify(harness) == ExitCode.OK

    captured = capsys.readouterr()
    assert captured.out == "test notification: delivered to owner_sms (live)\n"
    assert harness.voipms.sent() == [(OWNER_PHONE, TEST_MESSAGE)]
    assert "service.test_notification" in events(captured.err)


def test_test_notification_in_dry_run_only_logs(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config(sending=False)

    assert notify(harness) == ExitCode.OK

    captured = capsys.readouterr()
    assert captured.out.startswith("test notification: dry run: the message to owner_sms was")
    assert VOIPMS_HOST not in harness.network.hosts
    assert "provider.dry_run" in events(captured.err)


def test_test_notification_to_an_unknown_recipient_exits_3(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config()

    assert notify(harness, "r2025550199") == ExitCode.CONFIG

    err = capsys.readouterr().err
    assert "--recipient: not a configured recipient" in err
    assert "2025550199" not in err
    assert harness.voipms.calls == []


def test_test_notification_respects_the_global_cap(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config(per_hour=1, per_day=1)

    assert notify(harness) == ExitCode.OK
    assert notify(harness, "partner_sms") == ExitCode.NOT_DELIVERED

    out = capsys.readouterr().out
    assert "held back by the global rate limit: nothing was sent to partner_sms (live)" in out
    assert len(harness.voipms.sent()) == 1


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        ({"status": "mystery"}, "outcome unknown for owner_sms (live)"),
        ({"status": "invalid_dst"}, "not delivered to owner_sms (live): the provider refused the"),
        ({"status": "limit_reached"}, "not delivered to owner_sms (live): the provider refused it"),
    ],
)
def test_test_notification_reports_a_failed_send(
    harness: Harness, capsys: pytest.CaptureFixture[str], answer: object, message: str
) -> None:
    harness.write_config()
    harness.voipms.sends.append(answer)

    assert notify(harness) == ExitCode.NOT_DELIVERED

    assert message in capsys.readouterr().out


def test_test_notification_sends_nothing_else_that_is_due(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -10)
    harness.voipms.sends.append({"status": "limit_reached"})  # the alert waits for a retry
    with harness.service() as service:
        harness.cycle(service)
    assert len(harness.voipms.sent()) == 1

    assert notify(harness) == ExitCode.OK

    assert harness.voipms.texts()[1:] == [TEST_MESSAGE]
    capsys.readouterr()


def test_test_notification_masks_a_phone_shaped_recipient_name(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config(
        recipients={
            "owner_sms": {"provider": "voipms", "phone": "+1 202 555 0142"},
            "r2025550123": {"provider": "voipms", "phone": "+1 202 555 0123"},
        },
        rules=[freezer_rule(recipients=["owner_sms", "r2025550123"])],
    )

    assert notify(harness, "r2025550123") == ExitCode.OK

    captured = capsys.readouterr()
    assert captured.out == "test notification: delivered to [#1] (live)\n"
    assert "2025550123" not in captured.out + captured.err


def test_test_notification_while_the_relay_runs_exits_4(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.write_config()
    with harness.service():
        assert notify(harness) == ExitCode.STATE_LOCKED

    assert "another relay process" in capsys.readouterr().err
    assert harness.voipms.calls == []


def test_test_notification_with_an_unusable_configuration_exits_3(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    assert notify(harness) == ExitCode.CONFIG

    assert "configuration file: does not exist" in capsys.readouterr().err
