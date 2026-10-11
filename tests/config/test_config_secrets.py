"""Secret files and the Secret type."""

from __future__ import annotations

import copy
import errno
import json
import logging
import os
import pickle
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pydantic
import pytest

from vrm_alert_relay.config import (
    ConfigError,
    RelayConfig,
    RelaySecrets,
    Secret,
    SecretFileError,
    SecretTypeError,
    load_secrets,
    read_secret_file,
)
from vrm_alert_relay.config.secret import MAX_SECRET_BYTES

SecretWriter = Callable[..., str]
Data = dict[str, Any]
Parse = Callable[[Any], RelayConfig]

MASK = "**********"


# --- Secret type -----------------------------------------------------------


def test_secret_reveals_only_on_request(fake_secret: str) -> None:
    secret = Secret(fake_secret)
    assert secret.reveal() == fake_secret


def test_secret_never_appears_in_text_forms(fake_secret: str) -> None:
    secret = Secret(fake_secret)
    rendered = [
        str(secret),
        repr(secret),
        f"{secret}",
        f"{secret!r}",
        f"{secret!s}",
        f"{secret:>40}",
        "%s" % secret,  # noqa: UP031
        "%r" % secret,  # noqa: UP031
        "{}".format(secret),  # noqa: UP032
        str([secret]),
        repr({"token": secret}),
    ]
    for text in rendered:
        assert fake_secret not in text
        assert MASK in text
    assert repr(secret) == f"Secret('{MASK}')"
    assert f"{secret:>12}" == f"  {MASK}"


def test_secret_never_appears_in_logs(
    fake_secret: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        logging.getLogger("test").info(
            "token is %s / %r", Secret(fake_secret), Secret(fake_secret)
        )
    assert fake_secret not in caplog.text
    assert MASK in caplog.text


def test_secret_refuses_json_and_pickle(fake_secret: str) -> None:
    secret = Secret(fake_secret)
    with pytest.raises(TypeError) as caught:
        json.dumps({"token": secret})
    assert fake_secret not in str(caught.value)
    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(secret)


def test_secret_copy_equality_and_hashing(fake_secret: str) -> None:
    secret = Secret(fake_secret)
    assert copy.copy(secret) is secret
    assert copy.deepcopy(secret) is secret
    assert secret == Secret(fake_secret)
    assert secret != Secret("another-fake-secret")
    assert secret != fake_secret
    with pytest.raises(TypeError):
        hash(secret)


def test_secret_requires_a_string() -> None:
    with pytest.raises(TypeError):
        Secret(b"bytes")  # type: ignore[arg-type]


def test_secret_in_pydantic_models_is_masked(fake_secret: str) -> None:
    secrets = RelaySecrets(
        vrm_token=Secret(fake_secret), voipms_password=Secret(fake_secret)
    )
    outputs = [
        repr(secrets),
        str(secrets),
        str(secrets.model_dump()),
        json.dumps(secrets.model_dump()),
        json.dumps(secrets.model_dump(mode="json")),
        secrets.model_dump_json(),
    ]
    for text in outputs:
        assert fake_secret not in text
    assert secrets.model_dump()["vrm_token"] == MASK
    assert json.loads(secrets.model_dump_json())["voipms_password"] == MASK
    assert secrets.vrm_token is not None
    assert secrets.vrm_token.reveal() == fake_secret


@pytest.mark.parametrize(
    "build",
    [
        lambda s: RelaySecrets(vrm_token=s),
        lambda s: RelaySecrets(vrm_token=Secret("fake-other"), voipms_password=s),
        lambda s: RelaySecrets(unexpected=s),
        lambda s: RelaySecrets.model_validate({"homeassistant_token": s}),
        lambda s: RelaySecrets.model_validate([s]),
        lambda s: RelaySecrets.model_validate_json(json.dumps({"vrm_token": s})),
        lambda s: RelaySecrets(vrm_token=s.encode()),
    ],
)
def test_plain_values_are_refused_before_pydantic_validation(
    fake_secret: str, build: Callable[[str], Any]
) -> None:
    with pytest.raises(SecretTypeError) as caught:
        build(fake_secret)
    error = caught.value
    assert str(error) == "secret fields accept only Secret values read from files"
    assert not isinstance(error, pydantic.ValidationError)
    assert error.__cause__ is None and error.__context__ is None
    assert fake_secret not in repr(error)


def test_secret_field_validator_refuses_plain_values(fake_secret: str) -> None:
    class Holder(pydantic.BaseModel):
        token: Secret

    with pytest.raises(SecretTypeError):
        Holder(token=fake_secret)  # type: ignore[arg-type]


def test_remaining_validation_errors_hold_no_plaintext(fake_secret: str) -> None:
    with pytest.raises(pydantic.ValidationError) as caught:
        RelaySecrets(unexpected=Secret(fake_secret))  # type: ignore[call-arg]
    error = caught.value
    rendered = [str(error), repr(error), error.json(), repr(error.errors())]
    for text in rendered:
        assert fake_secret not in text
    assert error.errors()[0]["type"] == "extra_forbidden"


# --- read_secret_file ------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("fake-token\n", "fake-token"),
        ("fake-token\r\n", "fake-token"),
        ("fake-token", "fake-token"),
        (" fake token ", " fake token "),
        ("fäke-tøken\n", "fäke-tøken"),
    ],
)
def test_read_secret_file_strips_one_newline(
    secret_file: SecretWriter, content: str, expected: str
) -> None:
    result = read_secret_file(secret_file("s", content))
    assert result.secret.reveal() == expected
    assert result.group_or_world_readable is False


def test_read_secret_file_accepts_path_objects(
    secret_file: SecretWriter, fake_secret: str
) -> None:
    assert read_secret_file(Path(secret_file("s"))).secret.reveal() == fake_secret


def test_read_secret_file_follows_symlinks(
    secret_file: SecretWriter, tmp_path: Path, fake_secret: str
) -> None:
    link = tmp_path / "link"
    link.symlink_to(secret_file("s"))
    assert read_secret_file(link).secret.reveal() == fake_secret


def test_secret_at_size_limit_is_accepted(secret_file: SecretWriter) -> None:
    value = "x" * MAX_SECRET_BYTES
    assert read_secret_file(secret_file("s", value)).secret.reveal() == value


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("", "secret file is empty"),
        ("\n", "secret file is empty"),
        ("\r\n", "secret file is empty"),
        (
            "x" * (MAX_SECRET_BYTES + 1),
            f"secret file is larger than {MAX_SECRET_BYTES} bytes",
        ),
        ("fake-token\n\n", "secret file contains line breaks or control characters"),
        ("fake\ntoken\n", "secret file contains line breaks or control characters"),
        ("fake\rtoken", "secret file contains line breaks or control characters"),
        ("fake\x00token", "secret file contains line breaks or control characters"),
        ("fake\ttoken", "secret file contains line breaks or control characters"),
        (b"fake-\xfftoken", "secret file is not valid UTF-8"),
    ],
)
def test_unusable_secret_files_are_rejected_without_content(
    secret_file: SecretWriter, content: str | bytes, reason: str
) -> None:
    with pytest.raises(SecretFileError) as caught:
        read_secret_file(secret_file("s", content))
    assert caught.value.reason == reason
    assert str(caught.value) == reason
    assert caught.value.missing is False
    assert "token" not in str(caught.value)


def test_missing_secret_file(secrets_dir: Path) -> None:
    for path in (secrets_dir / "absent", secrets_dir / "absent" / "nested"):
        with pytest.raises(SecretFileError) as caught:
            read_secret_file(path)
        assert caught.value.missing is True
        assert caught.value.reason == "secret file does not exist"


def test_secret_file_under_a_regular_file(secret_file: SecretWriter) -> None:
    with pytest.raises(SecretFileError) as caught:
        read_secret_file(Path(secret_file("s")) / "nested")
    assert caught.value.missing is True


def test_directory_is_not_a_secret_file(secrets_dir: Path) -> None:
    with pytest.raises(SecretFileError, match="not a regular file"):
        read_secret_file(secrets_dir)


def test_fifo_is_not_read(secrets_dir: Path) -> None:
    fifo = secrets_dir / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(SecretFileError, match="not a regular file"):
        read_secret_file(fifo)


@pytest.mark.parametrize(
    ("mode", "permissive"),
    [
        (0o600, False),
        (0o400, False),
        (0o640, True),
        (0o604, True),
        (0o644, True),
        (0o620, False),
    ],
)
def test_permissive_modes_are_flagged(
    secret_file: SecretWriter, mode: int, permissive: bool
) -> None:
    assert (
        read_secret_file(secret_file("s", mode=mode)).group_or_world_readable
        is permissive
    )


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (errno.EACCES, "secret file is not readable (permission denied)"),
        (errno.EPERM, "secret file is not readable (permission denied)"),
        (errno.EIO, "secret file cannot be read (EIO)"),
    ],
)
def test_open_errors_are_reported(
    secret_file: SecretWriter, monkeypatch: pytest.MonkeyPatch, error: int, reason: str
) -> None:
    path = secret_file("s")

    def fail(*_args: Any) -> int:
        raise OSError(error, os.strerror(error), path)

    monkeypatch.setattr("vrm_alert_relay.config._files.os.open", fail)
    with pytest.raises(SecretFileError) as caught:
        read_secret_file(path)
    assert caught.value.reason == reason
    assert path not in str(caught.value)


def test_os_error_without_message(
    secret_file: SecretWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: Any) -> int:
        raise OSError()

    monkeypatch.setattr("vrm_alert_relay.config._files.os.open", fail)
    with pytest.raises(SecretFileError, match=r"cannot be read \(unknown\)"):
        read_secret_file(secret_file("s"))


def test_read_errors_are_reported(
    secret_file: SecretWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: Any) -> bytes:
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr("vrm_alert_relay.config._files.os.read", fail)
    with pytest.raises(SecretFileError, match=r"cannot be read \(EIO\)"):
        read_secret_file(secret_file("s"))


def test_file_growing_past_its_reported_size_is_rejected(
    secret_file: SecretWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = secret_file("s", "x" * (MAX_SECRET_BYTES + 10))
    real_fstat = os.fstat

    def small_fstat(fd: int) -> os.stat_result:
        fields = list(real_fstat(fd))
        fields[stat.ST_SIZE] = 1
        return os.stat_result(fields)

    monkeypatch.setattr("vrm_alert_relay.config._files.os.fstat", small_fstat)
    with pytest.raises(SecretFileError, match="larger than"):
        read_secret_file(path)


def test_short_reads_are_reassembled(
    secret_file: SecretWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = secret_file("s", "abcdef\n")
    real_read = os.read

    def one_byte(fd: int, _size: int) -> bytes:
        return real_read(fd, 1)

    monkeypatch.setattr("vrm_alert_relay.config._files.os.read", one_byte)
    assert read_secret_file(path).secret.reveal() == "abcdef"


# --- load_secrets ----------------------------------------------------------


def _write_all(secret_file: SecretWriter, mode: int = 0o600) -> None:
    for name in (
        "vrm_token",
        "voipms_username",
        "voipms_password",
        "ha_token",
        "webhook_token",
    ):
        secret_file(name, f"fake-{name}-value\n", mode)


def test_dry_run_reads_only_the_vrm_token(
    config_data: Data, parse: Parse, secret_file: SecretWriter
) -> None:
    _write_all(secret_file)
    for provider in ("voipms", "homeassistant", "webhook"):
        config_data["providers"][provider]["enabled"] = True
    secrets, warnings = load_secrets(parse(config_data))
    assert secrets.vrm_token is not None
    assert secrets.vrm_token.reveal() == "fake-vrm_token-value"
    assert secrets.voipms_username is None
    assert secrets.voipms_password is None
    assert secrets.homeassistant_token is None
    assert secrets.webhook_auth_header_value is None
    assert warnings == []


def test_live_providers_load_their_secrets(
    config_data: Data, parse: Parse, secret_file: SecretWriter
) -> None:
    _write_all(secret_file)
    config_data["sending"]["enabled"] = True
    for provider in ("voipms", "homeassistant", "webhook"):
        config_data["providers"][provider]["enabled"] = True
    secrets, warnings = load_secrets(parse(config_data))
    assert warnings == []
    revealed = {
        name: value.reveal()
        for name, value in (
            ("u", secrets.voipms_username),
            ("p", secrets.voipms_password),
            ("h", secrets.homeassistant_token),
            ("w", secrets.webhook_auth_header_value),
        )
        if value is not None
    }
    assert revealed == {
        "u": "fake-voipms_username-value",
        "p": "fake-voipms_password-value",
        "h": "fake-ha_token-value",
        "w": "fake-webhook_token-value",
    }


def test_live_webhook_without_auth_needs_no_secret(
    config_data: Data, parse: Parse, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token")
    config_data["sending"]["enabled"] = True
    webhook = config_data["providers"]["webhook"]
    webhook["enabled"] = True
    del webhook["auth_header_name"], webhook["auth_header_value_file"]
    secrets, _ = load_secrets(parse(config_data))
    assert secrets.webhook_auth_header_value is None


def test_live_provider_with_missing_secret_fails(
    config_data: Data, parse: Parse, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token")
    secret_file("voipms_username")
    config_data["sending"]["enabled"] = True
    config_data["providers"]["voipms"]["enabled"] = True
    with pytest.raises(ConfigError) as caught:
        load_secrets(parse(config_data))
    assert caught.value.problems == (
        "providers.voipms.password_file: secret file does not exist",
    )


def test_missing_vrm_token_fails_at_runtime(config_data: Data, parse: Parse) -> None:
    with pytest.raises(ConfigError) as caught:
        load_secrets(parse(config_data))
    assert caught.value.problems == ("vrm.token_file: secret file does not exist",)


def test_runtime_errors_never_contain_secret_content(
    config_data: Data, parse: Parse, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token", "fake-vrm-secret\x01value\n")
    secret_file("ha_token", "fake-ha-secret\nsecond-line\n")
    config_data["sending"]["enabled"] = True
    config_data["providers"]["homeassistant"]["enabled"] = True
    with pytest.raises(ConfigError) as caught:
        load_secrets(parse(config_data))
    text = str(caught.value)
    assert caught.value.problems == (
        "vrm.token_file: secret file contains line breaks or control characters",
        "providers.homeassistant.token_file: secret file contains line breaks or control characters",
    )
    assert "fake-" not in text and "second-line" not in text


def test_permissive_secret_files_produce_warnings(
    config_data: Data, parse: Parse, secret_file: SecretWriter
) -> None:
    _write_all(secret_file, mode=0o644)
    config_data["sending"]["enabled"] = True
    config_data["providers"]["homeassistant"]["enabled"] = True
    _, warnings = load_secrets(parse(config_data))
    permissive = (
        "secret file is readable by group or others; restrict it to mode 0600 or 0400"
    )
    assert warnings == [
        f"vrm.token_file: {permissive}",
        f"providers.homeassistant.token_file: {permissive}",
    ]
