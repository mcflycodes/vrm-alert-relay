"""Secret files and the Secret type."""

from __future__ import annotations

import copy
import errno
import inspect
import json
import logging
import os
import pickle
import stat
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pydantic
import pytest

from vrm_alert_relay.config import (
    ConfigError,
    RelayConfig,
    RelaySecrets,
    Secret,
    SecretFileError,
    SecretsImmutableError,
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


def test_secret_never_appears_in_logs(fake_secret: str, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        logging.getLogger("test").info("token is %s / %r", Secret(fake_secret), Secret(fake_secret))
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
    secrets = RelaySecrets(vrm_token=Secret(fake_secret), voipms_password=Secret(fake_secret))
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
        lambda s: RelaySecrets.model_construct(vrm_token=s),
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
    assert error.__cause__ is None
    assert error.__context__ is None
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


HIDDEN = "RelaySecrets(<hidden>)"


def _assert_unchanged(secrets: RelaySecrets, fake_secret: str) -> None:
    assert secrets.vrm_token is not None
    assert secrets.vrm_token.reveal() == fake_secret
    assert secrets.voipms_password is None


@pytest.mark.parametrize(
    "change",
    [
        lambda r, s: r.model_copy(update={"vrm_token": s}),
        lambda r, s: r.model_copy(update={"voipms_password": s}, deep=True),
        lambda r, s: r.model_copy(update={}),
        lambda r, s: r.copy(update={"vrm_token": s}),
        lambda r, s: r.copy(update={"voipms_password": Secret(s)}, deep=True),
        lambda r, s: r.copy(update={}),
        lambda r, s: copy.replace(r, vrm_token=s),
        lambda r, s: copy.replace(r),
        lambda r, s: setattr(r, "vrm_token", s),
        lambda r, s: setattr(r, "voipms_password", Secret(s)),
        lambda r, s: delattr(r, "vrm_token"),
        lambda r, s: pickle.dumps(r),
        lambda r, s: r.__setstate__({"__dict__": {"vrm_token": s}}),
    ],
    ids=[
        "model_copy_update",
        "model_copy_deep_update",
        "model_copy_empty_update",
        "deprecated_copy_update_plain",
        "deprecated_copy_update_secret",
        "deprecated_copy_empty_update",
        "copy_replace",
        "copy_replace_nothing",
        "setattr_plain",
        "setattr_secret",
        "delattr",
        "pickle",
        "setstate",
    ],
)
def test_relay_secrets_refuse_changes(
    fake_secret: str, change: Callable[[RelaySecrets, str], Any]
) -> None:
    secrets = RelaySecrets(vrm_token=Secret(fake_secret))
    with pytest.raises(SecretsImmutableError) as caught:
        change(secrets, fake_secret)
    error = caught.value
    assert str(error) == (
        "RelaySecrets cannot be changed, pickled, or built without validation; "
        "load the secrets again"
    )
    assert fake_secret not in repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None
    _assert_unchanged(secrets, fake_secret)


def test_relay_secrets_without_values_also_refuse_pickling() -> None:
    with pytest.raises(SecretsImmutableError):
        pickle.dumps(RelaySecrets())


@pytest.mark.parametrize(
    "duplicate",
    [
        copy.copy,
        copy.deepcopy,
        lambda r: r.model_copy(),
        lambda r: r.model_copy(deep=True),
        lambda r: r.model_copy(update=None),
    ],
    ids=["copy", "deepcopy", "model_copy", "model_copy_deep", "model_copy_none"],
)
def test_relay_secrets_copies_hold_only_secrets(
    fake_secret: str, duplicate: Callable[[RelaySecrets], RelaySecrets]
) -> None:
    secrets = RelaySecrets(vrm_token=Secret(fake_secret))
    duplicated = duplicate(secrets)
    assert duplicated == secrets
    assert isinstance(duplicated.vrm_token, Secret)
    assert repr(duplicated) == str(duplicated) == HIDDEN
    _assert_unchanged(duplicated, fake_secret)


def test_deprecated_copy_without_update_keeps_secrets(fake_secret: str) -> None:
    secrets = RelaySecrets(vrm_token=Secret(fake_secret))
    with pytest.warns(pydantic.PydanticDeprecatedSince20):
        duplicated = secrets.copy(deep=True)
    assert duplicated == secrets
    _assert_unchanged(duplicated, fake_secret)


_VALUE_PARAMETERS = frozenset(
    {
        "b",
        "changes",
        "data",
        "json_data",
        "obj",
        "path",
        "state",
        "update",
        "value",
        "values",
    }
)


def _value_entry_points() -> set[str]:
    """Every public or dunder BaseModel method with a parameter that carries values."""
    found: set[str] = set()
    for name in vars(pydantic.BaseModel):
        if name.startswith("_") and not name.startswith("__"):
            continue
        attr = inspect.getattr_static(pydantic.BaseModel, name)
        function = getattr(attr, "__func__", attr)
        if not inspect.isfunction(function):
            continue
        if _VALUE_PARAMETERS & set(inspect.signature(function).parameters):
            found.add(name)
    return found


Attack = Callable[[RelaySecrets, str, Path], object]


def _write_json(path: Path, value: str) -> Path:
    target = path / "secrets.json"
    target.write_text(json.dumps({"vrm_token": value}))
    return target


# Every way to feed values into a RelaySecrets, each tried with plaintext.
VALUE_ATTACKS: list[tuple[str, Attack]] = [
    ("__init__", lambda r, s, p: RelaySecrets(vrm_token=s)),
    ("__replace__", lambda r, s, p: copy.replace(r, vrm_token=s)),
    ("__setattr__", lambda r, s, p: setattr(r, "vrm_token", s)),
    ("__setstate__", lambda r, s, p: r.__setstate__({"__dict__": {"vrm_token": s}})),
    ("construct", lambda r, s, p: RelaySecrets.construct(vrm_token=s)),
    ("copy", lambda r, s, p: r.copy(update={"vrm_token": s})),
    ("from_orm", lambda r, s, p: RelaySecrets.from_orm(SimpleNamespace(vrm_token=s))),
    ("model_construct", lambda r, s, p: RelaySecrets.model_construct(vrm_token=s)),
    ("model_copy", lambda r, s, p: r.model_copy(update={"vrm_token": s})),
    ("model_validate", lambda r, s, p: RelaySecrets.model_validate({"vrm_token": s})),
    (
        "model_validate",
        lambda r, s, p: RelaySecrets.model_validate(
            SimpleNamespace(vrm_token=s), from_attributes=True
        ),
    ),
    (
        "model_validate_json",
        lambda r, s, p: RelaySecrets.model_validate_json(json.dumps({"vrm_token": s})),
    ),
    (
        "model_validate_strings",
        lambda r, s, p: RelaySecrets.model_validate_strings({"vrm_token": s}),
    ),
    ("parse_obj", lambda r, s, p: RelaySecrets.parse_obj({"vrm_token": s})),
    ("parse_raw", lambda r, s, p: RelaySecrets.parse_raw(json.dumps({"vrm_token": s}))),
    (
        "parse_raw",
        lambda r, s, p: RelaySecrets.parse_raw(
            pickle.dumps({"vrm_token": s}), proto="pickle", allow_pickle=True
        ),
    ),
    ("parse_file", lambda r, s, p: RelaySecrets.parse_file(_write_json(p, s))),
    ("validate", lambda r, s, p: RelaySecrets.validate({"vrm_token": s})),
]


def test_every_value_entry_point_is_attacked() -> None:
    assert _value_entry_points() == {name for name, _ in VALUE_ATTACKS}


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize(
    "attack",
    [attack for _, attack in VALUE_ATTACKS],
    ids=[f"{name}-{i}" for i, (name, _) in enumerate(VALUE_ATTACKS)],
)
def test_no_entry_point_yields_plaintext(fake_secret: str, tmp_path: Path, attack: Attack) -> None:
    original = RelaySecrets(vrm_token=Secret(fake_secret))
    plaintext = "fake-plaintext-for-entry-point-tests"
    # from_orm is refused by pydantic itself because from_attributes is off.
    refusals = (SecretTypeError, SecretsImmutableError, pydantic.PydanticUserError)
    with pytest.raises(refusals) as caught:
        attack(original, plaintext, tmp_path)
    assert plaintext not in repr(caught.value)
    assert plaintext not in str(caught.value)
    assert all(v is None or isinstance(v, Secret) for v in vars(original).values())
    _assert_unchanged(original, fake_secret)


def test_model_construct_refuses_plain_values(fake_secret: str) -> None:
    with pytest.raises(SecretTypeError):
        RelaySecrets.model_construct(vrm_token=fake_secret)
    built = RelaySecrets.model_construct(vrm_token=Secret(fake_secret))
    _assert_unchanged(built, fake_secret)


def test_relay_secrets_text_forms_are_fixed(fake_secret: str) -> None:
    secrets = RelaySecrets(vrm_token=Secret(fake_secret), voipms_password=Secret(fake_secret))
    assert repr(secrets) == str(secrets) == f"{secrets}" == HIDDEN
    assert list(secrets.__repr_args__()) == []
    assert list(secrets.__rich_repr__()) == []
    assert all(not info.repr for info in RelaySecrets.model_fields.values())
    assert fake_secret not in repr([secrets]) + repr({"s": secrets})


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


def test_read_secret_file_accepts_path_objects(secret_file: SecretWriter, fake_secret: str) -> None:
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
    assert read_secret_file(secret_file("s", mode=mode)).group_or_world_readable is permissive


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
    assert caught.value.problems == ("providers.voipms.password_file: secret file does not exist",)


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
        (
            "providers.homeassistant.token_file: "
            "secret file contains line breaks or control characters"
        ),
    )
    assert "fake-" not in text
    assert "second-line" not in text


def test_permissive_secret_files_produce_warnings(
    config_data: Data, parse: Parse, secret_file: SecretWriter
) -> None:
    _write_all(secret_file, mode=0o644)
    config_data["sending"]["enabled"] = True
    config_data["providers"]["homeassistant"]["enabled"] = True
    _, warnings = load_secrets(parse(config_data))
    permissive = "secret file is readable by group or others; restrict it to mode 0600 or 0400"
    assert warnings == [
        f"vrm.token_file: {permissive}",
        f"providers.homeassistant.token_file: {permissive}",
    ]
