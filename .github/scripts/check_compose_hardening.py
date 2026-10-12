"""Check that the rendered Compose example keeps its hardening (requirement R29).

Reads the output of ``docker compose config --format json`` on standard input
and exits non-zero, listing every problem, if any hardened setting is missing
or weakened. CI runs it on the example, and on deliberately weakened copies
that it must reject.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

SERVICES = {"relay"}
USER = "65532:65532"
STATE_TARGET = "/var/lib/vrm-alert-relay"
STATE_VOLUME = "state"
READ_ONLY_TARGETS = {"/etc/vrm-alert-relay/config.yaml"}
SECRETS = {
    "vrm_token",
    "voipms_username",
    "voipms_api_password",
    "homeassistant_token",
    "webhook_token",
    "homeassistant_ca.pem",
    "webhook_ca.pem",
}
REQUIRED_SECRETS = {"vrm_token"}
ENVIRONMENT = {
    "VRM_ALERT_RELAY_CONFIG",
    "VRM_ALERT_RELAY_STATE_DIR",
    "VRM_ALERT_RELAY_LOG_LEVEL",
}
SECRET_NAME = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL|AUTH", re.IGNORECASE)
FORBIDDEN_KEYS = (
    "cap_add",
    "cgroup",
    "device_cgroup_rules",
    "devices",
    "env_file",
    "group_add",
    "network_mode",
    "pid",
    "ports",
    "privileged",
    "tmpfs",
    "userns_mode",
    "uts",
    "volumes_from",
)


def _mount_problems(mounts: list[dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    writable = []
    for mount in mounts:
        source = str(mount.get("source", ""))
        target = mount.get("target")
        if "docker.sock" in source or "docker.sock" in str(target):
            problems.append(f"mount {target}: the Docker socket must never be mounted")
        if mount.get("read_only") is True:
            if mount.get("type") != "bind" or target not in READ_ONLY_TARGETS:
                problems.append(f"mount {target}: unexpected read-only mount")
        else:
            writable.append(mount)
    if len(writable) != 1:
        problems.append(f"expected exactly one writable mount, found {len(writable)}")
    for mount in writable:
        expected = (mount.get("type"), mount.get("source"), mount.get("target"))
        if expected != ("volume", STATE_VOLUME, STATE_TARGET):
            problems.append(
                f"mount {mount.get('target')}: the only writable mount must be the "
                f"'{STATE_VOLUME}' volume at {STATE_TARGET}"
            )
    return problems


def _secret_problems(relay: dict[str, Any], config: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    names = set()
    for entry in relay.get("secrets", []):
        name = entry.get("source")
        names.add(name)
        if name not in SECRETS:
            problems.append(f"secret {name}: not an expected secret")
        if entry.get("target") != f"/run/secrets/{name}":
            problems.append(f"secret {name}: must be mounted at /run/secrets/{name}")
        problems.extend(
            f"secret {name}: '{key}' is not supported without Swarm"
            for key in ("uid", "gid", "mode")
            if key in entry
        )
    problems.extend(f"secret {name}: required" for name in sorted(REQUIRED_SECRETS - names))
    for name, definition in config.get("secrets", {}).items():
        if set(definition) - {"name", "file"} or "file" not in definition:
            problems.append(f"secret {name}: must come from a file, and nothing else")
    return problems


def _environment_problems(relay: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for name in relay.get("environment", {}):
        if SECRET_NAME.search(name):
            problems.append(f"environment {name}: secrets must be files, not variables")
        elif name not in ENVIRONMENT:
            problems.append(f"environment {name}: not an expected variable")
    return problems


def _service_problems(relay: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    expected = {
        "user": USER,
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "ipc": "private",
    }
    for key, value in expected.items():
        if relay.get(key) != value:
            problems.append(f"{key}: must be {value!r}, found {relay.get(key)!r}")
    problems.extend(
        f"{key}: must not be set"
        for key in FORBIDDEN_KEYS
        if key in relay and relay[key] not in (False, None, [], {})
    )
    options = relay.get("logging", {}).get("options", {})
    if not {"max-size", "max-file"} <= set(options):
        problems.append("logging: max-size and max-file must be set")
    problems.extend(
        f"{key}: must be set" for key in ("mem_limit", "pids_limit") if not relay.get(key)
    )
    return problems


def problems_in(config: dict[str, Any]) -> list[str]:
    """Every way ``config`` (rendered Compose JSON) departs from the hardened example."""
    services = config.get("services", {})
    if set(services) != SERVICES:
        return [f"services: expected exactly {sorted(SERVICES)}, found {sorted(services)}"]
    relay = services["relay"]
    problems = _service_problems(relay)
    problems.extend(_mount_problems(relay.get("volumes", [])))
    problems.extend(_secret_problems(relay, config))
    problems.extend(_environment_problems(relay))
    volume = config.get("volumes", {}).get(STATE_VOLUME, {})
    if (
        volume.get("driver", "local") != "local"
        or volume.get("driver_opts")
        or volume.get("external")
    ):
        problems.append("volumes.state: must be a plain local volume")
    return problems


def main() -> None:
    problems = problems_in(json.load(sys.stdin))
    if problems:
        raise SystemExit(
            "Compose hardening check failed:\n" + "\n".join(f"  - {p}" for p in problems)
        )
    sys.stdout.write("Compose hardening check passed\n")


if __name__ == "__main__":
    main()
