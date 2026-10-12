"""Check that the Compose example keeps its hardening (requirement R29).

Reads ``docker compose config --format json`` for the example as shipped, on
standard input, and applies two layers:

1. **Golden comparison.** The rendered document, normalised, must equal the
   checked-in expected file exactly. Any change to the example's settings,
   including ones no rule anticipates, fails until the expected file is
   updated in the same change, where reviewers see it. Normalisation replaces
   only what legitimately varies between machines: the image reference, the
   state volume's name, the project name, and absolute paths under the
   repository.
2. **Invariants.** Explicit checks of the critical properties, so a careless
   update of the expected file still fails on them.

Exits non-zero listing every difference and violation. ``--update`` rewrites
the expected file from the input instead (review the result before committing).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

USER = "65532:65532"
STATE_TARGET = "/var/lib/vrm-alert-relay"
SECRET_NAME = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL|AUTH", re.IGNORECASE)
SOCKET = re.compile(r"docker\.sock|podman\.sock|containerd\.sock", re.IGNORECASE)


def normalise(config: dict[str, Any], root: str) -> dict[str, Any]:
    """``config`` with only machine-specific values replaced by placeholders."""
    project = config.get("name")
    text = json.dumps(config)
    if root:
        # JSON-escape the root so it matches inside encoded strings.
        prefix = json.dumps(root.rstrip("/") + "/")[1:-1]
        text = text.replace(prefix, "./")
    data: dict[str, Any] = json.loads(text)
    data.pop("name", None)
    relay = data.get("services", {}).get("relay")
    if isinstance(relay, dict) and "image" in relay:
        relay["image"] = "<image>"
    state = data.get("volumes", {}).get("state")
    if isinstance(state, dict) and "name" in state:
        state["name"] = "<state-volume>"
    for section in ("networks", "secrets"):
        for entry in data.get(section, {}).values():
            name = entry.get("name") if isinstance(entry, dict) else None
            if isinstance(name, str) and project and name.startswith(f"{project}_"):
                entry["name"] = "<project>_" + name[len(project) + 1 :]
    return data


def differences(expected: object, actual: object, path: str = "") -> list[str]:
    """Readable differences between two JSON values, one line each."""
    where = path or "<root>"
    if isinstance(expected, dict) and isinstance(actual, dict):
        lines: list[str] = []
        for key in sorted(expected.keys() | actual.keys()):
            sub = f"{path}.{key}" if path else key
            if key not in actual:
                lines.append(f"{sub}: missing (expected {json.dumps(expected[key])})")
            elif key not in expected:
                lines.append(f"{sub}: unexpected (found {json.dumps(actual[key])})")
            else:
                lines.extend(differences(expected[key], actual[key], sub))
        return lines
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return [f"{where}: expected {len(expected)} item(s), found {len(actual)}"]
        lines = []
        for index, (left, right) in enumerate(zip(expected, actual, strict=True)):
            lines.extend(differences(left, right, f"{path}[{index}]"))
        return lines
    if expected != actual or type(expected) is not type(actual):
        return [f"{where}: expected {json.dumps(expected)}, found {json.dumps(actual)}"]
    return []


def _mount_violations(relay: dict[str, Any]) -> list[str]:
    writable = [m for m in relay.get("volumes", []) if m.get("read_only") is not True]
    state = [
        m
        for m in writable
        if (m.get("type"), m.get("source"), m.get("target")) == ("volume", "state", STATE_TARGET)
    ]
    if len(writable) != 1 or len(state) != 1:
        message = (
            f"invariant mounts: the only writable mount must be the state volume at "
            f"{STATE_TARGET} (found {len(writable)} writable)"
        )
        return [message]
    return []


def invariant_violations(config: dict[str, Any]) -> list[str]:
    """The critical properties, checked explicitly."""
    services = config.get("services", {})
    if set(services) != {"relay"}:
        return [f"invariant services: expected only 'relay', found {sorted(services)}"]
    relay = services["relay"]
    required = {
        "user": USER,
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
    }
    violations = [
        f"invariant {key}: must be {json.dumps(value)}"
        for key, value in required.items()
        if relay.get(key) != value
    ]
    violations.extend(
        f"invariant {key}: must not be set"
        for key in ("privileged", "use_api_socket", "ports", "cap_add", "network_mode", "pid")
        if relay.get(key) not in (None, False, [], {})
    )
    violations.extend(_mount_violations(relay))
    if SOCKET.search(json.dumps(config)):
        violations.append("invariant: no container engine socket may be mounted or referenced")
    violations.extend(
        f"invariant environment {name}: secrets must be files, not variables"
        for name in relay.get("environment", {})
        if SECRET_NAME.search(name)
    )
    return violations


def main() -> None:
    parser = argparse.ArgumentParser(description="Check the Compose example's hardening.")
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--root", default="", help="repository root, for relative paths")
    parser.add_argument("--update", action="store_true", help="rewrite the expected file")
    args = parser.parse_args()

    actual = normalise(json.load(sys.stdin), args.root)
    if args.update:
        args.expected.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
        sys.stdout.write(f"wrote {args.expected}\n")
        return
    expected = json.loads(args.expected.read_text())
    problems = [f"golden {line}" for line in differences(expected, actual)]
    problems.extend(invariant_violations(actual))
    if problems:
        details = "".join(f"  - {problem}\n" for problem in problems)
        sys.stderr.write(f"Compose hardening check failed:\n{details}")
        raise SystemExit(1)
    sys.stdout.write("Compose hardening check passed: golden match and invariants hold\n")


if __name__ == "__main__":
    main()
