"""Check the runtime image's contract from inside it.

Runs with the image's own Python, because the image has no shell:

    docker run --rm --entrypoint /opt/venv/bin/python IMAGE /smoke/check_runtime_image.py

Checks the standard-library modules the relay relies on, time zone data, the
relay user's passwd entry, the working directory, the dynamic linker cache,
and that no shell or package manager is present. Prints one line per check
and exits non-zero listing every failure.
"""

from __future__ import annotations

import importlib
import os
import pwd
import sys
import zoneinfo
from pathlib import Path

RELAY_UID = 65532
WORKDIR = "/home/nonroot"
MODULES = ("ssl", "sqlite3", "hashlib", "zoneinfo", "pwd")
ABSENT = ("/bin/sh", "/bin/ash", "/bin/bash", "/bin/busybox", "/sbin/apk", "/usr/bin/apk")
TIME_ZONE = "America/Denver"


def checks() -> tuple[list[str], list[str]]:
    """Return (passed, failed) check descriptions."""
    passed: list[str] = []
    failed: list[str] = []

    def record(ok: bool, description: str) -> None:  # noqa: FBT001  # local helper
        (passed if ok else failed).append(description)

    for name in MODULES:
        try:
            importlib.import_module(name)
        except ImportError as error:
            record(ok=False, description=f"import {name}: {error}")
        else:
            record(ok=True, description=f"import {name}")

    try:
        zone = zoneinfo.ZoneInfo(TIME_ZONE)
    except zoneinfo.ZoneInfoNotFoundError as error:
        record(ok=False, description=f"zoneinfo {TIME_ZONE}: {error}")
    else:
        record(ok=True, description=f"zoneinfo {zone.key} loads")

    try:
        entry = pwd.getpwuid(RELAY_UID)
    except KeyError:
        record(ok=False, description=f"pwd.getpwuid({RELAY_UID}): no entry")
    else:
        record(
            ok=entry.pw_dir == WORKDIR,
            description=f"pwd.getpwuid({RELAY_UID}): {entry.pw_name} home {entry.pw_dir}",
        )

    cwd = Path.cwd()
    record(ok=str(cwd) == WORKDIR, description=f"working directory {cwd}")
    record(ok=os.geteuid() == RELAY_UID, description=f"effective UID {os.geteuid()}")

    cache = Path("/etc/ld.so.cache")
    size = cache.stat().st_size if cache.is_file() else 0
    record(ok=size > 0, description=f"{cache} present, {size} bytes")

    for path in ABSENT:
        record(ok=not os.path.lexists(path), description=f"{path} absent")

    record(
        ok=sys.version_info[:2] == (3, 13),
        description=f"Python {sys.version.split()[0]}",
    )
    return passed, failed


def main() -> None:
    passed, failed = checks()
    for line in passed:
        sys.stdout.write(f"ok: {line}\n")
    if failed:
        sys.stderr.write("".join(f"FAILED: {line}\n" for line in failed))
        raise SystemExit(1)
    sys.stdout.write(f"Runtime image checks passed: {len(passed)}\n")


if __name__ == "__main__":
    main()
