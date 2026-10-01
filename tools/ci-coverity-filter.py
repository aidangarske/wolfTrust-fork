#!/usr/bin/env python3
"""Remove dependency translation units before a Coverity Scan upload."""

import re
import subprocess
from pathlib import Path


def filter_capture():
    root = Path.cwd().resolve()
    dependencies = {root / "lib"}
    index = subprocess.check_output(["git", "ls-files", "--stage", "-z"])
    for entry in index.split(b"\0"):
        if entry.startswith(b"160000 "):
            dependencies.add(root / entry.split(b"\t", 1)[1].decode())

    command = ["cov-manage-emit", "--dir", "cov-int"]

    def owned(source):
        path = Path(source).resolve()
        return root in path.parents and not any(
            dependency in path.parents for dependency in dependencies
        )

    def list_units():
        output = subprocess.check_output(command + ["list"], text=True)
        print(output, end="")
        units = []
        for line in output.splitlines():
            if "->" not in line:
                continue
            match = re.fullmatch(
                r"\s*([0-9]+)\s+->\s+(/.+?)(?: \(recoverable errors\))?", line
            )
            if match is None:
                raise ValueError("Unrecognized Coverity translation unit listing")
            units.append((match[1], match[2]))
        if not units:
            raise ValueError("Coverity capture is empty")
        return units

    units = list_units()
    excluded = [unit for unit, source in units if not owned(source)]
    if excluded:
        subprocess.run(command + ["--tu", ",".join(excluded), "delete"],
                       check=True)
    retained = list_units()
    if any(not owned(source) for _, source in retained):
        raise ValueError("Coverity capture still contains dependency sources")
    print(f"Coverity scope: excluded {len(excluded)} dependency units; "
          f"retained {len(retained)} wolfTrust units")


if __name__ == "__main__":
    try:
        filter_capture()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"::error::{error}") from error
