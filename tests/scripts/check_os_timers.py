#!/usr/bin/env python3
"""Validate real RT700 OS task sleep/wake evidence from a retained console."""
import re
import sys
from pathlib import Path


def validate(text):
    for guest, os_name in (("guest0", "Zephyr"), ("guest1", "FreeRTOS")):
        prefix = guest + ": " + os_name
        if prefix + " kernel running" not in text:
            raise ValueError(prefix + " kernel marker missing")
        for task in ("A", "B"):
            matches = list(re.finditer(re.escape(prefix) + r" timer " + task +
                                       r" wake=(\d+) elapsed_ms=(\d+)", text))
            records = [match.groups() for match in matches]
            if [int(n) for n, _ in records] != list(range(1, 11)):
                raise ValueError(prefix + " task " + task +
                                 " requires ten ordered sleep/wake records")
            if any(not 100 <= int(ms) <= 30000 for _, ms in records):
                raise ValueError(prefix + " sleep duration outside bound")
            if sum(int(ms) for _, ms in records) > 30000:
                raise ValueError(prefix + " task duration outside bound")
            peer = "guest1" if guest == "guest0" else "guest0"
            peer_crypto = peer + ": wolfTrust FF-M mediated crypto dispatch verified"
            if peer_crypto not in text[matches[0].end():matches[-1].start()]:
                raise ValueError(prefix + " task " + task +
                                 " requires crypto progress from the peer")
        if prefix + " timers done errors=0" not in text:
            raise ValueError(prefix + " completion missing or timer error")
        crypto = guest + ": wolfTrust FF-M mediated crypto dispatch verified"
        if text.count(crypto) < 11:
            raise ValueError(prefix + " repeated mediated crypto missing")

    start = text.find("guest1: FreeRTOS critical start")
    end = text.find("guest1: FreeRTOS critical end errors=0", start)
    if start < 0 or end < 0 or "guest0:" not in text[start:end]:
        raise ValueError("FreeRTOS critical section requires live peer and retained BASEPRI")


def main():
    try:
        validate(Path(sys.argv[1]).read_text())
    except (ValueError, OSError, IndexError) as error:
        print("FAIL: RT700 OS timers: " + str(error), file=sys.stderr)
        return 1
    print("PASS: RT700 Zephyr and FreeRTOS task sleeps and peer crypto")
    return 0


if __name__ == "__main__":
    sys.exit(main())
