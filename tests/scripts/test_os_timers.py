#!/usr/bin/env python3
"""WT-FFM-0014/0055: reject incomplete or busy-delay OS timer reports."""
import unittest
from check_os_timers import validate


def report():
    lines = ["guest0: Zephyr kernel running", "guest1: FreeRTOS kernel running",
             "guest1: FreeRTOS critical start", "guest0: peer progress",
             "guest1: FreeRTOS critical end errors=0"]
    for n in range(1, 11):
        for guest, os_name in (("guest0", "Zephyr"), ("guest1", "FreeRTOS")):
            prefix = guest + ": " + os_name
            for task in ("A", "B"):
                lines.append(prefix + " timer " + task +
                             " wake=%d elapsed_ms=100" % n)
            lines.append(guest + ": wolfTrust FF-M mediated crypto dispatch verified")
    for guest, os_name in (("guest0", "Zephyr"), ("guest1", "FreeRTOS")):
        lines.append(guest + ": " + os_name + " timers done errors=0")
        lines.append(guest + ": wolfTrust FF-M mediated crypto dispatch verified")
    return "\n".join(lines)


class OSTimerReports(unittest.TestCase):
    def test_complete(self):
        validate(report())

    def test_zero_tick_busy_delay(self):
        with self.assertRaises(ValueError):
            validate(report().replace("elapsed_ms=100", "elapsed_ms=0"))

    def test_missing_second_task(self):
        with self.assertRaises(ValueError):
            validate(report().replace("timer B wake=10", "heartbeat"))

    def test_missing_crypto(self):
        with self.assertRaises(ValueError):
            validate(report().replace("mediated crypto dispatch verified", "idle"))

    def test_kernel_failure(self):
        with self.assertRaises(ValueError):
            validate(report().replace("FreeRTOS kernel running", "baremetal running"))

    def test_timer_error(self):
        with self.assertRaises(ValueError):
            validate(report().replace("errors=0", "errors=1"))


if __name__ == "__main__":
    unittest.main()
