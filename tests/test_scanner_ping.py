"""Regression tests for the existing Windows ping-scan worker.

The fake probe functions here are test doubles only; production still invokes
CMD_PING_DEVICE through tools.utils.terminal exactly as before.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Source modules live under src/ in this repository.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from networking.scanner import Scanner, CMD_PING_DEVICE


class PingScanWorkerTests(unittest.TestCase):
    def make_scanner(self):
        # Construct without interface discovery because these tests exercise
        # only completion/error coordination, not live network access.
        scanner = Scanner.__new__(Scanner)
        scanner._Scanner__ping_done = 0
        scanner.max_threads = 3
        scanner.ips = [
            "192.0.2.1",
            "192.0.2.2",
            "192.0.2.3",
        ]
        progress = []
        scanner.qt_progress_signal = progress.append
        scanner._test_progress = progress
        scanner.init = lambda: None
        scanner.generate_ips = lambda: None
        return scanner

    def test_failed_probe_does_not_leave_scan_waiting_forever(self):
        scanner = self.make_scanner()
        attempted = []

        def fake_probe(ip):
            attempted.append(ip)
            if ip.endswith(".2"):
                raise OSError("test-only simulated process-launch failure")

        scanner.ping = fake_probe

        self.assertTrue(scanner.ping_scan())
        self.assertCountEqual(attempted, scanner.ips)
        self.assertEqual(scanner._Scanner__ping_done, len(scanner.ips))
        self.assertEqual(scanner._test_progress, [1, 2, 3])

    def test_all_probe_process_launches_failing_is_reported(self):
        scanner = self.make_scanner()

        def fake_probe(_ip):
            raise OSError("test-only simulated process-launch failure")

        scanner.ping = fake_probe

        with self.assertRaisesRegex(RuntimeError, "All 3 ping commands failed"):
            scanner.ping_scan()
        self.assertEqual(scanner._Scanner__ping_done, len(scanner.ips))
        self.assertEqual(scanner._test_progress, [1, 2, 3])

    def test_existing_ping_command_string_is_unchanged(self):
        scanner = Scanner.__new__(Scanner)
        with patch("networking.scanner.terminal") as terminal:
            scanner.ping("192.0.2.9")
        terminal.assert_called_once_with(
            CMD_PING_DEVICE("192.0.2.9"),
            decode=False,
        )


if __name__ == "__main__":
    unittest.main()
