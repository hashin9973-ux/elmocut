"""Tests for the socket-independent CLI command mailbox."""
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tools.command_mailbox import send_mailbox_command, service_mailbox


class CommandMailboxTests(unittest.TestCase):
    def test_command_is_delivered_and_acknowledged(self):
        with tempfile.TemporaryDirectory() as directory:
            observed = []
            stop = threading.Event()

            def handle(command):
                observed.append(command)
                return True

            def poll():
                while not stop.is_set():
                    service_mailbox(handle, directory=directory)
                    stop.wait(0.01)

            worker = threading.Thread(target=poll, daemon=True)
            worker.start()
            try:
                self.assertTrue(
                    send_mailbox_command("PING", timeout=2.0, directory=directory)
                )
            finally:
                stop.set()
                worker.join(timeout=1.0)

            self.assertEqual(observed, ["PING"])

    def test_rejected_command_is_not_acknowledged_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            stop = threading.Event()

            def poll():
                while not stop.is_set():
                    service_mailbox(lambda _command: False, directory=directory)
                    stop.wait(0.01)

            worker = threading.Thread(target=poll, daemon=True)
            worker.start()
            try:
                self.assertFalse(
                    send_mailbox_command("BACKGROUND", timeout=2.0, directory=directory)
                )
            finally:
                stop.set()
                worker.join(timeout=1.0)

    def test_unknown_command_is_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Unsupported mailbox command"):
                send_mailbox_command("RUN_ARBITRARY_COMMAND", directory=directory)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_timeout_returns_false_and_cleans_request(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(
                send_mailbox_command("PING", timeout=0.05, directory=directory)
            )
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
