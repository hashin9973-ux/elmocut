"""Regression checks for the CLI-triggered existing ping-scan action."""
import ast
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gui.main import ElmoCut


class ScanHardRoutingTests(unittest.TestCase):
    def test_scan_hard_dispatches_to_ping_scan_type(self):
        fake = SimpleNamespace()
        calls = []

        def starter(**kwargs):
            calls.append(kwargs)
            return True

        fake.ScanThread_Starter = starter

        result = ElmoCut.scanHard(fake, silent=True, force=True)

        self.assertTrue(result)
        self.assertEqual(
            calls,
            [{"scan_type": 1, "silent": True, "force": True}],
        )

    def test_startup_does_not_call_resize_event_without_qt_event(self):
        source = (ROOT / "src" / "elmocut.py").read_text(encoding="utf-8")
        self.assertNotIn("GUI.resizeEvent()", source)
        self.assertIn("GUI.resizeTableColumns()", source)

    def test_socket_cleanup_supports_local_and_tcp_socket_api_names(self):
        source = (ROOT / "src" / "elmocut.py").read_text(encoding="utf-8")
        self.assertIn(
            'if hasattr(connection, "disconnectFromServer"):',
            source,
        )
        self.assertIn(
            'elif hasattr(connection, "disconnectFromHost"):',
            source,
        )

    def test_cli_ping_queues_scan_hard_for_existing_instance(self):
        source = (ROOT / "src" / "elmocut.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "GUI"
            and node.func.attr == "scanHard"
        ]
        self.assertGreaterEqual(len(calls), 2)
        self.assertTrue(any(
            any(k.arg == "force" and isinstance(k.value, ast.Constant) and k.value.value is True
                for k in call.keywords)
            for call in calls
        ))


if __name__ == "__main__":
    unittest.main()
