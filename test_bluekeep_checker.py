"""Regression tests for the davidfortytwo/bluekeep remediation.

DEFECT: bluekeep-checker.py used a bare `except:` which caught
KeyboardInterrupt and SystemExit, and reported an unreachable host with the
same message as a genuine negative ("not up or not vulnerable"). A scanner
cannot tell "host did not answer" from "host is patched".

Run with:  python test_bluekeep_checker.py
"""
import importlib.util
import os
import socket
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "bluekeep-checker.py")


def load_module():
    spec = importlib.util.spec_from_file_location("bluekeep_under_test", TARGET)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestBareExceptRemoved(unittest.TestCase):
    """DEFECT: bare `except:` at bluekeep-checker.py:20."""

    def test_no_bare_except_in_source(self):
        import ast
        with open(TARGET, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), TARGET)
        bare = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    bare.append(node.lineno)
        self.assertEqual(bare, [],
                         "bare except: at line(s) {} catches KeyboardInterrupt/SystemExit".format(bare))

    def test_no_bare_except_textual(self):
        with open(TARGET, encoding="utf-8") as fh:
            src = fh.read()
        for line in src.splitlines():
            self.assertNotEqual(line.strip(), "except:",
                                "bare except: found: {!r}".format(line))


class TestDistinctUnreachableOutcome(unittest.TestCase):
    """DEFECT: unreachable host reported identically to a real negative."""

    def setUp(self):
        self.mod = load_module()

    def test_unreachable_is_distinct_from_patched(self):
        # Force a connection timeout.
        def raise_timeout(*a, **kw):
            raise socket.timeout("timed out")

        real_socket = self.mod.socket.socket
        real_connect = socket.socket.connect
        socket.socket.connect = raise_timeout
        try:
            status, message = self.mod.check_bluekeep_vuln("192.0.2.1")
        finally:
            socket.socket.connect = real_connect
            socket.socket = real_socket

        self.assertEqual(status, self.mod.UNREACHABLE)
        self.assertNotEqual(status, self.mod.PATCHED)
        self.assertIn("UNREACHABLE", message)
        self.assertIn("unknown", message.lower())

    def test_connection_refused_is_unreachable_not_patched(self):
        def raise_refused(*a, **kw):
            raise ConnectionRefusedError(111, "Connection refused")

        real_connect = socket.socket.connect
        socket.socket.connect = raise_refused
        try:
            status, message = self.mod.check_bluekeep_vuln("192.0.2.1")
        finally:
            socket.socket.connect = real_connect

        self.assertEqual(status, self.mod.UNREACHABLE)

    def test_unreachable_message_is_not_the_old_conflated_one(self):
        with open(TARGET, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("is either not up or not vulnerable", src)

    def test_vulnerable_and_patched_statuses_exist(self):
        for name in ("VULNERABLE", "PATCHED", "UNREACHABLE", "ERROR"):
            self.assertTrue(hasattr(self.mod, name), "missing status constant " + name)


class TestKeyboardInterruptPropagates(unittest.TestCase):
    """A bare except: swallowed Ctrl-C; a typed catch must not."""

    def test_keyboard_interrupt_is_not_swallowed(self):
        mod = load_module()

        def raise_kbd(*a, **kw):
            raise KeyboardInterrupt()

        real_connect = socket.socket.connect
        socket.socket.connect = raise_kbd
        try:
            with self.assertRaises(KeyboardInterrupt):
                mod.check_bluekeep_vuln("192.0.2.1")
        finally:
            socket.socket.connect = real_connect


class TestVulnerablePathStillDetected(unittest.TestCase):
    """The fix must not break the actual detection."""

    def test_vulnerable_detection(self):
        mod = load_module()
        real_socket = socket.socket
        real_connect = socket.socket.connect
        real_send = socket.socket.send
        real_recv = socket.socket.recv

        socket.socket.connect = lambda *a, **kw: None
        socket.socket.send = lambda *a, **kw: 0
        socket.socket.recv = lambda *a, **kw: b"\x03\x00\x00\x0c\x00\x00"
        try:
            status, message = mod.check_bluekeep_vuln("192.0.2.1")
        finally:
            socket.socket.connect = real_connect
            socket.socket.send = real_send
            socket.socket.recv = real_recv
            socket.socket = real_socket

        self.assertEqual(status, mod.VULNERABLE)
        self.assertIn("VULNERABLE", message)

    def test_patched_detection(self):
        mod = load_module()
        real_connect = socket.socket.connect
        real_send = socket.socket.send
        real_recv = socket.socket.recv

        socket.socket.connect = lambda *a, **kw: None
        socket.socket.send = lambda *a, **kw: 0
        socket.socket.recv = lambda *a, **kw: b"\x03\x00\x00\x0d\x00\x00"
        try:
            status, message = mod.check_bluekeep_vuln("192.0.2.1")
        finally:
            socket.socket.connect = real_connect
            socket.socket.send = real_send
            socket.socket.recv = real_recv

        self.assertEqual(status, mod.PATCHED)


class TestReadmeCorrected(unittest.TestCase):
    """DEFECT: repo description claimed "Checker and exploit"; no exploit exists."""

    def test_readme_does_not_claim_an_exploit(self):
        readme = os.path.join(HERE, "README.md")
        with open(readme, encoding="utf-8") as fh:
            src = fh.read()
        low = src.lower()
        # It may mention that there is NO exploit, but must not claim one.
        self.assertIn("checker only", low)
        self.assertIn("no exploit", low)

    def test_readme_documents_unreachable(self):
        readme = os.path.join(HERE, "README.md")
        with open(readme, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("unreachable", src.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)