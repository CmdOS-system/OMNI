"""Real local pipe-draining tests; no WSL installation required."""
import io
import subprocess
import sys
import unittest
from unittest.mock import Mock

from omni.diagnostics import StderrCapture
from omni.process_manager import NativeProcessManager


class StderrCaptureTests(unittest.TestCase):
    def test_bounded_capture_drains_real_process_without_deadlock(self):
        process = subprocess.Popen(
            [sys.executable, "-c",
             "import sys; sys.stderr.buffer.write(b'x'*20000+b'END_MARKER'); sys.stderr.flush()"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        capture = StderrCapture(process.stderr, max_bytes=128)
        self.assertEqual(process.wait(timeout=10), 0)
        self.assertTrue(capture.wait(5))
        state = capture.snapshot()
        self.assertTrue(state["stderr_complete"])
        self.assertTrue(state["stderr_truncated"])
        self.assertLessEqual(len(state["stderr_tail"].encode("utf-8")), 128)
        self.assertTrue(state["stderr_tail"].endswith("END_MARKER"))

    def test_clean_text_and_empty_stderr(self):
        capture = StderrCapture(io.BytesIO(b"error\x00line\n"))
        self.assertTrue(capture.wait(5))
        self.assertEqual(capture.snapshot()["stderr_tail"], "error�line\n")
        empty = StderrCapture(io.BytesIO(b""))
        self.assertTrue(empty.wait(5))
        self.assertEqual(empty.snapshot()["stderr_tail"], "")
        self.assertFalse(empty.snapshot()["stderr_truncated"])

    def test_process_manager_exposes_only_owned_session_diagnostics(self):
        process = Mock(pid=123)
        process.poll.return_value = 7
        process.omni_stderr_capture = StderrCapture(io.BytesIO(b"Permission denied\n"))
        self.assertTrue(process.omni_stderr_capture.wait(5))
        manager = NativeProcessManager()
        manager.register("hello [WSL2]", process)
        row = manager.snapshot()[0]
        self.assertEqual(row["exit_code"], 7)
        self.assertEqual(row["diagnostics"]["stderr_tail"], "Permission denied\n")
        plain = Mock(pid=456)
        plain.poll.return_value = 0
        manager.register("native.exe", plain)
        self.assertNotIn("diagnostics", manager.snapshot()[1])

    def test_invalid_limit_rejected(self):
        with self.assertRaises(ValueError):
            StderrCapture(io.BytesIO(b""), max_bytes=0)


if __name__ == "__main__":
    unittest.main()
