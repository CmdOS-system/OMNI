import unittest
from unittest.mock import Mock
from omni.process_manager import NativeProcessManager


class NativeProcessManagerTests(unittest.TestCase):
    def fake_process(self, pid=42, exit_code=None):
        process = Mock(pid=pid)
        process.poll.return_value = exit_code
        return process

    def test_reject_invalid_process_handles_without_creating_sessions(self):
        manager = NativeProcessManager()
        invalid = [
            object(),
            Mock(pid=None),
            Mock(pid=0),
            Mock(pid=-1),
            Mock(pid=True),
            Mock(pid="123"),
        ]
        for process in invalid:
            with self.subTest(process=repr(process)):
                with self.assertRaises(ValueError):
                    manager.register("broken.exe", process)
        self.assertEqual(manager.snapshot(), [])
        self.assertEqual(manager.register("valid.exe", self.fake_process()), 1)

    def test_register_and_track_multiple_apps(self):
        manager = NativeProcessManager()
        a, b = self.fake_process(12), self.fake_process(13)
        first = manager.register("one.exe", a)
        second = manager.register("two.exe", b)
        self.assertNotEqual(first, second)
        self.assertEqual([row["pid"] for row in manager.snapshot()], [12, 13])
        a.poll.return_value = 0
        self.assertEqual(manager.snapshot()[0]["status"], "exited")
        self.assertEqual(manager.snapshot()[1]["status"], "running")

    def test_stop_requires_explicit_consent_and_targets_owned_child(self):
        manager = NativeProcessManager()
        proc = self.fake_process()
        session_id = manager.register("safe.exe", proc)
        with self.assertRaises(PermissionError):
            manager.stop(session_id)
        proc.terminate.assert_not_called()
        self.assertTrue(manager.stop(session_id, confirmed=True))
        proc.terminate.assert_called_once_with()
        self.assertEqual(manager.snapshot()[0]["status"], "stop_requested")

    def test_no_stop_after_exit_or_unknown_session(self):
        manager = NativeProcessManager()
        proc = self.fake_process(exit_code=5)
        session_id = manager.register("done.exe", proc)
        self.assertFalse(manager.stop(session_id, confirmed=True))
        proc.terminate.assert_not_called()
        with self.assertRaises(KeyError):
            manager.stop(999, confirmed=True)

    def test_exit_during_terminate_is_not_failure(self):
        manager = NativeProcessManager()
        proc = self.fake_process()
        proc.terminate.side_effect = ProcessLookupError()
        session_id = manager.register("race.exe", proc)
        self.assertFalse(manager.stop(session_id, confirmed=True))

    def test_history_limit_preserves_running_processes(self):
        manager = NativeProcessManager(max_history=2)
        a, b, c = self.fake_process(1), self.fake_process(2), self.fake_process(3)
        manager.register("one.exe", a)
        manager.register("two.exe", b)
        manager.register("three.exe", c)
        self.assertEqual(len(manager.snapshot()), 3)
        a.poll.return_value = 0
        self.assertEqual([row["pid"] for row in manager.snapshot()], [2, 3])


if __name__ == "__main__":
    unittest.main()
