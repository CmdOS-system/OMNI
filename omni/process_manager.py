"""Track only processes launched by OMNI's Windows native adapter.

This module is not a sandbox. A forced stop only targets the direct process;
children may survive. It never enumerates or terminates arbitrary host PIDs.
"""
from dataclasses import dataclass


@dataclass
class _Session:
    session_id: int
    name: str
    process: object
    stop_requested: bool = False


class NativeProcessManager:
    """In-memory native process registry with explicit stop authorization."""

    def __init__(self, max_history=100):
        if max_history < 1:
            raise ValueError("max_history must be positive")
        self._sessions = []
        self._next_id = 1
        self._max_history = max_history

    def register(self, name, process):
        if not isinstance(name, str) or not name or not hasattr(process, "pid"):
            raise ValueError("Invalid process registration")
        session = _Session(self._next_id, name, process)
        self._next_id += 1
        self._sessions.append(session)
        self._trim_finished()
        return session.session_id

    def _trim_finished(self):
        # Never discard active processes, even if there are many of them.
        while len(self._sessions) > self._max_history:
            finished_index = next((i for i, s in enumerate(self._sessions)
                                   if s.process.poll() is not None), None)
            if finished_index is None:
                break
            del self._sessions[finished_index]

    def snapshot(self):
        self._trim_finished()
        rows = []
        for session in self._sessions:
            code = session.process.poll()
            rows.append({
                "id": session.session_id,
                "name": session.name,
                "pid": session.process.pid,
                "status": ("exited" if code is not None else
                           "stop_requested" if session.stop_requested else "running"),
                "exit_code": code,
            })
        return rows

    def stop(self, session_id, *, confirmed=False):
        """Force-terminate the direct child after affirmative UI confirmation."""
        if not confirmed:
            raise PermissionError("Explicit confirmation is required to stop an app")
        session = next((s for s in self._sessions if s.session_id == session_id), None)
        if session is None:
            raise KeyError("This OMNI session no longer exists")
        if session.process.poll() is not None:
            return False
        try:
            session.process.terminate()
        except ProcessLookupError:
            # Process may have exited between poll() and terminate().
            return False
        session.stop_requested = True
        return True
