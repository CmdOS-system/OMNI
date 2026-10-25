"""Bounded in-memory stderr capture for OMNI-launched WSL processes.

Drains stderr asynchronously so a chatty guest cannot deadlock on a full pipe.
Only the most recent bytes are kept; output is never written to disk.
This is diagnostic information, not a sandbox or security log.
"""
import re
import threading


class StderrCapture:
    def __init__(self, stream, max_bytes=8192):
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self._stream = stream
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        self._tail = b""
        self._truncated = False
        self._complete = False
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self):
        try:
            while True:
                chunk = self._stream.read(4096)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                with self._lock:
                    combined = self._tail + chunk
                    if len(combined) > self._max_bytes:
                        self._truncated = True
                    self._tail = combined[-self._max_bytes:]
        finally:
            try:
                self._stream.close()
            finally:
                with self._lock:
                    self._complete = True

    def snapshot(self):
        with self._lock:
            tail, truncated, complete = self._tail, self._truncated, self._complete
        text = tail.decode("utf-8", errors="replace")
        text = re.sub(r"[\\x00-\\x08\\x0b-\\x1f\\x7f]", "�", text)
        return {"stderr_tail": text, "stderr_truncated": truncated,
                "stderr_complete": complete}

    def wait(self, timeout=None):
        """Wait for stderr EOF; intended for tests and completed processes."""
        self._thread.join(timeout)
        return not self._thread.is_alive()
