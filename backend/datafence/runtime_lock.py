"""OS-held single-process ownership; also used by offline consistent backups."""

import os
from pathlib import Path


class RuntimeLock:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.handle = (directory / ".runtime.lock").open("a+b")
        try:
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt
                if self.handle.read(1) == b"":
                    self.handle.write(b"0")
                    self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise RuntimeError("数据目录已被服务或维护任务占用；禁止多个进程同时使用") from None

    def close(self):
        if not self.handle.closed:
            self.handle.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
