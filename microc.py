"""
Prepare a docker image for chroot:

```shell
docker create --name temp python:3.13-slim
docker export temp > image.tar
mkdir root
tar -xvf image.tar -C root/
rm image.tar
```

fork bomb
:(){ :|:& };:
"""

import contextlib
import ctypes.util
import os
import socket
import subprocess
import sys
import time

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


class out:
    def __init__(self, message):
        self.message = f"{message:.<50}"

    @classmethod
    def print(cls, *args, flush=True, file=sys.stderr, **kwargs):
        print(*args, flush=flush, file=file, **kwargs)

    @classmethod
    def pprint(cls, *args, **kwargs):
        pid, uid = os.getpid(), os.getuid()
        cls.print(f"{pid:>7} {uid:>7}", *args, **kwargs)

    def __enter__(self):
        self.pprint(self.message, end="")
        self.start = time.perf_counter()

    def __exit__(self, exc_type, exc_value, tb):
        dt_ms = (time.perf_counter() - self.start) * 1_000_000
        if exc_value is None:
            self.print(f"[DONE] (took {dt_ms:.1f}us)")
        else:
            self.print(f"[ ERR] (took {dt_ms:.1f}us) {exc_value!r}")


def mount(source, target, fs_type, flags=0, data=""):
    if (
        libc.mount(
            source.encode(), target.encode(), fs_type.encode(), flags, data.encode()
        )
        == -1
    ):
        errno = ctypes.get_errno()
        raise OSError(
            errno, f"Failed to mount {source} to {target}: {os.strerror(errno)}"
        )


def umount(target):
    if libc.umount2(target.encode(), 0) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to unmount {target}: {os.strerror(errno)}")


@contextlib.contextmanager
def mnt(source, target, fs_type, flags=0, data=""):
    mount(source, target, fs_type, flags=0, data="")
    try:
        yield
    finally:
        umount(target)


def setuid(uid, host_uid, size=1):
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"{uid} {host_uid} {size}\n")
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny\n")


def setgid(gid, host_gid, size=1):
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"{gid} {host_gid} {size}\n")


def prepare(were, host_uid, host_gid):
    with out(f"[{were}] preparing user"):
        setuid(0, host_uid)
        setgid(0, host_gid)
    with out(f"[{were}] setting hostname"):
        socket.sethostname("bla")
    with out(f"[{were}] changing root"):
        os.chroot("./root")
        os.chdir("/")


def child(host_uid, host_gid):
    args = sys.argv[1:]
    prepare(" child", host_uid, host_gid)
    with mnt("proc", "proc", "proc"):
        out.pprint("[ child] running", args)
        # Hummm, I could use `os.execvp(args[0], args)` but then I cannot
        # cleanup :-(. But now the PID is going to be 2 instead of 1
        subprocess.run(args, check=True)
    exit(0)


def run():
    """Run a command in a new namespace."""
    print("    PID     UID  process Message")
    host_uid = os.getuid()
    host_gid = os.getgid()
    with out("[parent] preparing namespaces"):
        os.unshare(
            os.CLONE_NEWUSER | os.CLONE_NEWPID | os.CLONE_NEWNS | os.CLONE_NEWUTS
        )
    #prepare("parent", host_uid, host_gid)
    out.pprint(f"{'[parent] forking and waiting for child':.<50}[WAIT]")
    if pid := os.fork():
        _, status = os.waitpid(pid, 0)
        if status != 0:
            raise RuntimeError(f"Command failed with exit code: {status}")

    else:
        child(host_uid, host_gid)


run()
