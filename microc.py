"""
Prepare a docker image for chroot:

```shell
docker create --name temp python:3.13-slim
docker export temp > image.tar
mkdir root
tar -xvf image.tar -C root/
rm image.tar
```

"""

import ctypes.util
import os
import socket
import sys
import time

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def _init():
    mount = libc.mount
    mount.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    mount.restype = ctypes.c_int


class out:
    def __init__(self, message):
        self.message = f"{message:.<50}"

    @classmethod
    def print(cls, *args, flush=True, file=sys.stderr, **kwargs):
        print(*args, flush=flush, file=file, **kwargs)

    @classmethod
    def pprint(cls, *args, **kwargs):
        pid, uid = os.getpid(), os.getuid()
        cls.print(f"{pid:>6} {uid:>6}", *args, **kwargs)

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


def setuid(uid, host_uid, size=1):
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"{uid} {host_uid} {size}\n")
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny\n")


def setgid(gid, host_gid, size=1):
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"{gid} {host_gid} {size}\n")


def child(host_uid, host_gid):
    with out("[c] preparing user"):
        setuid(0, host_uid)
        setgid(0, host_gid)
    with out("[c] setting hostname"):
        socket.sethostname("bla")
    with out("[c] changing root"):
        os.chroot("./root")
        os.chdir("/")
    with out("[c] mounting proc"):
        mount("proc", "proc", "proc")
    args = sys.argv[1:]
    out.pprint("[c] running", args)
    # subprocess.run(args, check=True)
    os.execvp(args[0], args)
    exit(0)


def run():
    """Run a command in a new namespace."""
    host_uid = os.getuid()
    host_gid = os.getgid()
    with out("[p] preparing namespaces"):
        os.unshare(
            os.CLONE_NEWUSER | os.CLONE_NEWPID | os.CLONE_NEWNS | os.CLONE_NEWUTS
        )
    out.pprint(f"{'[p] forking and waiting for child':.<50}[WAIT]")
    if pid := os.fork():
        _, status = os.waitpid(pid, 0)
        if status != 0:
            raise RuntimeError(f"Command failed with exit code: {status}")
    else:
        child(host_uid, host_gid)


run()
