"""
Prepare a docker image for chroot:

```shell
docker create --name py313-slim python:3.13-slim
docker export py313-slim -o py313-slim.tar
docker rm py313-slim
mkdir root
tar -xvf py313-slim.tar -C root/
rm py313-slim.tar
```

fork bomb
:(){ :|:& };:
"""

import time

start = time.monotonic()

import ctypes.util
import enum
import os
import pathlib
import socket
import sys

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


# Mount tools ----------------------------------------------------------------

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


# Capabilities ---------------------------------------------------------------

# Capability version used by modern kernels
_LINUX_CAPABILITY_VERSION_3 = 0x20080522
_LINUX_CAPABILITY_U32S_3 = 2
CAP_SYS_ADMIN = 21


class CapUserHeader(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int),
    ]


class CapUserData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def capget(pid: int = 0):
    header = CapUserHeader(version=_LINUX_CAPABILITY_VERSION_3, pid=pid)
    data = (
        CapUserData * _LINUX_CAPABILITY_U32S_3
    )()  # two 32-bit words for 64-bit caps

    ret = libc.capget(ctypes.byref(header), ctypes.byref(data))
    if ret != 0:
        raise OSError(ctypes.get_errno(), "capget failed")
    return {
        "effective": data[0].effective | (data[1].effective << 32),
        "permitted": data[0].permitted | (data[1].permitted << 32),
        "inheritable": data[0].inheritable | (data[1].inheritable << 32),
    }


# Print tools ----------------------------------------------------------------

class out:
    prefix = '[parent]'

    def __init__(self, message):
        self.message = f"{message:.<50}"

    @classmethod
    def print(cls, *args, flush=True, file=sys.stderr, **kwargs):
        print(*args, flush=flush, file=file, **kwargs)

    @classmethod
    def pprint(cls, *args, **kwargs):
        ts = time.monotonic() - start
        pid, uid, gid = os.getpid(), os.getuid(), os.getgid()
        cls.print(f"{ts:10.6f} {pid:>7} {uid:>7}:{gid:<7} {cls.prefix} ", *args, **kwargs)

    def __enter__(self):
        self.pprint(self.message, end="")
        self.start = time.perf_counter()

    def __exit__(self, exc_type, exc_value, tb):
        dt_ms = (time.perf_counter() - self.start) * 1_000_000
        if exc_value is None:
            self.print(f"[DONE] (took {dt_ms:.1f}us)")
        else:
            self.print(f"[ ERR] (took {dt_ms:.1f}us) {exc_value!r}")


# Core -----------------------------------------------------------------------


def setuid(uid, host_uid, size=1):
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"{uid} {host_uid} {size}\n")
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny\n")


def setgid(gid, host_gid, size=1):
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"{gid} {host_gid} {size}\n")


def prepare(host_uid, host_gid, opts):
    with out(f"preparing user"):
        setuid(opts.user, host_uid)
        setgid(opts.group, host_gid)
    if host := opts.host:
        with out(f"setting hostname"):
            socket.sethostname(host)
    if root := opts.root:
        with out(f"changing root"):
            os.chroot(root)
    if pwd := opts.pwd:
        os.chdir(pwd)
    elif root:
        os.chdir("/")


def child(host_uid, host_gid, opts):
    args = opts.args
    prepare(host_uid, host_gid, opts)
    if opts.mount:
        with out("mounting /proc"):
            mount("proc", "/proc", "proc", 1 | 4 | 8) # 1 = READONLY; 4 = NODEV; 8 = NOEXEC
    out.pprint(
        "running",
    )
    # Hummm, I could use `os.execvp(args[0], args)` but then I cannot
    # cleanup :-(. But now the PID is going to be 2 instead of 1
    # subprocess.run(args, check=True)
    os.execvpe(args[0], args, {})


def run(opts):
    """Run a command in a new namespace."""
    print(" Timestamp     PID     UID:GID      Process Message")
    host_uid = os.getuid()
    host_gid = os.getgid()
    flags = os.CLONE_NEWUSER | os.CLONE_NEWPID | os.CLONE_NEWUTS
    if opts.mount:
        flags |= os.CLONE_NEWNS
    with out("preparing namespaces"):
        os.unshare(flags)
    out.pprint(f"{'forking and waiting for child':.<50}[WAIT]")
    if pid := os.fork():
        _, status, resources = os.wait4(pid, 0)
        exitcode = os.waitstatus_to_exitcode(status)
        if exitcode:
            msg = f"Command failed with exit code: {exitcode}"
        else:
            msg = "Child finished!"
        out.pprint(msg)
    else:
        out.prefix = "[ child]"
        child(host_uid, host_gid, opts)


def main(args=None):
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, default=None)
    parser.add_argument("--user", type=int, default=0)
    parser.add_argument("--group", type=int, default=0)
    parser.add_argument("--host", type=str, default=None)
    parser.add_argument("--pwd", type=str, default=None)
    parser.add_argument("--mount", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("args", nargs="+")
    opts = parser.parse_args(args=args)
    run(opts)


if __name__ == "__main__":
    main()
