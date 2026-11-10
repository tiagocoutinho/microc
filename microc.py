import time

start = time.monotonic()

import ctypes.util
import os
import pathlib
import socket
import sys

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


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


class out:
    prefix = "[parent]"

    def __init__(self, message):
        self.message = f"{message:.<50}"

    @classmethod
    def print(cls, *args, flush=True, file=sys.stderr, **kwargs):
        print(*args, flush=flush, file=file, **kwargs)

    @classmethod
    def pprint(cls, *args, **kwargs):
        ts = time.monotonic() - start
        pid, uid, gid = os.getpid(), os.getuid(), os.getgid()
        cls.print(
            f"{ts:10.6f} {pid:>7} {uid:>7}:{gid:<7} {cls.prefix} ", *args, **kwargs
        )

    def __enter__(self):
        self.pprint(self.message, end="")
        self.start = time.perf_counter()

    def __exit__(self, exc_type, exc_value, tb):
        dt_ms = (time.perf_counter() - self.start) * 1_000_000
        if exc_value is None:
            self.print(f"[DONE] (took {dt_ms:.1f}us)")
        else:
            self.print(f"[ ERR] (took {dt_ms:.1f}us) {exc_value}")


def setuid(uid, host_uid, size=1):
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"{uid} {host_uid} {size}\n")
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny\n")


def setgid(gid, host_gid, size=1):
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"{gid} {host_gid} {size}\n")


def prepare(host_uid, host_gid, config):
    with out(f"preparing user"):
        if (uid := config["user"]) is not None:
            setuid(uid, host_uid)
        if (gid := config["group"]) is not None:
            setgid(gid, host_gid)
    if host := config["host"]:
        with out(f"setting hostname to {host}"):
            socket.sethostname(host)
    if root := config["root"]:
        with out(f"changing root"):
            os.chroot(root)
    if pwd := config["pwd"]:
        os.chdir(pwd)
    elif root:
        os.chdir("/")


def child(host_uid, host_gid, config):
    command = config["command"]
    prepare(host_uid, host_gid, config)
    if config["mount"]:
        with out("mounting /proc"):
            mount(
                "proc", "/proc", "proc", 1 | 4 | 8
            )  # 1 = READONLY; 4 = NODEV; 8 = NOEXEC
    out.pprint(f"running {' '.join(command)!r}")
    if config["envmode"] == "replace":
        env = config["env"]
    else:
        env = os.environ | config["env"]
    os.execvpe(command[0], command, env)


def run(config):
    """Run a command in a new namespace."""
    print(" Timestamp     PID     UID:GID      Process Message")
    host_uid = os.getuid()
    host_gid = os.getgid()
    flags = os.CLONE_NEWUTS | os.CLONE_NEWUSER
    if config["user"] is None:
        config["user"] = host_gid
    if config["group"] is None:
        config["group"] = host_gid
    if config["mount"]:
        flags |= os.CLONE_NEWNS
    if config["pid1"]:
        flags |= os.CLONE_NEWPID
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
        try:
            child(host_uid, host_gid, config)
        except Exception as error:
            out.pprint(f"failed to run: {error}")
            sys.exit(1)


def main(args=None):
    import argparse

    Bool = argparse.BooleanOptionalAction
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, default=None)
    parser.add_argument("--user", type=int, default=None)
    parser.add_argument("--group", type=int, default=None)
    parser.add_argument("--host", type=str, default=None)
    parser.add_argument("--pwd", type=str, default=None)
    parser.add_argument("--mount", action=Bool, default=True)
    parser.add_argument("--pid1", action=Bool, default=True)
    parser.add_argument("--config", type=str, default=None)
    parser.add_argument("--envmode", choices=["append", "replace"], default="replace")
    parser.add_argument("command", nargs="+")
    opts = parser.parse_args(args=args)
    config = vars(opts)
    config.setdefault("env", {})
    if fname := config.pop("config"):
        import tomllib

        with open(fname, "rb") as f:
            config |= tomllib.load(f)
    if config["mount"] and not config["pid1"]:
        parser.error("mount needs pid1")
    run(config)


if __name__ == "__main__":
    main()
