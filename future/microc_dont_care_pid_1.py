import ctypes.util
import os
import socket
import sys
import subprocess

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def setuid(uid, host_uid, size=1):
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"{uid} {host_uid} {size}\n")
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny\n")


def setgid(gid, host_gid, size=1):
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"{gid} {host_gid} {size}\n")


def mount(source, target, fs_type, flags=0, data=""):
    source  = source.encode()
    target = target.encode()
    fs_type = fs_type.encode()
    data = data.encode()
    if libc.mount(source, target, fs_type, flags, data) != 0:
        errno = ctypes.get_errno()
        raise OSError(
            errno, f"Failed to mount {source} to {target}: {os.strerror(errno)}"
        )


def child():
    print("child!")
    os.chroot("./root")
    os.chdir("/")
#    mount("proc", "proc", "proc")
    _, _, *args = sys.argv
    os.execvp(args[0], args)
    #subprocess.run(args, check=True)


def run():
    host_uid = os.getuid()
    host_gid = os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWPID | os.CLONE_NEWNS | os.CLONE_NEWUTS)
    setuid(0, host_uid)
    setgid(0, host_gid)
    socket.sethostname("bla")
    args = [sys.executable, "microc2.py", "child"] + sys.argv[2:]
    print("exec", args)
    os.execvp(args[0], args)


command = sys.argv[1]
if command == "run":
    run()
elif command == "child":
    child()
else:
    print(f"Unknown command: {command!r}!")
