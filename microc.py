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

import os
import subprocess
import time
import ctypes.util
c = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
mount = c.mount
mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
mount.restype = ctypes.c_int

class out:
    def __init__(self, message):
        self.message = f"{message:.<50}"

    def __enter__(self):
        print(self.message, end="", flush=True)
        self.start = time.perf_counter()

    def __exit__(self, exc_type, exc_value, tb):
        dt_ms = (time.perf_counter() - self.start) * 1_000_000
        if exc_value is None:
            print(f"[DONE] (took {dt_ms:.1f}us)")
        else:
            print(f"[ERROR] (took {dt_ms:.1f}us) {exc_value!r}")


def mount_filesystem(source, target, fs_type, flags=0, data=None):
    source_b = source.encode()
    target_b = target.encode()
    fs_type_b = fs_type.encode()
    data_b = data.encode() if data else None

    result = mount(source_b, target_b, fs_type_b, flags, data_b)
    if result == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to mount {source} to {target}: {os.strerror(errno)}")
    else:
        print(f"Mounted {source} to {target} successfully")


def setuid(uid, host_uid, size=1):
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"{uid} {host_uid} {size}\n")
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny\n")

def setgid(gid, host_gid, size=1):
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"{gid} {host_gid} {size}\n")


def child(command):
    import socket

    host_uid = os.getuid()
    host_gid = os.getgid()

    with out("preparing namespaces"):
        os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWPID | os.CLONE_NEWNS | os.CLONE_NEWUTS)
    with out("preparing user"):
        setuid(0, host_uid)
        setgid(0, host_gid)
    with out("setting hostname"):
        socket.sethostname("bla")
    with out("changing root"):
        os.chroot("./root")
        os.chdir("/")
    try:
         with out("mounting proc"):
            mount_filesystem("proc", "proc", "proc")
    except Exception:
        pass
    print("running... ")
    subprocess.run(command, check=True)
    exit(0)


def run_command_in_namespace(command):
    """Run a command in a new namespace."""
    # Fork a new process to isolate namespaces
    if pid := os.fork():
        _, status = os.waitpid(pid, 0)
        if status != 0:
            raise RuntimeError(f"Command failed with exit code: {status}")
    else:
        child(command)


run_command_in_namespace(["bash"])
