#!/usr/bin/env python3
"""
isolate.py – Lightweight process isolator using Linux namespaces + cgroups
(similar in spirit to a minimal Docker / bubblewrap / unshare wrapper).

Process model (asyncio):
  - Parent uses asyncio.create_subprocess_exec
  - Namespace / rootfs / user / cgroup setup runs in preexec_fn (child side)
  - PID namespace still needs an internal fork after unshare(CLONE_NEWPID)
    because only a *child* of the unsharing process becomes PID 1

Isolates:
  - PID          (new process tree, child becomes PID 1)
  - User / Group (user namespace + UID/GID mapping)
  - Network      (none | host | bridge with veth + IP)
  - Filesystem   (mount namespace + optional chroot / rootfs)
  - Hostname     (UTS namespace)
  - Resources    (cgroup v2 memory + CPU limits)

--no-special-pid1 keeps a PID namespace but runs a tiny reaper as PID 1
so the command you pass is a normal child (no init signal/reaping semantics).

Requires Linux, root (or sufficient capabilities), and iproute2 (`ip`).
User namespaces allow limited rootless operation for some features.

Usage examples
--------------
  # Basic isolation
  sudo python3 isolate.py --hostname mybox -- /bin/bash

  # Avoid PID-1 special behaviour (reaper becomes PID 1, command is a child)
  sudo python3 isolate.py --no-special-pid1 --hostname mybox -- /bin/bash

  # Memory + CPU limits
  sudo python3 isolate.py --memory 256M --cpu 50% --hostname limited -- /bin/bash

  # Bridge networking with static IP
  sudo python3 isolate.py --net bridge --ip 10.200.0.2/24 --gateway 10.200.0.1 \\
      --hostname netbox -- /bin/bash

  # Full example with rootfs
  sudo python3 isolate.py --rootfs /path/to/rootfs --map-root \\
      --net bridge --ip 10.200.0.10/24 --gateway 10.200.0.1 \\
      --memory 512M --cpu 100% --hostname c1 -- /bin/sh
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import ctypes.util
import errno
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Step logging (stderr, print only — no logging module)
# ---------------------------------------------------------------------------

# Monotonic origin for relative timestamps (process start ≈ import time)
_PROCESS_T0 = time.perf_counter()


def _log_prefix() -> str:
    """Relative timestamp + uid:gid + pid of the process that is printing."""
    elapsed = time.perf_counter() - _PROCESS_T0
    uid, gid, pid = os.getuid(), os.getgid(), os.getpid()
    # Right-align uid so "uid:gid" reads as one unit (e.g. " 1000:1000")
    return f"[{elapsed:8.4f}s {uid:>5d}:{gid:<5d} {pid:>7d}] "


def eprint(*args, **kwargs):
    kwargs.setdefault("sep", "")
    kwargs.setdefault("file", sys.stderr)
    kwargs.setdefault("flush", True)
    print(*args, **kwargs)

def elprint(*args, **kwargs):
    eprint(_log_prefix(), *args, **kwargs)

class step:
    """
    Context manager that logs a step on a single stderr line.
    Each line is prepended with relative time since process start,
    uid:gid, and pid.  The start text is padded with '.' so every
    result marker begins at the same column:

        [  0.0012s     0:0      12345 ] → prepare cgroup.... [OK] (812 µs)
        [  0.0020s  1000:1000   12346 ] → unshare namespaces [OK] (45 µs)

    hold_line=False: print the start with a newline so concurrent child
    logs (e.g. during create_subprocess_exec) do not share the same line;
    the result is then a separate full line.
    """

    # Column where " [OK]" / " [ERROR]" begins (width of the left part
    # after the timestamp/pid prefix)
    WIDTH = 56

    def __init__(self, name: str, hold_line: bool = True):
        self.name = name
        self.hold_line = hold_line
        self._left = ""

    def __enter__(self) -> "step":
        self.t0 = time.perf_counter()
        head = f"→ {self.name} "
        pad = self.WIDTH - len(head)
        if pad < 1:
            pad = 1
        self._left = head + ("." * pad)
        if self.hold_line:
            elprint(self._left, end="")
        else:
            # Close the line immediately so child preexec logs stay clean
            elprint(self._left, " ...")
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        us = int((time.perf_counter() - self.t0) * 1_000_000)
        if self.hold_line:
            if exc_type is None:
                eprint(f" [OK] ({us} µs)")
            else:
                err = exc if exc is not None else exc_type
                eprint(f" [ERROR] ({us} µs): {err}")
        else:
            # Result on its own line (same columns as a normal step)
            if exc_type is None:
                elprint(self._left, f" [OK] ({us} µs)")
            else:
                err = exc if exc is not None else exc_type
                elprint(self._left, f" [ERROR] ({us} µs): {err}")


# ---------------------------------------------------------------------------
# Low-level helpers (libc)
# ---------------------------------------------------------------------------

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

MS_BIND = 0x1000
MS_REC = 0x4000
MS_PRIVATE = 0x40000
MS_RDONLY = 0x1
MNT_DETACH = 0x2
MS_NODEV = 0x4
MS_NOEXEC = 0x8

CLONE_NEWNS = getattr(os, "CLONE_NEWNS", 0x00020000)
CLONE_NEWUTS = getattr(os, "CLONE_NEWUTS", 0x04000000)
CLONE_NEWIPC = getattr(os, "CLONE_NEWIPC", 0x08000000)
CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
CLONE_NEWPID = getattr(os, "CLONE_NEWPID", 0x20000000)
CLONE_NEWNET = getattr(os, "CLONE_NEWNET", 0x40000000)
CLONE_NEWCGROUP = getattr(os, "CLONE_NEWCGROUP", 0x02000000)


def _check(ret: int, msg: str) -> None:
    if ret < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"{msg}: {os.strerror(e)}")


def mount(source: str, target: str, fstype: str = "",
          flags: int = 0, data: str = "") -> None:
    src = source.encode() if source else None
    tgt = target.encode()
    ft = fstype.encode() if fstype else None
    dt = data.encode() if data else None
    ret = libc.mount(src, tgt, ft, flags, dt)
    _check(ret, f"mount({source} -> {target})")


def umount(target: str, flags: int = 0) -> None:
    ret = libc.umount2(target.encode(), flags)
    _check(ret, f"umount({target})")


def pivot_root(new_root: str, put_old: str) -> None:
    ret = libc.pivot_root(new_root.encode(), put_old.encode())
    _check(ret, "pivot_root")


def sethostname(name: str) -> None:
    ret = libc.sethostname(name.encode(), len(name))
    _check(ret, "sethostname")


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def parse_size(s: str) -> str:
    """Human size → cgroup v2 memory.max value (bytes or 'max')."""
    s = s.strip().lower()
    if s == "max":
        return "max"
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmgt]i?b?)?", s)
    if not m:
        raise ValueError(f"invalid size: {s}")
    num = float(m.group(1))
    unit = (m.group(2) or "").lower()
    mult = {
        "": 1,
        "k": 1024, "kb": 1024, "ki": 1024, "kib": 1024,
        "m": 1024**2, "mb": 1024**2, "mi": 1024**2, "mib": 1024**2,
        "g": 1024**3, "gb": 1024**3, "gi": 1024**3, "gib": 1024**3,
        "t": 1024**4, "tb": 1024**4, "ti": 1024**4, "tib": 1024**4,
    }.get(unit)
    if mult is None:
        raise ValueError(f"unknown unit in size: {s}")
    return str(int(num * mult))


def parse_cpu_quota(s: str, period_us: int = 100_000) -> str:
    """Percentage or raw quota → cgroup v2 'quota period' string."""
    s = s.strip().lower()
    if s == "max":
        return f"max {period_us}"
    if re.fullmatch(r"\d+\s+\d+", s):
        return s
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*%?", s)
    if not m:
        raise ValueError(f"invalid cpu quota: {s}")
    pct = float(m.group(1))
    quota = max(1000, int(period_us * pct / 100.0))
    return f"{quota} {period_us}"


def run_ip(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ip", *args],
        check=check,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def ensure_bridge(name: str, gateway_cidr: Optional[str] = None) -> None:
    r = run_ip("link", "show", name, check=False)
    if r.returncode != 0:
        run_ip("link", "add", name, "type", "bridge")
        run_ip("link", "set", name, "up")
        if gateway_cidr:
            run_ip("addr", "add", gateway_cidr, "dev", name, check=False)
    else:
        run_ip("link", "set", name, "up", check=False)


def status_to_exitcode(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def setup_user_mapping(
    *,
    map_root: bool,
    uid: int,
    gid: int,
    uid_map: Optional[str],
    gid_map: Optional[str],
) -> None:
    try:
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny\n")
    except (FileNotFoundError, PermissionError, OSError):
        pass

    umap, gmap = f"0 {uid} 1", f"0 {gid} 1"
    if not map_root:
        if uid_map:
            umap = uid_map.replace(":", " ")
        if gid_map:
            gmap = gid_map.replace(":", " ")

    try:
        with open("/proc/self/uid_map", "w") as f:
            f.write(umap + "\n")
    except OSError as e:
        eprint(f"warning: could not write user maps ", umap, ": ", e)
    try:
        with open("/proc/self/gid_map", "w") as f:
            f.write(gmap + "\n")
    except OSError as e:
        eprint(f"warning: could not write group maps ", gmap, ": ", e)


def setup_container_network(
    *,
    net: str,
    veth_cont: Optional[str],
    ip: Optional[str],
    gateway: Optional[str],
) -> None:
    try:
        run_ip("link", "set", "lo", "up")
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    if net != "bridge" or not veth_cont:
        return

    for _ in range(40):
        r = run_ip("link", "show", veth_cont, check=False)
        if r.returncode == 0:
            break
        time.sleep(0.025)
    else:
        eprint("warning: container veth ", veth_cont ," not visible")
        return

    try:
        run_ip("link", "set", veth_cont, "name", "eth0")
        run_ip("link", "set", "eth0", "up")
        if ip:
            run_ip("addr", "add", ip, "dev", "eth0")
        if gateway:
            run_ip("route", "add", "default", "via", gateway, check=False)
    except subprocess.CalledProcessError as e:
        eprint("warning: container network setup failed: ", e)


def mount_proc() -> None:
    try:
        os.makedirs("/proc", exist_ok=True)
        mount("proc", "/proc", "proc", 1 | 4 | 8)
    except OSError as e:
        eprint("warning: could not mount /proc: ", e)


def enter_rootfs(rootfs: str) -> None:
    root = Path(rootfs)
    if not root.is_dir():
        eprint(f"rootfs is not a directory: ", rootfs)
        os._exit(1)

    os.chroot(str(root))
    os.chdir("/")
    mount_proc()

class Isolator:
    def __init__(
        self,
        command: List[str],
        *,
        hostname: Optional[str] = None,
        rootfs: Optional[str] = None,
        workdir: Optional[str] = None,
        uid_map: Optional[str] = None,
        gid_map: Optional[str] = None,
        map_root: bool = False,
        net: str = "none",
        ip: Optional[str] = None,
        gateway: Optional[str] = None,
        bridge: str = "isolate0",
        enable_pid: bool = True,
        enable_user: bool = True,
        enable_mount: bool = True,
        enable_uts: bool = True,
        enable_ipc: bool = True,
        enable_net: bool = True,
        no_special_pid1: bool = False,
        memory_limit: Optional[str] = None,
        memory_swap: Optional[str] = None,
        cpu_quota: Optional[str] = None,
        cgroup_parent: str = "/sys/fs/cgroup",
    ):
        self.command = command
        self.hostname = hostname
        self.rootfs = Path(rootfs).resolve() if rootfs else None
        self.workdir = workdir
        self.uid_map = uid_map
        self.gid_map = gid_map
        self.map_root = map_root
        self.net = net
        self.ip = ip
        self.gateway = gateway
        self.bridge = bridge
        self.enable_pid = enable_pid
        self.enable_user = enable_user
        self.enable_mount = enable_mount
        self.enable_uts = enable_uts
        self.enable_ipc = enable_ipc
        self.enable_net = enable_net and (net != "host")
        self.no_special_pid1 = bool(no_special_pid1 and enable_pid)
        self.memory_limit = memory_limit
        self.memory_swap = memory_swap
        self.cpu_quota = cpu_quota
        self.cgroup_parent = cgroup_parent

        self._uid = os.getuid()
        self._gid = os.getgid()

        self._cgroup_path: Optional[Path] = None
        self._veth_host: Optional[str] = None
        self._veth_cont: Optional[str] = None

    # ------------------------------------------------------------------
    # Public entry (asyncio)
    # ------------------------------------------------------------------

    def run(self) -> int:
        if not sys.platform.startswith("linux"):
            eprint("This tool only works on Linux (namespaces).")
            return 1
        return asyncio.run(self._run_async())

    async def _run_async(self) -> int:
        with step("prepare cgroup"):
            self._prepare_cgroup()

        if self.net == "bridge" and self.enable_net:
            with step("prepare host network (veth + bridge)"):
                self._prepare_host_network()

        # Sync pipes for bridge mode: child → parent "unshared", parent → child "ready"
        sync_unshared_r = sync_unshared_w = None
        sync_ready_r = sync_ready_w = None
        pass_fds: List[int] = []

        if self.net == "bridge" and self.enable_net:
            with step("create sync pipes for bridge handoff"):
                sync_unshared_r, sync_unshared_w = os.pipe()
                sync_ready_r, sync_ready_w = os.pipe()
                pass_fds = [sync_unshared_w, sync_ready_r]
                os.set_inheritable(sync_unshared_w, True)
                os.set_inheritable(sync_ready_r, True)

        flags = 0
        if self.enable_mount:
            flags |= CLONE_NEWNS
        if self.enable_uts:
            flags |= CLONE_NEWUTS
        if self.enable_ipc:
            flags |= CLONE_NEWIPC
        if self.enable_user:
            flags |= CLONE_NEWUSER
        if self.enable_pid:
            flags |= CLONE_NEWPID
        if self.enable_net:
            flags |= CLONE_NEWNET

        cfg = self._preexec_config(
            flags=flags,
            unshared_w=sync_unshared_w,
            ready_r=sync_ready_r,
        )

        def preexec() -> None:
            self._preexec_fn(cfg)

        try:
            # hold_line=False: child preexec logs must not share this line
            with step(f"create_subprocess_exec {self.command!r}",
                      hold_line=False):
                proc = await asyncio.create_subprocess_exec(
                    *self.command,
                    preexec_fn=preexec,
                    pass_fds=tuple(pass_fds) if pass_fds else (),
                    start_new_session=True,
                )
        except OSError as e:
            eprint("  [ERROR] create_subprocess_exec: ", e)
            self._cleanup_network()
            self._cleanup_cgroup()
            return 1
        finally:
            if sync_unshared_w is not None:
                try:
                    os.close(sync_unshared_w)
                except OSError:
                    pass
            if sync_ready_r is not None:
                try:
                    os.close(sync_ready_r)
                except OSError:
                    pass

        # Bridge: wait for child to enter netns, move veth, signal ready
        if self.net == "bridge" and self.enable_net and proc.pid:
            with step("wait for child netns unshare signal"):
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, os.read, sync_unshared_r, 1
                    )
                except OSError as e:
                    eprint("  [ERROR] reading unshare signal: ", e)
                finally:
                    try:
                        os.close(sync_unshared_r)
                    except OSError:
                        pass

            if self._veth_cont:
                with step(f"move {self._veth_cont} into netns of pid {proc.pid}"):
                    try:
                        run_ip("link", "set", self._veth_cont, "netns",
                               str(proc.pid))
                    except subprocess.CalledProcessError as e:
                        eprint("  [ERROR] move veth: ", e)
                        raise

            if self._veth_host:
                with step(f"attach {self._veth_host} to bridge {self.bridge}"):
                    try:
                        run_ip("link", "set", self._veth_host, "master",
                               self.bridge)
                        run_ip("link", "set", self._veth_host, "up")
                    except subprocess.CalledProcessError as e:
                        eprint("  [ERROR] attach veth to bridge: ", e)
                        raise

            with step("signal child that veth is ready"):
                try:
                    os.write(sync_ready_w, b"1")
                except OSError as e:
                    eprint("  [ERROR] writing ready signal: ", e)
                finally:
                    try:
                        os.close(sync_ready_w)
                    except OSError:
                        pass
        else:
            if sync_unshared_r is not None:
                try:
                    os.close(sync_unshared_r)
                except OSError:
                    pass
            if sync_ready_w is not None:
                try:
                    os.close(sync_ready_w)
                except OSError:
                    pass

        with step(f"wait for process pid={proc.pid}"):
            returncode = await proc.wait()

        with step("cleanup host network"):
            self._cleanup_network()
        with step("cleanup cgroup"):
            self._cleanup_cgroup()

        return returncode if returncode is not None else 1

    def _preexec_config(
        self,
        *,
        flags: int,
        unshared_w: Optional[int],
        ready_r: Optional[int],
    ) -> dict:
        """Snapshot of settings used inside preexec_fn."""
        return {
            "flags": flags,
            "enable_pid": self.enable_pid,
            "enable_user": self.enable_user,
            "enable_mount": self.enable_mount,
            "enable_uts": self.enable_uts,
            "enable_net": self.enable_net,
            "no_special_pid1": self.no_special_pid1,
            "hostname": self.hostname,
            "rootfs": str(self.rootfs) if self.rootfs else None,
            "workdir": self.workdir,
            "map_root": self.map_root,
            "uid_map": self.uid_map,
            "gid_map": self.gid_map,
            "net": self.net,
            "ip": self.ip,
            "gateway": self.gateway,
            "veth_cont": self._veth_cont,
            "cgroup_path": str(self._cgroup_path) if self._cgroup_path else None,
            "unshared_w": unshared_w,
            "ready_r": ready_r,
            "uid": self._uid,
            "gid": self._gid,
        }

    # ------------------------------------------------------------------
    # Runs in the subprocess child, before exec
    # ------------------------------------------------------------------

    def _preexec_fn(self, cfg: dict) -> None:
        flags: int = cfg["flags"]
        unshared_w: Optional[int] = cfg["unshared_w"]
        ready_r: Optional[int] = cfg["ready_r"]

        with step(f"unshare namespaces (flags=0x{flags:x})"):
            try:
                os.unshare(flags)
            except OSError as e:
                eprint(f"unshare failed: ", e)
                os._exit(1)

        # PID namespace: only a child of the unsharing process is PID 1
        if cfg["enable_pid"]:
            with step("fork for PID namespace (child becomes PID 1)"):
                pid = os.fork()
                if pid != 0:
                    # Intermediate process (still old PID ns): wait for real init
                    try:
                        _, status = os.waitpid(pid, 0)
                    except OSError:
                        os._exit(1)
                    os._exit(status_to_exitcode(status))
                # We are now PID 1 inside the new PID namespace

        # Tell parent we have entered the new netns (bridge mode)
        if unshared_w is not None:
            with step("signal parent: netns unshared"):
                try:
                    os.write(unshared_w, b"1")
                except OSError as e:
                    eprint(f"  [ERROR] unshare signal write: ", e)
                try:
                    os.close(unshared_w)
                except OSError:
                    pass

        # Wait until parent has moved the veth into this netns
        if ready_r is not None:
            with step("wait for parent: veth ready"):
                try:
                    os.read(ready_r, 1)
                except OSError as e:
                    eprint(f"  [ERROR] ready signal read: ", e)
                try:
                    os.close(ready_r)
                except OSError:
                    pass

        # User mapping (must be early while we can still write the maps)
        if cfg["enable_user"]:
            with step("setup user/group ID mapping"):
                setup_user_mapping(
                    map_root=cfg["map_root"],
                    uid=cfg["uid"],
                    gid=cfg["gid"],
                    uid_map=cfg["uid_map"],
                    gid_map=cfg["gid_map"],
                )

        # Private mounts
        if cfg["enable_mount"]:
            with step("make mounts private (MS_REC|MS_PRIVATE)"):
                try:
                    mount("none", "/", "", MS_REC | MS_PRIVATE)
                except OSError:
                    pass

        # Hostname
        if cfg["enable_uts"] and cfg["hostname"]:
            with step(f"set hostname to {cfg['hostname']!r}"):
                try:
                    sethostname(cfg["hostname"])
                except OSError as e:
                    eprint(f"warning: could not set hostname: ", e)
                    raise

        # Network inside the netns
        if cfg["enable_net"]:
            with step("setup container network (lo / eth0 / routes)"):
                setup_container_network(
                    net=cfg["net"],
                    veth_cont=cfg["veth_cont"],
                    ip=cfg["ip"],
                    gateway=cfg["gateway"],
                )

        # Rootfs / proc
        if cfg["rootfs"]:
            with step(f"enter rootfs {cfg['rootfs']!r}"):
                enter_rootfs(cfg["rootfs"])
        elif cfg["enable_mount"]:
            with step("mount /proc"):
                mount_proc()

        if cfg["workdir"]:
            with step(f"chdir to {cfg['workdir']!r}"):
                try:
                    os.chdir(cfg["workdir"])
                except OSError as e:
                    eprint("warning: cannot chdir to ", cfg['workdir'], ": ", e)
                    raise

        # Join cgroup
        if cfg["cgroup_path"]:
            with step(f"join cgroup {cfg['cgroup_path']}"):
                try:
                    Path(cfg["cgroup_path"], "cgroup.procs").write_text(
                        str(os.getpid()) + "\n"
                    )
                except OSError as e:
                    eprint("warning: could not join cgroup: ", e)
                    raise

        # Optional: stay as reaper (PID 1), let the user command be a child
        if cfg["no_special_pid1"]:
            with step("become PID-1 reaper (no-special-pid1)"):
                self._become_reaper_then_return()
            # Only the grandchild returns from preexec_fn and gets exec'd
            return

        # Returning from preexec_fn → kernel execs self.command in this process
        elprint("→ exec target command (returning from preexec_fn)...")

    def _become_reaper_then_return(self) -> None:
        """
        Fork once more.  This process (PID 1) becomes a signal-forwarding
        reaper and never returns.  The child returns from preexec_fn so
        create_subprocess_exec will exec the user command into it.
        """
        child_pid = os.fork()
        if child_pid != 0:
            # PID 1 reaper — never return to preexec / exec
            os._exit(self._run_as_init(child_pid))
        # Child returns → will be replaced by the target command

    def _run_as_init(self, main_child: int) -> int:
        forward = {
            signal.SIGTERM, signal.SIGINT, signal.SIGHUP,
            signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2,
        }

        def _forward(signum, frame):
            try:
                os.kill(main_child, signum)
            except OSError:
                pass

        for sig in forward:
            try:
                signal.signal(sig, _forward)
            except (OSError, ValueError):
                pass

        exit_code = 0
        while True:
            try:
                pid, status = os.waitpid(-1, 0)
            except ChildProcessError:
                break
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                break

            if pid == main_child:
                exit_code = status_to_exitcode(status)
                while True:
                    try:
                        os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        break
                    except OSError:
                        break
                break

        return exit_code

    # ------------------------------------------------------------------
    # Static helpers usable from preexec (no self mutation)
    # ------------------------------------------------------------------



    # ------------------------------------------------------------------
    # Host-side network + cgroup
    # ------------------------------------------------------------------

    def _prepare_host_network(self) -> None:
        suffix = uuid.uuid4().hex[:8]
        self._veth_host = f"vethh{suffix}"
        self._veth_cont = f"vethc{suffix}"

        if not self.ip:
            self.ip = "10.200.0.2/24"
        if not self.gateway:
            self.gateway = "10.200.0.1"

        bridge_cidr = None
        if self.gateway and self.ip and "/" in self.ip:
            bridge_cidr = f"{self.gateway}/{self.ip.split('/')[1]}"

        try:
            ensure_bridge(self.bridge, bridge_cidr)
            run_ip(
                "link", "add", self._veth_host, "type", "veth",
                "peer", "name", self._veth_cont,
            )
            run_ip("link", "set", self._veth_host, "up", check=False)
        except subprocess.CalledProcessError as e:
            eprint(f"error preparing host network: ", e)
            raise

    def _cleanup_network(self) -> None:
        if self._veth_host:
            try:
                run_ip("link", "delete", self._veth_host, check=False)
            except Exception:
                pass

    def _prepare_cgroup(self) -> None:
        if not (self.memory_limit or self.memory_swap or self.cpu_quota):
            return

        try:
            base = Path(self.cgroup_parent)
            if not (base / "cgroup.controllers").exists():
                eprint("warning: cgroup v2 hierarchy not found, resource limits disabled")
                return

            isolate_base = base / "isolate"
            isolate_base.mkdir(exist_ok=True)

            for ctrl_file in (
                base / "cgroup.subtree_control",
                isolate_base / "cgroup.subtree_control",
            ):
                if not ctrl_file.exists():
                    continue
                try:
                    current = ctrl_file.read_text().strip().split()
                    needed = []
                    if (self.memory_limit or self.memory_swap) and "memory" not in current:
                        needed.append("+memory")
                    if self.cpu_quota and "cpu" not in current:
                        needed.append("+cpu")
                    if needed:
                        ctrl_file.write_text(" ".join(needed) + "\n")
                except OSError:
                    pass

            name = f"iso-{os.getpid()}-{uuid.uuid4().hex[:6]}"
            path = isolate_base / name
            path.mkdir(exist_ok=True)
            self._cgroup_path = path

            if self.memory_limit:
                try:
                    (path / "memory.max").write_text(
                        parse_size(self.memory_limit) + "\n"
                    )
                except (ValueError, OSError) as e:
                    eprint(f"warning: could not set memory.max:", e)

            if self.memory_swap:
                try:
                    swap_file = path / "memory.swap.max"
                    if swap_file.exists():
                        swap_file.write_text(
                            parse_size(self.memory_swap) + "\n"
                        )
                except (ValueError, OSError) as e:
                    eprint("warning: could not set memory.swap.max: ", e)

            if self.cpu_quota:
                try:
                    (path / "cpu.max").write_text(
                        parse_cpu_quota(self.cpu_quota) + "\n"
                    )
                except (ValueError, OSError) as e:
                    eprint("warning: could not set cpu.max: ", e)

        except OSError as e:
            eprint(f"warning: cgroup setup failed: ", e)
            self._cgroup_path = None

    def _cleanup_cgroup(self) -> None:
        if not self._cgroup_path:
            return
        try:
            time.sleep(0.02)
            self._cgroup_path.rmdir()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run a command inside isolated Linux namespaces "
                    "with optional cgroup resource limits and bridge networking "
                    "(asyncio + create_subprocess_exec).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument("--hostname", "-H",
                   help="Set the hostname inside the UTS namespace")
    p.add_argument("--rootfs", "-r",
                   help="Path to a directory that becomes the new root "
                        "(chroot / pivot_root)")
    p.add_argument("--workdir", "-w",
                   help="Working directory inside the isolated environment")

    p.add_argument("--map-root", action="store_true",
                   help="Map the invoking user to UID/GID 0 inside the user namespace")
    p.add_argument("--uid-map",
                   help="UID mapping string 'inside:outside:count'")
    p.add_argument("--gid-map",
                   help="GID mapping string 'inside:outside:count'")

    p.add_argument("--net", choices=["none", "host", "bridge"], default="none",
                   help="Network mode: none | host | bridge (default: none)")
    p.add_argument("--ip",
                   help="Container IP/CIDR for --net bridge (default: 10.200.0.2/24)")
    p.add_argument("--gateway",
                   help="Default gateway for --net bridge (default: 10.200.0.1)")
    p.add_argument("--bridge", default="isolate0",
                   help="Bridge name for host-side veth (default: isolate0)")

    p.add_argument("--no-pid", action="store_true",
                   help="Do not create a new PID namespace")
    p.add_argument("--no-special-pid1", action="store_true",
                   help="Keep a PID namespace but run a tiny reaper as PID 1 "
                        "so the command is a normal child. Ignored with --no-pid.")
    p.add_argument("--no-user", action="store_true",
                   help="Do not create a new user namespace")
    p.add_argument("--no-mount", action="store_true",
                   help="Do not create a new mount namespace")
    p.add_argument("--no-uts", action="store_true",
                   help="Do not create a new UTS namespace")
    p.add_argument("--no-ipc", action="store_true",
                   help="Do not create a new IPC namespace")
    p.add_argument("--no-net", action="store_true",
                   help="Do not create a new network namespace (overrides --net)")

    p.add_argument("--memory",
                   help="Hard memory limit (e.g. 256M, 1G). Requires cgroup v2.")
    p.add_argument("--memory-swap",
                   help="Swap limit (e.g. 0, 512M). Requires cgroup v2.")
    p.add_argument("--cpu",
                   help="CPU quota: percentage (50%%, 200%%) or raw "
                        "'quota period' in microseconds. Requires cgroup v2.")

    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="Command and arguments to run (use -- to separate)")

    args = p.parse_args(argv)

    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        p.error("a command to execute is required")

    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    isolator = Isolator(
        command=args.command,
        hostname=args.hostname,
        rootfs=args.rootfs,
        workdir=args.workdir,
        uid_map=args.uid_map,
        gid_map=args.gid_map,
        map_root=args.map_root,
        net=args.net,
        ip=args.ip,
        gateway=args.gateway,
        bridge=args.bridge,
        enable_pid=not args.no_pid,
        enable_user=not args.no_user,
        enable_mount=not args.no_mount,
        enable_uts=not args.no_uts,
        enable_ipc=not args.no_ipc,
        enable_net=not args.no_net,
        no_special_pid1=args.no_special_pid1,
        memory_limit=args.memory,
        memory_swap=args.memory_swap,
        cpu_quota=args.cpu,
    )
    return isolator.run()


if __name__ == "__main__":
    sys.exit(main())
