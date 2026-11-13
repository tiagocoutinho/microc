#!/usr/bin/env python3
"""
isolate.py – Lightweight process isolator using Linux namespaces
(similar in spirit to a minimal Docker / bubblewrap / unshare wrapper).

Isolates:
  - PID          (new process tree, child becomes PID 1)
  - User / Group (user namespace + UID/GID mapping)
  - Network      (new empty network namespace, optional loopback)
  - Filesystem   (mount namespace + optional chroot / rootfs)
  - Hostname     (UTS namespace)

Designed so that CPU / memory limits (cgroups v2) can be added later
without changing the overall structure.

Requires Linux.  Most features need CAP_SYS_ADMIN (root) or appropriate
capabilities.  User namespaces can be used for limited rootless operation.

Usage examples
--------------
  # Simple isolation (new PID + mount + UTS + net, keep host user)
  sudo python3 isolate.py --hostname mybox -- /bin/bash

  # Run as mapped root inside a rootfs
  sudo python3 isolate.py --rootfs /path/to/rootfs --map-root --hostname c1 -- /bin/sh

  # Explicit UID/GID mapping (inside:outside:count)
  sudo python3 isolate.py --uid-map 0:1000:1 --gid-map 0:1000:1 -- /bin/id

  # Keep host network
  sudo python3 isolate.py --net host -- /bin/bash

  # Disable some namespaces
  sudo python3 isolate.py --no-pid --no-net --hostname only-hostname -- /bin/bash
"""

from __future__ import annotations

import argparse
import os
import sys
import signal
import ctypes
import ctypes.util
import errno
from pathlib import Path
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Low-level helpers (libc)
# ---------------------------------------------------------------------------

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

MS_BIND = 0x1000
MS_REC = 0x4000
MS_PRIVATE = 0x40000
MS_RDONLY = 0x1
MNT_DETACH = 0x2

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
# Namespace / isolation logic
# ---------------------------------------------------------------------------

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
        net: str = "none",          # "none" | "host"
        enable_pid: bool = True,
        enable_user: bool = True,
        enable_mount: bool = True,
        enable_uts: bool = True,
        enable_ipc: bool = True,
        enable_net: bool = True,
        # Future extension points for cgroups
        memory_limit: Optional[str] = None,   # e.g. "512M"
        cpu_quota: Optional[str] = None,      # e.g. "50%" or "50000 100000"
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
        self.enable_pid = enable_pid
        self.enable_user = enable_user
        self.enable_mount = enable_mount
        self.enable_uts = enable_uts
        self.enable_ipc = enable_ipc
        self.enable_net = enable_net and (net != "host")
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.cgroup_parent = cgroup_parent

        self._cgroup_path: Optional[Path] = None

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------

    def run(self) -> int:
        if not sys.platform.startswith("linux"):
            print("This tool only works on Linux (namespaces).", file=sys.stderr)
            return 1

        # Build the set of namespaces we will unshare
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

        # ------------------------------------------------------------------
        # 1. Optionally create a cgroup for future resource limits
        #    (placeholder – will be fully wired later)
        # ------------------------------------------------------------------
        self._prepare_cgroup()

        # ------------------------------------------------------------------
        # 2. Fork + unshare
        #    Important: for PID namespace the *child* becomes PID 1.
        # ------------------------------------------------------------------
        # We unshare everything except PID in the parent, then fork,
        # then the child finishes PID-related setup.  Alternatively we
        # can unshare all flags and then fork immediately.
        # The classic pattern is:
        #   unshare(CLONE_NEWPID | ...)  →  fork  →  child is PID 1
        try:
            os.unshare(flags)
        except OSError as e:
            print(f"unshare failed: {e}", file=sys.stderr)
            print("Hint: most namespace operations require root or CAP_SYS_ADMIN.",
                  file=sys.stderr)
            return 1

        # After unshare(CLONE_NEWPID) the *current* process is still in the
        # old PID namespace.  The first child we create will be PID 1 in the
        # new one.
        if self.enable_pid:
            pid = os.fork()
            if pid != 0:
                # Parent: wait for the isolated child and propagate exit status
                _, status = os.waitpid(pid, 0)
                self._cleanup_cgroup()
                if os.WIFEXITED(status):
                    return os.WEXITSTATUS(status)
                if os.WIFSIGNALED(status):
                    return 128 + os.WTERMSIG(status)
                return 1
            # Child continues – it is now PID 1 inside the new PID ns

        # ------------------------------------------------------------------
        # 3. User namespace mapping (must be done early, while we still can)
        # ------------------------------------------------------------------
        if self.enable_user:
            self._setup_user_mapping()

        # ------------------------------------------------------------------
        # 4. Mount namespace housekeeping
        # ------------------------------------------------------------------
        if self.enable_mount:
            # Make mounts private so they don't leak to the host
            try:
                mount("none", "/", "", MS_REC | MS_PRIVATE)
            except OSError:
                # Some kernels / contexts already have it private
                pass

        # ------------------------------------------------------------------
        # 5. Hostname
        # ------------------------------------------------------------------
        if self.enable_uts and self.hostname:
            try:
                sethostname(self.hostname)
            except OSError as e:
                print(f"warning: could not set hostname: {e}", file=sys.stderr)

        # ------------------------------------------------------------------
        # 6. Network (minimal – just bring loopback up)
        # ------------------------------------------------------------------
        if self.enable_net:
            self._setup_network()

        # ------------------------------------------------------------------
        # 7. Filesystem / rootfs
        # ------------------------------------------------------------------
        if self.rootfs:
            self._enter_rootfs()
        elif self.enable_mount:
            # Even without a full rootfs we can still isolate /proc
            self._mount_proc()

        # ------------------------------------------------------------------
        # 8. Working directory
        # ------------------------------------------------------------------
        if self.workdir:
            try:
                os.chdir(self.workdir)
            except OSError as e:
                print(f"warning: cannot chdir to {self.workdir}: {e}",
                      file=sys.stderr)

        # ------------------------------------------------------------------
        # 9. Move ourselves into the prepared cgroup (if any)
        # ------------------------------------------------------------------
        self._join_cgroup()

        # ------------------------------------------------------------------
        # 10. Exec the target command
        # ------------------------------------------------------------------
        try:
            os.execvp(self.command[0], self.command)
        except OSError as e:
            print(f"exec failed: {e}", file=sys.stderr)
            return 127

        return 0  # never reached

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _setup_user_mapping(self) -> None:
        """Write uid_map / gid_map.  Must be done before we drop privileges."""
        # Deny setgroups so we can write the maps as non-root (when using
        # user namespaces from an unprivileged process).
        try:
            with open("/proc/self/setgroups", "w") as f:
                f.write("deny\n")
        except (FileNotFoundError, PermissionError, OSError):
            pass

        uid = os.getuid()
        gid = os.getgid()

        if self.map_root:
            # Map host uid/gid → 0 inside
            uid_map = f"0 {uid} 1"
            gid_map = f"0 {gid} 1"
        else:
            uid_map = self.uid_map or f"0 {uid} 1"
            gid_map = self.gid_map or f"0 {gid} 1"

        try:
            with open("/proc/self/uid_map", "w") as f:
                f.write(uid_map + "\n")
            with open("/proc/self/gid_map", "w") as f:
                f.write(gid_map + "\n")
        except OSError as e:
            print(f"warning: could not write user maps: {e}", file=sys.stderr)
            print("  (user namespace mapping may be incomplete)", file=sys.stderr)

    def _setup_network(self) -> None:
        """Bring up the loopback interface inside the new netns."""
        # We use the ip command if available; pure netlink would be better
        # but adds complexity.  For a pure-Python version one can later
        # replace this with pyroute2 or raw netlink.
        try:
            import subprocess
            subprocess.run(["ip", "link", "set", "lo", "up"],
                           check=False, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            # ip not present – network isolation still works, just no lo
            pass

    def _mount_proc(self) -> None:
        """Mount a fresh /proc (required for a correct view inside PID ns)."""
        try:
            os.makedirs("/proc", exist_ok=True)
            mount("proc", "/proc", "proc", 0)
        except OSError as e:
            # May fail if we are not root / no CAP_SYS_ADMIN
            print(f"warning: could not mount /proc: {e}", file=sys.stderr)

    def _enter_rootfs(self) -> None:
        """Chroot or pivot_root into the supplied rootfs."""
        if not self.rootfs or not self.rootfs.is_dir():
            raise RuntimeError(f"rootfs does not exist or is not a directory: {self.rootfs}")

        # Make sure we have a place for the old root
        old_root = self.rootfs / "old_root"
        try:
            old_root.mkdir(exist_ok=True)
        except OSError:
            # Fallback to plain chroot if we cannot prepare pivot
            os.chroot(str(self.rootfs))
            os.chdir("/")
            self._mount_proc()
            return

        # Preferred modern approach: pivot_root
        try:
            # Bind-mount the rootfs onto itself so it becomes a mount point
            mount(str(self.rootfs), str(self.rootfs), "", MS_BIND | MS_REC)
            pivot_root(str(self.rootfs), str(old_root))
            os.chdir("/")
            # Unmount the old root (now visible as /old_root)
            try:
                umount("/old_root", MNT_DETACH)
                os.rmdir("/old_root")
            except OSError:
                pass
        except OSError:
            # Fallback
            os.chroot(str(self.rootfs))
            os.chdir("/")

        self._mount_proc()

        # Minimal /dev (optional – many programs need at least null, zero, …)
        try:
            os.makedirs("/dev", exist_ok=True)
            # You can add more device nodes or a tmpfs + mknod here
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Cgroup placeholders (ready for the next iteration)
    # ------------------------------------------------------------------

    def _prepare_cgroup(self) -> None:
        """
        Create a dedicated cgroup for this process tree.
        Currently only prepares the directory; actual limits are applied
        when --memory / --cpu options are added.
        """
        if not (self.memory_limit or self.cpu_quota):
            return

        # Example layout that will be used later:
        #   /sys/fs/cgroup/isolate/<random-or-pid>
        try:
            base = Path(self.cgroup_parent)
            if not (base / "cgroup.controllers").exists():
                # Not a pure cgroup-v2 hierarchy
                return

            name = f"isolate-{os.getpid()}"
            path = base / name
            path.mkdir(exist_ok=True)
            self._cgroup_path = path

            # Enable controllers we care about
            controllers = path.parent / "cgroup.subtree_control"
            if controllers.exists():
                # Best-effort; may already be enabled higher up
                try:
                    with open(controllers, "a") as f:
                        f.write("+memory +cpu\n")
                except OSError:
                    pass

            # Apply limits when the options are present
            if self.memory_limit:
                # Accept human-readable values later; for now expect bytes or "max"
                limit_file = path / "memory.max"
                if limit_file.exists():
                    limit_file.write_text(self.memory_limit + "\n")

            if self.cpu_quota:
                # Format: "quota period"  (both in µs) or a percentage string
                cpu_file = path / "cpu.max"
                if cpu_file.exists():
                    cpu_file.write_text(self.cpu_quota + "\n")

        except OSError as e:
            print(f"warning: cgroup setup failed: {e}", file=sys.stderr)
            self._cgroup_path = None

    def _join_cgroup(self) -> None:
        if not self._cgroup_path:
            return
        try:
            procs = self._cgroup_path / "cgroup.procs"
            procs.write_text(str(os.getpid()) + "\n")
        except OSError as e:
            print(f"warning: could not join cgroup: {e}", file=sys.stderr)

    def _cleanup_cgroup(self) -> None:
        if not self._cgroup_path:
            return
        try:
            # After the child has exited the cgroup should be empty
            self._cgroup_path.rmdir()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run a command inside isolated Linux namespaces "
                    "(PID, user, network, mount, UTS).",
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

    # User / group
    p.add_argument("--map-root", action="store_true",
                   help="Map the invoking user to UID/GID 0 inside the user namespace")
    p.add_argument("--uid-map",
                   help="UID mapping string 'inside:outside:count' "
                        "(default: 0:<current-uid>:1 when --map-root is used)")
    p.add_argument("--gid-map",
                   help="GID mapping string 'inside:outside:count'")

    # Network
    p.add_argument("--net", choices=["none", "host"], default="none",
                   help="Network mode: 'none' = new empty netns, "
                        "'host' = share host network (default: none)")

    # Toggle individual namespaces
    p.add_argument("--no-pid", action="store_true",
                   help="Do not create a new PID namespace")
    p.add_argument("--no-user", action="store_true",
                   help="Do not create a new user namespace")
    p.add_argument("--no-mount", action="store_true",
                   help="Do not create a new mount namespace")
    p.add_argument("--no-uts", action="store_true",
                   help="Do not create a new UTS namespace")
    p.add_argument("--no-ipc", action="store_true",
                   help="Do not create a new IPC namespace")
    p.add_argument("--no-net", action="store_true",
                   help="Do not create a new network namespace "
                        "(overrides --net)")

    # Future resource limits (already accepted so the CLI stays stable)
    p.add_argument("--memory",
                   help="Memory limit for the cgroup (e.g. 512M, 1G). "
                        "Requires cgroup v2.  (placeholder for next version)")
    p.add_argument("--cpu",
                   help="CPU quota (e.g. '50000 100000' for 50%% of one core, "
                        "or a percentage).  Requires cgroup v2.  "
                        "(placeholder for next version)")

    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="Command and arguments to run (use -- to separate)")

    args = p.parse_args(argv)

    # Clean the classic "--" separator
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
        enable_pid=not args.no_pid,
        enable_user=not args.no_user,
        enable_mount=not args.no_mount,
        enable_uts=not args.no_uts,
        enable_ipc=not args.no_ipc,
        enable_net=not args.no_net,
        memory_limit=args.memory,
        cpu_quota=args.cpu,
    )
    return isolator.run()


if __name__ == "__main__":
    sys.exit(main())
