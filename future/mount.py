import ctypes
import enum

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


class MountFlag(enum.IntEnum):
    """Mount flags."""

    #: Mount read-only.
    RDONLY = 1
    #: Ignore suid and sgid bits.
    NOSUID = 2
    #: Disallow access to device special files.
    NODEV = 4
    #: Disallow program execution.
    NOEXEC = 8
    #: Writes are synced at once.
    SYNCHRONOUS = 16
    #: Alter flags of a mounted FS.
    REMOUNT = 32
    #: Allow mandatory locks on an FS.
    MANDLOCK = 64
    #: Directory modifications are synchronous.
    DIRSYNC = 128
    #: Do not follow symlinks.
    NOSYMFOLLOW = 256
    #: Do not update access times.
    NOATIME = 1024
    #: Do not update directory access times.
    NODIRATIME = 2048
    #: Bind directory at different place.
    BIND = 4096
    MOVE = 8192
    REC = 16384
    SILENT = 32768
    #: VFS does not apply the umask.
    POSIXACL = 1 << 16
    #: Change to unbindable.
    UNBINDABLE = 1 << 17
    #: Change to private.
    PRIVATE = 1 << 18
    #: Change to slave.
    SLAVE = 1 << 19
    #: Change to shared.
    SHARED = 1 << 20
    #: Update atime relative to mtime/ctime.
    RELATIME = 1 << 21
    #: This is a kern_mount call.
    KERNMOUNT = 1 << 22
    #: Update inode I_version field.
    I_VERSION = 1 << 23
    #: Always perform atime updates.
    STRICTATIME = 1 << 24
    #: Update the on-disk [acm]times lazily.
    LAZYTIME = 1 << 25
    ACTIVE = 1 << 30
    NOUSER = 1 << 31


class UmountFlag(enum.IntEnum):
    """Unmount flags."""

    #: Force unmounting.
    MNT_FORCE = 1
    #: Just detach from the tree.
    MNT_DETACH = 2
    #: Mark for expiry.
    MNT_EXPIRE = 4
    #: Don't follow symlink on umount.
    UMOUNT_NOFOLLOW = 8


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