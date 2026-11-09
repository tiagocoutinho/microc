import ctypes

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

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
