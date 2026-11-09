import ctypes
import os
import subprocess
import sys
from ctypes import c_int, c_uint64, c_void_p

# Load libc
libc = ctypes.CDLL('libc.so.6')

# Define clone3 flags (same as clone)
CLONE_NEWUSER = 0x10000000  # User namespace
CLONE_NEWUTS = 0x04000000   # UTS namespace

# Define struct clone_args for clone3
class CloneArgs(ctypes.Structure):
    _fields_ = [
        ("flags", c_uint64),
        ("pidfd", c_uint64),
        ("child_tid", c_uint64),
        ("parent_tid", c_uint64),
        ("exit_signal", c_uint64),
        ("stack", c_uint64),
        ("stack_size", c_uint64),
        ("tls", c_uint64),
    ]

# Function to execute in the child process
def child_func():
    try:
        # Set hostname in the new UTS namespace
        new_hostname = "new-hostname"
        result = libc.sethostname(new_hostname.encode('utf-8'), len(new_hostname))
        if result != 0:
            print(f"Child: Failed to set hostname: {os.strerror(ctypes.get_errno())}", file=sys.stderr)
            sys.exit(1)

        # Run the hostname command
        process = subprocess.run("hostname", shell=True, capture_output=True, text=True)
        print(f"Child: Subprocess output: {process.stdout.strip()}")
        print(f"Child: Subprocess error (if any): {process.stderr.strip()}")
        print(f"Child: Return code: {process.returncode}")
        sys.exit(process.returncode)
    except Exception as e:
        print(f"Child: Error: {e}", file=sys.stderr)
        sys.exit(1)

def run_clone3_subprocess(flags):
    # Allocate stack for the child process
    stack_size = 1024 * 1024  # 1MB stack
    stack = ctypes.create_string_buffer(stack_size)
    stack_ptr = ctypes.addressof(stack) + stack_size  # Stack grows downward

    # Set up clone_args
    clone_args = CloneArgs(
        flags=flags,
        pidfd=0,
        child_tid=0,
        parent_tid=0,
        exit_signal=0,  # No signal on child exit
        stack=stack_ptr,
        stack_size=stack_size,
        tls=0
    )

    # Call clone3
    SYS_clone3 = 435  # System call number for clone3 (may vary by architecture)
    result = libc.syscall(SYS_clone3, ctypes.byref(clone_args), ctypes.sizeof(clone_args))
    if result == -1:
        raise OSError(f"clone3 failed: {os.strerror(ctypes.get_errno())}")

    if result == 0:
        # Child process: configure user namespace mappings
        try:
            with open('/proc/self/uid_map', 'w') as uid_map:
                uid_map.write(f"{os.getuid()} {os.getuid()} 1\n")
            with open('/proc/self/setgroups', 'w') as setgroups:
                setgroups.write('deny\n')
            with open('/proc/self/gid_map', 'w') as gid_map:
                gid_map.write(f"{os.getgid()} {os.getgid()} 1\n")
        except OSError as e:
            print(f"Child: Failed to set UID/GID mappings: {e}", file=sys.stderr)
            sys.exit(1)

        # Execute child function
        child_func()
        import time;time.sleep(1)
        sys.exit(0)

    # Parent process: wait for child
    pid, status = os.waitpid(result, 0)
    if os.WIFEXITED(status):
        exit_code = os.WEXITSTATUS(status)
        print(f"Parent: Child process {pid} exited with code {exit_code}")
    else:
        print(f"Parent: Child process {pid} terminated abnormally")

if __name__ == "__main__":
    # Combine flags for user and UTS namespaces
    flags = CLONE_NEWUSER | CLONE_NEWUTS
    print(f"Starting clone3 with flags: {flags:#x}")
    run_clone3_subprocess(flags)
