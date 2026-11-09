import os
import sys
import subprocess


def execute(args):
    print(os.getpid(), "Preparing", args)
    flags = os.CLONE_NEWUSER | os.CLONE_NEWUTS | os.CLONE_NEWPID
    os.unshare(flags)
    # Update the UID/GID mappings for the user namespace
    with open('/proc/self/uid_map', 'w') as uid_map:
        uid_map.write(f"{os.getuid()} {os.getuid()} 1\n")
    with open('/proc/self/setgroups', 'w') as setgroups:
        setgroups.write('deny\n')
    with open('/proc/self/gid_map', 'w') as gid_map:
        gid_map.write(f"{os.getgid()} {os.getgid()} 1\n")
    
    import socket
    socket.sethostname("bla")
    print(os.getpid(), "Running", args)
    os.execvp(args[0], args)

def run(args):
    local, cmd, *args = sys.argv
    cmd = [sys.executable, local, "execute", *args]
    print(os.getpid(), "Running", cmd)
    r = subprocess.run(cmd)
    print(os.getpid(), "Finished", r.returncode)

def main():
    cmd = sys.argv[1]
    if cmd == "run":
        run(sys.argv)
    elif cmd == "execute":
        execute(sys.argv[2:])
    else:
        print(f"Unknown command {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()