import os
import socket

TEXT = f"""\
PID: {os.getpid()}
UID: {os.getuid()}
GID: {os.getuid()}
CWD: {os.getcwd()}

host: {socket.gethostname()}"""

print(TEXT)