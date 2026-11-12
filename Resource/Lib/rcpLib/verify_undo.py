#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""一次性验证：undo acl all 命令是否被执行、设备返回什么。"""
import telnetlib
import time
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

tn = telnetlib.Telnet("192.168.128.235", 9999, timeout=30)
tn.read_until(b"user:", timeout=30)
tn.write(b"sysadmin\r\n")
tn.read_until(b"password:", timeout=30)
tn.write(b"sysadmin\r\n")
tn.read_until(b"sysadmin", timeout=30)
time.sleep(0.5)
tn.read_very_eager()
tn.write(b"config\r\n")
tn.read_until(b"sysadmin(config)#", timeout=30)
tn.write(b"terminal length 0\r\n")
tn.read_until(b"sysadmin(config)#", timeout=30)

tn.write(b"show rule number\r\n")
out = tn.read_until(b"sysadmin(config)#", timeout=30)
print("===== show rule number (undo 前) =====")
print(out.decode(errors="ignore"))

tn.write(b"undo acl all\r\n")
out = tn.read_until(b"sysadmin(config)#", timeout=60)
print("===== undo acl all 命令输出 =====")
print(out.decode(errors="ignore"))

tn.write(b"show rule number\r\n")
out = tn.read_until(b"sysadmin(config)#", timeout=30)
print("===== show rule number (undo 后) =====")
print(out.decode(errors="ignore"))

tn.close()
