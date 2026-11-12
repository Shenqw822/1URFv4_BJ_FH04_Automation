#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ACL 规则重复下发/删除压力测试。

流程（默认重复 500 次，可用命令行参数指定次数）：
    1. 运行 RcpApiNew_2.py，向设备下发 4000 条 L2 规则
    2. telnet 执行 show rule number，记录规则数量
    3. telnet 执行 undo acl all，删除所有规则
    4. telnet 执行 show rule number，记录 rcptotal/total/rcpforward 字段值

用法：
    E:/app/python/python.exe loop_acl_test.py            # 跑 500 轮
    E:/app/python/python.exe loop_acl_test.py 2          # 先跑 2 轮验证脚本本身

日志写入同目录 loop_acl_test.log。
"""
import os
import re
import sys
import time
import telnetlib
import subprocess
import datetime

# Windows 控制台中文乱码修复（Python 3.7+）
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---------------- 设备连接参数 ----------------
HOST = "192.168.128.235"   # 被测设备 IP
PORT = 9999                # telnet 登录端口
USER = "sysadmin"          # 登录用户名
PWD = "sysadmin"           # 登录密码
PROMPT = b"sysadmin(config)#"   # 配置模式提示符

# ---------------- 测试参数 ----------------
LOOPS = 500              # 默认循环次数
EXPECT = 4000            # 下发后预期规则数量（rcptotal/total/rcpforward 均应等于该值）
RC_FILE = "RcpApiNew_2.py"
LOG_FILE = "loop_acl_test.log"

RC_DIR = os.path.dirname(os.path.abspath(__file__))
RC_PATH = os.path.join(RC_DIR, RC_FILE)
LOG_PATH = os.path.join(RC_DIR, LOG_FILE)


def log(msg):
    line = "[%s] %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_rcp():
    """运行 RcpApiNew_2.py 下发 4000 条 L2 规则，返回进程退出码。"""
    result = subprocess.run(
        [sys.executable, RC_PATH],
        cwd=RC_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    return result.returncode


def telnet_login():
    """连接并登录设备，进入配置模式，返回 telnet 连接对象。"""
    tn = telnetlib.Telnet(HOST, PORT, timeout=30)
    tn.read_until(b"user:", timeout=30)
    tn.write(USER.encode() + b"\r\n")
    tn.read_until(b"password:", timeout=30)
    tn.write(PWD.encode() + b"\r\n")
    tn.read_until(b"sysadmin", timeout=30)   # 等待登录后提示符（sysadmin> / sysadmin#）
    time.sleep(0.5)
    tn.read_very_eager()
    tn.write(b"config\r\n")
    tn.read_until(PROMPT, timeout=30)
    tn.write(b"terminal length 0\r\n")
    tn.read_until(PROMPT, timeout=30)
    return tn


def run_cli(tn, cmd, timeout=60):
    """在 telnet 连接上执行一条命令，返回命令输出文本。"""
    tn.write(cmd.encode() + b"\r\n")
    out = tn.read_until(PROMPT, timeout=timeout)
    return out.decode(errors="ignore")


def parse_fields(out):
    """解析 show rule number 输出中的 "key : value" 字段，返回字典。"""
    fields = {}
    for m in re.finditer(r"(\S[\w ]*?)\s*:\s*(\d+)", out):
        fields[m.group(1).strip()] = int(m.group(2))
    return fields


def main():
    global LOOPS
    if len(sys.argv) > 1:
        LOOPS = int(sys.argv[1])

    log("===== 开始 ACL 重复下发/删除测试，共 %d 轮 =====" % LOOPS)
    start_all = time.time()
    add_fail = 0      # 下发后数量不为 EXPECT 的轮数
    fail_count = 0    # 脚本异常（RCP退出码非0 / telnet异常）的轮数

    for i in range(1, LOOPS + 1):
        t0 = time.time()
        # 1. 下发 4000 条 L2 规则
        rc = run_rcp()
        t_rcp = time.time() - t0

        if rc != 0:
            fail_count += 1
            log("[第 %d/%d 轮] RCP 下发异常退出(returncode=%d)，跳过本轮" % (i, LOOPS, rc))
            continue

        # 2-4. telnet 查询 -> 删除 -> 再查询
        tn = None
        try:
            tn = telnet_login()
            out1 = run_cli(tn, "show rule number")
            f1 = parse_fields(out1)
            total1 = f1.get("total")
            rcptotal1 = f1.get("rcptotal")
            rcpforward1 = f1.get("rcpforward")

            run_cli(tn, "undo acl all")
            out2 = run_cli(tn, "show rule number")
            f2 = parse_fields(out2)
            total2 = f2.get("total")
            rcptotal2 = f2.get("rcptotal")
            rcpforward2 = f2.get("rcpforward")
        except Exception as e:
            fail_count += 1
            log("[第 %d/%d 轮] 异常: %s: %s" % (i, LOOPS, type(e).__name__, e))
            continue
        finally:
            if tn:
                try:
                    tn.close()
                except Exception:
                    pass

        # 下发后验算：rcptotal/total/rcpforward 应全为 EXPECT
        add_ok = (total1 == EXPECT and rcptotal1 == EXPECT and rcpforward1 == EXPECT)
        if not add_ok:
            add_fail += 1

        add_info = "total=%s rcptotal=%s rcpforward=%s" % (total1, rcptotal1, rcpforward1)
        del_info = "total=%s rcptotal=%s rcpforward=%s" % (total2, rcptotal2, rcpforward2)
        add_mark = "OK" if add_ok else "FAIL(期望%d)" % EXPECT

        log("[第 %d/%d 轮] 下发后 %s [%s] -> undo acl all 后 %s (rcp耗时 %.1fs)"
            % (i, LOOPS, add_info, add_mark, del_info, t_rcp))

    total_time = time.time() - start_all
    log("===== 测试完成: 共 %d 轮, 下发数量异常 %d 轮, 脚本异常 %d 轮, 总耗时 %.1fs ====="
        % (LOOPS, add_fail, fail_count, total_time))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已手动中断 (Ctrl+C)")
