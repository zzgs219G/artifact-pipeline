#!/usr/bin/env python3
"""test-siglog-retry.py — 文件日志的契约

逻辑（用户定的，就这一条）：
  检测文件夹是否存在 → 存在就打印；不存在，过 2 秒再打印。

唯一的坑：日志由 constructor 调用，constructor 在主线程上。
所以"等 2 秒"必须在后台线程 —— 主线程睡 2 秒，App 就起不来。
（2026-11-25 真机事故：写成同步 usleep 后 App 点了图标进不去。）

为什么不靠其它模块的线程：只勾 --sigcheck 不勾 --envcheck 时，
envcheck 的看门狗根本不存在。日志必须自给自足。
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
NCLOG_C = os.path.join(ROOT, "scripts", "guard", "src", "nc_log.c")
SIGCHK = os.path.join(ROOT, "scripts", "guard", "src", "sig_check.c")
ENVCHK = os.path.join(ROOT, "scripts", "guard", "src", "env_check.c")

fails = []


def ok(m):
    print(f"  ✅ {m}")


def bad(m):
    fails.append(m)
    print(f"  ❌ {m}")


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//[^\n]*', '', text)
    return text


def main():
    print("== 文件日志：存在就打印，不存在过 2 秒再打印 ==")
    c = open(NCLOG_C, encoding="utf-8").read()
    code = strip_comments(c)

    # ── T1 三层逻辑齐备 ───────────────────────────────────────────────
    (ok if "nc_log_dir_exists" in code else bad)("T1a 有「文件夹存在吗」检查")
    (ok if "nc_log_write" in code else bad)("T1b 有「写一行」")
    (ok if "nc_log_later" in code else bad)("T1c 有「过 2 秒再打印」")

    # ── T2 sleep 只能在后台线程里 ─────────────────────────────────────
    # 反向：把 sleep 挪回 nc_log_line → 这行红（并会真的卡死 App）。
    lt = re.search(r"static void \*nc_log_later\(.*?\n\}", code, re.S)
    (ok if lt and "sleep" in lt.group(0)
     else bad)("T2 sleep 在 nc_log_later 后台线程内")
    mline = re.search(r"void nc_log_line\(.*?\n\}", code, re.S)
    lb = mline.group(0) if mline else ""
    (ok if "sleep" not in lb
     else bad)("T2b nc_log_line 内无 sleep（它由 constructor 调用）")

    # ── T3 写不了就打 logcat 并标 [no-file] ───────────────────────────
    (ok if "[no-file]" in code
     else bad)("T3 写不了文件时打 logcat（标 [no-file]）")

    # ── T4 不耦合其它模块（只勾 --sigcheck 时 envcheck 不存在）────────
    ec = strip_comments(open(ENVCHK, encoding="utf-8").read())
    (ok if "nc_log_retry" not in ec and "nc_log_wait" not in ec
     else bad)("T4 日志不耦合 env_check 看门狗（自给自足）")

    # ── T5 两份旧实现必须已消失 ───────────────────────────────────────
    sc = strip_comments(open(SIGCHK, encoding="utf-8").read())
    (ok if "envlog_detect" not in ec and "envlog_ready" not in ec
     else bad)("T5a env_check.c 不再自带 envlog 实现")
    (ok if "siglog_detect" not in sc and "siglog_ready" not in sc
     else bad)("T5b sig_check.c 不再自带 siglog 实现")

    # ── T6 已砍掉的复杂度不得复活 ─────────────────────────────────────
    for gone in ("nc_log_summary", "nc_log_late_flush",
                 "nc_log_dir_probe", "NC_LOG_WAIT_MS", "nc_log_retry"):
        (ok if gone not in code and gone not in sc and gone not in ec
         else bad)(f"T6 {gone}（已砍掉的复杂度）未复活")

    # ── T7 不缓冲日志文本（不引入明文常驻内存）────────────────────────
    (ok if not re.search(r"static\s+char\s+\w*buf\w*\[\s*\d{4,}\s*\]", code)
     else bad)("T7 不缓冲日志文本（无大块明文常驻）")

    print(f"\n=== 结果: {11 - len(fails)} 通过, {len(fails)} 失败 ===")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
