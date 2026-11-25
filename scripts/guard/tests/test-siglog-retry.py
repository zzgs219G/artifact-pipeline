#!/usr/bin/env python3
"""test-siglog-retry.py — 文件日志「目录没建就等 2 秒」的契约

═══ 这个模块解决什么问题（真机实测）═══
日志目录 /storage/emulated/0/Android/data/<pkg>/files 不是系统在启动时
创建，而是【第一次有文件写入时才被隐式创建】。本 so 的 constructor 跑在
那之前，所以第一次写日志时目录必然不存在。

实测时间线（2026-11-25 09:19，干净安装 + 只启动一次）：
  09:19:19.611  进程启动
  09:19:19.719  constructor 探测 → 目录不存在（mkdir 得 EACCES 13）
  09:19:21.740  等 2 秒后重试 → 目录已可写 → 写入成功

另外两条实测结论：
  · <pkg>/ 这层 App 无权自建 —— 父目录 Android/data 权限 drwxrws--x
    （其他用户 --x，能进不能写），mkdir 必然 EACCES。只能等，不能强建。
  · 目录出现时间不可预测（实测 2 秒 ~ 104 秒），所以等待必须可重复。

═══ 设计（用户拍板的极简版）═══
  目录没建 → 等 2 秒再查；建了 → 直接写。
  砍掉了中途试过的：探测配额、失败节流、异步轮询线程、结论摘要。
  理由：它们的总收益只是"首次启动多一条摘要"，代价是 400 行 + 一堆
  互相影响的开关。

═══ 为什么用"读源码断言结构"而不是运行时测试 ═══
触发条件（files/ 目录尚未创建）只在真机首次启动那一瞬间存在，宿主端
没有这个中间层。真机测试又进不了 CI。所以钉住"能让修复成立的结构"，
与 test-trusted-route.py 同源。
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
NCLOG_C = os.path.join(ROOT, "scripts", "guard", "src", "nc_log.c")
NCLOG_H = os.path.join(ROOT, "scripts", "guard", "src", "nc_log.h")
SIGCHK = os.path.join(ROOT, "scripts", "guard", "src", "sig_check.c")
ENVCHK = os.path.join(ROOT, "scripts", "guard", "src", "env_check.c")

fails = []


def ok(m):
    print(f"  ✅ {m}")


def bad(m):
    fails.append(m)
    print(f"  ❌ {m}")


def strip_comments(text):
    """去掉 C 注释 —— 本模块大量断言会被注释里的历史说明误判。"""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//[^\n]*', '', text)
    return text


def main():
    print("== 文件日志：目录没建就等 2 秒 ==")
    c = open(NCLOG_C, encoding="utf-8").read()
    h = open(NCLOG_H, encoding="utf-8").read()
    code = strip_comments(c)

    # ── T1 有"等待 + 重查"的循环（本模块的核心）────────────────────────
    m = re.search(r"int nc_log_open\(void\)\s*\{(.*?)\n\}", c, re.S)
    if not m:
        bad("找不到 nc_log_open()")
        return 1
    body = m.group(1)
    ok("定位到 nc_log_open()")
    (ok if "nc_log_retry" in code
     else bad)("T1 有 nc_log_retry()（饭没好，过会儿再看）")

    # ── T2 重试由【独立线程】驱动，不是主线程原地等 ─────────────────────
    ec0 = strip_comments(open(ENVCHK, encoding="utf-8").read())
    (ok if "nc_log_retry()" in ec0
     else bad)("T2 nc_log_retry 由 env_check 看门狗（独立线程）调用")

    # ── T3 看门狗调 retry 的位置必须在循环内（每轮都试）────────────────
    wd = re.search(r"static void \*env_watchdog.*?\n\}", ec0, re.S)
    (ok if wd and "nc_log_retry()" in wd.group(0)
     else bad)("T3 nc_log_retry 在看门狗循环内（每轮重试一次）")

    # ── T4 哨兵不存在时【立刻放弃】，不等待 ────────────────────────────
    # 哨兵没开是常态（用户不开日志），不能为此让启动白等 10 秒。
    # 判据：哨兵 access 失败的分支里直接落 0 并 return（不是继续往下等）
    seg = re.search(r"access\(sentinel,\s*F_OK\)\s*!=\s*0\)\s*\{(.{0,200}?)\n\s*\}",
                    body, re.S)
    (ok if seg and "nc_log_state = 0" in seg.group(1) and "return 0" in seg.group(1)
     else bad)("T4 哨兵不存在时立刻放弃（不进入等待）")

    # ── T5 目录不可写时打到 logcat，带 [no-file] 标记 ─────────────────
    (ok if "[no-file]" in code
     else bad)("T5 文件写不了时打 logcat 并标 [no-file]（排障不丢信息）")

    # ── T6 只有一个状态机：两份旧实现必须已消失 ────────────────────────
    ec = strip_comments(open(ENVCHK, encoding="utf-8").read())
    sc = strip_comments(open(SIGCHK, encoding="utf-8").read())
    (ok if "envlog_detect" not in ec and "envlog_ready" not in ec
     else bad)("T6a env_check.c 不再自带 envlog 实现（已委托 nc_log）")
    (ok if "siglog_detect" not in sc and "siglog_ready" not in sc
     else bad)("T6b sig_check.c 不再自带 siglog 实现（已委托 nc_log）")

    # ── T7 已砍掉的复杂度不得复活 ──────────────────────────────────────
    # 这是本次回滚的核心：中途加过的四样东西全部删除，防止有人"顺手加回来"。
    for gone, why in (
        ("nc_log_summary",       "结论摘要"),
        ("nc_log_late_flush",    "异步补写线程"),
        ("nc_log_dir_probe",     "独立轮询探针"),
        ("NC_LOG_WAIT_MS",       "同步等待参数（会导致启动卡死）"),
    ):
        (ok if gone not in strip_comments(c) and gone not in strip_comments(h)
         and gone not in strip_comments(sc) and gone not in strip_comments(ec)
         else bad)(f"T7 {gone}（{why}）已彻底移除")

    # ── T8 不缓冲日志文本（不引入明文常驻内存）────────────────────────
    # 用户提出"内存缓冲不安全"，成立：解密后的明文常驻 .bss，Frida
    # Memory.scan 可整块读走，与"字符串必须密文化"的纪律冲突。
    (ok if not re.search(r"(static\s+)?char\s+\w*buf\w*\[\s*\d{4,}\s*\]", code)
     else bad)("T8 不缓冲日志文本（无大块明文常驻内存）")

    print(f"\n=== 结果: {10 - len(fails)} 通过, {len(fails)} 失败 ===")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
