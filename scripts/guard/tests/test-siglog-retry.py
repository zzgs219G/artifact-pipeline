#!/usr/bin/env python3
"""test-siglog-retry.py — 「首次启动没日志」bug 的结构契约

═══ 这个 bug 是什么（用户真机实测）═══
装完 App【第一次】打开，sigcheck_log.txt 永远不出现；关掉再打开【第二次】
就有了。同包、同哨兵、同 uid，唯一的差别是"第几次"。

根因在 scripts/guard/src/sig_check.c 的 siglog_detect():
  · 函数第二行就 `siglog_ready = 0`（先假定失败）
  · 而 constructor 阶段 /storage/emulated/0 的 FUSE 可能还没为本 uid 挂载好
    → access(sentinel) 因 EACCES 失败 → 直接 return
    → siglog_ready 永久留在 0 → 本次进程再也不会写文件日志
  · 第二次启动 FUSE 已就绪（首次启动间接促成了挂载）→ 正常

═══ 为什么用"读源码 + 断言结构"而不是运行时测试 ═══
这个 bug 的触发条件是【FUSE 挂载未就绪】——只在真机首次启动那一瞬间存在，
宿主端（Termux/CI）根本没有 FUSE 这个中间层，构造不出来。而真机测试
无法进 CI（无 adb）。

所以退而钉住【能让 bug 复现/修复的代码结构】，并配反向验证：
改回原来的写法 → 本测试必红。这与 test-trusted-route.py 的做法同源
（那里也钉 "return -2 的位置"，因为那个 bug 同样是时序性的）。
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
SRC = os.path.join(ROOT, "scripts", "guard", "src", "sig_check.c")

fails = []


def ok(m):
    print(f"  ✅ {m}")


def bad(m):
    fails.append(m)
    print(f"  ❌ {m}")


def main():
    print("== siglog 重试语义（首次启动没日志的修法）==")
    s = open(SRC, encoding="utf-8").read()

    # 取出 siglog_detect 的整个函数体
    m = re.search(r"static void siglog_detect\(void\)\s*\{(.*?)\n\}", s, re.S)
    if not m:
        bad("找不到 siglog_detect()")
        return 1
    body = m.group(1)
    ok("定位到 siglog_detect()")

    # ── T1 失败不得【无条件】落 0（原 bug 的核心）────────────────────
    # 原写法：函数第二行 `siglog_ready = 0;` —— 一次失败即永久关闭。
    # 现在的 0 只允许出现在「试够上限」那一支里，且必须受计数保护。
    first_zero = re.search(r"siglog_ready\s*=\s*0", body)
    if first_zero:
        before = body[:first_zero.start()]
        (ok if "SIGLOG_MAX_TRIES" in before
         else bad)("T1 落 0 只在「试够上限」之后（不是函数开头无条件预设）")
    else:
        bad("T1 找不到任何落 0 的分支（应当有一条「试够了就放弃」）")

    # ── T2 有重试上限计数 ───────────────────────────────────────────
    (ok if "siglog_tries" in body and "SIGLOG_MAX_TRIES" in body
     else bad)("T2 有重试计数上限（哨兵真不存在时不能无限 access）")

    # ── T3 失败分支保持 -1（即"不写 0"就 return）───────────────────
    # 用 SIGLOG_FAIL 宏或裸 return，关键是失败路径里没有 siglog_ready = 0
    fail_paths = re.findall(r"SIGLOG_FAIL\([^)]*\)", body)
    (ok if fail_paths else bad)("T3 失败分支走统一出口（SIGLOG_FAIL/裸 return）")
    # 「试够次数才落 0」这一支必须存在，否则永远不放弃
    (ok if re.search(r"siglog_tries\s*>=\s*SIGLOG_MAX_TRIES", body)
     else bad)("T3b 试够上限后落 0（不无限重试）")

    # ── T4 siglog() 在未探测时触发探测 ─────────────────────────────
    # 这是修法的第二半：detect 保住 -1 之后，必须有人再触发它，
    # 否则 constructor 那次失败就再也没人重试。
    m2 = re.search(r"static void siglog\(const char \*prio.*?\n\}", s, re.S)
    if not m2:
        bad("找不到 siglog()")
    else:
        sbody = m2.group(0)
        (ok if re.search(r"if \(siglog_ready < 0\)\s*siglog_detect\(\)", sbody)
         else bad)("T4 siglog() 在 siglog_ready<0 时先调 siglog_detect()")

    # ── T5 两个写日志函数都必须：未探测时触发探测 + fopen 失败退回 -1 ──
    # ⚠️ 2026-11-25 实测踩到：本测试第一版只查 siglog()，而 LOGI_S/LOGE_S
    # 走的是【另一个函数】siglog_fmt1()。只修前者等于修了一半 ——
    # 中文文案（签名校验的绝大多数日志）仍然首次启动不可见。
    # 所以两个函数都要断言，缺一个就红。
    for fname in ("siglog", "siglog_fmt1"):
        mf = re.search(rf"static void {fname}\(.*?\n\}}", s, re.S)
        if not mf:
            bad(f"T5 找不到 {fname}()")
            continue
        fb = mf.group(0)
        (ok if re.search(r"if \(siglog_ready < 0\)\s*siglog_detect\(\)", fb)
         else bad)(f"T5a {fname}() 未探测时先调 siglog_detect()")
        fm = re.search(r'fp = fopen\(siglog_path, "a"\);(.{0,300}?)\n\s*clock_gettime',
                       fb, re.S)
        seg = fm.group(1) if fm else ""
        (ok if "siglog_ready = -1" in seg and "siglog_ready = 0" not in seg
         else bad)(f"T5b {fname}() fopen 失败退回 -1（可重试），不落 0")

    # ── T6 失败原因进 logcat（不能静默）─────────────────────────────
    # 判据：siglog_detect 里出现 LOGI(...) 的身影。
    # ⚠️ 必须用早期 LOGI（logcat only）：LOGI_S 定义在文件后部，此处不可见；
    #    若有人"顺手统一"成 LOGI_S，编译会炸 —— 那也是对的（早发现）。
    (ok if re.search(r'\bLOGI\(', body)
     else bad)("T6 失败原因进 logcat（用户能看到「为什么没日志」）")

    # ── T7 单独识别「哨兵被建成目录」这一独立成因 ───────────────────
    (ok if "S_ISDIR" in body
     else bad)("T7 单独识别「哨兵被建成目录」（与「不存在」区分开）")

    # ── T8 日志目录不存在时自己建（首次启动的第二个坑）──────────────
    # 实测（2026-11-25 真机）：干净安装后第一次启动，
    # /storage/emulated/0/Android/data/<pkg>/files 【目录还不存在】
    # （系统在 App 首次运行时才建）→ access(W_OK) 得 ENOENT →
    # 判"不可写" → 日志关闭。nox 的报告模块能写出 ncguard_log.md，
    # 正是因为它自己 mkdir 了。
    (ok if "ENOENT" in body and "mkdir(" in body
     else bad)("T8 目录不存在时自己 mkdir（首启 files/ 尚未创建）")
    # 反向：删掉 ENOENT 分支 → 这行红。

    print(f"\n=== 结果: {10 - len(fails)} 通过, {len(fails)} 失败 ===")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
