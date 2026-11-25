#!/usr/bin/env python3
"""test-siglog-retry.py — 「首次启动没日志」的结构契约

═══ 这个 bug 是什么（用户真机实测）═══
装完 App【第一次】打开，sigcheck_log.txt 永远不出现；关掉再打开【第二次】
就有了。同包、同哨兵、同 uid，唯一的差别是"第几次"。

═══ 根因（两层，都已实测确认）═══
① 探测是"一次性"的：失败后 siglog_ready 永久留在 0，本次进程再也不写。
   而 constructor 期 /storage/emulated/0 的 FUSE 可能还没为本 uid 就绪。
② 日志目录 /…/<pkg>/files 由 system_server 在「应用数据目录初始化」时创建，
   晚于本 so 的 constructor；且 <pkg>/ 这一层 App **无权自建**
   （父目录 drwxrws--x，其他用户 --x）。真机实测：
       nc_log: mkdir ... failed (pkg_rc=13 files_rc=2)
   pkg_rc=13 = EACCES，证明是权限模型决定的，不是能靠 mkdir 绕过的。

═══ 现在的设计（2026-11-25）═══
日志实现已抽取到 scripts/guard/src/nc_log.c（唯一实现）：
  · 失败保持 -1（可重试），落 0 只发生在「试够 NC_LOG_MAX_TRIES 次」
  · 目录不存在时尝试 mkdir（<pkg>/ 与 files/ 两层）
  · 仍失败则保持可重试，并由 sig_check.c constructor 末尾的
    nc_log_late_flush() 起短延时线程（1~2 秒）补写一条【摘要】
  · 摘要只存 3 个整数（rc / 路数 / 裁决码）——
    缓冲全文会让解密后的明文常驻 .bss，Frida Memory.scan 可整块读走，
    与"字符串必须密文化"的纪律冲突（用户提出后定下的取舍）

═══ 为什么用"读源码 + 断言结构"而不是运行时测试 ═══
这个 bug 的触发条件是【FUSE 挂载未就绪 / 系统目录尚未创建】——只在真机
首次启动那一瞬间存在，宿主端（Termux/CI）没有这两个中间层，构造不出来；
真机测试又进不了 CI。所以钉住"能让 bug 复现/修复的代码结构"，
与 test-trusted-route.py 同源（那里钉的也是时序性 bug 的代码位置）。
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
NCLOG = os.path.join(ROOT, "scripts", "guard", "src", "nc_log.c")
SIGCHK = os.path.join(ROOT, "scripts", "guard", "src", "sig_check.c")
ENVCHK = os.path.join(ROOT, "scripts", "guard", "src", "env_check.c")

fails = []


def strip_comments(text):
    """去掉 C 注释，只留代码 —— 本模块大量断言会被注释里的"历史说明"误判。
    （实测踩过：T10 只因注释里写着 `envlog_ready = 0` 就报红。）"""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//[^\n]*', '', text)
    return text


def ok(m):
    print(f"  ✅ {m}")


def bad(m):
    fails.append(m)
    print(f"  ❌ {m}")


def main():
    print("== 文件日志：首次启动可写性契约 ==")
    s = open(NCLOG, encoding="utf-8").read()

    m = re.search(r"int nc_log_open\(void\)\s*\{(.*?)\n\}", s, re.S)
    if not m:
        bad("找不到 nc_log_open()")
        return 1
    body = m.group(1)
    ok("定位到 nc_log_open()")

    # ── T1 失败不得【无条件】落 0（原 bug 的核心）──────────────────────
    first_zero = re.search(r"nc_log_state\s*=\s*0", body)
    if first_zero:
        before = body[:first_zero.start()]
        (ok if "NC_LOG_MAX_TRIES" in before or "SIGCHECK_HOST_TEST" in before
         else bad)("T1 落 0 有前置条件（不是函数开头无条件预设）")
    else:
        bad("T1 找不到任何落 0 的分支（应当有一条「试够了就放弃」）")

    # ── T2 有重试上限 ─────────────────────────────────────────────────
    (ok if "NC_LOG_MAX_TRIES" in s
     else bad)("T2 有重试计数上限（哨兵真不存在时不能无限探测）")

    # ── T3 目录不存在时自己 mkdir（首启 files/ 尚未创建）──────────────
    code = strip_comments(s)
    (ok if "mkdir(" in code and ("ENOENT" in code or "EEXIST" in code)
     else bad)("T3 目录不存在时尝试 mkdir（首启 files/ 尚未创建）")

    # ── T4 mkdir 失败不致命：保持可重试 ───────────────────────────────
    # 真机实测 pkg_rc=13(EACCES) —— <pkg>/ 由系统托管，App 无权建。
    # 此时必须"保持 -1 等下次"，而不是判死。
    mm = re.search(r"static int nc_log_mkdir_target\(.*?\n\}", s, re.S)
    mb = mm.group(0) if mm else ""
    (ok if "EEXIST" in mb
     else bad)("T4 mkdir 把 EEXIST 当正常（系统可能已建好）")

    # ── T5 目录不可写时 nc_log_open 返回 0 但【不落 0 状态】───────────
    (ok if re.search(r"dir not ready yet", body)
     else bad)("T5 目录未就绪时留诊断信息并保持可重试")

    # ── T6 两个写日志函数都必须：未就绪时触发探测 + fopen 失败退回 -1 ──
    # ⚠️ 2026-11-25 实测踩到：第一版只查 siglog()，而 LOGI_S/LOGE_S 走
    #    的是另一个函数。只修前者等于修了一半 —— 中文文案仍然首启不可见。
    #    抽取到 nc_log.c 后只剩一个 nc_log_line()，但仍要对它断言，
    #    防止将来又被人拆成两份。
    ml = re.search(r"void nc_log_line\(.*?\n\}", s, re.S)
    lb = ml.group(0) if ml else ""
    (ok if re.search(r"if \(nc_log_state < 0\)\s*nc_log_open\(\)", lb)
     else bad)("T6a nc_log_line() 未探测时先调 nc_log_open()")
    (ok if "nc_log_state = -1" in lb and "nc_log_state = 0" not in lb
     else bad)("T6b nc_log_line() fopen 失败退回 -1（可重试），不落 0")

    # ── T7 摘要只存整数，不存日志文本（安全取舍的落实）────────────────
    (ok if re.search(r"signed char nc_sum_\w+", s)
     else bad)("T7 首启摘要用 signed char 存整数（不引入明文常驻）")

    # ── T7b 摘要只在【非负】时覆盖 ────────────────────────────────────
    # 三个值分散在不同分支填（routes 在 sig_collect_fp 汇总点、
    # verdict 在放行分支、rc 在 env_check 解锁处）。若后写分支用 -1
    # 无条件覆盖，先写的信息就丢 —— 实测 routes 一直是 -1。
    ms = re.search(r"void nc_log_summary\(.*?\n\}", s, re.S)
    sb = ms.group(0) if ms else ""
    (ok if re.search(r"if \(routes\s+>= 0\)", sb)
     and re.search(r"if \(verdict\s+>= 0\)", sb)
     else bad)("T7b 摘要只更新非负值（分支互不覆盖）")

    # ── T8 延时补写存在，且延时在 1~2 秒（用户明确要求"一两秒出结果"）──
    mt = re.search(r"nc_log_late_thread\(.*?\n\}", s, re.S)
    tb = mt.group(0) if mt else ""
    delays = [int(x) for x in re.findall(r"sleep\((\d+)\)", tb)]
    (ok if delays and all(1 <= d <= 2 for d in delays)
     else bad)(f"T8 延时线程在 1~2 秒内重试（实得 sleep={delays}）")

    # ── T9 constructor 末尾必须触发延时补写 ───────────────────────────
    sc = open(SIGCHK, encoding="utf-8").read()
    # ⚠️ 不能写 `.*?\n\}` —— __attribute__((constructor)) 本身带括号，
    #    非贪婪匹配会在那里提前收尾。改成锚定函数名。
    me = re.search(r"sig_check_entry\(void\)\s*\{(.*?)\n\}", sc, re.S)
    eb = me.group(1) if me else ""
    (ok if "nc_log_late_flush" in strip_comments(eb)
     else bad)("T9 sig_check constructor 末尾调 nc_log_late_flush()")

    # ── T10 两份旧实现必须已消失（防止有人把它加回来）────────────────
    ec = strip_comments(open(ENVCHK, encoding="utf-8").read())
    (ok if "envlog_detect" not in ec and "envlog_ready" not in ec
     else bad)("T10 env_check.c 不再自带 envlog 实现（已委托 nc_log）")
    sc_code = strip_comments(sc)
    (ok if "siglog_detect" not in sc_code and "siglog_ready" not in sc_code
     else bad)("T10b sig_check.c 不再自带 siglog 实现（已委托 nc_log）")

    print(f"\n=== 结果: {13 - len(fails)} 通过, {len(fails)} 失败 ===")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
