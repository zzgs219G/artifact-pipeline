#!/usr/bin/env python3
"""test-trusted-route.py — 多路取证书「可信路线优先」判据的静态契约

==== 背景（2026-11-25）====
旧判据是「任意两路指纹不一致 → 杀」。盲区（真机事故 Nivii）：
加固 + 去校验组合包里，3 路 libc 被重定向到 origin.apk（诱饵证书）、
3 路内联 svc 读到真 base.apk → 3:3 分裂 → 主人自己签的包也闪退。

类比：门卫只清点"陌生面孔"，不看"主人是否在场"。

新判据：可信路线（svc/syscall/sysfd）优先 —— hook 够不到它们，
读到的必然是当前安装包。与基准一致 → 放行；不一致 → 杀。
详见 scripts/guard/docs/多路取证书判定逻辑.md。

==== 为什么要静态断言 ====
宿主端编不出内联 svc（`#if defined(__aarch64__) || defined(__arm__)`
在宿主为假）→ 无法在宿主复现 3:3 分裂场景。本测试改钉【代码结构】：
  T1 sig_check.c 有 sig_route_is_trusted 且覆盖 3/4/5 三条
  T2 sig_guard2.c 有独立实现的 g2_route_is_trusted（零共享约束）
  T3 mismatch → return -2 只出现在「可信路线不可用」的分支里
  T4 trust 判定发生在「与基准比对」之前（不能先杀后问）
  T5 文档存在且含关键结论（防文档漂移）

⚠️ 反向验证（已做）：把 T3 的 return -2 挪回可信分支之前 → T3 红。
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
SIG1 = os.path.join(ROOT, "scripts", "guard", "src", "sig_check.c")
SIG2 = os.path.join(ROOT, "scripts", "guard", "src", "sig_guard2.c")
DOC = os.path.join(ROOT, "scripts", "guard", "docs", "多路取证书判定逻辑.md")

PASS = FAIL = 0


def ok(m):
    global PASS
    PASS += 1
    print(f"  ✅ {m}")


def bad(m):
    global FAIL
    FAIL += 1
    print(f"  ❌ {m}", file=sys.stderr)


def main():
    for p in (SIG1, SIG2, DOC):
        if not os.path.isfile(p):
            print(f"❌ 缺文件: {p}", file=sys.stderr)
            return 1
    s1 = open(SIG1, encoding="utf-8").read()
    s2 = open(SIG2, encoding="utf-8").read()
    doc = open(DOC, encoding="utf-8").read()

    # ── T1 第一线：可信路线函数覆盖 3/4/5 ──
    m = re.search(r"static int sig_route_is_trusted\(int route\)\s*\{(.*?)\n\}", s1, re.S)
    if not m:
        bad("T1 sig_check.c 缺 sig_route_is_trusted")
    else:
        body = m.group(1)
        missing = [r for r in ("SIG_ROUTE_SYSCALL", "SIG_ROUTE_SVC", "SIG_ROUTE_FD")
                   if r not in body]
        if missing:
            bad(f"T1 可信路线漏了: {missing}")
        elif any(r in body for r in ("SIG_ROUTE_OPENAT", "SIG_ROUTE_OPENAT64")):
            bad("T1 可信路线误含 libc 路线（openat/openat64 会被去校验 hook）")
        else:
            ok("T1 第一线可信路线 = syscall/svc/sysfd（不含任何 libc 路线）")

    # ── T2 第二线：独立实现（零代码共享）──
    if "g2_route_is_trusted" not in s2:
        bad("T2 sig_guard2.c 缺 g2_route_is_trusted（第二线未同步）")
    elif "sig_route_is_trusted" in s2.replace("g2_route_is_trusted", ""):
        bad("T2 第二线调用了第一线的函数（违反零代码共享）")
    else:
        ok("T2 第二线有独立实现的 g2_route_is_trusted")

    # ── T3 return -2 只在可信路线不可用的分支 ──
    # 判据：sig_collect_fp 里，`return -2` 必须出现在含
    # "trusted_from" 判空之后（即 trusted_from < 0 的路径）。
    blk = re.search(r"static int sig_collect_fp\(unsigned char actual\[32\]\)\s*\{(.*)\n\}",
                    s1, re.S)
    if not blk:
        bad("T3 找不到 sig_collect_fp")
    else:
        b = blk.group(1)
        pos_trust = b.find("trusted_from >= 0")
        pos_ret2 = [m.start() for m in re.finditer(r"return -2", b)]
        if pos_trust < 0:
            bad("T3 sig_collect_fp 里没有 trusted_from 判定（判据未生效）")
        elif not pos_ret2:
            bad("T3 没有 return -2（劫持判定被删了？）")
        elif any(p < pos_trust for p in pos_ret2):
            bad("T3 存在「可信路线判定之前」的 return -2 —— 又变成「先杀后问」"
                "（这正是 Nivii 闪退的根因）")
        else:
            ok(f"T3 所有 return -2 都在可信路线判定之后（共 {len(pos_ret2)} 处）")

    # ── T4 可信路线的指纹要交给基准比对，不是直接 return 0 放行 ──
    # 第一线：放行前必须调 derive_expected（与 SIG_HASH_STORED 比对）
    if "derive_expected((const unsigned char *)trusted_fp, expect)" not in s1:
        bad("T4 第一线未把可信路线指纹与基准比对（直接放行 = 失去防护）")
    elif "SIG_HASH_STORED" not in s1:
        bad("T4 找不到基准 SIG_HASH_STORED")
    else:
        ok("T4 第一线：可信路线指纹与基准比对后才放行")

    # 第二线：g2_verify 负责比对（g2_collect_fp 只采数据）
    if "g2_collect_fp(fp)" not in s2 or "g2_derive(fp, expected)" not in s2:
        bad("T4b 第二线 g2_verify 未做基准比对")
    else:
        ok("T4b 第二线：采集与比对仍分离（g2_verify 拿可信指纹与 SG2_STORED 比）")

    # ── T5 文档含关键结论 ──
    keys = ["主人", "陌生人", "可信路线", "内联 svc", "去校验"]
    missing = [k for k in keys if k not in doc]
    if missing:
        bad(f"T5 判定逻辑文档缺关键内容: {missing}")
    else:
        ok("T5 判定逻辑文档在，且含「主人/陌生人」比喻与可信路线结论")

    print(f"=== 结果: {PASS} 通过, {FAIL} 失败 ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
