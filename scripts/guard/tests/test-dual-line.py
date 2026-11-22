#!/usr/bin/env python3
"""test-dual-line.py — 双签名校验线的【独立性】契约测试（纯 stdlib，秒级）。

【为什么需要它】
  `AGENTS.md` §1 把 `sig_check.c` / `sig_guard2.c` 称作"双线互备"，
  设计意图是：攻击者破解/改掉一条线，另一条仍在判定。
  但此前**没有任何测试证明这个意图成立**：
    · test-sig-verify.sh 只测第一线（sig_check.c）
    · test-sig-guard2.sh 只测第二线（sig_guard2.c）
    · 两条各自绿 ≠ 双线互备成立

  本测试钉的是"独立性"这个契约本身，而不是任何一条线的判定逻辑。

【测什么】
  D1 两条线不共享判定常量（SIG_* vs SG2_*，改了不会互相顶替）
  D2 两条线的轮1 不同源（第二线带 "G2" 域分隔）
  D3 两条线的轮2 公式不同（同一条派生逻辑被复用 = 一条破全破）
  D4 两条线的处置路径不同（同一路径 = 一个 patch 断两条）
  D5 两条线各自有 constructor 入口
  D6 两条线不 include 对方的头文件（零代码共享）
  D7 ⚠️ **如实标注共享面**：APK 定位都走 dladdr/maps —— 这是单点，
     不是缺陷，但必须在文档里写明，不能宣称"完全独立"

【这一条最重要的意义】
  D7 是"反向断言"：它断言两条线【确实】共用 APK 定位。
  将来若有人"优化"成各自独立定位，D7 会红 —— 那时应当更新文档并
  放宽 D7，而不是把 D7 删掉。写死"已知共享面"，防止文档与代码漂移。

用法: python3 scripts/guard/tests/test-dual-line.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
SRC = os.path.join(ROOT, 'scripts', 'guard', 'src')
L1 = os.path.join(SRC, 'sig_check.c')
L2 = os.path.join(SRC, 'sig_guard2.c')
GEN = os.path.join(ROOT, 'scripts', 'guard', 'hash', 'make-sig-hash.sh')

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  ✅ {msg}")


def bad(msg):
    global FAIL
    FAIL += 1
    print(f"  ❌ {msg}", file=sys.stderr)


def check(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        bad(f"{name}{(' — ' + detail) if detail else ''}")


def read(p):
    with open(p, encoding='utf-8') as f:
        return f.read()


def code_only(text):
    """去注释行 —— 注释里写历史形态是允许的，断言只看真实代码。"""
    out = []
    for ln in text.splitlines():
        st = ln.lstrip()
        if st.startswith(('*', '/*', '//')):
            continue
        out.append(ln)
    return '\n'.join(out)


def main():
    for p in (L1, L2, GEN):
        if not os.path.isfile(p):
            print(f"❌ 缺少 {p}", file=sys.stderr)
            return 1

    l1_raw, l2_raw = read(L1), read(L2)
    l1, l2 = code_only(l1_raw), code_only(l2_raw)
    gen = read(GEN)

    print("[D1] 两条线不共享判定常量（改一条不会连带另一条）")

    # 第一线用 SIG_HASH_STORED / SIG_SALT；第二线用 SG2_STORED / SG2_SALT。
    # 若第二线开始引用 SIG_*，说明有人把它"统一"了 —— 那会让双线退化单线。
    check("第一线用 SIG_HASH_STORED", 'SIG_HASH_STORED' in l1)
    check("第二线用 SG2_STORED", 'SG2_STORED' in l2)
    check("第二线【不】引用 SIG_HASH_STORED（否则两线共用一个标准值）",
          'SIG_HASH_STORED' not in l2,
          "共享标准值 = 改一处两条线同废，违背双线设计")
    check("第二线【不】引用 SIG_SALT",
          re.search(r'\bSIG_SALT\b', l2) is None,
          "共享盐 = 一条被反推，另一条同时失效")

    print("[D2] 两条线的轮1 不同源（第二线带域分隔）")
    # 第一线轮1 = SHA256(fp)；第二线轮1 = SHA256(b"G2" || fp)
    check("生成侧第二线的轮1 有 G2 域分隔",
          re.search(r'sha256\(\s*b"G2"\s*\+', gen) is not None
          or re.search(r'sha256\(b"G2"', gen) is not None,
          "缺域分隔 → 两线轮1 相同 → 派生逻辑退化为同一份")
    check("C 侧第二线的轮1 也喂了 G2",
          re.search(r'"G2"', l2) is not None)
    check("C 侧第一线的轮1 没有 G2",
          re.search(r'"G2"', l1) is None)

    print("[D3] 两条线的轮2 公式不同（复用 = 一条破全破）")
    # 生成侧：线1 用 0x9E 扩散；线2 用 (i*7)%16 取盐 + 0x5B/0x3D
    gen1 = re.search(r'\(\(i \* (0x[0-9A-Fa-f]+)\) & 0xFF\)', gen)
    check("生成侧能识别出线1 的扩散系数", gen1 is not None)
    if gen1:
        check("线1 的扩散系数不是 0x5B（那是线2 的）",
              gen1.group(1).lower() != '0x5b',
              "两线用同一系数 = 派生逻辑可互相推导")
    # 第二线特有的"步进取盐"
    check("生成侧线2 用 (i * 7) % 16 取盐（线1 是 i % 16）",
          re.search(r'salt\[\s*\(\s*i\s*\*\s*7\s*\)\s*%\s*16\s*\]', gen) is not None,
          "线2 若也写成 i % 16，两条线的盐序完全相同")
    check("C 侧第二线同样用 (i * 7) % 16",
          re.search(r'\(\s*i\s*\*\s*7\s*\)\s*%', l2) is not None)

    print("[D4] 两条线的处置路径不同（同一路径 = 一个 patch 断两条）")
    # 第一线：delayed_kill（延时随机 abort，藏崩溃原因）
    # 第二线：g2_fail → tgkill + watchdog
    check("第一线有 delayed_kill", 'delayed_kill' in l1)
    check("第二线有自己的失败入口 g2_fail",
          re.search(r'g2_fail\s*\(', l2) is not None)
    check("第二线走 tgkill（不是第一线的 abort 路径）",
          'tgkill' in l2,
          "处置路径相同 → 攻击者 patch 一处即同时绕过两条线")
    check("第二线【不】调用第一线的 delayed_kill",
          'delayed_kill' not in l2,
          "复用第一线的处置 = 单点，双线形同虚设")

    print("[D5] 两条线各自有 constructor 入口（互不依赖启动顺序）")
    # 第一线：sig_check_entry
    check("第一线有 constructor 入口",
          re.search(r'__attribute__\(\(constructor\)\)', l1) is not None)
    check("第二线有 constructor 入口 g2_entry",
          re.search(r'__attribute__\(\(constructor\)\)\s*\n\s*static void g2_entry',
                    l2) is not None,
          "少一个入口 = 少一条线")

    print("[D6] 两条线不 include 对方的头文件（零代码共享）")
    inc1 = set(re.findall(r'#include\s+"([^"]+)"', l1))
    inc2 = set(re.findall(r'#include\s+"([^"]+)"', l2))
    check("第一线不 include 第二线的头",
          'sig_guard2.h' not in inc1, str(sorted(inc1)))
    check("第二线不 include 第一线的头",
          'sig_hash.h' not in inc2 and 'sig_log_data.h' not in inc2,
          str(sorted(inc2)))
    check("两线唯一的共享是段契约头（设计允许）",
          'nc_guard_layout.h' in inc1 and 'nc_guard_layout.h' in inc2,
          "共享段名/尺寸契约是必须的，不算破坏独立性")

    print("[D7] ⚠️ 如实标注共享面：APK 定位（已知单点，非缺陷）")
    # 两条线的 APK 定位都依赖 dladdr + /proc/self/maps。
    # 这不是要修的 bug —— 定位方法没有第二套可行方案（/data/app 扫描在
    # Android 11+ 被 SELinux 拒）。但必须在文档里写明，不能宣称"完全独立"。
    check("第一线用 dladdr 定位 so", 'dladdr' in l1)
    check("第二线也用 dladdr 定位 so", 'dladdr' in l2,
          "若第二线改成了别的定位方式，说明独立性提升了 —— "
          "此时应更新本断言与 AGENTS.md 的说明，而不是删掉这条")
    check("第一线读 /proc/self/maps", 'masp' in l1 or 'maps' in l1)
    check("第二线也读 /proc/self/maps", 'maps' in l2)

    # 文档必须如实写明这个共享面（防"宣称完全独立"漂移）
    agents = os.path.join(ROOT, 'AGENTS.md')
    if os.path.isfile(agents):
        a = read(agents)
        check("AGENTS.md 写明双线的共享面（APK 定位）",
              'APK 定位' in a or 'dladdr' in a,
              "文档宣称完全独立、而实际共享定位 = 下一次误判的种子")

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
