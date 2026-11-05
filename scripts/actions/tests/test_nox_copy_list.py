#!/usr/bin/env python3
"""test_nox_copy_list.py — 校验 protect.sh 的 nox 源码拷贝清单是完整的。

【为什么需要】
  2026-11-06 从 nox 的 nc_guard_boot.c 拆出 nc_guard_xor.c 时，
  只改了 nox 仓库里的三处清单（test.sh / make-zip-lib.sh / nox CLI），
  漏了消费方 artifact-pipeline 的 `protect.sh`。

  后果：源码形态的 nox 包构建时 nc_guard_xor.c 不被拷贝 →
  链接缺 ncg_xor_key → 解锁链断 → 真机 fail-closed 杀进程。
  而这一路是【构建期就失败】还是【真机才崩】，取决于符号引用是否被
  --gc-sections 顺带裁掉 —— 属于"可能静默"的那一类。

  这是"改一处必须 grep 所有消费方"的第四次复发（报错七同源）。
  所以用断言钉住：protect.sh 的 cp 清单必须覆盖 nox 包里的全部 .c。

【判据】
  以 nox 仓库的 LIB_SRCS（make-zip-lib.sh）为真相源 —— 那是"装进包里
  的 .c 清单"。protect.sh 的拷贝清单必须与它一致。

  拿不到 nox 仓库时（CI 未 clone ../nox）跳过并明确打印，不假绿。

用法: python3 scripts/actions/tests/test_nox_copy_list.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
PROTECT = os.path.join(ROOT, 'scripts', 'pipelines', 'protect.sh')
NOX_REPO = os.path.abspath(os.path.join(ROOT, '..', 'nox'))
NOX_MKZIP = os.path.join(NOX_REPO, 'scripts', 'make-zip-lib.sh')

PASS = 0
FAIL = 0


def ok(m):
    global PASS
    PASS += 1
    print(f"  ✅ {m}")


def bad(m):
    global FAIL
    FAIL += 1
    print(f"  ❌ {m}", file=sys.stderr)


def check(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        bad(f"{name}{(' — ' + detail) if detail else ''}")


def main():
    ps = open(PROTECT, encoding='utf-8').read()

    print("[1/3] protect.sh 里源码形态的拷贝清单")
    # 抓取 nox_guard_has_src 分支内的 cp 行
    m = re.search(
        r'if nox_guard_has_src "\$GUARD_SRC"; then(.*?)GUARD_LIB_DIR=""',
        ps, re.S)
    check("找到源码形态拷贝分支", m is not None)
    if not m:
        print(f"通过 {PASS}，失败 {FAIL}")
        return 1
    # ⚠️ 必须只匹配【代码行】，不能匹配注释 —— 注释里也会写文件名。
    # 2026-11-06 实测踩过：反向验证时 sed 删掉了 cp 行，但注释里还有
    # `# nc_guard_xor.c（...）`，正则照样命中 → 断言恒绿、抓不到漏拷。
    # 这与 AGENTS.md 记的 T24「断言只查代码行不查注释」是同一个坑。
    code_lines = [ln for ln in m.group(1).splitlines()
                  if not ln.lstrip().startswith('#')]
    copied = sorted(set(re.findall(r'nc_guard_[a-z_]+\.c', '\n'.join(code_lines))))
    check(f"至少拷 5 个 .c（实得 {len(copied)}）", len(copied) >= 5, str(copied))

    print("[2/3] 与 nox 仓库的打包清单对照")
    if not os.path.isfile(NOX_MKZIP):
        print(f"  ⚠️ 跳过：找不到 {NOX_MKZIP}（CI 未 clone ../nox 时正常）")
    else:
        mk = open(NOX_MKZIP, encoding='utf-8').read()
        # LIB_SRCS="nc_guard_boot nc_guard_probe ..."（不带 .c 后缀）
        mm = re.search(r'^LIB_SRCS="([^"]+)"', mk, re.M)
        check("make-zip-lib.sh 有 LIB_SRCS", mm is not None)
        if mm:
            want = sorted(f'{x}.c' for x in mm.group(1).split())
            check("protect.sh 拷贝清单 == nox 打包清单",
                  copied == want,
                  f"protect.sh={copied}  nox={want}")
            missing = [x for x in want if x not in copied]
            check("没有漏拷的 .c", not missing, f"漏了: {missing}")

    print("[3/3] 关键文件必须在清单里（回归锚点）")
    # nc_guard_xor.c 是 2026-11-06 拆出来的，漏过一次
    check("nc_guard_xor.c 在拷贝清单里（2026-11-06 漏过一次）",
          'nc_guard_xor.c' in copied, str(copied))
    check("nc_guard_boot.c 在清单里", 'nc_guard_boot.c' in copied)
    check("nc_guard_probe.c 在清单里（.ncx/.nck 段本体）",
          'nc_guard_probe.c' in copied)

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
