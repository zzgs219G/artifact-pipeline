#!/usr/bin/env python3
"""test_guard_max.py — --guard-max 预设的静态契约（方案四）

断言（读源码，不执行构建——build_config 依赖完整 argparse 命名空间）：
① elif 链中 guard_max 位于 all 之后（重防护优先级最高）
② guard_max 的预填含 vmp=True（与 --all 的关键差异：all 不含 vmp）
③ --std 的预填不含 vmp（2026-11-10 用户决定不变）
④ help 文案含两层 VMP 的区分（【消费方层 VMP】+ 两个独立层）
⑤ 防护清单函数存在且被 main 调用（_print_guard_sheet）
反向验证：删掉 guard_max 分支的 vmp=True → ② 红。
"""
import re
import sys

SRC = "scripts/trigger_build.py"


def main():
    s = open(SRC, encoding="utf-8").read()
    fails = []

    def ok(m):
        print(f"  ✅ {m}")

    def bad(m):
        fails.append(m)
        print(f"  ❌ {m}")

    m = re.search(r"if args\.all:.*?elif args\.guard_max:(.*?)elif args\.std:",
                  s, re.S)
    if not m:
        bad("guard_max 分支不存在或位置错误（应在 all 之后、std 之前）")
        return 1
    ok("guard_max 位于 all 之后（重防护优先级最高）")
    blk = m.group(1)
    (ok if "vmp=True" in blk else bad)("guard_max 预填含 vmp=True（与 --all 的关键差异）")
    (ok if "packer=False" in blk else bad)("guard_max 不含 packer（加壳仍需显式）")

    std_blk = s[s.index("elif args.std:"):s.index("elif not any_switch:")]
    (ok if "vmp=False" in std_blk else bad)("--std 不含 vmp（2026-11-10 决定不变）")

    (ok if "【消费方层 VMP】" in s and "两个独立层" in s
     else bad)("help 文案区分两层 VMP")

    (ok if "_print_guard_sheet(args)" in s and "def _print_guard_sheet" in s
     else bad)("防护清单函数存在且被 main 调用")

    print(f"=== 结果: {5 - len(fails)} 通过, {len(fails)} 失败 ===")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
