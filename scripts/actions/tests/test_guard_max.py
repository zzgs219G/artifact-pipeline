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
import json
import os
import re
import sys

SRC = "scripts/trigger_build.py"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))


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

    (ok if "_print_guard_sheet(args, config)" in s
     and "def _print_guard_sheet(args, config" in s
     else bad)("防护清单函数存在且被 main 用展开后的 config 调用")

    # ── 防护清单必须读【展开后的 config】，不能读 args 原始参数 ──────────
    #
    # 2026-11-25 实测 bug：清单原来写 getattr(args,'vmp'/'sigcheck')，而预设
    # 档位（--guard-max / --std / --all）是在 build_config 里把模块展开到
    # config 里的，args 上仍是 False → 用 --guard-max 出包时清单固定显示
    # "消费方层 VMP ❌ / 两道签名防线 —（未勾）"，**与实际产物相反**。
    # 这是"会撒谎的清单"，比没有清单更糟：它存在的唯一目的就是让人核对。
    shell_blk = s[s.index("def _print_guard_sheet"):]
    (ok if "isinstance(config, str)" in shell_blk and "json.loads" in shell_blk
     else bad)("清单从 config 取模块状态（需先 json.loads —— build_config 返回 JSON 文本）")
    (ok if 'getattr(args, "vmp"' not in shell_blk
     else bad)("清单不再用 args.vmp 判消费方层 VMP（预设档位下会撒谎）")
    (ok if 'getattr(args, "sigcheck"' not in shell_blk
     else bad)("清单不再用 args.sigcheck 判签名防线（预设档位下会撒谎）")
    # soguard 是对象：enabled 是总开关，vm 是虚拟化子项。
    # 只看 enabled 会把 "--vmp --no-vm"（只混淆不虚拟化）说成 VMP 已开。
    (ok if 'sg.get("enabled")' in shell_blk and 'sg.get("vm"' in shell_blk
     else bad)("清单同时看 soguard.enabled 与 soguard.vm（--no-vm 时不谎报）")

    # ── 构建流程必须【可达】─────────────────────────────────────────────
    #
    # 2026-11-25 实测的灾难性 bug：commit e6e4cb4 把 _print_guard_sheet /
    # _nox_vmp_present 插进了 main() 函数体【中间】，于是 main() 打完清单
    # 就结束，"上传 APK / 触发构建 / 等结果 / 下载" 这 162 行成了
    # _nox_vmp_present 之后的无主代码（Python 语法允许，只是永不被执行）。
    #
    # 症状：脚本退出码 0、清单打得漂漂亮亮、网关侧零新任务 —— **假装成功**。
    # 而 e6e4cb4 带来的 test_guard_max.py 只检查"源码里有没有这段文字"，
    # 所以 5 条断言全绿，bug 活了整整一天。
    #
    # 教训与 AGENTS §2.2 同源：测试不许只看文本存在，要看【行为可达】。
    # 这里用 AST 判断：main() 的函数体里必须有对落点函数的调用。
    import ast as _ast
    tree = _ast.parse(s)
    main_fn = next((n for n in tree.body
                    if isinstance(n, _ast.FunctionDef) and n.name == "main"), None)
    (ok if main_fn is not None else bad)("main() 函数存在")

    def _calls(fn):
        """收集 fn 体内所有被调用的函数名。"""
        names = set()
        if fn is None:
            return names
        for node in _ast.walk(fn):
            if isinstance(node, _ast.Call):
                f = node.func
                if isinstance(f, _ast.Name):
                    names.add(f.id)
                elif isinstance(f, _ast.Attribute):
                    names.add(f.attr)
        return names

    main_calls = _calls(main_fn)
    (ok if "_print_guard_sheet" in main_calls
     else bad)("main() 实际调用了 _print_guard_sheet（不是只有定义）")
    # 构建落点：修复后是 _do_build；若将来改名，这里要同步
    (ok if "_do_build" in main_calls
     else bad)("main() 实际调用了构建落点（上传/触发/下载）—— 防「打了清单却从不构建」")

    # 反向兜底：这些关键动作必须在【某个函数体内】，不能是模块级裸代码。
    # 裸代码在模块顶层会执行，但如果在 main() 之外则不会被 main 触发。
    build_fn = next((n for n in tree.body
                     if isinstance(n, _ast.FunctionDef) and n.name == "_do_build"), None)
    (ok if build_fn is not None else bad)("_do_build() 存在（构建动作有归属函数）")
    build_src = _ast.get_source_segment(s, build_fn) if build_fn else ""
    for needle in ("上传 APK 到 R2", "触发构建"):
        (ok if needle in (build_src or "")
         else bad)(f"「{needle}」在 _do_build 体内（不是模块级无主代码）")

    # ── trigger_build 发出的 soguard 字段必须与 schema 一致 ─────────────
    #
    # 2026-11-25 CI run 45494974037 全量失败：trigger_build.py 发
    #   soguard: {vm,mba,flatten,bcf,param_aggregate,indirect_call,
    #             indirect_branch,vm_flatten}
    # 而 config-schema.json 只认 {vm,mba,param_aggregate,vm_flatten} →
    # resolve-config.py 直接拒绝执行 → args.txt 从未生成 →
    #   "grep: build/schema_rules/args.txt: No such file" →
    #   "❌ 未勾选任何模块"。表象像"参数没传"，真因是 schema 拒收。
    #
    # 断言方式：从【生产 schema】读合法子 key，再从 trigger_build 的
    # soguard 字面量里抽 key，比对两者 —— 不手抄清单（§2.2）。
    schema_path = os.path.join(ROOT, "configs", "v1", "config-schema.json")
    try:
        sc = json.load(open(schema_path, encoding="utf-8"))
        allowed = set()
        for m in sc.get("modules", []):
            if isinstance(m, dict) and m.get("key") == "soguard":
                allowed = {c["key"] for c in m.get("children", [])}
                break
        (ok if allowed else bad)("从 schema 读到 soguard 合法子 key")

        # 从 trigger_build.py 的 "soguard": {...} 字面量里抽实际发出的 key
        msg = re.search(r'"soguard"\s*:\s*\{(.*?)\}', s, re.S)
        sent = set(re.findall(r'"(\w+)"\s*:', msg.group(1))) if msg else set()
        (ok if sent else bad)("从 trigger_build.py 读到实发 soguard key")

        extra = sent - allowed - {"enabled"}   # enabled 是模块总开关，schema 里叫别的
        missing = allowed - sent
        (ok if not extra
         else bad)(f"trigger_build 不向 schema 发未定义子 key（多发了: {sorted(extra)}）")
        (ok if not missing
         else bad)(f"trigger_build 覆盖 schema 全部子 key（漏了: {sorted(missing)}）")
    except (OSError, json.JSONDecodeError, KeyError) as e:
        bad(f"schema/trigger_build 一致性检查无法执行: {e}")

    print(f"=== 结果: {19 - len(fails)} 通过, {len(fails)} 失败 ===")
    return 1 if fails else 0
if __name__ == "__main__":
    sys.exit(main())
