#!/usr/bin/env python3
"""test_obfuscate_args.py — obfuscate 模块的参数契约测试。

【为什么需要】
  2026-11-05 接入 Amice 混淆时新增 schema 模块 `obfuscate` 与两个子开关
  `--obfuscate-mba` / `--obfuscate-flatten`。这类"新增模块"改动最容易
  漏同步三处（AGENTS.md 报错速查里记过两次同类事故）：

    ① configs/v1/config-schema.json   —— UI 定义
    ② scripts/actions/check-schema.py —— 模块顺序断言（硬编码列表）
    ③ scripts/actions/resolve-config.py 解析 → args.txt

  三者任一未同步的症状：UI 能勾但 protect.sh 收不到参数（静默失效），
  或 check-schema 直接报错。本测试把它们钉在一起。

【测什么】
  T1 schema 里 obfuscate 的结构（parent + 两个 flag 子项）
  T2 check-schema 的顺序断言与 schema 实际顺序一致
  T3 resolve-config 把勾选转成正确 argv（含子项默认值）
  T4 protect.sh 认识这三个参数
  T5 protect.sh 的 fail-fast：勾了混淆但没有 so 来源 / 没有 bundle

【不测什么】
  真实 Amice 编译（需要 848MB bundle，见 CI 的 amice-integrate job）。

用法: python3 scripts/actions/tests/test_obfuscate_args.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
SCHEMA = os.path.join(ROOT, 'configs', 'v1', 'config-schema.json')
CHECK = os.path.join(ROOT, 'scripts', 'actions', 'check-schema.py')
RESOLVE = os.path.join(ROOT, 'scripts', 'actions', 'resolve-config.py')
PROTECT = os.path.join(ROOT, 'scripts', 'pipelines', 'protect.sh')
LIBNDK = os.path.join(ROOT, 'scripts', 'lib', 'lib-ndk.sh')

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


def read(p):
    with open(p, encoding='utf-8') as f:
        return f.read()


def resolve(cfg):
    """在临时 workspace 里跑 resolve-config.py，返回 args.txt 的行列表。"""
    tmp = tempfile.mkdtemp(prefix='obf-test-')
    os.makedirs(os.path.join(tmp, 'configs', 'v1'))
    with open(SCHEMA, encoding='utf-8') as f:
        schema_text = f.read()
    with open(os.path.join(tmp, 'configs', 'v1', 'config-schema.json'),
              'w', encoding='utf-8') as f:
        f.write(schema_text)
    env = dict(os.environ)
    env['INPUT_PROTECT_CONFIG'] = json.dumps(cfg, ensure_ascii=False)
    env['GITHUB_WORKSPACE'] = tmp
    r = subprocess.run([sys.executable, RESOLVE], env=env, cwd=tmp,
                       capture_output=True, text=True)
    args_path = os.path.join(tmp, 'schema_rules', 'args.txt')
    lines = []
    if os.path.isfile(args_path):
        with open(args_path, encoding='utf-8') as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
    return r.returncode, lines, r.stdout + r.stderr


def main():
    schema = json.loads(read(SCHEMA))
    mods = {m['key']: m for m in schema['modules']}
    ps = read(PROTECT)
    ndk = read(LIBNDK)

    print("[1/5] schema 结构")
    check("obfuscate 模块存在", 'obfuscate' in mods)
    ob = mods.get('obfuscate', {})
    check("是 parent（有子项）", ob.get('type') == 'parent', ob.get('type'))
    check("arg 是 --obfuscate", ob.get('arg') == '--obfuscate', ob.get('arg'))
    check("默认关闭（混淆有风险，不能默认开）", ob.get('default') is False,
          str(ob.get('default')))
    kids = {c['key']: c for c in ob.get('children', [])}
    check("有 mba 与 flatten 两个子项",
          set(kids) == {'mba', 'flatten'}, str(sorted(kids)))
    check("mba 默认开启（低风险）", kids.get('mba', {}).get('default') is True)
    check("flatten 默认关闭（高风险，必须显式开）",
          kids.get('flatten', {}).get('default') is False)
    for k, want in (('mba', '--obfuscate-mba'),
                    ('flatten', '--obfuscate-flatten')):
        check(f"{k} 的 arg_on == {want}",
              kids.get(k, {}).get('arg_on') == want,
              str(kids.get(k, {}).get('arg_on')))

    print("[2/5] check-schema 的顺序断言与 schema 同步")
    r = subprocess.run([sys.executable, CHECK, SCHEMA],
                       capture_output=True, text=True)
    check("check-schema 通过", r.returncode == 0, r.stderr[-300:])
    # 断言它是【真的】在验顺序，而不是随便写了个列表
    cs = read(CHECK)
    m = re.search(r'assert keys == \[(.*?)\]', cs, re.S)
    check("check-schema 里有顺序断言", m is not None)
    if m:
        in_assert = [x.strip().strip('"\'') for x in m.group(1).split(',') if x.strip()]
        in_assert = [x for x in in_assert if x]
        actual = [x['key'] for x in schema['modules']]
        check("断言列表 == schema 实际顺序", in_assert == actual,
              f"断言={in_assert} 实际={actual}")

    print("[3/5] resolve-config 转 argv")
    rc, lines, out = resolve({
        'schema_version': 1, 'sigcheck': True,
        'obfuscate': {'enabled': True, 'mba': True},
    })
    check("mba 勾选 → 生成 --obfuscate + --obfuscate-mba",
          rc == 0 and '--obfuscate' in lines and '--obfuscate-mba' in lines,
          f"rc={rc} lines={lines}")
    check("未勾 flatten 时不出现 --obfuscate-flatten",
          '--obfuscate-flatten' not in lines, str(lines))

    rc, lines, out = resolve({
        'schema_version': 1, 'sigcheck': True,
        'obfuscate': {'enabled': True, 'mba': False, 'flatten': True},
    })
    check("flatten 勾选 → 生成 --obfuscate + --obfuscate-flatten",
          rc == 0 and '--obfuscate-flatten' in lines, f"lines={lines}")

    rc, lines, out = resolve({
        'schema_version': 1, 'sigcheck': True,
        'obfuscate': {'enabled': False},
    })
    check("父模块关闭 → 完全不出现在 args",
          rc == 0 and not any('obfuscate' in x for x in lines), str(lines))

    print("[4/5] protect.sh 认识三个参数")
    for a in ('--obfuscate', '--obfuscate-mba', '--obfuscate-flatten'):
        check(f"protect.sh 的 case 有 {a}",
              re.search(re.escape(a) + r'\)', ps) is not None)

    print("[5/5] fail-fast（不静默降级）")
    # 这两个是本次接入最容易写成"静默跳过"的地方
    check("勾了混淆但没有 so 来源 → 显式报错",
          '没有可混淆的 so' in ps)
    check("勾了混淆但找不到 bundle → 显式报错",
          '找不到 Amice bundle' in ps)
    check("勾了混淆但没选任何子项 → 显式报错",
          '没选任何混淆强度' in ps)
    # ndk 侧：缺 llvm-lib 也不能静默
    check("lib-ndk.sh 缺 llvm-lib 时显式报错",
          'AMICE_LLVM_LIB' in ndk and 'libLLVM' in ndk)
    check("lib-ndk.sh 无混淆时走原路径（不改变既有行为）",
          'PATH="$ANDROID_NDK_HOME:$PATH" ndk-build' in ndk)

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
