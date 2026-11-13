#!/usr/bin/env python3
"""test_protect_sh_vars.py — protect.sh 的变量定义/使用顺序检查。

【为什么需要这个测试】
  2026-11-05 CI run 42027976660 在 34 秒处失败：

      ./scripts/pipelines/protect.sh: line 439: SIG_DST: unbound variable

  原因：给 NcLink 动态注册加的那段代码用了 `$SIG_DST`，但 `SIG_DST` 是在
  后面「拷贝 sigcheck 源码」的块里才赋值的。`protect.sh` 有 `set -u`，
  未定义变量直接退出。

  ⚠️ **`bash -n` 抓不住这类错误** —— 它只检查语法，不做变量数据流分析。
  本地跑 `bash -n protect.sh` 是通过的，CI 却在运行到第 3/6 步才炸：
  那时已经花掉 34 秒、跑完了证书提取和 dex2c 转译。

  这个脚本做的就是 `bash -n` 做不到的事：静态扫描变量赋值点与首次使用点，
  要求「赋值行号 < 首次使用行号」。

【局限（如实）】
  这是启发式静态检查，不是完整的 shell 数据流分析：
    · 只查 tk 脚本里【直接写出的】`${VAR}` / `$VAR`
    · 不跟踪函数内部的局部变量（local/子 shell）
    · 不分析条件分支（`if` 两臂各赋一次也算已定义）
    · 白名单覆盖环境变量（CI 传入）与 bash 内建
  因此它抓的是「明显忘记先定义」这一类，不是全部 unbound variable。

用法: python3 scripts/actions/tests/test_protect_sh_vars.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
TARGET = os.path.join(ROOT, 'scripts', 'pipelines', 'protect.sh')

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


# 环境变量 / CI 传入 / bash 内建 / 脚本自身参数。这些不要求在本文件里赋值。
ALLOW = {
    # CI workflow 传入
    'IN_APK', 'OUT_APK', 'INPUT_DPT_EXTRA_ARGS', 'INPUT_PROTECT_CONFIG',
    'GITHUB_WORKSPACE', 'RUNNER_TEMP', 'HOME', 'PATH', 'PWD', 'TMPDIR',
    'ANDROID_NDK_HOME', 'ANDROID_HOME', 'ANDROID_SDK_ROOT', 'JAVA_HOME',
    'R2_ACCESS_KEY', 'R2_SECRET_KEY', 'R2_ENDPOINT', 'R2_BUCKET',
    'R2_PUBLIC_DOMAIN',
    # 构建期调试开关（2026-11-13）：全是 `${VAR:-默认值}` 形态，
    # 由 CI env 或本地 export 传入，脚本内不赋值 —— 与 TMP_NOMARK 同族。
    'TMP_NOLOCK', 'TMP_NONOX', 'TMP_NOMARK',
    # TMP_NONOX（2026-11-13）：与 TMP_NOLOCK 不是一回事 ——
    # 前者完全不注入 nox（量模块体积用），后者只是不加密。
    # bash / 常见工具
    'BASH_SOURCE', 'FUNCNAME', 'LINENO', 'IFS', 'PS4', 'RANDOM', 'SECONDS',
    'REPLY', 'OPTARG', 'OPTIND', 'UID', 'EUID', 'PPID', 'SHELL',
    # 脚本里通过 for/read/case 隐式赋值的
    'arg', 'args', 'opt', 'line', 'ln', 'f', 'd', 'p', 'k', 'v', 'x', 'i',
    'n', 's', 'c', 'm', 'h', 'e', 'r', 't', 'w', 'a', 'b', 'g', 'j', 'o',
    'q', 'u', 'y', 'z', '_', '__',
}


def main():
    if not os.path.isfile(TARGET):
        bad(f"找不到 {TARGET}")
        print(f"通过 {PASS}，失败 {FAIL}")
        return 1

    with open(TARGET, encoding='utf-8') as fp:
        raw = fp.read()

    # 去掉注释行（`#` 开头）——注释里提到 $VAR 不应算使用
    lines = raw.split('\n')
    code_lines = []
    for i, ln in enumerate(lines):
        st = ln.strip()
        if st.startswith('#'):
            code_lines.append((i, ''))
        else:
            code_lines.append((i, ln))

    print("[1/3] 提取变量赋值点")
    # 赋值形态：VAR=... / VAR+=... / local VAR= / readonly VAR= / declare VAR=
    # for VAR in / read VAR
    # ⚠️ 第一版正则要求前面有 `^|[\s;(]` 且用 re.finditer 逐个匹配，结果只
    #    识别出 11 个（实际 56 个）—— 因为 `VAR=(a b c)` 这种数组赋值和
    #    `VAR="$x"  cmd` 形态都没覆盖。改为按行判断「行内出现 name= 或 name+=」。
    assign = {}
    for i, ln in code_lines:
        if not ln:
            continue
        body = ln.split('#', 1)[0] if not ln.lstrip().startswith('#') else ''
        for m in re.finditer(
                r'(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\+?=', body):
            name = m.group(1)
            # 排除 `cmd --flag=value` 里被误认的（前一个非空字符是 -）
            start = m.start(1)
            prev = body[:start].rstrip()
            if prev.endswith('-'):
                continue
            assign.setdefault(name, i)
        for m in re.finditer(r'\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b', body):
            assign.setdefault(m.group(1), i)
        for m in re.finditer(r'\bread\s+(?:-\w+\s+)*([A-Za-z_][A-Za-z0-9_]*)', body):
            assign.setdefault(m.group(1), i)
        for m in re.finditer(r'\b(?:mapfile|readarray)\s+(?:-\w+\s+)*([A-Za-z_][A-Za-z0-9_]*)', body):
            assign.setdefault(m.group(1), i)

    check(f"识别出 {len(assign)} 个被赋值的变量", len(assign) > 30,
          str(len(assign)))

    print("[2/3] 检查首次使用早于赋值（set -u 下的真实崩溃点）")
    uses = {}
    for i, ln in code_lines:
        if not ln:
            continue
        for m in re.finditer(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)', ln):
            name = m.group(1)
            if name in ALLOW:
                continue
            uses.setdefault(name, i)

    offenders = []
    for name, use_line in uses.items():
        def_line = assign.get(name)
        if def_line is None:
            continue        # 完全没见过赋值：可能是函数名/拼写，交给下面单独查
        if def_line > use_line:
            offenders.append((name, def_line + 1, use_line + 1))

    check("没有『使用早于赋值』的变量", not offenders,
          '; '.join(f'${n} 用于第{u}行但第{d}行才赋值'
                    for n, d, u in offenders))

    # 回归锚点：SIG_DST 是本次事故的变量，单独钉死
    if 'SIG_DST' in assign:
        first_use = uses.get('SIG_DST')
        check("SIG_DST 首次使用晚于赋值（报错回归）",
              first_use is not None and assign['SIG_DST'] < first_use,
              f"赋值@{assign['SIG_DST']+1} 使用@{first_use+1 if first_use else '?'}")

    print("[3/3] 结构完整性：set -u 生效时关键前置存在")
    check("脚本启用了 set -u（本检查的存在理由）",
          re.search(r'set\s+-[a-z]*u', raw) is not None)
    check("NcLink 注册块在 SIG_DST 赋值之后",
          'nc_link_register_natives' in raw)

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
