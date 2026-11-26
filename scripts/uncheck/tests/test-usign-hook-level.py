#!/usr/bin/env python3
"""test-usign-hook-level.py — native hook 分层（hookLevel）的静态回归

用法: python3 scripts/uncheck/tests/test-usign-hook-level.py

=== 为什么这个测试存在（2026-11-27）===

`hookLevel` 决定 usign_hook.c 注册几个 libc hook（1=核心 3=全量）。
它存在的原因：18 个 hook 全挂会波及与签名校验无关的代码 ——
实测 JMComic（Capacitor WebView）在两层模式下图片/网络加载失败，
仅 Java 层正常。

这个开关错了的后果是「包能装上但用不了」或「校验绕不过」，
两种都不会让构建变红。所以三层链路都要钉住：
  ① C 侧：proxy 必须有 orig NULL 兜底（否则降档后反而更容易崩）
  ② C 侧：level 分发结构存在（核心档不注册边缘 hook）
  ③ Java 侧：hookLevel 从 sigfix.json 读，且透传给 JNI
  ④ 产物侧：sigfix.json 里真的写了 hookLevel

=== 关于 ① 的重要性（真 bug，不是假想）

旧实现每个 proxy 都直接调 orig_xxx(...)，而 hook_one() 失败时
orig_xxx 保持 NULL。如果 shadowhook 半成功（stub 装了但没给回原函数
指针），proxy 一被调用就是空指针崩溃。加兜底后返回 -1/ENOSYS。
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
C_SRC = ROOT / "scripts/uncheck/payload/c/usign_hook.c"
JAVA = ROOT / "scripts/uncheck/payload/src/com/nc/uncheck/SigFix.java"
RUNPY = ROOT / "scripts/uncheck/run.py"

passed, failed = [], []


def chk(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  {detail}" if detail and not cond else ""))


c = C_SRC.read_text(encoding="utf-8")
j = JAVA.read_text(encoding="utf-8")
r = RUNPY.read_text(encoding="utf-8")

print("[① proxy 全部有 orig NULL 兜底]")
# 找出所有 static 函数定义里的 proxy_xxx
proxies = re.findall(r'^static\s+[\w\s\*]+?\b(proxy_\w+)\s*\(', c, re.M)
chk("找到 proxy 函数", len(proxies) >= 17, f"实得 {len(proxies)}")
missing = []
for p in proxies:
    # 该函数体内（到下一个 static 定义或文件尾）必须出现 "== NULL) {" 判空
    m = re.search(r'^static\s+[\w\s\*]+?\b' + re.escape(p) + r'\s*\(.*?^}', c, re.M | re.S)
    body = m.group(0) if m else ""
    if not re.search(r'if\s*\(\s*orig_\w+\s*==\s*NULL\s*\)', body):
        missing.append(p)
chk("每个 proxy 都判了 orig NULL", not missing, f"缺: {missing}")

print("\n[② C 侧的 level 分发结构]")
chk("定义了三个档位常量",
    all(k in c for k in ("NC_HOOK_LEVEL_CORE", "NC_HOOK_LEVEL_FULL", "NC_HOOK_LEVEL_ALL")))
chk("有 s_hook_level 变量", "s_hook_level" in c)
chk("核心档有 early return（不注册边缘 hook）",
    re.search(r'if\s*\(lv\s*<\s*NC_HOOK_LEVEL_FULL\)', c) is not None)
chk("openat2/statx/opendir 各自独立成档（4/5/6）",
    all(re.search(rf'if\s*\(lv\s*>=\s*{n}\)[\s\S]{{0,200}}{fn}', c) is not None
        for n, fn in ((4, 'openat2'), (5, 'statx'), (6, 'opendir'))))
# 核心档的 7 个函数必须在 if 之前注册（无条件）
core_block = c.split("if (lv < NC_HOOK_LEVEL_FULL)")[0]
for fn in ("open", "open64", "__open_2", "fopen", "fopen64", "access", "stat"):
    chk(f"核心档无条件注册 {fn}", f'hook_one("{fn}"' in core_block.split("patch_all")[-1])

print("\n[③ Java 侧透传]")
chk("native 声明带 int level",
    re.search(r'native boolean nativeHookApkPath\(String\s+\w+,\s*String\s+\w+,\s*int\s+\w+\)', j) is not None)
chk("调用点传了 sHookLevel", "nativeHookApkPath(apkPath, rep.getAbsolutePath(), sHookLevel)" in j)
chk("从 sigfix.json 读 hookLevel", 'optInt("hookLevel"' in j)
chk("越界值在 native 侧钳位", "if (level < NC_HOOK_LEVEL_CORE)" in c and "if (level > NC_HOOK_LEVEL_ALL)" in c)

print("\n[④ 产物侧：run.py 写 hookLevel]")
chk("cfg 里含 hookLevel", "'hookLevel'" in r)
chk("从环境变量读且有默认值 6（=全量，与历史行为一致）",
    "USIGN_HOOK_LEVEL" in r and "'6'" in r)

print("\n[⑤ shell 层]")
sh = (ROOT / "scripts/uncheck/uncheck.sh").read_text(encoding="utf-8")
chk("uncheck.sh 有 --hook-level", "--hook-level)" in sh)
chk("导出 USIGN_HOOK_LEVEL", 'export USIGN_HOOK_LEVEL' in sh)

print()
if failed:
    print(f"❌ 失败 {len(failed)} 项 / 通过 {len(passed)} 项")
    for x in failed:
        print(f"   · {x}")
    sys.exit(1)
print(f"✅ 全部通过：{len(passed)} 项断言")
