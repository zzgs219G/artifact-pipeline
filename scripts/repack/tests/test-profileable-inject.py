#!/usr/bin/env python3
"""test-profileable-inject.py — profileable 注入位置与断言的回归测试

用法: python3 scripts/repack/tests/test-profileable-inject.py

=== 为什么这个测试存在（2026-11-26）===

`--profileable` 注入 `<profileable android:shell="true"/>` 以开 shell 采样许可。
它此前 **零测试**，而实现把元素插在了 `<application>` 之前：

    <uses-permission .../>
      <profileable android:shell="true"/>    ← 错：成了 manifest 直接子元素
    <application ...>

`<profileable>` 按 AOSP 是 `<application>` 的子元素。插错位置 → aapt2 判为
未知元素（静默忽略），采样许可从未生效，而构建不报错、日志说"注入完成"。

这个测试做两件事：
  ① 从 lib-repack.sh 里【抽取】真实的注入代码跑一遍（不复制实现 —— 
     复制品会与生产漂移，见 AGENTS.md §2.2）
  ② 断言注入结果在 <application> 体内，且 <manifest> 的直接子元素不变
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LIB = ROOT / "scripts/lib/lib-repack.sh"

fails = []
passed = []


def chk(name, cond, detail=""):
    (passed if cond else fails).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  {detail}" if detail and not cond else ""))


SAMPLE = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:name=".A" android:label="x" android:theme="@style/T">
    <activity android:name=".M"/>
  </application>
</manifest>
"""

# 属性值里有 '>' 的极端情况：注入器必须跳过属性内的 '>'
SAMPLE_GT = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
  <application android:name=".A" android:label="a &gt; b">
    <activity android:name=".M"/>
  </application>
</manifest>
"""


def extract_inject_code() -> str:
    """从生产脚本里抽出注入用的 python heredoc 原文。"""
    src = LIB.read_text(encoding="utf-8")
    # 第一个 heredoc：`python3 - "$mf" <<'PY' ... PY`（注入）
    m = re.search(r"python3 - \"\$mf\" <<'PY'\n(.*?)\nPY\n", src, re.S)
    if not m:
        raise SystemExit("❌ 抽不到注入代码（lib-repack.sh 的 heredoc 形态变了）")
    return m.group(1)


def run_inject(code: str, manifest: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        mf = Path(td) / "AndroidManifest.xml"
        mf.write_text(manifest, encoding="utf-8")
        r = subprocess.run(
            [sys.executable, "-", str(mf)], input=code,
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise SystemExit(f"❌ 注入执行失败: {r.stderr}")
        return mf.read_text(encoding="utf-8")


def inside_application(xml: str) -> str:
    m = re.search(r"<application\b[^>]*>(.*?)</application>", xml, re.S)
    return m.group(1) if m else ""


print("[profileable 注入]")
code = extract_inject_code()

# ① 常规形态：注入后必须在 <application> 内
out = run_inject(code, SAMPLE)
chk("注入后 <profileable> 在 <application> 体内", "<profileable" in inside_application(out))
chk("注入后 <profileable> 不在 <manifest> 直下（旧 bug 形态）",
    re.search(r"<manifest\b[^>]*>\s*(?:<uses-permission[^>]*/>\s*)?<profileable", out) is None)

# ② 原有子元素不能被破坏（activity 仍在）
chk("原有 <activity> 仍在", '<activity android:name=".M"/>' in out)
# ③ 幂等：已存在则跳过（第二次注入不重复）
run_inject(code, out)
chk("重复注入不产生第二个 <profileable>", out.count("<profileable") == 1)
# ④ 属性含 '>' 的形态：不能把 '>' 误当标签结束
out_gt = run_inject(code, SAMPLE_GT)
chk("属性值含 &gt; 时仍插在 <application> 体内",
    "<profileable" in inside_application(out_gt))

# ⑤ 生产脚本必须带产物侧断言（防只注入不校验）
lib_src = LIB.read_text(encoding="utf-8")
chk("生产脚本带「必须在 <application> 内」的断言",
    "不在 <application> 内" in lib_src)

print()
if fails:
    print(f"❌ 失败 {len(fails)} 项 / 通过 {len(passed)} 项")
    for f in fails:
        print(f"   · {f}")
    sys.exit(1)
print(f"✅ 全部通过：{len(passed)} 项断言")
