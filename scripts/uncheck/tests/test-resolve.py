#!/usr/bin/env python3
"""test-resolve.py — configs/v2 卡片解释器（scripts/uncheck/resolve.py）的回归

用法: python3 scripts/uncheck/tests/test-resolve.py

=== 为什么这个测试存在（2026-11-27）===

新增了 `layer` 子项（both / java）。它决定是否投放 libusign.so，
而那个 .so 会全局 hook libc 的 open/stat/readlink —— WebView/Capacitor/
Flutter 类 App 被它影响后会出现图片、网络加载失败。

这个开关错一个方向，后果是「包能装上但用不了」，而构建全程是绿的。
所以四类判据必须钉住：
  ① layer=java   → 参数里有 --java-only
  ② layer=both   → 没有 --java-only
  ③ 旧 App 布尔快照（uncheck: true）→ 按默认 both，不能报错
  ④ 非法取值 → 报错退出，不能静默回落到某个层

前两条是功能，后两条是"错的时候必须吵"。
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RESOLVE = ROOT / "scripts/uncheck/resolve.py"

passed, failed = [], []


def chk(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  {detail}" if detail and not cond else ""))


def run(cfg, *extra):
    """把 cfg 喂给 resolve.py，返回 (rc, args_list, stderr)。"""
    if cfg is None:
        p = subprocess.run([sys.executable, str(RESOLVE), *extra],
                           capture_output=True, text=True)
    else:
        p = subprocess.run([sys.executable, str(RESOLVE), "-"],
                           input=json.dumps(cfg), capture_output=True, text=True)
    args = [ln for ln in p.stdout.splitlines() if ln.startswith("--")]
    return p.returncode, args, p.stderr


print("[仅 Java 层：layer=java]")
rc, args, err = run({"schema_version": 2, "uncheck": {"enabled": True, "layer": "java"}})
chk("rc=0", rc == 0, err)
chk("含 --java-only", "--java-only" in args, str(args))
chk("含 --uncheck", "--uncheck" in args, str(args))

print("[两层：layer=both]")
rc, args, err = run({"schema_version": 2, "uncheck": {"enabled": True, "layer": "both"}})
chk("rc=0", rc == 0, err)
chk("不含 --java-only", "--java-only" not in args, str(args))
chk("含 --uncheck", "--uncheck" in args, str(args))

print("[默认值：缺 layer → both]")
rc, args, err = run({"schema_version": 2, "uncheck": {"enabled": True}})
chk("rc=0", rc == 0, err)
chk("未追加 --java-only（按 schema default=both）", "--java-only" not in args, str(args))

print("[旧 App 布尔快照兼容]")
rc, args, err = run({"schema_version": 2, "uncheck": True})
chk("uncheck:true 仍可用（rc=0）", rc == 0, err)
chk("布尔快照按 both 处理", "--java-only" not in args, str(args))

print("[错的时候必须吵]")
rc, args, err = run({"schema_version": 2, "uncheck": {"enabled": True, "layer": "native"}})
chk("非法 layer 报错退出", rc != 0, f"rc={rc} args={args}")
chk("报错信息点名 layer", "layer" in err, err[:120])

rc, args, err = run({"schema_version": 2, "uncheck": {"enabled": False, "layer": "java"}})
chk("enabled=false 拒绝出包", rc != 0, f"rc={rc}")

rc, args, err = run({"schema_version": 2, "uncheck": {"enabled": True, "bogus": 1}})
chk("未定义子项报错", rc != 0, f"rc={rc}")

rc, args, err = run({"schema_version": 1, "uncheck": True})
chk("版本不符报错", rc != 0, f"rc={rc}")

print("[--defaults 与 --print-json]")
rc, args, err = run(None, "--defaults")
chk("--defaults 可跑且只出 --uncheck", rc == 0 and args == ["--uncheck"], f"rc={rc} args={args}")

p = subprocess.run([sys.executable, str(RESOLVE), "--print-json"],
                   capture_output=True, text=True)
ok = p.returncode == 0
if ok:
    try:
        sch = json.loads(p.stdout)
        m0 = sch["modules"][0]
        ok = m0.get("type") == "parent" and any(
            c["key"] == "layer" for c in m0.get("children", []))
    except Exception:
        ok = False
chk("--print-json 输出含 layer 子项（App 用它渲染 UI）", ok)

print()
if failed:
    print(f"❌ 失败 {len(failed)} 项 / 通过 {len(passed)} 项")
    for f in failed:
        print(f"   · {f}")
    sys.exit(1)
print(f"✅ 全部通过：{len(passed)} 项断言")
