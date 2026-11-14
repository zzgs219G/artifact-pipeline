#!/usr/bin/env python3
"""render-summary.py 的契约测试。

## 为什么需要

任务页摘要是"给人看"的功能，很容易在改动中悄悄退化（模块漏列、
启用的显示成未启用、子选项丢失），而这类退化不会让构建设红 ——
只有人点开任务页才会发现，且往往是几个月后。

这组断言钉住四件事：
  ① 启用的模块必须出现在「启用」列表，未启用的出现在「未启用」列表
  ② 未启用的模块【也要】列进表格（否则读者分不清"没勾"和"没渲染"）
  ③ 子选项的取值要正确渲染（flag → ✅/⬜；text → 行数；留空 → 提示）
  ④ 解析失败要优雅降级，不能抛异常（摘要失败不该让构建红）

## 反向验证

把 is_enabled() 改成恒 True → ① 必红
把未启用模块从表格里跳过 → ② 必红
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCRIPT = ROOT / "scripts" / "actions" / "render-summary.py"

ok = 0
bad = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global ok, bad
    if cond:
        ok += 1
        print(f"  ✅ {name}")
    else:
        bad += 1
        print(f"  ❌ {name}" + (f" —— {detail}" if detail else ""))


def render(cfg, **env_extra) -> str:
    """跑一次 render-summary.py，返回写入的 markdown。"""
    env = dict(os.environ)
    env["PROTECT_CONFIG"] = json.dumps(cfg) if not isinstance(cfg, str) else cfg
    env.pop("NO_LOCK", None)
    env.pop("NO_NOX", None)
    env.pop("AMICE_PROBE", None)
    env.update({k.upper(): str(v) for k, v in env_extra.items()})
    with tempfile.NamedTemporaryFile("w+", suffix=".md", delete=False) as f:
        out = f.name
    env["GITHUB_STEP_SUMMARY"] = out
    try:
        subprocess.run([sys.executable, str(SCRIPT)], env=env,
                       capture_output=True, timeout=30)
        return Path(out).read_text(encoding="utf-8")
    finally:
        Path(out).unlink(missing_ok=True)


print("── ① 启用/未启用分组 ──")
md = render({
    "schema_version": 1,
    "sigcheck": True,
    "dex2c": {"enabled": False},
    "soguard": {"enabled": True},
    "stringenc": {"enabled": False},
    "antidiff": False,
    "envcheck": False,
    "packer": {"enabled": False},
})
check("摘要含「启用 2 个模块」", "启用 2 个模块" in md, md[:200])
check("启用列表含 签名校验", "签名校验" in md)
check("启用列表含 so层保护", "so层保护" in md)
check("未启用列表含 Dex2C", "未启用 5 个" in md and "Dex2C" in md)

print("── ② 未启用的模块也要出现在表格里 ──")
# Dex2C 未启用，但它必须有一行（否则读者无法判断"没勾"还是"漏渲染"）
check("未启用模块仍有表格行", "| **Dex2C** | `dex2c` | ⬜ 未启用 |" in md,
      [l for l in md.splitlines() if "Dex2C" in l])

print("── ③ 子选项渲染 ──")
md2 = render({
    "schema_version": 1,
    "sigcheck": True,
    "soguard": {"enabled": True, "vm": True, "mba": True, "flatten": False,
            "indirect_call": True, "indirect_branch": False,
            "vm_flatten": False},
    "stringenc": {"enabled": True, "stub_impl": "native", "algo": "chacha20",
                  "dex2c_stub": True, "rules_file": "com.a.**\ncom.b.**"},
})
check("flag 开 → ✅ 开", "| ✅ 开 | `--obfuscate-mba` |" in md2,
      [l for l in md2.splitlines() if "mba" in l])
check("flag 关 → ⬜ 关", "⬜ 关" in md2)
check("结构性混淆也在表格里且带参数",
      "| ✅ 开 | `--obfuscate-indirect-call` |" in md2,
      [l for l in md2.splitlines() if "indirect" in l])
check("rules_file 显示行数", "已填（2 行规则）" in md2,
      [l for l in md2.splitlines() if "rules_file" in l])
check("text 值原样", "| chacha20 |" in md2)

# rules_file 留空时的提示
md3 = render({"schema_version": 1, "stringenc": {"enabled": True, "rules_file": ""}})
check("rules_file 留空有提示", "留空 = 自动抽主类" in md3)

print("── ④ 测试开关 ──")
md4 = render({"schema_version": 1, "sigcheck": True}, no_lock=True)
check("no_lock 开启时出现在摘要", "no_lock" in md4 and "不可发布" in md4)
md5 = render({"schema_version": 1, "sigcheck": True})
check("未开测试开关时不出现该节", "不可发布" not in md5)

print("── ⑤ 降级：解析失败不抛异常 ──")
md6 = render("{this is not json")
check("非法 JSON 时输出警告", "解析失败" in md6)
check("非法 JSON 时仍回显原文", "this is not json" in md6)

md7 = render("")
check("空配置时输出提示", "未收到 protect_config" in md7)

print("── ⑥ 全不勾的告警 ──")
md8 = render({"schema_version": 1})
check("全不勾时明确警告", "没有勾选任何加固模块" in md8)

print()
print(f"通过 {ok}，失败 {bad}")
sys.exit(1 if bad else 0)
