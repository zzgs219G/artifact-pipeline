#!/usr/bin/env python3
"""把 protect_config 渲染成 GitHub Actions 任务页顶部的 Markdown 摘要。

## 为什么需要这个文件

用户原话：「勾选了模块，但是并不知道勾选了什么模块……为什么不在流水线的
那个任务界面里点进去你就能发现了，而还要自己去日志里面找是什么鬼啊？」

此前任务页（GitHub Actions 的 run 页面）只有一个日志入口。想知道"这次
勾了什么"必须：

  · 翻构建日志找 `勾选 N 个模块，按固定顺序执行: ...`
  · 或者回 App 里看上次的勾选快照

两样都绕。而 GitHub 提供 `$GITHUB_STEP_SUMMARY`：写进去的 Markdown 会
渲染成 run 页面**顶部的富文本**（不是日志），点开任务第一眼就在。

## 输出什么

  · 一行结论（勾了几个、哪些是测试开关）
  · 一张模块表（✅ 启用 / ⬜ 未启用 + 中文名 + 子选项取值）
  · 硬编码模块的参数（--vmp 之类，取自 schema 的 arg 字段）
  · 测试开关单列（不进 App UI 的那几个）

## 设计纪律

⚠️ ① 中文名与 arg 全部取自 config-schema.json，不在本文件硬编码。
      模块改名/新增时这里零改动 —— 否则又会多一处需要同步的地方。
⚠️ ② 任何解析失败都退化为「原样打印 protect_config 的 JSON」，
      绝不因为摘要生成失败让构建红。摘要只是展示层。
⚠️ ③ 未启用的模块也列出来（灰色 ⬜）。只列启用的话，读者无法判断
      "是没勾还是没渲染"。
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA = ROOT / "configs" / "v1" / "config-schema.json"

# 不进 App 勾选 UI、只由 CI/CLI 传的测试开关。
# 与 config-schema.json 无关 —— 它们刻意的就不在 schema 里（见各开关的注释）。
TEST_SWITCHES = {
    "no_lock": "跳过 so 锁箱（.ncx/.ncxr/.ncxh 保持明文）",
    "no_nox": "完全不注入 nox（量模块自身体积用）",
    "amice_probe": "只跑 Amice 插件探路，不出包",
}


def die_soft(msg: str) -> None:
    """摘要失败不能影响构建。打到 stderr 并正常退出。"""
    print(f"[summary] {msg}", file=sys.stderr)
    sys.exit(0)


def load_schema() -> dict:
    try:
        return json.loads(SCHEMA.read_text(encoding="utf-8"))
    except Exception as e:
        die_soft(f"读 schema 失败: {e}")
        return {}


def is_enabled(module: dict, cfg) -> bool:
    """与 resolve-config.py 的 read_enabled 保持同一语义。

    leaf   → 顶层布尔
    parent → 对象里的 .enabled
    旧版 App 可能把 parent 当 leaf 提交顶层布尔，两种都接受。
    """
    if cfg is None:
        return False
    if module.get("type") == "parent":
        if isinstance(cfg, bool):
            return cfg
        if isinstance(cfg, dict):
            return bool(cfg.get("enabled", False))
        return False
    if isinstance(cfg, dict):
        return bool(cfg.get("enabled", False))
    return bool(cfg) if isinstance(cfg, bool) else False


def render_child(line: list, child: dict, val) -> None:
    """把一个子选项渲染成表格里的一行（缩进 + 取值）。"""
    label = child.get("label") or child["key"]
    kind = child.get("value_kind", "")

    if kind == "flag":
        shown = "✅ 开" if val is True else "⬜ 关"
    elif kind == "rules_file":
        if not val:
            shown = "（留空 = 自动抽主类）"
        else:
            n = len(str(val).strip().splitlines())
            shown = f"已填（{n} 行规则）"
    elif isinstance(val, bool):
        shown = "✅ 是" if val else "⬜ 否"
    elif val in (None, ""):
        shown = f"（默认 {child.get('default', '') or '空'}）"
    else:
        shown = str(val)

    arg = child.get("arg_on", "")
    arg_shown = f"`{arg}`" if (arg and shown.startswith("✅")) else "—"
    line.append(f"| &nbsp;&nbsp;└ {label} | `{child['key']}` | {shown} | {arg_shown} |")


def main() -> None:
    raw = os.environ.get("PROTECT_CONFIG", "").strip()
    out_path = os.environ.get("GITHUB_STEP_SUMMARY", "")

    lines: list = []

    if not raw:
        lines.append("## ⚠️ 未收到 protect_config")
        lines.append("")
        lines.append("本次触发没有传模块配置（可能是非 workflow_dispatch 事件）。")
        _flush(lines, out_path)
        return

    try:
        cfg = json.loads(raw)
    except Exception as e:
        lines.append("## ⚠️ protect_config 解析失败")
        lines.append("")
        lines.append(f"`{e}`")
        lines.append("")
        lines.append("```json")
        lines.append(raw)
        lines.append("```")
        _flush(lines, out_path)
        return

    schema = load_schema()
    modules = schema.get("modules", [])

    # ── 统计 ──────────────────────────────────────────────────────
    on, off = [], []
    for m in modules:
        (on if is_enabled(m, cfg.get(m["key"])) else off).append(m.get("label") or m["key"])

    # ── 标题区 ────────────────────────────────────────────────────
    name = os.environ.get("DISPLAY_NAME", "").strip()
    lines.append(f"## 📦 加固任务：{name}" if name else "## 📦 加固任务")
    lines.append("")

    if not on:
        lines.append("> ⚠️ **没有勾选任何加固模块** —— 这条流水线跑完不会产生防护效果。")
    else:
        lines.append(f"**启用 {len(on)} 个模块**：{' · '.join(on)}")
    if off:
        lines.append("")
        lines.append(f"未启用 {len(off)} 个：{(' · '.join(off))}")
    lines.append("")

    # ── 模块明细表 ────────────────────────────────────────────────
    lines.append("### 模块明细")
    lines.append("")
    lines.append("| 模块 | key | 状态 | 参数 |")
    lines.append("|:---|:---|:---:|:---|")

    for m in modules:
        key = m["key"]
        label = m.get("label") or key
        cfg_node = cfg.get(key)
        enabled = is_enabled(m, cfg_node)
        arg = m.get("arg", "")
        mark = "✅ 启用" if enabled else "⬜ 未启用"
        arg_shown = f"`{arg}`" if enabled and arg else "—"
        lines.append(f"| **{label}** | `{key}` | {mark} | {arg_shown} |")

        # 子选项：只对启用的模块展开（未启用时子项无意义）
        if enabled and isinstance(cfg_node, dict):
            for child in m.get("children", []):
                ck = child["key"]
                if ck in cfg_node:
                    render_child(lines, child, cfg_node[ck])
                else:
                    render_child(lines, child, child.get("default"))

    # ── 测试开关 ──────────────────────────────────────────────────
    active_switches = []
    for sw, desc in TEST_SWITCHES.items():
        # GitHub Actions 的 boolean input 渲染成 "true"/"false" 字符串
        v = os.environ.get(sw.upper(), "").strip().lower()
        if v in ("true", "1", "yes", "on"):
            active_switches.append(f"| `{sw}` | ✅ 已开启 | {desc} |")

    if active_switches:
        lines.append("")
        lines.append("### ⚠️ 测试开关（产物不可发布）")
        lines.append("")
        lines.append("| 开关 | 状态 | 说明 |")
        lines.append("|:---|:---:|:---|")
        lines.extend(active_switches)

    # ── 原始 JSON（折叠）─────────────────────────────────────────
    lines.append("")
    lines.append("<details><summary>原始 protect_config（点击展开）</summary>")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(cfg, ensure_ascii=False, indent=2))
    lines.append("```")
    lines.append("")
    lines.append("</details>")

    _flush(lines, out_path)


def _flush(lines: list, out_path: str) -> None:
    text = "\n".join(lines) + "\n"
    if out_path:
        try:
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(text)
            print("[summary] 已写入任务摘要", file=sys.stderr)
        except Exception as e:
            print(f"[summary] 写摘要失败（不影响构建）: {e}", file=sys.stderr)
    else:
        # 本地调试：没有 GITHUB_STEP_SUMMARY 时打到 stdout
        print(text)


if __name__ == "__main__":
    main()
