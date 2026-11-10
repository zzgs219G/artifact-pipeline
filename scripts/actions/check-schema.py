#!/usr/bin/env python3
"""configs/v1/config-schema.json 校验：
- JSON 可解析
- schema_version 与目录名一致（§10.6）
- 模块 key 唯一、arg 格式、required 结构
"""
import json
import re
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    d = json.load(f)

assert d["schema_version"] == 1, f"schema_version 应为 1（目录 v1），实际 {d['schema_version']}"

keys = []
for m in d["modules"]:
    k = m["key"]
    keys.append(k)
    assert m["type"] in ("leaf", "parent"), f"{k}: type 非法"
    # 注意: --dex2c 含数字,字符类必须含 0-9;^--[a-z-]+$ 匹配不了它(勿"修正"回文档原样)
    assert re.fullmatch(r"--[a-z0-9-]+", m["arg"]), f"{k}: arg 非法 {m['arg']}"
    if m["type"] == "parent":
        for c in m["children"]:
            if "required" in c:
                r = c["required"]
                assert r["when"] == "always", f"{k}.{c['key']}: v1 只允许 when=always（§10.3）"
                if "unless" in r:
                    u = r["unless"]
                    assert set(u) == {"key", "is"}, f"{k}.{c['key']}: unless 必须是 key+is（D4）"
            # select 与 radio 都是"从 options 里选一个"的渲染形态，校验规则相同。
            # 区别只在 UI（下拉 vs 横向单选），执行语义都是 value_kind=choice。
            if c["type"] in ("select", "radio"):
                vals = [o["value"] for o in c["options"]]
                assert c["default"] in vals, f"{k}.{c['key']}: default 不在 options"
                # value_kind=choice（2026-11-09）：值从 options 里选一个，
                # 选中项的 arg_on 追加进 argv。三条结构断言，缺一条都会到
                # 运行期才暴露（resolve-config 会 die，但报的是"配置错了"
                # 而不是"schema 写错了"，排障方向完全不同）：
                if c.get("value_kind") == "choice":
                    vs = [o["value"] for o in c["options"]]
                    assert len(vs) == len(set(vs)), f"{k}.{c['key']}: options 的 value 重复"
                    for o in c["options"]:
                        assert o.get("label"), f"{k}.{c['key']}: option {o.get('value')!r} 缺 label"
                        assert "arg_on" in o, f"{k}.{c['key']}: option {o.get('value')!r} 缺 arg_on（默认项写空串）"
                    # 旧 App 快照兼容映射（resolve-config 里 isinstance(bool) 分支）
                    # 靠"恰好一个带 arg_on 的选项"成立，多于一个就不该走兼容路径。
                    nd = [o for o in c["options"] if o.get("arg_on")]
                    assert len(nd) <= 1, (
                        f"{k}.{c['key']}: 带 arg_on 的 option 有 {len(nd)} 个，"
                        f"旧快照布尔值无法确定映射（最多 1 个）")

            # 子项依赖（2026-11-09）：visible_when: {key, equals}
            # 语义 = 本子项只在 key 的取值等于 equals 时存在。四条断言，
            # 全是"写错了要到运行期才炸、且炸得不像 schema 问题"的类型：
            if "visible_when" in c:
                vw = c["visible_when"]
                assert set(vw) == {"key", "equals"}, (
                    f"{k}.{c['key']}: visible_when 必须是 key+equals")
                assert isinstance(vw["key"], str) and isinstance(vw["equals"], str), (
                    f"{k}.{c['key']}: visible_when 的 key/equals 必须是字符串")
                # ① 必须指向【同模块内】的子项 —— 跨模块取值语义未定义（模块可能整个未启用）
                sib = {s["key"]: s for s in m["children"]}
                assert vw["key"] in sib, (
                    f"{k}.{c['key']}: visible_when.key={vw['key']!r} 不是同模块的子项")
                assert vw["key"] != c["key"], (
                    f"{k}.{c['key']}: visible_when 不能引用自己")
                # ② 被依赖方必须是带 options 的 choice，否则 equals 无意义
                dep = sib[vw["key"]]
                assert dep.get("value_kind") == "choice", (
                    f"{k}.{c['key']}: visible_when.key={vw['key']!r} 必须是 "
                    f"value_kind=choice（当前 {dep.get('value_kind')!r}）")
                # ③ equals 必须是该 choice 的合法 option，否则该子项永远不可见
                #    （静默永不显示 = 用户永远看不到这个功能，比报错难查得多）
                dvals = [o["value"] for o in dep["options"]]
                assert vw["equals"] in dvals, (
                    f"{k}.{c['key']}: visible_when.equals={vw['equals']!r} "
                    f"不在 {vw['key']} 的 options {dvals} 里")
                # ④ 被依赖方自身不能也有 visible_when（链式依赖无法保证求值顺序，
                #    UI 与 resolver 各实现一遍必然漂移）
                assert "visible_when" not in dep, (
                    f"{k}.{c['key']}: visible_when 不支持链式（{vw['key']} 自己也有 visible_when）")

assert len(keys) == len(set(keys)), "模块 key 重复"
# key 顺序 = 勾选 UI 的展示顺序 = protect.sh 的固定执行顺序
# （protect.sh 阶段序：指纹 → dex2c 转译(唯一引擎) → 组装 NDK(含 envcheck 并入 libnc.so) → 编译
#   → mark-native → stringenc → anti-diff → 回编 → packer。
#   envcheck 在 NDK 组装阶段并入 so，与 packer 一样排在列表末位。）
# ⚠️ 旧引擎 dcc 已于 2026-12 下线、2026-10 从 schema 移除，此处断言不得再要求它。
# obfuscate（2026-11-05）：so 层混淆，编译期生效 → 紧跟 dex2c 之后
#（两者都作用于 so 产物；它必须排在 NDK 编译之前的参数汇总里）。
# vmp（2026-11-10）：指令级虚拟化，同样是编译期 pass、同样作用于 so，
# 排在 obfuscate 之后（与它并列在"编译期 so 变换"这一组里）。
assert keys == ["sigcheck", "dex2c", "obfuscate", "vmp", "stringenc", "antidiff",
                "envcheck", "packer"], keys
print("schema OK:", keys)
