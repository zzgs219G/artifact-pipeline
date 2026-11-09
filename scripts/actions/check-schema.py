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
            if c["type"] == "select":
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

assert len(keys) == len(set(keys)), "模块 key 重复"
# key 顺序 = 勾选 UI 的展示顺序 = protect.sh 的固定执行顺序
# （protect.sh 阶段序：指纹 → dex2c 转译(唯一引擎) → 组装 NDK(含 envcheck 并入 libnc.so) → 编译
#   → mark-native → stringenc → anti-diff → 回编 → packer。
#   envcheck 在 NDK 组装阶段并入 so，与 packer 一样排在列表末位。）
# ⚠️ 旧引擎 dcc 已于 2026-12 下线、2026-10 从 schema 移除，此处断言不得再要求它。
# obfuscate（2026-11-05）：so 层混淆，编译期生效 → 紧跟 dex2c 之后
#（两者都作用于 so 产物；它必须排在 NDK 编译之前的参数汇总里）。
assert keys == ["sigcheck", "dex2c", "obfuscate", "stringenc", "antidiff",
                "envcheck", "packer"], keys
print("schema OK:", keys)
