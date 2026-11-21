#!/usr/bin/env python3
"""resolve-config.py 验收测试（设计方案 §7 验收清单 + §10 追加项）。

纯 stdlib，无 pytest 依赖：直接以子进程跑 resolve-config.py，断言输出。
覆盖：
  T1 sigcheck 单独勾选            → args.txt == ["--sigcheck"]
  T2 dex2c 单独勾选 + 规则        → --dex2c + 规则文件路径（workspace 相对）
  T3 dex2c 联合 sigcheck 留空规则 → --dex2c 不带文件参数（§7 重点）
  T2b dcc 已下架（2026-12）       → 旧 App 提交 dcc key → 报错退出（保险丝 a，防幽灵勾选项）
  T3b dcc 已下架（2026-12）       → 联合 sigcheck 提交 dcc key → 同样报错（不豁免）
  T4 stringenc 勾选未填规则       → 解析器 fail（App 端同规则应拦截）
  T6 全家桶组合                   → 参数齐全、顺序固定
  T7 未知顶层 key                 → 报错退出（保险丝 a，§10.1 反向）
  T8 config 缺失其余模块 key      → 视为 disabled 不报错（§10.1 正向）
  T9 schema_version 缺失          → 报错（必填校验）
  T10 schema_version 偏高         → 报错提示更新流水线（保险丝 a0）
  T11 全部 disabled               → 报错（保险丝 e）
  T12 规则内容含空格/特殊字符      → 原样写入文件，argv 仅相对路径（§7）
  T13 未知模块内子 key            → 报错退出（保险丝 a 模块内）
  T14 cwd 无关性（§10.5）          → 任意 cwd 下运行结果一致
  T15 args.txt 结尾无多余空行（§10.2）
  T6b/T6c packer(基础加壳)          → leaf 模块，只吐 --packer，与共存模块顺序固定
  T6d 旧 App 快照无 packer 键       → 视为 disabled，不报错（§10.1 正向）
  T6e/T6f stringenc.dex2c_stub       → 缺省/显式 false 均不追加；显式 true 追加（T6o）
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))   # tests → actions → scripts → 仓库根
SCRIPT = os.path.join(HERE, "..", "resolve-config.py")
SCHEMA = os.path.join(ROOT, "configs", "v1", "config-schema.json")

passed = failed = 0


def run(config_obj, cwd=None):
    """在独立临时根中运行解析器，返回 (rc, args_lines, files, stderr)。"""
    tmp = tempfile.mkdtemp(prefix="rc-test-")
    os.makedirs(os.path.join(tmp, "configs", "v1"))
    shutil.copy(SCHEMA, os.path.join(tmp, "configs", "v1", "config-schema.json"))
    env = dict(os.environ)
    env["INPUT_PROTECT_CONFIG"] = json.dumps(config_obj, ensure_ascii=False)
    env["GITHUB_WORKSPACE"] = tmp
    p = subprocess.run(
        [sys.executable, SCRIPT], env=env, cwd=cwd or tmp,
        capture_output=True, text=True,
    )
    args_lines, files = [], {}
    rules_dir = os.path.join(tmp, "build", "schema_rules")
    if os.path.isdir(rules_dir):
        for name in sorted(os.listdir(rules_dir)):
            with open(os.path.join(rules_dir, name), encoding="utf-8") as f:
                files[name] = f.read()
        if "args.txt" in files:
            args_lines = [l for l in files["args.txt"].splitlines() if l.strip()]
    shutil.rmtree(tmp, ignore_errors=True)
    # 第四项返回 stdout+stderr 合并：回执（_dump_plan）打在 stdout，
    # 报错打在 stderr，断言两者都要能查。2026-11-22 前只返回 stderr，
    # 导致"回执里有没有某子项"这类断言永远查不到（T19e 曾因此恒假）。
    return p.returncode, args_lines, files, (p.stdout or "") + (p.stderr or "")


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}  {detail}")


def cfg(**kw):
    base = {"schema_version": 1, "sigcheck": False,
            "dex2c": {"enabled": False},
            "stringenc": {"enabled": False},
            "antidiff": False, "envcheck": False, "packer": False}
    base.update(kw)
    return base


print("== resolve-config.py 验收测试 ==")

# T1
rc, args, files, err = run(cfg(sigcheck=True))
check("T1 sigcheck 单独勾选 → 仅 --sigcheck", rc == 0 and args == ["--sigcheck"], f"rc={rc} err={err}")

# T2
rc, args, files, err = run(cfg(dex2c={"enabled": True, "rules_file": "**/com.test.**"}))
check("T2 dex2c+规则 → --dex2c + workspace 相对规则路径",
      rc == 0 and args == ["--dex2c", "build/schema_rules/dex2c.txt"]
      and files.get("dex2c.txt", "").strip() == "**/com.test.**",
      f"rc={rc} args={args}")

# T3（§7 重点）
rc, args, files, err = run(cfg(sigcheck=True, dex2c={"enabled": True, "rules_file": ""}))
check("T3 dex2c+sigcheck 留空规则 → --dex2c 无文件参数",
      rc == 0 and args == ["--sigcheck", "--dex2c"], f"rc={rc} args={args} err={err}")

# T3c（2026-11-12 解除 sigcheck 耦合）: 只勾 dex2c + 规则留空也必须放行。
# 此前 required.unless 绑在 sigcheck 上，导致用户必须连带勾选签名校验才能出包。
# 但自动抽主类的实际输入只有 APK 的 Manifest（make-filter-from-apk.py），
# 与 sigcheck 产物无关 —— 那个限制是从 apk-protect-action 迁入时带进来的。
rc, args, files, err = run(cfg(dex2c={"enabled": True, "rules_file": ""}))
check("T3c 只 dex2c 留空规则 → 放行（不再要求 sigcheck）",
      rc == 0 and args == ["--dex2c"], f"rc={rc} args={args} err={err}")

# T2b（2026-12 dcc 引擎下架：schema 已删 dcc 模块块，旧 App 快照提交 dcc key
# 必须被保险丝 a 拒绝——静默忽略会变成"勾了没生效"的幽灵勾选项）
rc, args, files, err = run(cfg(dcc={"enabled": True, "rules_file": "**/com.test.**"}))
check("T2b dcc 已下架 → 提交 dcc key 报错退出（保险丝 a）",
      rc != 0 and "dcc" in err and "未定义" in err, f"rc={rc} args={args} err={err}")

# T3b（下架同样不因联合 sigcheck 而豁免：旧快照的 dcc key 一律拒绝）
rc, args, files, err = run(cfg(sigcheck=True, dcc={"enabled": True, "rules_file": ""}))
check("T3b dcc 已下架+联合 sigcheck → 仍报错退出（不豁免）",
      rc != 0 and "dcc" in err and "未定义" in err, f"rc={rc} args={args} err={err}")

# T4
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": ""}))
check("T4 stringenc 留空规则 → fail-fast", rc != 0 and "规则为空" in err, f"rc={rc} err={err}")

# T6
rc, args, files, err = run(cfg(sigcheck=True, envcheck=True, antidiff=True, packer=True,
                               dex2c={"enabled": True, "rules_file": "**/com.test.**"},
                               stringenc={"enabled": True, "rules_file": "**/com.s.**",
                                          "dex2c_stub": True}))
expect = ["--sigcheck", "--dex2c", "build/schema_rules/dex2c.txt",
          "--stringenc", "build/schema_rules/stringenc.txt", "--dex2c-stub",
          "--anti-diff", "--envcheck", "--packer"]
check("T6 全家桶 → 参数齐全且顺序固定", rc == 0 and args == expect, f"rc={rc} args={args}")

# T6e stringenc.dex2c_stub 子复选框(2026-10 联动; 2026-11-09 改回 default true):
# 缺省 → 追加 --dex2c-stub。演进史：
#   · 2026-10-16 从 true 改成 false：当时 protect.sh 的依赖校验是
#     "必须与 --dex2c 同时勾选"，于是默认 true + 只勾 stringenc = 构建失败。
#   · 2026-11-02 那次架构修正删掉了"必须 --dex2c"（改走 stringenc 自己的
#     LINK_STUB 接口，见 protect.sh:308 —— 条件是 WANT_STRINGENC && WANT_DEX2C_STUB），
#     风险根因消失。
#   · 2026-11-09 改回 true：它是保护强度项（把解密桩内核也抽离 dex），
#     代价只是构建 +30~60s（解包/回编 2 次），运行期无损。
#     与 trigger_build.py 的 --all 预设口径一致（那里也默认带它）。
# 显式 false 仍可不追加（见 T6f）；flag 分支：值是布尔、不写规则文件。
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "com.a.**"}))
check("T6e stringenc.dex2c_stub 缺省 → 按 default(false) 不追加",
      rc == 0 and args == ["--stringenc", "build/schema_rules/stringenc.txt"],
      f"rc={rc} args={args} err={err}")

# T6f 显式不勾 → 不追加(老路径:桩留在 dex)
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "com.a.**",
                                          "dex2c_stub": False}))
check("T6f stringenc.dex2c_stub=false → 不追加 --dex2c-stub",
      rc == 0 and args == ["--stringenc", "build/schema_rules/stringenc.txt"],
      f"rc={rc} args={args} err={err}")

# T6o 显式勾选 → 追加。resolver 不做跨模块配对判断(stringenc+dex2c 才合法),
# 缺配对由 protect.sh 的依赖校验 fail-fast 拦截——分工:resolver 管"勾了就传",
# 流水线管"组合非法拒收"。
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "com.a.**",
                                          "dex2c_stub": True}))
check("T6o stringenc.dex2c_stub=true → 追加 --dex2c-stub",
      rc == 0 and args == ["--stringenc", "build/schema_rules/stringenc.txt",
                           "--dex2c-stub"], f"rc={rc} args={args} err={err}")

# T6b packer:新增的加壳模块是 leaf(无子选项),勾选只吐一个 --packer
rc, args, files, err = run(cfg(packer=True))
check("T6b packer 单独勾选 → 仅 --packer", rc == 0 and args == ["--packer"],
      f"rc={rc} args={args} err={err}")

# T6c packer 与其余模块共存 → 顺序固定,packer 落在最后
rc, args, files, err = run(cfg(sigcheck=True, envcheck=True, antidiff=True, packer=True))
check("T6c packer 与其余共存 → --packer 在末尾",
      rc == 0 and args == ["--sigcheck", "--anti-diff", "--envcheck", "--packer"],
      f"rc={rc} args={args} err={err}")

# T6d 旧版 App 快照(config 无 packer 键)→ 视为 disabled,不报错(§10.1 正向)
rc, args, files, err = run({"schema_version": 1, "sigcheck": True})
check("T6d config 缺 packer 键 → 视为 disabled(旧 App 向后兼容)",
      rc == 0 and args == ["--sigcheck"], f"rc={rc} args={args} err={err}")

# T6e(报错四十三)packer 升 parent:子复选框 smaller(体积优化,默认 true)
rc, args, files, err = run(cfg(packer={"enabled": True, "smaller": True}))
# ⚠️ 2026-11-02：exclude_x86 的 schema default 改 false→true（用户拍板：
# 体积排除也该默认勾上）。所以这三条断言的 args 末尾多了 --exclude-abi 两项。
check("T6e 勾 packer+smaller → --packer --packer-smaller（exclude_x86 默认开）",
      rc == 0 and args == ["--packer", "--packer-smaller", "--exclude-abi", "x86,x86_64"],
      f"rc={rc} args={args} err={err}")

# T6f 子键缺失 → 按 schema default(true)
rc, args, files, err = run(cfg(packer={"enabled": True}))
check("T6f 缺 smaller 子键 → 按 default(true) 吐 --packer-smaller",
      rc == 0 and args == ["--packer", "--packer-smaller", "--exclude-abi", "x86,x86_64"],
      f"rc={rc} args={args} err={err}")

# T6g 显式不勾 smaller → 只吐 --packer
rc, args, files, err = run(cfg(packer={"enabled": True, "smaller": False}))
check("T6g smaller=false → 仅 --packer（exclude_x86 仍按默认开）",
      rc == 0 and args == ["--packer", "--exclude-abi", "x86,x86_64"],
      f"rc={rc} args={args} err={err}")

# T6h smaller 非布尔 → 报错退出(布尔校验)
rc, args, files, err = run(cfg(packer={"enabled": True, "smaller": "yes"}))
check("T6h smaller 非布尔 → 报错退出", rc != 0 and "布尔" in err, f"rc={rc} err={err}")

# T6i parent 整体不勾 → 子字段无效;无任何模块启用时走保险丝 e fail-fast
rc, args, files, err = run(cfg(packer={"enabled": False, "smaller": True}))
check("T6i packer 不勾 → 子字段无效,无启用模块走保险丝 e",
      rc != 0 and "没有任何加固模块被启用" in err, f"rc={rc} err={err}")

# T6j 旧版 App 快照顶层 bool 形态(packer: true)→ 兼容,子字段不参与(旧行为保持,
# 不吐 --packer-smaller——旧快照提交时无此概念,不引入行为漂移)
rc, args, files, err = run(cfg(packer=True))
check("T6j 旧 bool 快照 → 仅 --packer(旧行为,不默认叠加子选项)",
      rc == 0 and args == ["--packer"], f"rc={rc} args={args} err={err}")

# T6k(报错四十四)带值参数标准件:勾 exclude_x86 → arg_on 与 arg_value 各占一行
rc, args, files, err = run(cfg(packer={"enabled": True, "smaller": True, "exclude_x86": True}))
check("T6k 勾 exclude_x86 → --packer --packer-smaller --exclude-abi x86,x86_64",
      rc == 0 and args == ["--packer", "--packer-smaller", "--exclude-abi", "x86,x86_64"],
      f"rc={rc} args={args} err={err}")

# T6l exclude_x86 缺失 → 按 schema default(true) 追加（2026-11-02 改）
rc, args, files, err = run(cfg(packer={"enabled": True, "smaller": True}))
check("T6l 缺 exclude_x86 子键 → default(true) 追加 --exclude-abi",
      rc == 0 and args == ["--packer", "--packer-smaller", "--exclude-abi", "x86,x86_64"],
      f"rc={rc} args={args} err={err}")

# T6m 显式不勾 → 不追加
rc, args, files, err = run(cfg(packer={"enabled": True, "exclude_x86": False}))
check("T6m exclude_x86=false → 仅体积优化线",
      rc == 0 and args == ["--packer", "--packer-smaller"], f"rc={rc} args={args} err={err}")

# T6n exclude_x86 非布尔 → 报错退出(布尔校验同 flag)
rc, args, files, err = run(cfg(packer={"enabled": True, "exclude_x86": "yes"}))
check("T6n exclude_x86 非布尔 → 报错退出", rc != 0 and "布尔" in err, f"rc={rc} err={err}")

# T7（§10.1 反向）
rc, args, files, err = run(cfg(unknown_mod=True))
check("T7 未知顶层 key → 报错退出（保险丝 a）", rc != 0 and "未定义" in err, f"rc={rc} err={err}")

# T8（§10.1 正向）
rc, args, files, err = run({"schema_version": 1, "sigcheck": True})
check("T8 config 缺失其余模块 key → 视为 disabled 不报错",
      rc == 0 and args == ["--sigcheck"], f"rc={rc} args={args} err={err}")

# T9
c = cfg(sigcheck=True)
del c["schema_version"]
rc, args, files, err = run(c)
check("T9 缺 schema_version → 报错", rc != 0 and "schema_version" in err, f"rc={rc} err={err}")

# T10（保险丝 a0）
rc, args, files, err = run(cfg(sigcheck=True, schema_version=2))
check("T10 schema_version 偏高 → 报错提示更新流水线", rc != 0 and "更新流水线" in err, f"rc={rc} err={err}")

# T11（保险丝 e）
rc, args, files, err = run(cfg())
check("T11 全部 disabled → 报错", rc != 0 and "没有" in err, f"rc={rc} err={err}")

# T12（§7：特殊字符规则）
tricky = "**/com.test.**  # 注释 行 !排除\nactivity*\n\n$HOME `id` ; rm -rf\n"
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": tricky}))
check("T12 特殊字符规则 → 原样写入文件、argv 仅相对路径",
      rc == 0 and args == ["--stringenc", "build/schema_rules/stringenc.txt"]
      and files.get("stringenc.txt") == tricky,
      f"rc={rc} args={args}")

# T13
rc, args, files, err = run(cfg(dex2c={"enabled": True, "rules_file": "x", "rogue": 1}))
check("T13 模块内未知子 key → 报错退出", rc != 0 and "未定义" in err, f"rc={rc} err={err}")

# T14（§10.5：cwd 无关）
rc, args, files, err = run(cfg(sigcheck=True), cwd="/")
check("T14 任意 cwd 运行 → 结果一致（仓库根推算）", rc == 0 and args == ["--sigcheck"], f"rc={rc} err={err}")

# T15（§10.2）
rc, args, files, err = run(cfg(sigcheck=True, envcheck=True))
raw = files.get("args.txt", "")
check("T15 args.txt 一行一个、结尾无多余空行", rc == 0 and raw == "--sigcheck\n--envcheck\n", f"raw={raw!r}")

# T16 v1.2 回退:antidiff 已回退 leaf,变换 F 并入本体固定开启,不再有子复选框。
# 旧 parent dict 形态提交(含已下线 reencode 字段)→ 按 .enabled 读,只吐模块 arg
rc, args, files, err = run(cfg(antidiff={"enabled": True, "reencode": True}))
check("T16 旧 parent dict 形态(勾选 reencode) → 兼容,只吐 --anti-diff",
      rc == 0 and args == ["--anti-diff"], f"rc={rc} args={args} err={err}")

# T16b 旧 parent dict 形态(不勾 reencode)→ 同样只吐模块 arg(变换 F 固定开,行为一致)
rc, args, files, err = run(cfg(antidiff={"enabled": True, "reencode": False}))
check("T16b 旧 parent dict 形态(不勾 reencode) → 只吐 --anti-diff",
      rc == 0 and args == ["--anti-diff"], f"rc={rc} args={args} err={err}")

# T16c 旧 parent dict 形态(缺 reencode)→ 同样兼容
rc, args, files, err = run(cfg(antidiff={"enabled": True}))
check("T16c 旧 parent dict 形态(缺 reencode) → 兼容,只吐 --anti-diff",
      rc == 0 and args == ["--anti-diff"], f"rc={rc} args={args} err={err}")

# T16d 旧版 App 顶层 bool 形态 → 兼容,只吐模块 arg
rc, args, files, err = run(cfg(sigcheck=True, antidiff=True))
check("T16d 顶层 bool 形态 antidiff=true → 兼容,只吐模块 arg",
      rc == 0 and args == ["--sigcheck", "--anti-diff"], f"rc={rc} args={args} err={err}")

# T16e 旧 parent dict 形态 enabled 非布尔 → 报错
rc, args, files, err = run(cfg(antidiff={"enabled": "yes"}))
check("T16e 旧 dict 形态 enabled 非布尔 → 报错退出",
      rc != 0 and "布尔" in err, f"rc={rc} err={err}")

# ── T17: stringenc.stub_impl 已下线（2026-11-22）──────────────────────
# 语义变更史（这条链路改过三次，每次都值得记）：
#   11-09 上午：flag（布尔）→ 云端首跑传 "native" 报 400，改成布尔 True。
#   11-09 下午：改 choice（枚举字符串）。理由是 flag 形态下"两个复选框能
#               同时勾"，互斥只靠报错兜底；choice 让"二选一"在数据结构层成立。
#   11-22：整项下线 —— Java 桩归档（docs/备份/java桩-归档-2026-11-22/），
#           C 桩成为唯一实现，没有可选项了。
#
# ⚠️ 关键约束：**存量 App 快照里一定还有这个 key**，必须静默剥离。
# 若按保险丝 a 直接 die，所有旧 App 用户的构建会全部失败。
# 所以下面这组断言验的是"剥离"，不是"报错"。
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**",
                                          "stub_impl": "c"}))
check("T17a 旧快照 stub_impl='c' → 静默剥离，不报错",
      rc == 0, f"rc={rc} err={err}")
check("T17a2 剥离后不残留 --stringenc-native（C 桩已是唯一实现，不再需要该参数）",
      rc == 0 and "--stringenc-native" not in args, f"args={args}")

rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**",
                                          "stub_impl": "java"}))
check("T17b 旧快照 stub_impl='java' → 同样静默剥离（Java 桩已归档）",
      rc == 0 and "--stringenc-native" not in args, f"rc={rc} args={args} err={err}")

rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**"}))
# ⚠️ 注意 argv 顺序：rules_file 路径必须紧跟 --stringenc（见 T18），
# 而 dex2c_stub(default=true) 的 arg 会排在路径之后。
check("T17c 不带 stub_impl → 正常（新快照形态）",
      rc == 0 and args == ["--stringenc", "build/schema_rules/stringenc.txt"],
      f"rc={rc} args={args} err={err}")

# 任意值都该被剥离（不再有"枚举校验"这回事，key 本身已不存在于 schema）
for bad in ("native", 1, True, None, ["x"]):
    rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**",
                                              "stub_impl": bad}))
    check(f"T17d 旧快照 stub_impl={bad!r} → 静默剥离不报错",
          rc == 0, f"rc={rc} err={err}")

# 但**其它**未定义子 key 仍然必须被保险丝 a 拦住（剥离只针对白名单）
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**",
                                          "totally_unknown_key": 1}))
check("T17e 其它未知子 key 仍被保险丝 a 拒绝（剥离只针对已下线白名单）",
      rc != 0 and "未定义的子 key" in err, f"rc={rc} err={err}")

# 反向：只剥离已下线 key，同模块的现存 key 不受影响
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**",
                                          "stub_impl": "java",
                                          "dex2c_stub": True}))
check("T17f 剥离 stub_impl 后，现存子项 dex2c_stub 照常生效",
      rc == 0 and "--dex2c-stub" in args, f"rc={rc} args={args} err={err}")

# ── T18: 规则文件路径必须紧跟模块 arg（与 schema children 顺序解耦）─────
# 为什么必须有这条：2026-11-09 把 stub_impl 从数组末位提到首位（UI 上把
# 大文本框 rules_file 挪到后面，免得把「解密桩也抽进 so」挤到看不见），
# 结果 argv 变成 `--stringenc --dex2c-stub build/schema_rules/stringenc.txt`。
# 而 protect.sh:123 的取值守卫是 `if [[ $# -ge 1 && "$1" != --* ]]`
# ——下一个 token 以 -- 开头就认为"没给规则文件"→ STRING_RULES 为空
# → protect.sh:241 报「必须提供类名规则文件」→ exit 1。
# 即：**改 UI 排序把构建改挂了**，且 T6/T6o 当时才抓到（纯顺序断言过期）。
# 修法是把路径延迟到子项循环结束后插回 arg 正后方，从此与数组顺序无关。
# 本条直接钉"结果"而非"顺序"：不论 schema 怎么排，--stringenc 后必须是路径。
for label, order in [("stub_impl 在前", {"stub_impl": "java", "dex2c_stub": True}),
                     ("stub_impl 在后", {"dex2c_stub": True, "stub_impl": "java"})]:
    rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**", **order}))
    idx = args.index("--stringenc") if "--stringenc" in args else -1
    nxt = args[idx + 1] if 0 <= idx < len(args) - 1 else None
    check(f"T18 {label} → 规则路径紧跟 --stringenc（protect.sh 取值守卫前提）",
          rc == 0 and nxt == "build/schema_rules/stringenc.txt",
          f"rc={rc} args={args} err={err}")

# 反向：若把路径排到 flag 之后，模拟 protect.sh 的守卫判断应为"未提供规则"
# （证明这条断言不是自证，而是真的覆盖了一个会让构建失败的条件）
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**",
                                          "dex2c_stub": True, "stub_impl": "c"}))
idx = args.index("--stringenc") if "--stringenc" in args else -1
nxt = args[idx + 1] if 0 <= idx < len(args) - 1 else None
check("T18c 纯C桩 + dex2c_stub 同勾 → resolver 不拦（分工：protect.sh 管组合非法）",
      rc == 0 and nxt == "build/schema_rules/stringenc.txt",
      f"rc={rc} args={args} err={err}")

# ── T19: dex2c_stub 现在是普通子项（2026-11-22 解绑 visible_when）───
# 历史：它曾声明 visible_when={key:stub_impl, equals:"java"}，语义是
# 「只在 Java 桩时存在」。**Java 桩下线后这个依赖失去意义**，因为：
#   · dex2c_stub 是【dex2c 内部接口】的开关，作用对象是「流水线中途注入
#     的 Java 代码」；解密桩只是它当前的唯一调用方，不是它的定义。
#   · 加新的 Java 插桩模块时它会重新有对象，不该被"桩实现"绑死。
# 所以 visible_when 已移除，它现在恒显示、按自身 default 生效。

# 1) 默认值生效（default=true）
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**"}))
check("T19a dex2c_stub 缺失 → 按 default(false) 不追加",
      rc == 0 and "--dex2c-stub" not in args, f"rc={rc} args={args} err={err}")

# 2) 显式关掉
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**",
                                          "dex2c_stub": False}))
check("T19b dex2c_stub=false → 不追加",
      rc == 0 and "--dex2c-stub" not in args, f"rc={rc} args={args} err={err}")

# 3) 显式开启
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**",
                                          "dex2c_stub": True}))
check("T19c dex2c_stub=true → 追加",
      rc == 0 and "--dex2c-stub" in args, f"rc={rc} args={args} err={err}")

# 4) 旧快照：带已下线的 stub_impl 时，dex2c_stub 仍要正常生效
#    （剥离 stub_impl 不能连带影响同模块的现存子项）
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**",
                                          "stub_impl": "java", "dex2c_stub": True}))
check("T19d 旧快照 stub_impl='java' + dex2c_stub=true → 剥离前者，后者照常追加",
      rc == 0 and "--dex2c-stub" in args, f"rc={rc} args={args} err={err}")

# 5) 回执一致性：dex2c_stub 不再被 visible_when 隐藏，回执里必须出现
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": "**"}))
check("T19e 回执里出现 dex2c_stub（不再被 visible_when 隐藏）",
      rc == 0 and "解密桩也抽进 so" in err, f"rc={rc} err={err}")

# 6) 回执里不许出现已下线的 stub_impl
check("T19f 回执里不出现已下线的 stub_impl",
      rc == 0 and "解密桩实现" not in err, f"err={err}")

print(f"\n结果: {passed} 通过, {failed} 失败")
sys.exit(1 if failed else 0)
