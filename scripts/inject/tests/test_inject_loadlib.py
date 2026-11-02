#!/usr/bin/env python3
"""test_inject_loadlib.py — inject-loadlib.py 的回归测试（纯 stdlib，秒级，无外部依赖）。

【为什么补这个测试】
  这个文件是冻结模块，历史上出过 14 次事故（见 docs/变更历史.md），
  却一直没有独立测试 —— AGENTS.md 把它列在「冻结资产的能力边界」里。
  53 条历史报错中，本文件相关的最多。事故类型集中在：
    · 报错四/五：Manifest 变成文本 XML → 产物是灰包；AXML 分支缺失
    · 报错七：  SMALI_DIR_RE 双重转义 → 多 dex 目录全 miss
    · 报错三十八/三十九：native 壳上误插、<clinit> 与 onCreate 互相连累
    · 幂等失效 → 多模块共存时重复插 loadLibrary

【测什么 / 不测什么】
  只测纯函数（正则、寄存器计数、插桩结果字符串、Manifest 文本解析）。
  androguard（二进制 AXML）分支需要外部依赖，本地/CI 环境不一定有，
  不在这里测 —— 它的行为由 make-filter-from-apk.py 的同款逻辑 +
  流水线集成覆盖。测试宁可少测，也不要因为环境缺失而静默跳过（假绿）。

用法: python3 scripts/inject/tests/test_inject_loadlib.py
"""
import importlib.util
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TARGET = os.path.join(ROOT, "scripts", "inject", "inject-loadlib.py")


def _load():
    """按路径加载带连字符的模块（不能常规 import）。"""
    spec = importlib.util.spec_from_file_location("inject_loadlib", TARGET)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


IL = _load()

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


# ══════════════════════════════════════════════════════════════════════
# ① SMALI_DIR_RE —— 报错七的原始事故点
# ══════════════════════════════════════════════════════════════════════
print("① SMALI_DIR_RE（报错七：双重转义导致多 dex 全 miss）")

for good in ("smali", "smali_classes2", "smali_classes3", "smali_classes21"):
    check(f"匹配 {good}", bool(IL.SMALI_DIR_RE.match(good)))
for bad_name in ("smali_classes", "smalix", "smali_classesA", "res", "smali_classes2x"):
    check(f"不匹配 {bad_name!r}", not IL.SMALI_DIR_RE.match(bad_name))

# 报错七的病灶是 '\\d'（字面反斜杠+d）。直接检查源码字符串形态，
# 而不是只靠行为断言 —— 行为断言在只有 smali/ 的用例下会漏掉这个 bug。
src = open(TARGET, encoding="utf-8").read()
m = re.search(r"^SMALI_DIR_RE\s*=\s*re\.compile\((.+)\)\s*$", src, re.M)
check("SMALI_DIR_RE 定义存在", m is not None)
if m:
    pat = m.group(1)
    check("正则里没有双重转义的 \\\\d", "\\\\d" not in pat,
          f"实际为 {pat}（报错七复发形态：只命中裸 smali/）")

# 三份同源副本必须一致（报错七教训：改一处漏另外两处）
print("①b SMALI_DIR_RE 三处副本一致性（报错七教训）")
copies = {
    "inject-loadlib.py": os.path.join(ROOT, "scripts/inject/inject-loadlib.py"),
    "inject-javacheck.py": os.path.join(ROOT, "scripts/sigcheck/javalink/inject-javacheck.py"),
}
for name, path in copies.items():
    if not os.path.isfile(path):
        check(f"{name} 存在", False)
        continue
    t = open(path, encoding="utf-8").read()
    mm = re.search(r"^SMALI_DIR_RE\s*=\s*re\.compile\((.+?)\)\s*(?:#.*)?$", t, re.M)
    check(f"{name} 定义了 SMALI_DIR_RE", mm is not None)
    if mm:
        check(f"{name} 与 inject-loadlib 同源", mm.group(1).strip() == m.group(1).strip(),
              f"{mm.group(1).strip()} != {m.group(1).strip() if m else '?'}")


# ══════════════════════════════════════════════════════════════════════
# ② _count_param_regs —— 决定 .registers 模式下 v0 是否可用
# ══════════════════════════════════════════════════════════════════════
print("② _count_param_regs（J/D 占 2 个寄存器）")

cases = [
    ("", 0),
    ("I", 1),
    ("J", 2),                      # long 占 2
    ("D", 2),                      # double 占 2
    ("II", 2),
    ("JD", 4),                     # 2+2
    ("Ljava/lang/String;", 1),
    ("[I", 1),
    ("[[I", 1),
    ("[Ljava/lang/String;", 1),
    ("Landroid/os/Bundle;I", 2),
    ("IJLjava/lang/String;D", 6),  # 1+2+1+2
]
for sig, want in cases:
    got = IL._count_param_regs(sig)
    check(f"({sig}) → {want}", got == want, f"实际 {got}")


# ══════════════════════════════════════════════════════════════════════
# ③ _inject_into_method_body —— 寄存器策略是防闪退的关键
# ══════════════════════════════════════════════════════════════════════
print("③ _inject_into_method_body（寄存器不足必须跳过，不能硬插）")

CLINIT = IL._CLINIT_HEADER_RE

# 3a. 正常 .locals 1 → 头插
body = (".method static constructor <clinit>()V\n"
        "    .locals 1\n\n"
        "    return-void\n"
        ".end method\n")
new, st = IL._inject_into_method_body(body, CLINIT, "nc")
check(".locals 1 头插成功", st == "prepended", st)
check("插入了正确 so 名", 'const-string v0, "nc"' in new)
check("插入了 loadLibrary", "System;->loadLibrary(Ljava/lang/String;)V" in new)
check("插入点在 .locals 之后", new.index("loadLibrary") > new.index(".locals 1"))

# 3b. .locals 0 → 必须跳过（给 .registers +1 会让参数寄存器全体平移）
body0 = (".method static constructor <clinit>()V\n"
         "    .locals 0\n\n"
         "    return-void\n"
         ".end method\n")
new0, st0 = IL._inject_into_method_body(body0, CLINIT, "nc")
check(".locals 0 → no-local-register", st0 == "no-local-register", st0)
check(".locals 0 时内容未被改动", new0 == body0)

# 3c. 已有 loadLibrary → already（幂等）
body_a = (".method static constructor <clinit>()V\n"
          "    .locals 1\n\n"
          '    const-string v0, "other"\n'
          "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
          "    return-void\n"
          ".end method\n")
new_a, st_a = IL._inject_into_method_body(body_a, CLINIT, "nc")
check("已有 loadLibrary → already", st_a == "already", st_a)
check("already 时内容逐字节不变", new_a == body_a)

# 3d. .registers 模式：N > 参数寄存器数才能用 v0
#     static，1 个 int 参数 → 占 1 个 → .registers 2 可用
body_r = (".method static foo(I)V\n"
          "    .registers 2\n\n"
          "    return-void\n"
          ".end method\n")
new_r, st_r = IL._inject_into_method_body(body_r, re.compile(r'^\.method\s[^\n]*\bfoo\(', re.M), "nc")
check(".registers 2 / 1 参数 → prepended", st_r == "prepended", st_r)

# 3e. .registers 恰好等于参数数 → 无局部 → 必须跳过
body_r0 = (".method static foo(I)V\n"
           "    .registers 1\n\n"
           "    return-void\n"
           ".end method\n")
new_r0, st_r0 = IL._inject_into_method_body(
    body_r0, re.compile(r'^\.method\s[^\n]*\bfoo\(', re.M), "nc")
check(".registers 1 / 1 参数 → no-local-register", st_r0 == "no-local-register", st_r0)

# 3f. virtual 方法：this 占 1 个
body_v = (".method public onCreate(Landroid/os/Bundle;)V\n"
          "    .registers 3\n\n"
          "    return-void\n"
          ".end method\n")
new_v, st_v = IL._inject_into_method_body(body_v, IL._ONCREATE_HEADER_RE, "nc")
check("virtual .registers 3 / this+1 参数 → prepended", st_v == "prepended", st_v)

body_v0 = (".method public onCreate(Landroid/os/Bundle;)V\n"
           "    .registers 2\n\n"
           "    return-void\n"
           ".end method\n")
new_v0, st_v0 = IL._inject_into_method_body(body_v0, IL._ONCREATE_HEADER_RE, "nc")
check("virtual .registers 2 / this+1 参数 → 跳过", st_v0 == "no-local-register", st_v0)

# 3g. 方法不存在
new_nm, st_nm = IL._inject_into_method_body("nothing here", CLINIT, "nc")
check("无目标方法 → no-method", st_nm == "no-method", st_nm)

# 3h. 缺 .registers/.locals 声明
body_nr = (".method static constructor <clinit>()V\n"
           "    return-void\n"
           ".end method\n")
new_nr, st_nr = IL._inject_into_method_body(body_nr, CLINIT, "nc")
check("缺寄存器声明 → no-registers", st_nr == "no-registers", st_nr)


# ══════════════════════════════════════════════════════════════════════
# ④ inject_loadlib_to_entrypoints —— 双保险互不连累
# ══════════════════════════════════════════════════════════════════════
print("④ 双保险插桩（<clinit> 与 onCreate 各自独立幂等）")


def mk_workspace(className, body):
    d = tempfile.mkdtemp()
    pkg = className[1:-1].rsplit("/", 1)[0]
    d2 = os.path.join(d, "smali", *pkg.split("/"))
    os.makedirs(d2, exist_ok=True)
    with open(os.path.join(d2, os.path.basename(className[1:-1]) + ".smali"), "w") as fp:
        fp.write(body)
    return d


CLS = "Lcom/demo/Act;"
base = (".class public Lcom/demo/Act;\n"
        ".super Landroid/app/Activity;\n"
        "\n"
        ".method public onCreate(Landroid/os/Bundle;)V\n"
        "    .registers 3\n\n"
        "    return-void\n"
        ".end method\n")

ws = mk_workspace(CLS, base)
r1 = IL.inject_loadlib_to_entrypoints(CLS, ws, "nc")
check("无 <clinit> → inserted", r1["clinit"] == "inserted", r1["clinit"])
check("有 onCreate → prepended", r1["onCreate"] == "prepended", r1["onCreate"])

# 幂等：重跑两处都应是 already（关键：不能 clinit 已插就跳过 onCreate）
r2 = IL.inject_loadlib_to_entrypoints(CLS, ws, "nc")
check("重跑 clinit → already", r2["clinit"] == "already", r2["clinit"])
check("重跑 onCreate → already（不被 clinit 连累）", r2["onCreate"] == "already", r2["onCreate"])

with open(IL.find_smali_file_by_class(ws, CLS)) as fp:
    final = fp.read()
check("最终只插入一份 <clinit>", final.count(".method static constructor <clinit>()V") == 1)
check("最终 loadLibrary 出现两次（双保险）", final.count("loadLibrary") == 2,
      f"实际 {final.count('loadLibrary')}")

# 4b. 类未 override onCreate → no-method，但 clinit 仍插
base2 = (".class public Lcom/demo/NoAct;\n"
         ".super Landroid/app/Activity;\n")
ws2 = mk_workspace("Lcom/demo/NoAct;", base2)
r3 = IL.inject_loadlib_to_entrypoints("Lcom/demo/NoAct;", ws2, "nc")
check("未 override onCreate → no-method", r3["onCreate"] == "no-method", r3["onCreate"])
check("但仍插了 <clinit>", r3["clinit"] == "inserted", r3["clinit"])

# 4c. 类文件不存在
r4 = IL.inject_loadlib_to_entrypoints("Lcom/nope/Gone;", ws2, "nc")
check("类不存在 → 双 missing", r4 == {"clinit": "missing", "onCreate": "missing"}, str(r4))


# ══════════════════════════════════════════════════════════════════════
# ⑤ inject_loadlib_to_class / find_smali_file_by_class —— 多 dex
# ══════════════════════════════════════════════════════════════════════
print("⑤ 多 dex 目录定位（smali / smali_classes2 …）")

ws3 = tempfile.mkdtemp()
p2 = os.path.join(ws3, "smali_classes2", "com", "deep")
os.makedirs(p2, exist_ok=True)
with open(os.path.join(p2, "D.smali"), "w") as fp:
    fp.write(".class public Lcom/deep/D;\n.super Ljava/lang/Object;\n")

found = IL.find_smali_file_by_class(ws3, "Lcom/deep/D;")
check("smali_classes2 里的类能找到", found is not None and found.endswith("D.smali"), str(found))

check("不存在的类 → None", IL.find_smali_file_by_class(ws3, "Lcom/deep/Nope;") is None)
check("类名无分号也能定位", IL.find_smali_file_by_class(ws3, "Lcom/deep/D") is not None)

# 幂等（整类级）
res1 = IL.inject_loadlib_to_class("Lcom/deep/D;", ws3, "nc")
check("首次插入 → inserted", res1 == "inserted", res1)
res2 = IL.inject_loadlib_to_class("Lcom/deep/D;", ws3, "nc")
check("重跑 → already", res2 == "already", res2)
with open(found) as fp:
    c = fp.read()
check("只插了一份", c.count("loadLibrary") == 1, f"实际 {c.count('loadLibrary')}")

# 已有其它 so 的 loadLibrary → already（多模块共存）
ws4 = tempfile.mkdtemp()
p3 = os.path.join(ws4, "smali", "com", "x")
os.makedirs(p3, exist_ok=True)
with open(os.path.join(p3, "X.smali"), "w") as fp:
    fp.write('.class public Lcom/x/X;\n.super Ljava/lang/Object;\n'
             '.method static constructor <clinit>()V\n    .locals 1\n\n'
             '    const-string v0, "other"\n'
             '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
             '    return-void\n.end method\n')
res3 = IL.inject_loadlib_to_class("Lcom/x/X;", ws4, "nc")
check("已有别的 so → already（不重复插）", res3 == "already", res3)


# ══════════════════════════════════════════════════════════════════════
# ⑥ Manifest 文本解析 —— LAUNCHER 识别（报错四/五相关）
# ══════════════════════════════════════════════════════════════════════
print("⑥ Manifest 文本解析（LAUNCHER 识别 / 相对类名补全）")

MAIN_LAUNCHER = ('<action android:name="android.intent.action.MAIN"/>'
                 '<category android:name="android.intent.category.LAUNCHER"/>')

man = f'''<?xml version="1.0"?>
<manifest package="com.demo.app">
  <application>
    <activity android:name=".MainActivity">
      <intent-filter>{MAIN_LAUNCHER}</intent-filter>
    </activity>
    <activity android:name="com.other.Hard" android:enabled="true">
      <intent-filter>{MAIN_LAUNCHER}</intent-filter>
    </activity>
    <activity android:name=".NotLauncher">
      <intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter>
    </activity>
    <activity android:name="SelfClose" />
  </application>
</manifest>'''

res = IL._find_launchers_in_text(man, None)
check("相对名 .MainActivity 补全为 com.demo.app.MainActivity",
      "Lcom/demo/app/MainActivity;" in res, str(res))
check("绝对名 com.other.Hard 原样",
      "Lcom/other/Hard;" in res, str(res))
check("无 LAUNCHER 的 activity 不入选", "Lcom/demo/app/NotLauncher;" not in res)
check("非限定短名 SelfClose 补全（但无 LAUNCHER，不入选）",
      "Lcom/demo/app/SelfClose;" not in res)
check("结果已排序去重", res == sorted(set(res)), str(res))

# enabled=false 的 LAUNCHER
# ⚠️ 2026-11-02 行为变更：此前本用例断言「不跳过」，因为
#    docs/流程文档.md §2 步骤 3 写着「enabled=false 的跳过」但代码没实现，
#    测试把差异钉住等实现。**现已实现**（CI 41430277787 实证驱动）：
#    com.app.lxkd20251026 的 FirstActivity enabled=false、AliasIcon1
#    enabled=true 且是 activity-alias → 抽到 alias 类里没有任何方法
#    → dex2c "No methods compiled!" → 构建失败。
#    现在断言反转为「必须跳过」。
man_dis = f'''<manifest package="com.d">
  <application>
    <activity android:name=".Disabled" android:enabled="false">
      <intent-filter>{MAIN_LAUNCHER}</intent-filter>
    </activity>
  </application>
</manifest>'''
r_dis = IL._find_launchers_in_text(man_dis, None)
check("enabled=false 必须跳过（2026-11-02 实现）",
      "Lcom/d/Disabled;" not in r_dis, str(r_dis))

# activity-alias：必须解析 targetActivity（alias 自身无代码）
man_alias = f'''<manifest package="com.f">
  <application>
    <activity android:name=".Real" android:enabled="false">
      <intent-filter>{MAIN_LAUNCHER}</intent-filter>
    </activity>
    <activity-alias android:name=".Icon1" android:enabled="true"
                    android:targetActivity="com.f.Real">
      <intent-filter>{MAIN_LAUNCHER}</intent-filter>
    </activity-alias>
    <activity-alias android:name=".Icon2" android:enabled="false"
                    android:targetActivity="com.f.Real">
      <intent-filter>{MAIN_LAUNCHER}</intent-filter>
    </activity-alias>
  </application>
</manifest>'''
r_alias = IL._find_launchers_in_text(man_alias, None)
check("activity-alias 解析为 targetActivity（实测样本同款结构）",
      r_alias == ['Lcom/f/Real;'], str(r_alias))
check("activity-alias 自身不得入选", "Lcom/f/Icon1;" not in r_alias)
check("enabled=false 的 alias 也要跳过", "Lcom/f/Icon2;" not in r_alias)

# 交替顺序回归：<(activity|activity-alias)\b 会让 activity 先命中，
# 导致 activity-alias 被当成 activity 处理（找不到 </activity-alias>、
# 也不解析 targetActivity）。本用例钉死顺序。
man_order = f'''<manifest package="com.g">
  <application>
    <activity-alias android:name=".A" android:targetActivity="com.g.T">
      <intent-filter>{MAIN_LAUNCHER}</intent-filter>
    </activity-alias>
  </application>
</manifest>'''
r_order = IL._find_launchers_in_text(man_order, None)
check("正则交替顺序：activity-alias 不得被误判为 activity",
      r_order == ['Lcom/g/T;'], str(r_order))

# 没有 LAUNCHER → 空列表（调用方据此 exit 2）
r_none = IL._find_launchers_in_text('<manifest package="com.e"><application/></manifest>', None)
check("无 LAUNCHER → 空列表", r_none == [], str(r_none))

# 文本 Manifest 缺 package 属性
check("缺 package 属性不崩",
      IL._find_launchers_in_text(f'<manifest><application><activity android:name=".A">'
                                 f'<intent-filter>{MAIN_LAUNCHER}</intent-filter>'
                                 f'</activity></application></manifest>', None) == ['L/A;'],
      "相对名补全在无 package 时应拼成 L/A;")


# ══════════════════════════════════════════════════════════════════════
# ⑦ CLI 参数解析
# ══════════════════════════════════════════════════════════════════════
print("⑦ CLI 参数解析（protect.sh 依赖这些语义）")

d, t, s, l, e = IL._parse_cli_args(["out", "Lcom/a/B;"])
check("基本位置参数", (d, t, s, l, e) == ("out", "Lcom/a/B;", "nc", False, False), str((d, t, s, l, e)))

d, t, s, l, e = IL._parse_cli_args(["out", "--launcher", "--entrypoints"])
check("--launcher --entrypoints", (d, t, l, e) == ("out", None, True, True), str((d, t, l, e)))

d, t, s, l, e = IL._parse_cli_args(["--so-name", "guard", "out", "Lcom/a/B;"])
check("--so-name 前置", s == "guard" and d == "out", str((d, s)))

d, t, s, l, e = IL._parse_cli_args(["out", "Lcom/a/B;", "--so-name", "x"])
check("--so-name 后置", s == "x", s)


print()
print(f"═══ 结果: {PASS} 通过, {FAIL} 失败 ═══")
sys.exit(1 if FAIL else 0)
