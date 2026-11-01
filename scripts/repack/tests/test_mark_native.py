#!/usr/bin/env python3
"""test_mark_native.py — mark-native.py 的回归测试（纯 stdlib，秒级，无外部依赖）。

【为什么补这个测试】
  冻结模块，53 条历史报错里涉及它 11 次，却没有脚本级独立测试。
  事故类型（见 docs/变更历史.md）：
    · 报错十：方法名解析用贪婪正则 → access$000(Lcom/A;->onCreate(...))V
      这类参数内嵌方法引用的行会把名字解析成参数里的 onCreate，误杀无关方法
    · 报错十三：.end method 被一并吞掉 → 回编报 missing END_METHOD_DIRECTORY
    · 报错三十九：native 壳被再次处理 / onCreate 壳被凭空造方法体
    · exit 3 语义：有方法没找到时必须非零退出，不许静默忽略

【测什么 / 不测什么】
  只测纯函数：compiled_methods 解析、类名提取、单个 smali 的 native 化与
  插桩结果、exit code 语义。不测 androguard / apktool（外部依赖）。

用法: python3 scripts/repack/tests/test_mark_native.py
"""
import importlib.util
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TARGET = os.path.join(ROOT, "scripts", "repack", "mark-native.py")

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


def _load():
    spec = importlib.util.spec_from_file_location("mark_native", TARGET)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MN = _load()


def mk_smali(body, subdir="smali"):
    """造一个解包目录，写入给定的 smali 内容，返回 (解包目录, smali 路径)。"""
    d = tempfile.mkdtemp()
    cls = re.search(r"^\.class[^\n]*?(L[^;\s]+;)", body, re.M)
    assert cls, "测试用例的 smali 必须含 .class 行"
    rel = cls.group(1)[1:-1] + ".smali"
    p = os.path.join(d, subdir, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fp:
        fp.write(body)
    return d, p


def write_methods(pairs):
    """pairs: [(full_name)] → 写 compiled_methods.txt，返回路径。"""
    p = os.path.join(tempfile.mkdtemp(), "compiled_methods.txt")
    with open(p, "w") as fp:
        fp.write("\n".join(pairs) + "\n")
    return p


# ══════════════════════════════════════════════════════════════════════
# ① parse_compiled_methods —— 格式必须与 dex2c full_name 一致（无箭头）
# ══════════════════════════════════════════════════════════════════════
print("① parse_compiled_methods（dcc full_name 格式：分号后直接跟方法名，无 ->）")

txt = write_methods([
    "Lcom/a/MainActivity;onCreate(Landroid/os/Bundle;)V",
    "Lcom/a/MainActivity;run()V",
    "Lcom/b/Util;compute(IJ)Ljava/lang/String;",
])
got = MN.parse_compiled_methods(txt)
check("解析出 3 条", len(got) == 3, str(len(got)))
check("类名是斜杠格式（含 L 与 ;）",
      ("Lcom/a/MainActivity;", "onCreate", "(Landroid/os/Bundle;)V") in got, str(got))
check("无参方法", ("Lcom/a/MainActivity;", "run", "()V") in got)
check("多参数返回值", ("Lcom/b/Util;", "compute", "(IJ)Ljava/lang/String;") in got)

# 带 -> 的行是【非法】格式（用户常见误写），必须被拒绝而不是静默接受
txt2 = write_methods([
    "Lcom/a/B;->onCreate()V",
    "Lcom/a/B;ok()V",
])
got2 = MN.parse_compiled_methods(txt2)
check("带 -> 的非法行被丢弃", ("Lcom/a/B;", "->onCreate", "()V") not in got2, str(got2))
check("同文件里的合法行仍被解析", ("Lcom/a/B;", "ok", "()V") in got2, str(got2))
check("带 -> 的行不会被当成方法名 onCreate",
      not any(n.startswith("-") for (_c, n, _p) in got2), str(got2))

# 空行/空白容忍
txt3 = write_methods(["", "Lcom/a/B;x()V", "   ", ""])
check("空行被跳过", len(MN.parse_compiled_methods(txt3)) == 1)


# ══════════════════════════════════════════════════════════════════════
# ② class_name_of
# ══════════════════════════════════════════════════════════════════════
print("② class_name_of")

d, p = mk_smali('.class public Lcom/demo/X;\n.super Ljava/lang/Object;\n')
check("提取类名", MN.class_name_of(p) == "Lcom/demo/X;", str(MN.class_name_of(p)))

d2 = tempfile.mkdtemp()
p2 = os.path.join(d2, "NoClass.smali")
open(p2, "w").write(".super Ljava/lang/Object;\n")
check("无 .class 行 → None", MN.class_name_of(p2) is None)


# ══════════════════════════════════════════════════════════════════════
# ③ process_smali —— 报错十（贪婪正则误杀）与报错十三（吞 .end method）
# ══════════════════════════════════════════════════════════════════════
print("③ process_smali 方法名解析（报错十：参数里嵌方法引用）")

# 报错十的真实形态：access$000(Lcom/A;->onCreate(...))V 这类合成方法
S = """\
.class public Lcom/demo/Act;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .registers 3

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    return-void
.end method

.method synthetic static access$000(Lcom/demo/Act;Landroid/os/Bundle;)V
    .registers 3

    invoke-virtual {p0, p1}, Lcom/demo/Act;->onCreate(Landroid/os/Bundle;)V

    return-void
.end method

.method public untouched()V
    .registers 1

    return-void
.end method
"""
d, p = mk_smali(S)
targets = {("Lcom/demo/Act;", "onCreate", "(Landroid/os/Bundle;)V")}
n = MN.process_smali(p, targets)
check("只 native 化 1 个方法", n == 1, str(n))
out = open(p).read()

check("onCreate 变成 native",
      re.search(r"^\.method native public onCreate\(Landroid/os/Bundle;\)V$", out, re.M) is not None,
      "未找到 native 化的 onCreate")
check("access$000 未被误杀（报错十）",
      ".method synthetic static access$000" in out, "合成方法被误改")
check("untouched 未被误改", ".method public untouched()V" in out)
check("untouched 方法体仍在", "return-void" in out)

# 报错十三：native 化后必须保留 .end method
check("native 方法后有 .end method（报错十三）",
      re.search(r"\.method native public onCreate[^\n]*\n\.end method", out) is not None,
      "缺失 .end method → 回编报 missing END_METHOD_DIRECTORY")
check(".method 与 .end method 数量配平",
      out.count(".method ") == len(re.findall(r"^\.end method$", out, re.M)),
      f"{out.count('.method ')} 个 .method vs {len(re.findall(r'^.end method$', out, re.M))} 个 .end method")
# native 方法不能有任何方法体：onCreate 段内不得残留指令。
# ⚠️ 不能用全局 "invoke-super 计数 == 0" —— 同一文件里未被打桩的 keep()
# 也可能有 invoke-super，那样断言就是错的（第一版这么写，自造假失败）。
_onc_seg = re.search(r"\.method native public onCreate[^\n]*\n\.end method", out)
check("onCreate 变成空 native 壳（无方法体）", _onc_seg is not None,
      "onCreate 段内仍有指令")

# 插桩：类原本无 <clinit> → 新建一个
check("新建了 <clinit>", ".method static constructor <clinit>()V" in out)
check("插入了 loadLibrary",
      'invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V' in out)
check("so 名为 nc", 'const-string v0, "nc"' in out)


# 3b. 已有 <clinit> → 头插，不重复新建
print("③b 已有 <clinit> → 头插而不是新建")

S2 = """\
.class public Lcom/demo/B;
.super Ljava/lang/Object;

.method static constructor <clinit>()V
    .locals 1

    return-void
.end method

.method public go()V
    .registers 1

    return-void
.end method
"""
d, p = mk_smali(S2)
n = MN.process_smali(p, {("Lcom/demo/B;", "go", "()V")})
out = open(p).read()
check("go 被 native 化", n == 1, str(n))
check("只有一个 <clinit>", out.count(".method static constructor <clinit>()V") == 1,
      str(out.count(".method static constructor <clinit>()V")))
check("loadLibrary 插入", "loadLibrary" in out)

# 3c. 已有 loadLibrary → 幂等（不重复插）
print("③c 已有 loadLibrary → 幂等")

S3 = """\
.class public Lcom/demo/C;
.super Ljava/lang/Object;

.method static constructor <clinit>()V
    .locals 1

    const-string v0, "nc"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method

.method public go()V
    .registers 1

    return-void
.end method
"""
d, p = mk_smali(S3)
MN.process_smali(p, {("Lcom/demo/C;", "go", "()V")})
out = open(p).read()
check("loadLibrary 只出现 1 次", out.count("loadLibrary") == 1, str(out.count("loadLibrary")))

# 3d. 构造器不许 native 化
print("③d 构造器不允许 native（dex 校验会拒）")

S4 = """\
.class public Lcom/demo/D;
.super Ljava/lang/Object;

.method public <init>()V
    .registers 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method
"""
d, p = mk_smali(S4)
n = MN.process_smali(p, {("Lcom/demo/D;", "<init>", "()V")})
check("<init> 未被 native 化", n == 0, str(n))
check("<init> 方法体完好", "invoke-direct" in open(p).read())

# 3e. 无匹配目标 → 文件不改动
print("③e 无匹配目标 → 文件逐字节不变")

d, p = mk_smali(S)
before = open(p).read()
n = MN.process_smali(p, {("Lcom/other/None;", "x", "()V")})
check("返回 0", n == 0, str(n))
check("文件逐字节不变", open(p).read() == before)

# 3f. 缺 .end method → 不改动（防越界）
print("③f 缺 .end method 时不越界改动")

S5 = """\
.class public Lcom/demo/E;
.super Ljava/lang/Object;

.method public broken()V
    .registers 1

    return-void
"""
d, p = mk_smali(S5)
before = open(p).read()
try:
    n = MN.process_smali(p, {("Lcom/demo/E;", "broken", "()V")})
    check("不抛异常", True)
    check("缺 .end method 时不 native 化", n == 0, str(n))
    check("文件未被破坏", open(p).read() == before)
except IndexError as e:
    bad(f"缺 .end method 时抛异常：{e}")


# ══════════════════════════════════════════════════════════════════════
# ④ find_smali_files —— 多 dex 目录
# ══════════════════════════════════════════════════════════════════════
print("④ find_smali_files（多 dex 目录遍历）")

d = tempfile.mkdtemp()
for sub in ("smali", "smali_classes2", "smali_classes3"):
    os.makedirs(os.path.join(d, sub, "com", "x"), exist_ok=True)
    open(os.path.join(d, sub, "com", "x", sub + ".smali"), "w").write(".class public Lcom/x/A" + sub + ";\n")
# 干扰项：非 smali 目录
os.makedirs(os.path.join(d, "res", "raw"), exist_ok=True)
open(os.path.join(d, "res", "raw", "junk.smali"), "w").write("junk")

found = sorted(os.path.relpath(x, d) for x in MN.find_smali_files(d))
check("找到 3 个 smali 目录下的文件", len(found) == 3, str(found))
check("smali_classes2 被覆盖", any("smali_classes2" in f for f in found), str(found))
check("smali_classes3 被覆盖", any("smali_classes3" in f for f in found), str(found))
check("非 smali 目录被排除", not any(f.startswith("res") for f in found), str(found))


# ══════════════════════════════════════════════════════════════════════
# ⑤ CLI 退出码语义 —— exit 3 是流水线的失败信号
# ══════════════════════════════════════════════════════════════════════
print("⑤ CLI 退出码（3 = 有方法没找到，流水线必须失败）")


def run_cli(methods, decl):
    d, _p = mk_smali(decl)
    m = write_methods(methods)
    r = subprocess.run([sys.executable, TARGET, m, d], capture_output=True, text=True)
    return r


# 5a. 全部命中 → 0
r = run_cli(["Lcom/demo/F;go()V"],
            ".class public Lcom/demo/F;\n.super Ljava/lang/Object;\n"
            ".method public go()V\n    .registers 1\n\n    return-void\n.end method\n")
check("全部命中 → exit 0", r.returncode == 0, f"rc={r.returncode}")

# 5b. 有方法找不到 → 3
r = run_cli(["Lcom/demo/F;go()V", "Lcom/demo/Gone;nope()V"],
            ".class public Lcom/demo/F;\n.super Ljava/lang/Object;\n"
            ".method public go()V\n    .registers 1\n\n    return-void\n.end method\n")
check("有方法找不到 → exit 3", r.returncode == 3, f"rc={r.returncode}")
check("提示了未找到的方法数", "未在 smali 中找到" in r.stderr, r.stderr[:120])

# 5c. 参数错误
r = subprocess.run([sys.executable, TARGET], capture_output=True, text=True)
check("缺参数 → 非 0", r.returncode != 0, f"rc={r.returncode}")

d = tempfile.mkdtemp()
r = subprocess.run([sys.executable, TARGET, "/nonexistent/compiled.txt", d],
                   capture_output=True, text=True)
check("compiled_methods 不存在 → 非 0", r.returncode != 0, f"rc={r.returncode}")

m = write_methods(["Lcom/a/B;x()V"])
r = subprocess.run([sys.executable, TARGET, m, "/nonexistent/dir"],
                   capture_output=True, text=True)
check("解包目录不存在 → 非 0", r.returncode != 0, f"rc={r.returncode}")


print()
print(f"═══ 结果: {PASS} 通过, {FAIL} 失败 ═══")
sys.exit(1 if FAIL else 0)
