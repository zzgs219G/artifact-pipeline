#!/usr/bin/env python3
"""test-payload-sync.py — 载荷产物（smali/dex）必须与 Java 源码一致

用法: python3 scripts/uncheck/tests/test-payload-sync.py

=== 为什么这个测试存在（2026-11-27 我自己的失误）===

我把 SigFix.java 的 nativeHookApkPath 从 2 个参数改成 3 个（加 hookLevel），
然后直接出包 —— **忘了重跑 build.sh**。于是：

  SigFix.java     2026-11-27 01:31   (String,String,I)Z
  SigFix.smali    2026-11-23 22:32   (String,String)Z     ← 产物用的是这个

JNI 按签名找函数，Java 声明与 so 导出对不上 → 注册失败 → **native hook
一个都没装上**。而构建全程是绿的，产物也装得上、跑得起来，只是某个功能
静默失效 —— 我还据此得出了"档 4 有问题"的错误结论，白测了两轮。

AGENTS.md §2 早就写着「改完 Java 必须重跑对应 build-*.sh」，我还是漏了。
文字纪律防不住，所以要一条可执行的检查。

=== 判据 ===

① SigFix.smali 里 nativeHookApkPath 的方法描述符
   == 从 SigFix.java 的 native 声明推导出的描述符
② 调用点的 invoke 参数寄存器数 == 方法描述符的参数个数
   （2026-11-22 真机踩过：少写一个参数 → dalvik verifier 报
     VerifyError，本地汇编全绿，只有真机才炸）
③ payload.dex / boot.dex 存在且 mtime 不早于源码（提示性，不判红 ——
   产物会随 build.sh 更新，CI 里 checkout 的时间戳无意义）
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PAYLOAD = ROOT / "scripts/uncheck/payload"
JAVA = PAYLOAD / "src/com/nc/uncheck/SigFix.java"
SMALI = PAYLOAD / "SigFix.smali"

passed, failed = [], []


def chk(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  {detail}" if detail and not cond else ""))


JTYPE = {
    "int": "I", "long": "J", "boolean": "Z", "byte": "B",
    "char": "C", "short": "S", "float": "F", "double": "D",
    "void": "V",
}
# 常见类简写 → 全限定名（native 声明里通常只写简名）
JCLASS = {
    "String": "java/lang/String",
    "Object": "java/lang/Object",
    "Context": "android/content/Context",
}


def java_proto_to_smali(params: list[str]) -> str:
    """把 Java 参数类型列表转成 smali 描述符括号部分。"""
    out = "("
    for p in params:
        p = p.strip()
        if p.endswith("[]"):
            out += "[" + JTYPE.get(p[:-2], "Ljava/lang/Object;")
        elif p in JTYPE:
            out += JTYPE[p]
        else:
            out += "L" + JCLASS.get(p, p.replace(".", "/")) + ";"
    return out + ")"


j = JAVA.read_text(encoding="utf-8")
sm = SMALI.read_text(encoding="utf-8")

print("[① Java 声明 ↔ smali 方法描述符]")
m = re.search(
    r'native\s+[\w.]+\s+(nativeHookApkPath)\s*\(([^)]*)\)', j)
chk("Java 里有 nativeHookApkPath 声明", m is not None)
if m:
    # 每个参数形如 "String apkPath"，取【类型部分】（空格前），不是参数名
    params = [p.strip().rsplit(" ", 1)[0] for p in m.group(2).split(",") if p.strip()]
    want = java_proto_to_smali(params) + "Z"
    # smali 里对同名 native 方法的声明
    ms = re.search(
        r'\.method[^\n]*\bnativeHookApkPath\(([^)]*)\)(\S+)', sm)
    chk("smali 里有同名 native 声明", ms is not None)
    if ms:
        got = "(" + ms.group(1) + ")" + ms.group(2)
        chk(f"描述符一致（Java 推出 {want}）", got == want,
            f"smali 是 {got} —— 说明改了 Java 没重跑 build.sh")
        # ② invoke 的参数寄存器数
        for inv in re.finditer(
                r'invoke-static\s+\{([^}]*)\},\s*Lcom/nc/uncheck/SigFix;->nativeHookApkPath\(\S+\)Z', sm):
            nregs = len([x for x in inv.group(1).split(",") if x.strip()])
            # 描述符里每个参数占一个寄存器（long/double 占 2，本方法没有）
            inner = want[1:want.rindex(")")]
            nargs = len(re.findall(r'\[*(?:[IJZBCSFD]|L[^;]+;)', inner))
            chk(f"调用点寄存器数 {nregs} == 参数数 {nargs}", nregs == nargs,
                "少写参数 → 真机 VerifyError（本地汇编全绿）")

print("\n[② 产物存在性]")
for f in ("payload.dex", "boot.dex", "SigFix.smali", "SigFixApp.smali"):
    p = PAYLOAD / f
    chk(f"{f} 存在", p.is_file())

print("\n[③ 产物与源码的 mtime（仅提示）]")
if JAVA.is_file() and SMALI.is_file():
    jm, sm_m = JAVA.stat().st_mtime, SMALI.stat().st_mtime
    if sm_m < jm:
        print(f"  ⚠️  SigFix.smali 比 SigFix.java 旧 "
              f"({int((jm - sm_m) / 60)} 分钟)，记得重跑 payload/build.sh")
    else:
        print("  ✅ smali 不比 Java 旧")

print()
if failed:
    print(f"❌ 失败 {len(failed)} 项 / 通过 {len(passed)} 项")
    for x in failed:
        print(f"   · {x}")
    print("\n修法：bash scripts/uncheck/payload/build.sh"
          "（需 SIGFIX_ANDROID_JAR 与 SIGFIX_D8）")
    sys.exit(1)
print(f"✅ 全部通过：{len(passed)} 项断言")
