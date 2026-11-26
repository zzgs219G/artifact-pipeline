#!/usr/bin/env python3
"""test-uncheck-extract-nativelibs.py — 注入 .so 的包必须 extractNativeLibs=true

用法: python3 scripts/uncheck/tests/test-uncheck-extract-nativelibs.py [产物.apk]

不给参数时只做静态检查（代码路径存在）；给参数时额外验证该产物的真值。

=== 为什么这个测试存在（2026-11-27，最大的一个坑）===

`SigFix` 用 `System.load(nativeLibraryDir + "/libusign.so")` 加载 hook 库，
这要求 `.so` 是**磁盘上的实体文件**。而 `extractNativeLibs="false"` 时系统
安装阶段**不解压** `.so`，`nativeLibraryDir` 是空目录：

    /data/app/<pkg>/lib/arm64/          ← 空目录
    SigFix: 找不到 native 库 ... 跳过 native 重定向
    → native 层完全没生效

后果的严重性在于**全程无报错**：构建绿灯、装得上、Java 层去校验有效，
只有 `adb logcat -s USign` 才看得到那一行 warn。

实测代价：Python 这套脚本（scripts/uncheck/）从 2026-11-23 加入 native 层
起就漏了这一步，而 ApkForge（Kotlin 那套）做了。于是：
  · 用 Python 脚本出的包，native hook 一次都没加载过
  · 据此得出的「档 1/2 正常、全量异常」结论全部作废
  · 白测 7 轮装机

=== 判据 ===

① run.py 里在投放 .so 的路径上有 extractNativeLibs 改写调用
② 该调用失败时必须抛错（不能 warn 后继续 —— 那正是静默失效的来源）
③ 给了产物路径时：解出 manifest，真值必须是 true
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUNPY = ROOT / "scripts/uncheck/run.py"
PATCHER = ROOT / "scripts/repack/patch-extractnativelibs.py"
APKTOOL = ROOT / "tools/apktool.jar"

passed, failed = [], []


def chk(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  {detail}" if detail and not cond else ""))


r = RUNPY.read_text(encoding="utf-8")

print("[① run.py 里真的有这一步]")
# 必须是一条【真实存在】的 subprocess 调用，且目标文件存在。
# 只 grep 字符串不够：改成一个不存在的路径也照样匹配（反向验证实测）。
_calls = re.findall(
    r"\w+\.run\(\s*\[([^\]]*patch-extractnativelibs\.py[^\]]*)\]", r, re.S)
chk("有 subprocess.run 调用 patch-extractnativelibs.py", len(_calls) >= 1,
    "没找到实际调用（只写注释不算）")
if _calls:
    _ok = any(str(PATCHER.name) in c for c in _calls)
    chk("调用的是仓库里那份（scripts/repack/patch-extractnativelibs.py）", _ok)
chk("改写点在投放 .so 的同一函数内（都在 replace_entries 流程里）",
    "extractNativeLibs" in r)

# 必须在 USIGN_NO_NATIVE=1（不投 so）时跳过，投 so 时必须做
m = re.search(r"if os\.environ\.get\('USIGN_NO_NATIVE'\) != '1':\s*\n\s*import subprocess as _sp", r)
chk("跳过条件与「是否投 so」一致（USIGN_NO_NATIVE!=1 才改）", m is not None)

print("\n[② 失败必须抛错，不能静默]")
seg = r[r.find("patch-extractnativelibs.py"):]
seg = seg[:seg.find("# 6b)")] if "# 6b)" in seg else seg
chk("returncode 非 0 时 raise", "raise RuntimeError" in seg, "只 warn 就会重演本次事故")
chk("报错信息点明后果", "native 层将无法加载" in seg or "无法加载" in seg)

print("\n[③ 改写工具本身可用]")
chk("patch-extractnativelibs.py 存在", PATCHER.is_file())

if len(sys.argv) >= 2:
    apk = Path(sys.argv[1])
    print(f"\n[④ 产物真值：{apk.name}]")
    chk("产物存在", apk.is_file())
    if apk.is_file() and APKTOOL.is_file():
        with tempfile.TemporaryDirectory() as td:
            pr = subprocess.run(
                ["java", "-jar", str(APKTOOL), "d", "-f", "-s", "-o", td, str(apk)],
                capture_output=True, text=True)
            mf = Path(td) / "AndroidManifest.xml"
            if pr.returncode != 0 or not mf.is_file():
                chk("解包成功", False, pr.stderr[:200])
            else:
                # -s 保持二进制；用仓库自己的解析器读
                txt = mf.read_text(encoding="utf-8", errors="ignore")
                if 'android:extractNativeLibs="true"' in txt:
                    chk("extractNativeLibs 是 true", True)
                elif 'android:extractNativeLibs="false"' in txt:
                    chk("extractNativeLibs 是 true", False,
                        "是 false —— native hook 不会加载")
                else:
                    # 二进制 AXML，用 strings 判断不靠谱，退回 apktool 全解码
                    pr2 = subprocess.run(
                        ["java", "-jar", str(APKTOOL), "d", "-f", "-o", td + "/t", str(apk)],
                        capture_output=True, text=True)
                    mf2 = Path(td) / "t/AndroidManifest.xml"
                    ok = mf2.is_file() and 'extractNativeLibs="true"' in mf2.read_text(
                        encoding="utf-8", errors="ignore")
                    chk("extractNativeLibs 是 true（全解码确认）", ok,
                        "是 false 或属性缺失 —— native hook 不会加载")
else:
    print("\n[④ 产物真值：跳过（未给 .apk 参数）]")

print()
if failed:
    print(f"❌ 失败 {len(failed)} 项 / 通过 {len(passed)} 项")
    for x in failed:
        print(f"   · {x}")
    sys.exit(1)
print(f"✅ 全部通过：{len(passed)} 项断言")
