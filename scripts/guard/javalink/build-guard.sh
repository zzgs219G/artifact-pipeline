#!/usr/bin/env bash
# build-guard.sh — javalink 注入类编译链: *.java → javac → d8 → baksmali → *.smali
#
# ══ 为什么要有这个脚本（2026-11-22）═════════════════════════════════════
#
# inject-javacheck.py 原来把 Guard / NcLink 的 smali **手写在 Python 字符串里**。
# stub-src/*.java 只是"人读参照"，从不参与构建。
#
# 这个形态踩过坑（2026-11-22 真机实证）：
#   手写 smali 时给 Os.setenv(String,String,Z)V 只写了两个寄存器，
#   SmaliBuilder 照样汇编通过、本地测试全绿，真机却在类校验阶段被拒：
#     VerifyError: expected 2 argument registers, signature has 3 or more
#   → 整个 NativeGuard 类加载失败 → onCreate 直接 FATAL。
#
#   汇编器只管语法，**不校验实参个数**；只有 dalvik verifier 会。而真机
#   是唯一的 verifier 环境 —— 这类错误只能在装机时暴露，代价极高。
#
# 本项目对同类问题的既有规则（scripts/string-enc/README.md:60）：
#   「自动生成的中间产物，人永远不要手改」
# StrDec（string-enc 的解密桩）一直遵守这条：.java 是真相源，.smali 由
# build-stub.sh 生成并入库。**本脚本把同一条纪律补到 javalink 上。**
#
# 当年没这么做的理由是"宿主无 d8"（见 NcLink.java 头注）。实测该前提
# 已不成立：javac / d8.jar / android.jar / apktool.jar 都在手边。
#
# ══ 用法 ═════════════════════════════════════════════════════════════════
#   scripts/guard/javalink/build-guard.sh          # 生成到 stub-src/
#   scripts/guard/javalink/build-guard.sh <输出目录>
#
# 依赖：javac / java
#       tools/d8.jar                                     （仓库内，固定版本）
#       tools/apktool.jar                                （仓库内，提供 baksmali）
#       android.jar  ← 环境变量 ANDROID_JAR 指定，或自动搜 Gradle 缓存
#
# ══ 产物 ═════════════════════════════════════════════════════════════════
#   stub-src/*.smali  ← 由同目录 .java 编译产出，**数量不固定**
#
# ⚠️ 这些 .smali **入库**，inject-javacheck.py 运行时直接读它们做类名/占位符
#    替换。不要在运行时再编译（CI 上没有 android.jar，且每次构建多 3-5 秒）。
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ROOT="$(cd "$_HERE/../../.." && pwd)"

D8_JAR="$_ROOT/scripts/string-enc/tools/d8.jar"
APKTOOL="$_ROOT/tools/apktool.jar"

SRC_DIR="$_HERE/stub-src"
OUT_DIR="${1:-$SRC_DIR}"

# ── android.jar：优先环境变量，其次 Gradle 缓存 / SDK（本机/CI 都可能有）──
# 判据：必须真的含 android/system/Os.class —— Os.setenv 要用它。
# 有些"占位 jar"只有骨架类，编译能过但产物是错的，所以必须查实体。
if [[ -z "${ANDROID_JAR:-}" ]]; then
    _cands=()
    shopt -s nullglob
    _cands+=("$HOME"/.gradle/caches/*/transforms/*/transformed/android.jar)
    _cands+=("$HOME"/android-sdk/platforms/android-*/android.jar)
    [[ -n "${ANDROID_HOME:-}"     ]] && _cands+=("$ANDROID_HOME"/platforms/android-*/android.jar)
    [[ -n "${ANDROID_SDK_ROOT:-}" ]] && _cands+=("$ANDROID_SDK_ROOT"/platforms/android-*/android.jar)
    shopt -u nullglob

    for _c in "${_cands[@]+"${_cands[@]}"}"; do
        [[ -f "$_c" ]] || continue
        # ⚠️ 不能写 `unzip -l "$_c" | grep -qF ...`（2026-11-22 踩过两次）：
        #   ① set -o pipefail 下 unzip 对坏 jar 返回非 0 → 整条管道判失败
        #   ② grep -q 提前关闭管道 → unzip 收到 SIGPIPE → 同样非 0
        #   两者都会让"明明匹配上了"的 jar 被判不匹配。
        #   改成先把清单落到变量再查，彻底绕开管道语义。
        _list="$(unzip -l "$_c" 2>/dev/null || true)"
        if [[ "$_list" == *"android/system/Os.class"* ]]; then
            ANDROID_JAR="$_c"
            break
        fi
    done
fi

for f in "$D8_JAR" "$APKTOOL" "${ANDROID_JAR:-}"; do
    [[ -f "$f" ]] || {
        echo "❌ 缺依赖: ${f:-<ANDROID_JAR 未找到>}" >&2
        echo "   设 ANDROID_JAR=/path/to/android.jar 后重试" >&2
        exit 1
    }
done
echo "▶ android.jar: $ANDROID_JAR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/classes" "$WORK/dex" "$WORK/src"

# ── 1) javac ────────────────────────────────────────────────────────────
# 编 stub-src 下的全部 .java（NcLink 是 Guard 的依赖，必须一起编）。
cp "$SRC_DIR"/*.java "$WORK/src/"
javac -nowarn -cp "$ANDROID_JAR" -d "$WORK/classes" "$WORK/src"/*.java
echo "✔ javac 通过"

# ── 2) d8 → dex ─────────────────────────────────────────────────────────
find "$WORK/classes" -name '*.class' -print0 | xargs -0 \
  java -cp "$D8_JAR" com.android.tools.r8.D8 --release --min-api 26 \
       --lib "$ANDROID_JAR" --output "$WORK/dex"
echo "✔ d8 通过"

# ── 3) dex → apk 容器 → baksmali ────────────────────────────────────────
# apktool 只吃 apk/dex 容器，不吃裸 dex 文件（同 build-stub.sh 的做法）。
python3 - "$WORK" <<'PY'
import sys, zipfile
w = sys.argv[1]
with zipfile.ZipFile(f"{w}/guard.apk", "w") as z:
    z.write(f"{w}/dex/classes.dex", "classes.dex")
PY
java -jar "$APKTOOL" d -f -r --no-res -o "$WORK/smali_out" "$WORK/guard.apk" >/dev/null 2>&1
echo "✔ baksmali 通过"

# ── 4) 落到 stub-src/ ───────────────────────────────────────────────────
# ⚠️ 不硬编码类名列表（2026-11-22 真机踩坑）：
#    原来写 `for cls in Guard Guard$Hb NcLink`，而 Guard.java 一度用匿名
#    Runnable，javac 编出的是 Guard$1 而不是 Guard$Hb →
#    dex 里缺类 → startHeartbeat 抛 NoClassDefFoundError → 心跳线程起不来
#    → env_watchdog 8 秒杀进程 → App 反复重启、进不去主页。
#
#    根因是硬编码：**编译出几个 class 由源码决定**（加内部类、加匿名类、
#    用 lambda 都会多文件），列名字必然漏。改成"编译出什么就产出什么"。
mkdir -p "$OUT_DIR"
_produced=0
while IFS= read -r _clsfile; do
    _cls="$(basename "$_clsfile" .class)"
    # baksmali 的输出布局随 dex 内包路径走，按文件名找，不猜目录层级。
    src="$(find "$WORK/smali_out" -name "${_cls}.smali" -type f | head -1)"
    [[ -n "$src" ]] || { echo "❌ baksmali 未产出 ${_cls}.smali" >&2; exit 1; }

    python3 - "$src" "$OUT_DIR/$_cls.smali" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding='utf-8').read()
# 去掉调试信息：.line 序号 + .source 文件名（会泄露原始 Java 文件名，
# 且对产物毫无用处 —— 与 build-stub.sh 同一处理）
text = re.sub(r'^[ \t]*\.line[ \t]+\d+[ \t]*\n', '', text, flags=re.M)
text = re.sub(r'^[ \t]*\.source[ \t]+.*\n', '', text, flags=re.M)
open(dst, 'w', encoding='utf-8').write(text)
PY
    echo "    → ${_cls}.smali ($(grep -c '' "$OUT_DIR/$_cls.smali") 行)"
    _produced=$((_produced + 1))
done < <(find "$WORK/classes" -name '*.class' -type f | sort)

[[ "$_produced" -gt 0 ]] || { echo "❌ 没产出任何 smali" >&2; exit 1; }
echo "    共 ${_produced} 个类"

echo "✅ 注入类编译完成"
echo
echo "⚠️ inject-javacheck.py 读的是这些 .smali。改 stub-src/*.java 后"
echo "   必须重跑本脚本，否则源码与入库产物不一致。"
