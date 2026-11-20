#!/usr/bin/env bash
# build.sh — 载荷编译链: SigFix.java → javac → d8 → baksmali → SigFix.smali
#
# 与 string-enc/build-stub.sh 同一模式（有先例、有纪律）：
#   · smali 是自动生成的中间产物，人永远不要手改
#   · 编译前把占位符换成哨兵值（临时副本，绝不回写仓库里的源码）
#   · 产出后自检锚点，缺失 fail-fast
#
# 用法: build.sh [输出目录](默认 payload/)
# 依赖: javac / tools/d8.jar($SIGFIX_D8 可覆盖) / android.jar($SIGFIX_ANDROID_JAR)
#       / tools/apktool.jar
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ROOT="$(dirname "$(dirname "$(dirname "$_HERE")")")"        # payload → uncheck → scripts → 仓库根
APKTOOL="${_ROOT}/tools/apktool.jar"

SRC="$_HERE/src/com/nc/uncheck/SigFix.java"
OUT_DIR="${1:-$_HERE}"

D8_JAR="${SIGFIX_D8:-$_ROOT/scripts/string-enc/tools/d8.jar}"

# android.jar：优先显式指定，其次常见位置。只用于 javac 的类型检查与常量池，
# 不进产物 —— 但版本必须 >= 目标 App 可能用到的最高 API，否则 signingInfo 等
# 字段编译期就不认。
ANDROID_JAR="${SIGFIX_ANDROID_JAR:-}"
if [ -z "$ANDROID_JAR" ]; then
  for cand in \
    "$HOME/tmp/toolchain/android-all.jar" \
    "$HOME/android-sdk/platforms/android-37/android.jar" \
    "$HOME/android-sdk/platforms/android-36/android.jar" \
    "${ANDROID_HOME:-$HOME/android-sdk}/platforms/android-37/android.jar" \
    "${ANDROID_HOME:-$HOME/android-sdk}/platforms/android-36/android.jar"
  do
    [ -f "$cand" ] && { ANDROID_JAR="$cand"; break; }
  done
fi

# 哨兵值。必须与 SigFix.java 的占位符不同（否则「未被替换」的自检无法成立），
# 且必须是一个 inject.py 能稳定搜索结果、长度固定的串。
SENTINEL="NCSIGFIXSENTINELCERTB64PLACEHOLDER0000000000000000000000000000000"

for f in "$SRC" "$APKTOOL" "$D8_JAR"; do
  [ -f "$f" ] || { echo "❌ 缺依赖: $f" >&2; exit 1; }
done
[ -n "$ANDROID_JAR" ] && [ -f "$ANDROID_JAR" ] \
  || { echo "❌ 找不到 android.jar，请设 SIGFIX_ANDROID_JAR=<path>" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> javac (android.jar = $ANDROID_JAR)"
mkdir -p "$WORK/src/com/nc/uncheck" "$WORK/classes"
# 在临时副本里把占位符换成哨兵，仓库源码保持占位符形态
sed "s|__NC_SIGFIX_CERT_B64__|${SENTINEL}|" \
    "$SRC" > "$WORK/src/com/nc/uncheck/SigFix.java"
grep -q "\"${SENTINEL}\"" "$WORK/src/com/nc/uncheck/SigFix.java" \
  || { echo "❌ 哨兵替换失败: SigFix.java 的 CERT_B64 声明行形态变了" >&2; exit 1; }

# -source/-target 8：d8 的脱糖以 8 为基线最稳；不开 lambda 也就没有脱糖依赖。
javac -source 8 -target 8 -encoding UTF-8 \
      -bootclasspath "$ANDROID_JAR" -cp "$ANDROID_JAR" \
      -d "$WORK/classes" \
      "$WORK/src/com/nc/uncheck/SigFix.java" 2>&1 | grep -vE "^注|^Note|bootstrap class path" || true
[ -f "$WORK/classes/com/nc/uncheck/SigFix.class" ] \
  || { echo "❌ javac 未产出 SigFix.class" >&2; exit 1; }

echo "==> d8 (min-api 21)"
mkdir -p "$WORK/dex"
find "$WORK/classes" -name '*.class' -print0 | xargs -0 \
  java -cp "$D8_JAR" com.android.tools.r8.D8 \
       --release --min-api 21 --output "$WORK/dex"
[ -f "$WORK/dex/classes.dex" ] || { echo "❌ d8 未产出 classes.dex" >&2; exit 1; }

echo "==> baksmali (借 apktool，它只吃 apk/dex 容器)"
python3 - "$WORK" <<'PY'
import sys, zipfile, os
work = sys.argv[1]
with zipfile.ZipFile(os.path.join(work, "sigfix.apk"), "w") as z:
    z.write(os.path.join(work, "dex", "classes.dex"), "classes.dex")
PY
java -jar "$APKTOOL" d -f -r --no-res -o "$WORK/smali_out" "$WORK/sigfix.apk" >/dev/null 2>&1
SMALI_IN="$WORK/smali_out/smali/com/nc/uncheck/SigFix.smali"
[ -f "$SMALI_IN" ] || { echo "❌ baksmali 未产出 SigFix.smali" >&2; exit 1; }

echo "==> 修整 smali + 自检锚点"
mkdir -p "$OUT_DIR"
# ⚠️ 必须收集【所有】产物：SigFix 有内部类 SigFix$IpmHandler，
#    只拷主类会让产物在运行期 NoClassDefFoundError（本模块历史的第一个坑）。
SMALI_DIR_IN="$WORK/smali_out/smali/com/nc/uncheck"
COUNT=$(find "$SMALI_DIR_IN" -maxdepth 1 -name 'SigFix*.smali' | wc -l)
[ "$COUNT" -ge 1 ] || { echo "❌ baksmali 未产出任何 SigFix*.smali" >&2; exit 1; }
echo "    baksmali 产出 $COUNT 个 smali（含内部类）"

for f in "$SMALI_DIR_IN"/SigFix*.smali; do
  python3 - "$f" "$OUT_DIR/$(basename "$f")" "$SENTINEL" <<'PY'
import re, sys
src, dst, sentinel = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src, encoding='utf-8').read()

# 1) 去调试信息：产物要进别人的包，不带源文件名与行号
text = re.sub(r'^[ \t]*\.line[ \t]+\d+[ \t]*$', '', text, flags=re.M)
text = re.sub(r'^[ \t]*\.source[ \t]+.*\n', '', text, flags=re.M)
# 2) 去掉多余空行（baksmali 删 .line 后留下的）
text = re.sub(r'\n{3,}', '\n\n', text)

base = dst.rsplit('/', 1)[-1]

# 自检 A：不得残留 Java 源码痕迹（泄露实现语言/思路）
for bad in ('.java', 'SigFix.java'):
    if bad in text:
        raise SystemExit(f'❌ {base} 残留源码痕迹: {bad}')

# 下面几条只针对主类
if base == 'SigFix.smali':
    if sentinel not in text:
        raise SystemExit(
            '❌ smali 里找不到哨兵证书串。\n'
            '   d8 可能把 CERT_B64 优化掉了（判定为未使用）。\n'
            '   检查 SigFix.java 里 CERT_B64 是否仍被 install() 读取。')
    if '.class public final Lcom/nc/uncheck/SigFix;' not in text:
        raise SystemExit('❌ 类描述符不是 Lcom/nc/uncheck/SigFix;（inject.py 按此名查找）')
    if 'method public static install(Landroid/content/Context;)V' not in text:
        raise SystemExit('❌ 缺少 install(Landroid/content/Context;)V 入口')
    open(dst, 'w', encoding='utf-8').write(text)
    print(f'✅ {base}: {len(text.splitlines())} 行 / 哨兵 1 处')
else:
    open(dst, 'w', encoding='utf-8').write(text)
    print(f'✅ {base}: {len(text.splitlines())} 行（内部类）')
PY
done

echo "==> 完成。产物目录: $OUT_DIR/ （SigFix.smali + 内部类）"
