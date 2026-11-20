#!/usr/bin/env bash
# build.sh — 载荷编译链（两段式）
#
#   SigFix.java      → javac → d8 → baksmali → SigFix.smali      （进 App 的 dex）
#   SigFixImpl.java  → javac → d8 → payload.dex                  （进 assets，运行时投放）
#
# ⚠️ 为什么必须两段（2026-11-21 真机实测后重构）：
#   目标是反射访问隐藏 API，而 Android 9+ 的拦截判定依据是
#   **加载该 Class 的 DexFile 的 domain**。
#   同一个 dex 里的类，domain 就是应用域 → 反射被拦
#   （实测 Android 17：setHiddenApiExemptions 直接 blocked，
#    报 NoSuchMethodException，hook 完全装不上）。
#
#   而用 `new DexFile(path)`（不传 ClassLoader）加载的 dex 会走
#   BootClassLoader，其 domain 是平台域 → 不受拦截。
#   所以「真正干活的类」必须单独成一个 dex 文件，
#   由引导器（SigFix，留在 App 的 dex 里）在运行时投放 + 加载。
#
#   把两者编在同一个 dex 里，或让 SigFixImpl 跟 App 一起被打包 —— 都会
#   退回应用域，绕不过去。这是本模块最核心的一条结构约束。
#
# 用法: build.sh [输出目录](默认 payload/)
# 依赖: javac / tools/d8.jar($SIGFIX_D8) / android.jar($SIGFIX_ANDROID_JAR)
#       / tools/apktool.jar
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ROOT="$(dirname "$(dirname "$(dirname "$_HERE")")")"        # payload → uncheck → scripts → 仓库根
APKTOOL="${_ROOT}/tools/apktool.jar"

SRC_BOOT="$_HERE/src/com/nc/uncheck/SigFix.java"
SRC_IMPL="$_HERE/src/com/nc/uncheck/SigFixImpl.java"
OUT_DIR="${1:-$_HERE}"

D8_JAR="${SIGFIX_D8:-$_ROOT/scripts/string-enc/tools/d8.jar}"

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

# 哨兵证书串。必须与 inject.py 的 SENTINEL 逐字一致。
SENTINEL="NCSIGFIXSENTINELCERTB64PLACEHOLDER0000000000000000000000000000000"

for f in "$SRC_BOOT" "$SRC_IMPL" "$APKTOOL" "$D8_JAR"; do
  [ -f "$f" ] || { echo "❌ 缺依赖: $f" >&2; exit 1; }
done
[ -n "$ANDROID_JAR" ] && [ -f "$ANDROID_JAR" ] \
  || { echo "❌ 找不到 android.jar，请设 SIGFIX_ANDROID_JAR=<path>" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> javac (android.jar = $ANDROID_JAR)"
mkdir -p "$WORK/src/com/nc/uncheck" "$WORK/classes"
# 只在临时副本里替换占位符，仓库源码保持占位符形态
cp "$SRC_BOOT" "$WORK/src/com/nc/uncheck/SigFix.java"
# 其余源文件原样拷过去（SigFixImpl / ArtProbe / Probe ... 新增文件自动纳入）
for f in "$_HERE"/src/com/nc/uncheck/*.java; do
  b=$(basename "$f")
  [ "$b" = "SigFix.java" ] && continue
  cp "$f" "$WORK/src/com/nc/uncheck/$b"
done
# 证书改为运行时从 assets/nc_sigfix/sigfix.json 读取，dex 里不再烘焙任何
# 目标相关数据 —— dex 因此是**静态资产**，可入 git、可下载、可缓存。

javac -source 8 -target 8 -encoding UTF-8 \
      -bootclasspath "$ANDROID_JAR" -cp "$ANDROID_JAR" \
      -d "$WORK/classes" \
      "$WORK"/src/com/nc/uncheck/*.java 2>&1 \
  | grep -vE "^注|^Note|bootstrap class path|obsolete|Xlint" || true

for c in SigFix SigFixImpl; do
  [ -f "$WORK/classes/com/nc/uncheck/$c.class" ] \
    || { echo "❌ javac 未产出 $c.class" >&2; exit 1; }
done

# ── 第一段：引导器 → SigFix.smali（进 App 的 dex）──────────────────────
echo "==> d8 引导器 (min-api 21)"
mkdir -p "$WORK/dex-boot"
# 引导器组：SigFix（生命周期注入用）+ SigFixApp（Manifest 挂载用）。
# 这两个类必须留在 App 的 dex 里（普通应用域），
# 只有 SigFixImpl 才需要进 payload.dex 由 BootClassLoader 加载。
BOOT_CLASSES=()
while IFS= read -r f; do
  base=$(basename "$f")
  case "$base" in
    SigFix.class|SigFix\$*|SigFixApp.class|SigFixApp\$*) BOOT_CLASSES+=("$f") ;;
  esac
done < <(find "$WORK/classes/com/nc/uncheck" -name '*.class' | sort)
[ "${#BOOT_CLASSES[@]}" -gt 0 ] || { echo "❌ 引导器组为空" >&2; exit 1; }
echo "    引导器收 ${#BOOT_CLASSES[@]} 个 class"
java -cp "$D8_JAR" com.android.tools.r8.D8 --release --min-api 21 \
     --output "$WORK/dex-boot" "${BOOT_CLASSES[@]}"
[ -f "$WORK/dex-boot/classes.dex" ] || { echo "❌ 引导器 d8 失败" >&2; exit 1; }

python3 - "$WORK" <<'PY'
import sys, zipfile, os
work = sys.argv[1]
with zipfile.ZipFile(os.path.join(work, "boot.apk"), "w") as z:
    z.write(os.path.join(work, "dex-boot", "classes.dex"), "classes.dex")
PY
java -jar "$APKTOOL" d -f -r --no-res -o "$WORK/boot_smali" "$WORK/boot.apk" >/dev/null 2>&1
[ -d "$WORK/boot_smali/smali" ] || { echo "❌ 引导器 baksmali 失败" >&2; exit 1; }

mkdir -p "$OUT_DIR"
for f in "$WORK/boot_smali/smali/com/nc/uncheck/"*.smali; do
  cp "$f" "$OUT_DIR/$(basename "$f")"
done

# ── 第二段：实现类 → payload.dex（进 assets，运行时由 DexFile 加载）────
echo "==> d8 实现类 (min-api 21)"
mkdir -p "$WORK/dex-impl"
# 收集 com/nc/uncheck 下所有 class，但**排除引导器 SigFix**（它必须留在 App 的 dex 里）
IMPL_CLASSES=()
while IFS= read -r f; do
  base=$(basename "$f")
  case "$base" in
    SigFix.class|SigFix\$*|SigFixApp.class|SigFixApp\$*) continue ;;   # 引导器组，不进 payload
  esac
  IMPL_CLASSES+=("$f")
done < <(find "$WORK/classes/com/nc/uncheck" -name '*.class' | sort)
[ "${#IMPL_CLASSES[@]}" -gt 0 ] || { echo "❌ payload 里没有任何 class" >&2; exit 1; }
echo "    payload 收 ${#IMPL_CLASSES[@]} 个 class"
java -cp "$D8_JAR" com.android.tools.r8.D8 --release --min-api 21 \
     --output "$WORK/dex-impl" "${IMPL_CLASSES[@]}"
[ -f "$WORK/dex-impl/classes.dex" ] || { echo "❌ 实现类 d8 失败" >&2; exit 1; }
cp "$WORK/dex-impl/classes.dex" "$OUT_DIR/payload.dex"

# ── 修整 + 自检 ─────────────────────────────────────────────────────
echo "==> 修整 smali + 自检"
python3 - "$OUT_DIR" "$SENTINEL" <<'PY'
import glob, os, re, sys

out_dir, sentinel = sys.argv[1], sys.argv[2]

def strip_debug(text):
    text = re.sub(r'^[ \t]*\.line[ \t]+\d+[ \t]*$', '', text, flags=re.M)
    text = re.sub(r'^[ \t]*\.source[ \t]+.*\n', '', text, flags=re.M)
    return re.sub(r'\n{3,}', '\n\n', text)

boot_files = sorted(glob.glob(os.path.join(out_dir, 'SigFix*.smali')))
if not boot_files:
    raise SystemExit('❌ 没有产出任何 SigFix*.smali')

for p in boot_files:
    base = os.path.basename(p)
    # 先清理调试信息（.source 带原文件名），再检查残留 —— 顺序反了会把
    # 还没清理的 ".source \"SigFix.java\"" 当成残留而误报。
    t = strip_debug(open(p, encoding='utf-8').read())
    if '.java' in t:
        raise SystemExit(f'❌ {base} 残留源码痕迹: .java')
    if base == 'SigFixApp.smali':
        if 'class public Lcom/nc/uncheck/SigFixApp;' not in t.split('\n')[0] \
                and '.class public Lcom/nc/uncheck/SigFixApp;' not in t:
            pass   # 类声明行格式由 d8 决定，不强校验
    if base == 'SigFix.smali':
        if 'method public static install(Landroid/content/Context;)V' not in t:
            raise SystemExit('❌ SigFix.smali 缺少 install(Landroid/content/Context;)V')
    open(p, 'w', encoding='utf-8').write(t)
    print(f'✅ {base}: {len(t.splitlines())} 行')

# payload.dex 自检：必须是合法 dex，且含实现类
dex = os.path.join(out_dir, 'payload.dex')
if not os.path.isfile(dex):
    raise SystemExit('❌ 没有产出 payload.dex')
raw = open(dex, 'rb').read()
if raw[:4] != b'dex\n':
    raise SystemExit('❌ payload.dex magic 非法')
if b'com/nc/uncheck/SigFixImpl' not in raw:
    raise SystemExit('❌ payload.dex 里找不到 SigFixImpl')
# 引导器绝不能出现在 payload.dex 里（否则说明两段混编，绕法失效）
if b'com/nc/uncheck/SigFix;' in raw.replace(b'com/nc/uncheck/SigFixImpl', b''):
    raise SystemExit(
        '❌ payload.dex 里混进了引导器 SigFix —— 两段必须严格分开，\n'
        '   否则实现类会退回应用域，BootClassLoader 绕法失效。')
print(f'✅ payload.dex: {len(raw)} B，含 SigFixImpl，未混入引导器')
PY

echo "==> 完成。产物目录: $OUT_DIR/"
echo "    SigFix*.smali  → 注入进 App 的 dex（引导器）"
echo "    payload.dex    → 放进 assets/nc_sigfix/（BootClassLoader 加载）"
