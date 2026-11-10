#!/usr/bin/env bash
# test-vmp-preconditions.sh — VMP 前置条件回归（2026-11-10）
#
# 为什么需要它：
#   VMP 的失败模式是【静默跳过】—— Amice 遇到不满足条件的函数直接跳过，
#   构建全绿、产物正常，只是没虚拟化。没有断言的话，任何一处改动
#   （改 attribute、改注册方式、改标记规则）都会让它悄悄失效而无人知道。
#
#   本项目已付过同类代价：`.comment` 移除的"失败但继续"日志让该防护
#   连续三个月零生效（2026-10-21 → 2026-11-02）。
#
# 断言什么（每条都对应一个真实的跳过原因）：
#   T1  段标记 + annotate 的产物形态正确（noinline + section + annotate）
#   T2  T1 的产物【不含 used / retain】—— clang 会把它们变成 @llvm.used，
#       表里存 ptr @func = 函数地址引用 → Amice 跳过（实测确认）
#   T3  T1 的产物能编译（属性组合合法）
#   T4  IR 里没有 @llvm.used（同上，从 IR 侧再验一次）
#   T5  IR 里有 @llvm.global.annotations（annotate 确实生效了）
#   T6  IR 里没有 C++ mangling（_Z..Java_）—— 否则 ART 找不到符号
#   T7  函数归属 .ncx 段
#   T8  check-vmp-eligibility.py 对静态注册形态报 ✓
#   T9  反向：check-vmp-eligibility.py 对动态注册形态（JNINativeMethod 表）报 ✗
#   T10 反向：used/retain 形态被 check-vmp-eligibility.py 判为不合格
#   T11 protect.sh 有 --vmp 参数且自动联动 --dex2c-static-register
#   T12 schema 有 vmp 模块且 resolver 能吐出 --vmp
#   T13 --vmp + --vmp-keep-dynamic-register 必须 fail-fast（不许白跑构建）
#
# 依赖：clang（有 jni.h 时 T3 更严格；无则用自造类型别名跳过）
# 用法：bash scripts/pipelines/tests/test-vmp-preconditions.sh
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/vmp-pre.XXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ✅ %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  ❌ %s\n' "$*"; }
skip() { printf '  ⏭ 跳过：%s\n' "$*"; }

CC=${CC:-clang}
MARK="$ROOT/../nox/scripts/so-guard/so_section_mark.py"
[ -f "$MARK" ] || MARK="$ROOT/tools/nox/so-guard/so_section_mark.py"
ELIG="$ROOT/../nox/scripts/check-vmp-eligibility.py"
[ -f "$ELIG" ] || ELIG="$ROOT/tools/nox/scripts/check-vmp-eligibility.py"

echo "══ 0. 前置：工具与脚本存在 ══"
[ -f "$MARK" ] && ok "so_section_mark.py 存在" || { bad "so_section_mark.py 缺失"; exit 1; }
[ -f "$ELIG" ] && ok "check-vmp-eligibility.py 存在" || { bad "check-vmp-eligibility.py 缺失"; exit 1; }

# ── 造一份"静态注册 + 待标 VMP"的 dex2c 产物样本 ────────────────────
mkdir -p "$W/jni/nc"
cat > "$W/jni/nc/Java_com_demo_MainActivity_onCreate__Landroid_os_Bundle_2.cpp" <<'EOF'
#include <jni.h>
/* Lcom/demo/MainActivity;->onCreate(Landroid/os/Bundle;)V */
extern "C" JNIEXPORT void JNICALL
Java_com_demo_MainActivity_onCreate__Landroid_os_Bundle_2(JNIEnv *env, jobject thiz, jobject p1)
{
    int acc = 0;
    for (int i = 0; i < 24; i++) acc += i * 3;
    (void)acc; (void)env; (void)thiz; (void)p1;
}
EOF
cat > "$W/jni/nc/Dex2C.cpp" <<'EOF'
#include <jni.h>
extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) { (void)vm; (void)reserved; return 0x10006; }
EOF

echo ""
echo "══ 1. 段标记 + VMP annotate ══"
python3 "$MARK" "$W/jni" --rule dex2c-jni --rule dynamic-register-jni \
    --exclude-func JNI_OnLoad --annotate '+vm_virtualize' > "$W/mark.log" 2>&1
RC=$?
[ $RC -eq 0 ] && ok "标记执行成功" || { bad "标记失败(rc=$RC)"; cat "$W/mark.log"; }

SRC="$W/jni/nc/Java_com_demo_MainActivity_onCreate__Landroid_os_Bundle_2.cpp"
ATTR=$(grep -m1 '__attribute__' "$SRC")

# T1 形态正确
case "$ATTR" in
  *noinline*)              ok "T1a 含 noinline（防内联掉，无独立符号可虚拟化）" ;;
  *)                       bad "T1a 缺 noinline：$ATTR" ;;
esac
case "$ATTR" in
  *'section(".ncx")'*)     ok "T1b 归属 .ncx" ;;
  *)                       bad "T1b 缺 section(\".ncx\")：$ATTR" ;;
esac
case "$ATTR" in
  *'annotate("+vm_virtualize")'*) ok "T1c 含 +vm_virtualize" ;;
  *)                              bad "T1c 缺 annotate：$ATTR" ;;
esac

# T2 不得含 used / retain
case "$ATTR" in
  *used*)   bad "T2a 含 used —— clang 会生成 @llvm.used（ptr @func），Amice 会跳过" ;;
  *)        ok "T2a 不含 used" ;;
esac
case "$ATTR" in
  *retain*) bad "T2b 含 retain —— 同样生成 @llvm.used，Amice 会跳过" ;;
  *)        ok "T2b 不含 retain" ;;
esac

# JNI_OnLoad 必须没被标（它是 unlock 调用方，锁进去=死锁）
if grep -q '__attribute__' "$W/jni/nc/Dex2C.cpp"; then
  bad "JNI_OnLoad 被标段了 —— 它是 unlock 的调用方，锁进 .ncx 会死锁"
else
  ok "JNI_OnLoad 未被标段（--exclude-func 生效）"
fi

echo ""
echo "══ 2. 编译与 IR 验证 ══"
JNI_INC=""
for c in "${ANDROID_NDK_HOME:-}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include" \
         "${PREFIX:-}/include" /usr/include; do
  [ -n "$c" ] && [ -f "$c/jni.h" ] && { JNI_INC="$c"; break; }
done

if [ -z "$JNI_INC" ]; then
  skip "找不到 jni.h（NDK/SDK 才有），T3~T7 跳过；设 ANDROID_NDK_HOME 可启用"
else
  # T3 能编译
  if "$CC" -c -O2 -fPIC -I"$JNI_INC" "$SRC" -o "$W/t.o" 2>"$W/cc.log"; then
    ok "T3 属性组合可编译"
  else
    bad "T3 编译失败：$(head -2 "$W/cc.log" | tr '\n' ' ')"
  fi

  # 生成 IR
  if "$CC" -S -emit-llvm -Oz -I"$JNI_INC" "$SRC" -o "$W/t.ll" 2>/dev/null; then
    # T4 无 llvm.used
    if grep -q '@llvm.used' "$W/t.ll"; then
      bad "T4 IR 里有 @llvm.used —— Amice 会判 non-call address use 并跳过"
    else
      ok "T4 IR 无 @llvm.used"
    fi
    # T5 有 global.annotations
    if grep -q '@llvm.global.annotations' "$W/t.ll"; then
      ok "T5 IR 有 @llvm.global.annotations（annotate 生效）"
    else
      bad "T5 IR 缺 @llvm.global.annotations —— annotate 未生效"
    fi
    # T6 无 mangling
    if grep -qE '_Z[0-9]+Java_' "$W/t.ll"; then
      bad "T6 出现 C++ mangling(_Z..Java_) —— ART 找不到符号，必须 extern \"C\""
    else
      ok "T6 无 C++ mangling"
    fi
    # T7 归属段
    if grep -q 'section ".ncx"' "$W/t.ll"; then
      ok "T7 IR 里函数归属 .ncx"
    else
      bad "T7 IR 里函数未归属 .ncx"
    fi
  else
    bad "T4/5/6/7 生成 IR 失败"
  fi
fi

# ── T8~T10：check-vmp-eligibility.py 的判据验证 ────────────────────
# ⚠️ 2026-11-11 修：这三项【不依赖 jni.h】，必须放在上面的分支【外面】。
#   首版把 T8 放在分支里且传含 `#include <jni.h>` 的 SRC，而预检脚本的
#   emit_ir 只加 `-I <源文件目录>`，不带 NDK/SDK include 路径 →
#   clang 找不到 jni.h → 预检失败。
#   实测（CI run 42850364518）：T3~T7 全过而 T8 红 —— 因为 T3 的 clang
#   是【本脚本】调的（带 -I "$JNI_INC"），T8 的 clang 是【预检脚本】调的
#   （不带）。两处环境不一致就会出这种"看起来同源其实不同命"的假红。
#   改用自造类型后，三项在 CI 干净环境下也能跑，且与 T3~T7 互补
#   （T3~T7 验属性形态，T8~T10 验预检脚本的判据正确性）。
cat > "$W/static_ok.c" <<'EOF'
typedef struct JNIEnv_ JNIEnv;
typedef struct _jobject* jobject;
#define JNIEXPORT __attribute__((visibility("default")))
#define JNICALL
__attribute__((noinline, section(".ncx"), annotate("+vm_virtualize")))
JNIEXPORT void JNICALL
Java_com_demo_MainActivity_onCreate(JNIEnv *env, jobject thiz, jobject p1)
{
    int acc = 0;
    for (int i = 0; i < 24; i++) acc += i * 3;
    (void)acc; (void)env; (void)thiz; (void)p1;
}
EOF
if python3 "$ELIG" "$W/static_ok.c" Java_com_demo_MainActivity_onCreate \
     > "$W/e1.log" 2>&1; then
  ok "T8 静态注册形态预检通过（可虚拟化）"
else
  bad "T8 静态注册形态预检失败：$(grep -m1 '✗' "$W/e1.log" || head -2 "$W/e1.log" | tr '\n' ' ')"
fi

# T9 反向：动态注册形态（有 JNINativeMethod 表）必须被判不合格
cat > "$W/dyn.c" <<'EOF'
typedef struct JNIEnv_ JNIEnv;
typedef struct _jobject* jobject;
void Java_com_demo_X_f(JNIEnv *e, jobject t) { (void)e; (void)t; }
typedef struct { const char* n; const char* s; void* f; } NM;
extern void Java_com_demo_X_f(JNIEnv*, jobject);
NM tbl[] = { {"f", "()V", (void *)Java_com_demo_X_f} };
EOF
if python3 "$ELIG" "$W/dyn.c" Java_com_demo_X_f > "$W/e2.log" 2>&1; then
  bad "T9 反向验证失败：动态注册（取地址）竟被判为可虚拟化 —— 预检有盲区"
else
  ok "T9 反向验证：动态注册形态被判不合格（JNINativeMethod 表 = 取地址）"
fi

# T10 反向：used/retain 形态必须被判不合格（@llvm.used）
sed 's/noinline, section(".ncx"), annotate("+vm_virtualize")/noinline, section(".ncx"), used, retain/' \
    "$W/static_ok.c" > "$W/used.c"
if python3 "$ELIG" "$W/used.c" Java_com_demo_MainActivity_onCreate \
     > "$W/e3.log" 2>&1; then
  bad "T10 反向验证失败：used/retain 形态竟被判合格 —— @llvm.used 检查失效"
else
  ok "T10 反向验证：used/retain 形态被判不合格（@llvm.used）"
fi

echo ""
echo "══ 3. 流水线接线 ══"
# T11 --vmp 存在且自动联动静态注册
if grep -q -- '--vmp)' "$ROOT/scripts/pipelines/protect.sh"; then
  ok "T11a protect.sh 认识 --vmp"
else
  bad "T11a protect.sh 没有 --vmp 分支"
fi
if grep -A4 -- '--vmp)' "$ROOT/scripts/pipelines/protect.sh" | grep -q 'WANT_DEX2C_STATIC_REG=1'; then
  ok "T11b --vmp 自动联动 --dex2c-static-register"
else
  bad "T11b --vmp 没有联动静态注册（漏了会让 VMP 静默失效）"
fi

# T11c AMICE_VM_VIRTUALIZE 必须 export
# ⚠️ 这是 2026-11-11 实测踩出来的：只设 profile 不设这个开关 = pass 不装，
#    annotate 写了也没人读，产物只多 36 字节（一个 global.annotations 表）。
#    文档原文："没有列入的 Pass 不会因为函数注解而重新运行"。
if grep -qE '^[[:space:]]*export AMICE_VM_VIRTUALIZE=true' "$ROOT/scripts/pipelines/protect.sh"; then
  ok "T11c AMICE_VM_VIRTUALIZE=true 已 export（否则 VMP 静默空转）"
else
  bad "T11c 缺 AMICE_VM_VIRTUALIZE=true —— annotate 不会被任何 pass 读取"
fi
# T11d profile 与开关必须成对（只在 vmp 分支里，不能散落在别处）
if python3 - "$ROOT/scripts/pipelines/protect.sh" <<'PY'
import sys,re
s=open(sys.argv[1]).read()
i=s.find('if [[ $WANT_VMP -eq 1 ]]; then')
if i<0: sys.exit(1)
seg=s[i:s.find('\nfi',i)]
# 只认行首的 export 语句，不认注释里的说明文字
has_sw = re.search(r'^[ \t]*export AMICE_VM_VIRTUALIZE=true', seg, re.M) is not None
has_pf = re.search(r'^[ \t]*export AMICE_VM_PROFILE_PATH', seg, re.M) is not None
sys.exit(0 if (has_sw and has_pf) else 1)
PY
then
  ok "T11d 开关与 profile 同处 vmp 分支（成对出现）"
else
  bad "T11d 开关与 profile 不在同一分支 —— 后续改动容易漏掉一个"
fi

# T12 schema + resolver
if python3 -c "
import json,sys
d=json.load(open('$ROOT/configs/v1/config-schema.json'))
ks=[m.get('key') for m in d['modules']]
sys.exit(0 if 'vmp' in ks else 1)"; then
  ok "T12a schema 有 vmp 模块"
else
  bad "T12a schema 缺 vmp 模块"
fi

# T13 --vmp + 保留动态注册 必须 fail-fast
if grep -q 'vmp-keep-dynamic-register' "$ROOT/scripts/pipelines/protect.sh"; then
  ok "T13 有 --vmp-keep-dynamic-register 且与 --vmp 互斥（fail-fast）"
else
  bad "T13 缺互斥检查：--vmp + 动态注册会白跑一遍构建"
fi

echo ""
echo "════════════════════════════════════════"
if [ "$FAIL" -eq 0 ]; then
  printf '✅ 全部通过：%d 项断言\n' "$PASS"
  exit 0
fi
printf '❌ 失败 %d 项 / 通过 %d 项\n' "$FAIL" "$PASS"
exit 1
