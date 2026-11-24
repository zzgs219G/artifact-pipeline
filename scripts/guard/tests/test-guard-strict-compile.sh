#!/usr/bin/env bash
# test-guard-strict-compile.sh — guard/src 的【严格模式】编译门禁
#
# 【为什么需要它】
#   2026-11-22 发现：CI 里没有任何 step 用 -Werror 编译 scripts/guard/src/*.c。
#   所有跑它们的测试（test-sig-verify / test-sig-guard2 / test-lsgs-strings /
#   test-so-lock）都只传 -O1/-O2，不带 -Wall -Wextra -Werror。
#
#   代价是实打实的：
#     · sig_guard2.c 的 `certs_len` set-but-not-used → 真的少了一个边界检查
#     · sig_guard2.c 的 off_t/unsigned 混比 → 整数回绕，可被恶意 APK 利用
#     · sig_check.c 的 unused variable/function → 说明有死代码没人清理
#   这些告警一直在，但从没拦过任何东西。**告警存在但没人看 = 没有告警。**
#
# 【做什么】
#   对 guard/src 下每个 .c 用三种模式编一遍，任一告警即失败：
#     ① 真机 arm64（无宏）
#     ② 真机 armv7（无宏）
#     ③ 宿主 SIGCHECK_HOST_TEST
#   ⚠️ 三种都要测：条件编译分支不同，只测一种会漏掉另一半。
#      本门禁加上时就是这样发现 siglog_testapk_env 只在宿主模式下暴露的。
#
# 【依赖】
#   · NDK（真机两档）—— 没有则跳过那两档并打印原因，不假红
#   · 生成的头文件（sig_hash.h / sig_guard2.h / sig_log_data.h）
#     —— 由本脚本自动生成到临时目录，不用仓库里的陈旧副本
#
# 用法: bash scripts/guard/tests/test-guard-strict-compile.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SRC="$ROOT/scripts/guard/src"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

pass=0; fail=0; skip=0
ok()  { echo "  ✅ $1"; pass=$((pass+1)); }
bad() { echo "  ❌ $1"; fail=$((fail+1)); }
skp() { echo "  ⚠️ 跳过：$1"; skip=$((skip+1)); }

echo "══════════════════════════════════════════════════"
echo "guard/src 严格编译门禁（-Wall -Wextra -Werror）"
echo "══════════════════════════════════════════════════"

# ── 生成本次编译所需的头文件 ────────────────────────────────────────
APK="$ROOT/scripts/样本.apk"
if [[ -f "$APK" ]]; then
  # ls_guard_src 顺序必须与 protect.sh 一致（否则标记枚举顺序不同，
# 但本门禁只关心能否编译，顺序不影响告警判定）
  bash "$ROOT/scripts/guard/hash/make-sig-hash.sh" "$APK" \
       "$T/sig_hash.h" "$T/sig_guard2.h" >"$T/gen1.log" 2>&1 \
    || { echo "❌ sig_hash.h 生成失败"; tail -3 "$T/gen1.log"; exit 1; }
else
  skp "缺 $APK，无法生成 sig_hash.h（真机档也需要它）"
fi
if ! python3 "$ROOT/scripts/guard/log/make-sig-log.py" \
      "$SRC/sig_check.c" "$SRC/env_check.c" "$SRC/env_probes.c" \
      "$SRC/sig_guard2.c" "$SRC/nc_log.c" "$T/sig_log_data.h" >"$T/gen2.log" 2>&1; then
  echo "❌ sig_log_data.h 生成失败"; tail -3 "$T/gen2.log"; exit 1
fi

# 段契约头来自上游 nox
LAYOUT=""
for cand in "$ROOT/tools/nox/so-guard/nc_guard_layout.h" \
            "$(dirname "$ROOT")/nox/scripts/so-guard/nc_guard_layout.h"; do
  [[ -f "$cand" ]] && { LAYOUT="$(dirname "$cand")"; break; }
done
if [[ -z "$LAYOUT" ]]; then
  skp "找不到 nc_guard_layout.h（需 tools/nox 或 ../nox）"
fi

INC=(-I"$T" -I"$SRC")
[[ -n "$LAYOUT" ]] && INC+=(-I"$LAYOUT")

# 要检查的文件：guard/src 下所有 .c
FILES=()
while IFS= read -r f; do FILES+=("$f"); done < <(find "$SRC" -maxdepth 1 -name '*.c' | sort)
echo "  待检文件：${#FILES[@]} 个"
echo

# ── ① ② 真机两档 ──────────────────────────────────────────────────
NDKBIN=""
if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
  NDKBIN="$(ls -d "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin 2>/dev/null | head -1)"
fi
if [[ -z "$NDKBIN" ]]; then
  skp "ANDROID_NDK_HOME 未设置或无效 —— 真机两档未检查"
else
  for abi in aarch64-linux-android24 armv7a-linux-androideabi24; do
    CC="$NDKBIN/${abi}-clang"
    if [[ ! -x "$CC" ]]; then skp "$abi 编译器不存在"; continue; fi
    echo "[$abi]"
    for f in "${FILES[@]}"; do
      base="$(basename "$f")"
      if out=$("$CC" -c -O2 -Wall -Wextra -Werror "${INC[@]}" \
                 -o /dev/null "$f" 2>&1); then
        ok "$base"
      else
        bad "$base"
        echo "$out" | grep -E "error:|warning:" | head -4 | sed 's/^/      /'
      fi
    done
  done
fi

# ── ③ 宿主测试档（SIGCHECK_HOST_TEST 宏）─────────────────────────────
#
# ⚠️⚠️ 这一档【必须用 NDK 交叉编译器】，不能用宿主编译器。
#     走了两轮弯路的记录（CI run 45006692729 / 45006964724）：
#
#   第一版：用 nc_pick_host_cc（纯 x86_64 clang）
#     → 本地 Termux 绿，CI 红：android/log.h / jni.h 全找不到。
#       宿主 clang 根本没有 Android 头。
#
#   第二版：加 -idirafter 指向 NDK sysroot（只补头）
#     → 头找到了，但暴露出更深的问题：
#       · arm_acle.h 不存在（它是 aarch64 专有头，x86_64 不可能有）
#       · gettid / Dl_info / dladdr 缺失（glibc 与 bionic 的差异）
#     这些不是代码 bug，是"用错误的编译器编"。想靠补 include 绕过，
#     只会一路撞到下一个不兼容点。
#
#   第三版（本版）：用 NDK 的 aarch64-clang 编，只加 SIGCHECK_HOST_TEST 宏。
#     产物是 ARM ELF、跑不了 —— 但【本档只做编译期检查，不运行】，
#     所以没关系。这是既有的正确做法：test-lsgs-strings.sh 的 SO_CC
#     也是走 NDK 编 sig_check.c/env_check.c（那边注释写过同样的理由）。
#
# 换句话说：这一档验的是"开宿主宏时还能不能编过"，不是"能不能在宿主跑"。
echo "[host 宏档 SIGCHECK_HOST_TEST（NDK 交叉编译，只编不跑）]"
if [[ -z "$NDKBIN" ]]; then
  skp "无 NDK，宿主宏档未检查"
else
  HCC="$NDKBIN/aarch64-linux-android24-clang"
  if [[ ! -x "$HCC" ]]; then
    skp "缺 $HCC"
  else
    for f in "${FILES[@]}"; do
      base="$(basename "$f")"
      if out=$("$HCC" -c -O2 -Wall -Wextra -Werror \
                 -DSIGCHECK_HOST_TEST "${INC[@]}" -o /dev/null "$f" 2>&1); then
        ok "$base (host 宏)"
      else
        bad "$base (host 宏)"
        echo "$out" | grep -E "error:|warning:" | head -4 | sed 's/^/      /'
      fi
    done
  fi
fi

echo
echo "══════════════════════════════════════════════════"
echo "结果: $pass 通过, $fail 失败, $skip 跳过"
echo "══════════════════════════════════════════════════"
echo
echo "⚠️ 本门禁只保证【编译期无告警】，不等于行为正确。"
echo "   行为验证见 test-sig-verify / test-sig-guard2 / test-sigblock-bounds。"
[[ $fail -eq 0 ]] || exit 1
