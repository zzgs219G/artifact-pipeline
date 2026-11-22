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
      "$SRC/sig_guard2.c" "$T/sig_log_data.h" >"$T/gen2.log" 2>&1; then
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

# ── ③ 宿主模式 ────────────────────────────────────────────────────
#
# ⚠️⚠️ 这一档在 CI 上踩过一次（run 45006692729 全红）：
#     本地 Termux 的 clang 能找到 android/log.h / jni.h / arm_acle.h
#     （它们就在 /data/data/com.termux/files/usr/include 附近），
#     而 CI 的宿主编译器是纯 x86_64 clang，【找不到任何 Android 头】——
#     于是 8 个文件 7 个 fatal error: android/log.h No such file。
#
#     这不是被测代码的问题，是本脚本漏给了 include 路径。
#     修法：宿主档也要把 NDK 的 sysroot include 加进来（只要头，不交叉编译）。
#     注意不能直接用 nc_pick_ndk_cc —— 那是 ARM 交叉编译器，
#     而本档要的是【在本机能跑的宿主 clang + Android 头】。
echo "[host SIGCHECK_HOST_TEST]"
# shellcheck source=../../lib/host-cc.sh
source "$ROOT/scripts/lib/host-cc.sh"
HOST_CC="$(nc_pick_host_cc || command -v clang || command -v gcc)"
if [[ -z "$HOST_CC" ]]; then
  skp "找不到宿主编译器"
else
  # 找一个可用的 NDK sysroot include（arm64 优先，退回 armv7）
  SYSINC=""
  if [[ -n "$NDKBIN" ]]; then
    for t in aarch64-linux-android armv7a-linux-androideabi; do
      d="$NDKBIN/../sysroot/usr/include"
      [[ -d "$d" ]] && { SYSINC="$d"; break; }
    done
  fi
  # ⚠️⚠️ 必须用 -idirafter，不能用 -I。
  #
  #   -I 把 NDK 的 include 插到【系统头之前】→ 宿主的 stdlib.h 解析时
  #   会先看到 bionic 的 bits/*，两者混用 → 一堆 "unused parameter __l"
  #   之类的库内告警（实测 4 个文件因此红）。host-cc.sh 的
  #   nc_has_sysroot 注释里记过同一个坑：「自带 sysroot 时传 -I 反而
  #   打乱头文件解析顺序」。
  #
  #   -idirafter 把 NDK include 放到【所有系统路径之后】：
  #   宿主头优先（stdlib.h 用宿主那份），只有宿主找不到的
  #   android/log.h / jni.h / arm_acle.h 才落到 NDK 那份。这才是
  #   "宿主 clang + 少量 Android 头"想要的语义。
  HINC=("${INC[@]}")
  if [[ -n "$SYSINC" ]]; then
    HINC+=(-idirafter "$SYSINC")
    echo "  （宿主档 -idirafter NDK 头：$SYSINC）"
  else
    echo "  ⚠️ 没找到 NDK sysroot，宿主档可能因缺 android/log.h 而失败"
  fi
  for f in "${FILES[@]}"; do
    base="$(basename "$f")"
    if out=$("$HOST_CC" -c -O2 -Wall -Wextra -Werror \
               -DSIGCHECK_HOST_TEST "${HINC[@]}" -o /dev/null "$f" 2>&1); then
      ok "$base (host)"
    else
      bad "$base (host)"
      echo "$out" | grep -E "error:|warning:" | head -4 | sed 's/^/      /'
    fi
  done
fi

echo
echo "══════════════════════════════════════════════════"
echo "结果: $pass 通过, $fail 失败, $skip 跳过"
echo "══════════════════════════════════════════════════"
echo
echo "⚠️ 本门禁只保证【编译期无告警】，不等于行为正确。"
echo "   行为验证见 test-sig-verify / test-sig-guard2 / test-sigblock-bounds。"
[[ $fail -eq 0 ]] || exit 1
