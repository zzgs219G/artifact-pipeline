#!/usr/bin/env bash
# host-cc.sh — 选出【能在本机执行产物】的编译器（source 使用，不直接跑）
#
# ══ 为什么需要这个文件（2026-11-22）══════════════════════════════════
#
# 本仓库有一类测试叫「宿主端测试」：它们编译 C 代码成**本机可执行文件**，
# 然后真的跑起来验证逻辑（对拍密钥流、dlopen 取符号、UTF-8 编解码边界…）。
# 这类测试的产物必须在**当前机器上能执行**。
#
# 但 CI 里有个陷阱：`setup-toolchain` 为了让 jni.h / android/log.h 可达，
# 会把裸 `clang` 转发到 NDK 的 target 包装器（aarch64-linux-androidNN-clang）。
# 于是 `CC=clang` 编出来的是 **Android ARM 产物**，而 GitHub runner 是
# **x86_64** —— 编得出来，但跑不起来，断言全部拿到空字符串。
#
# 症状极具误导性：不是"编译失败"，而是"期望 X 实得 （空）"，
# 看起来像被测代码有 bug，实际是工具链选错了。2026-11-22 为这个
# 排查了整整一轮（327 项假红 → 1 项 → 184 项，逐个文件发现）。
#
# ══ 判据：可执行性，不是名字 ═════════════════════════════════════════
#
# 不能用 `basename $CC` 是否含 "android" 来判断 —— CI 的转发器就叫 `clang`。
# 唯一可靠的判据是：**编个最小程序跑一下**。跑得通才是宿主编译器。
#
# ══ 用法 ════════════════════════════════════════════════════════════
#
#   source "$(dirname "$0")/host-cc.sh"
#   CC="$(nc_pick_host_cc)" || { echo "跳过：无可用宿主编译器"; exit 0; }
#
#   # 需要 jni.h（只编译不执行）时另取一个：
#   NDK_CC="$(nc_pick_ndk_cc)"   # 没有 NDK 就回落成 CC
#
# 返回值打印到 stdout；失败返回非 0（调用方自行决定 skip 还是红）。

# nc_pick_host_cc — 打印一个能在本机执行的编译器名（clang/gcc/cc 里第一个可用的）
nc_pick_host_cc() {
    local d c
    d="$(mktemp -d)" || return 1
    # shellcheck disable=SC2064
    printf 'int main(void){return 0;}\n' > "$d/t.c" || { rm -rf "$d"; return 1; }
    for c in clang gcc cc; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" "$d/t.c" -o "$d/t" >/dev/null 2>&1 && "$d/t" >/dev/null 2>&1; then
            rm -rf "$d"
            echo "$c"
            return 0
        fi
    done
    rm -rf "$d"
    return 1
}

# nc_pick_ndk_cc — 打印一个带 Android sysroot 的编译器（找不到就打印宿主的）
#   优先 NDK target 包装器（自带 sysroot，无需 -I）；其次 $ANDROID_NDK_HOME 下的；
#   都没有则回落到 nc_pick_host_cc 的结果。
nc_pick_ndk_cc() {
    local c
    local roots=("${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}" "$HOME"/android-ndk-r*)
    for r in "${roots[@]}"; do
        [ -n "$r" ] || continue
        for c in "$r"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android[0-9]*-clang; do
            [ -x "$c" ] && { echo "$c"; return 0; }
        done
    done
    nc_pick_host_cc
}

# nc_has_sysroot <cc> — cc 能否不带 -I 直接编进 jni.h + stdlib.h
#   用于判断"要不要传 -I 指向 sysroot"：自带 sysroot 时传 -I 反而打乱
#   头文件解析顺序（stdlib.h 会从宿主取 → 报一堆看似无关的错）。
nc_has_sysroot() {
    local cc="${1:-clang}"
    printf '#include <jni.h>\n#include <stdlib.h>\n' \
        | "$cc" -x c -fsyntax-only - >/dev/null 2>&1
}
