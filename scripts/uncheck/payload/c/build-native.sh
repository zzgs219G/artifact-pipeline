#!/usr/bin/env bash
# build-native.sh —— 编译 native 层 APK 路径重定向库
#
# 产物：payload/lib/libusign_{arm64,armv7}.so
#
# 依赖：Android NDK（含 clang）。可用 USIGN_NDK=<ndk 根目录> 覆盖。
#
# ==== 这一层解决什么 ====
# Java 层 hook（PackageInfo.CREATOR / PMS 代理 / signingInfo）只能拦
# "通过 PackageManager 问签名"的路径。目标 App 若绕开 PMS 自己读 APK：
#   · Java:   new ZipFile(getPackageResourcePath()) → META-INF/*.RSA
#   · native: open/fopen + fstat + mmap 解析 APK Signing Block（v2/v3）
# 就完全不生效。本库把 open/fopen 等的路径重定向到 origin.apk。
#
# ==== hook 框架：字节跳动 shadowhook（inline hook）====
# 选择理由：
#   · inline hook 比 PLT/GOT hook 覆盖面广（能拦 libc 内部直调）
#   · 维护活跃（Android 4.1~17），xhook 已多年停更
# 静态链入 libusign.so（不额外投放 libshadowhook.so），
# 避免目标 App 自带同名库时冲突。
#
# ⚠️ third_party/shadowhook/shadowhook.c 已打一处补丁：
#   原版 sh_linker_init() 失败 → init 整体报 errno 12 → hook 全部失效。
#   该函数只服务「自动 hook 后续新加载的 so」，本项目不需要
#   （目标 so 在 Application 初始化前已加载），已降级为警告。
#   HyperOS V816 / Android 16 上必需此补丁（linker 私有符号取不到）。
#
# ==== 为什么只 hook 路径类函数，不 hook fd 类 ====
# open 返回的 fd 指向 origin.apk 后，后续 fstat/mmap/read 自然正确。
# 反过来 hook fstat/mmap 需要在进程级维护 fd→path 映射，成本高且易出错。
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD="$(dirname "$_HERE")"                 # payload/
SH="$PAYLOAD/third_party/shadowhook"          # shadowhook 源码（已打补丁）
OUT="$PAYLOAD/lib"
SRC="$_HERE/usign_hook.c"

log_info() { printf '\033[32m[lib]\033[0m %s\n' "$*"; }
log_err()  { printf '\033[31m[lib]\033[0m %s\n' "$*" >&2; }

NDK_ROOT="${USIGN_NDK:-}"
if [ -z "$NDK_ROOT" ]; then
  # GitHub Actions (nttld/setup-ndk) 设 ANDROID_NDK_ROOT
  NDK_ROOT="${ANDROID_NDK_ROOT:-}"
fi
if [ -z "$NDK_ROOT" ]; then
  # Termux 本地：自动探测 ~/android-ndk-*
  for cand in "$HOME"/android-ndk-*/android-ndk-* "$HOME"/android-ndk-*/android-ndk "$HOME"/android-ndk-*; do
    [ -x "$cand/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" ] && { NDK_ROOT="$cand"; break; }
  done
fi
[ -n "$NDK_ROOT" ] || { log_err "找不到 NDK，设 USIGN_NDK=<ndk 根目录>"; exit 1; }
TC="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"
log_info "NDK: $NDK_ROOT"

[ -f "$SRC" ] || { log_err "缺源文件: $SRC"; exit 1; }
[ -d "$SH" ]  || { log_err "缺 shadowhook 源码: $SH"; exit 1; }

# 确认补丁在位（漏了会在 Android 16 上 errno 12）
grep -q 'PATCHED（USign）' "$SH/shadowhook.c" \
  || log_err "⚠️ shadowhook.c 的 linker mod 补丁不在，Android 16 上可能 init 失败"

mkdir -p "$OUT"

# $1=abi 名  $2=clang 前缀  $3=shadowhook 架构子目录
build_abi() {
  local abi="$1" cc="$2" arch="$3" api=21
  local work; work="$(mktemp -d)"

  log_info "编译 shadowhook 静态库 ($abi) ..."
  (
    cd "$SH"
    local files=()
    while IFS= read -r f; do files+=("$f"); done < <(
      ls *.c 2>/dev/null
      ls "arch/$arch"/*.c 2>/dev/null
      ls "arch/$arch"/*.S 2>/dev/null
      ls common/*.c 2>/dev/null
      ls third_party/*/*.c 2>/dev/null
    )
    [ "${#files[@]}" -gt 0 ] || { log_err "shadowhook 源文件为空"; exit 1; }
    local objs=()
    for f in "${files[@]}"; do
      local o="$work/sh_$(echo "$f" | tr '/' '_').o"
      "$TC/${cc}${api}-clang" -O2 -fPIC -c "$f" -o "$o" \
        -I. -Iinclude -I"arch/$arch" -Icommon \
        -Ithird_party/xdl -Ithird_party/bsd -Ithird_party/lss \
        || { log_err "编译失败: $f"; exit 1; }
      objs+=("$o")
    done
    "$TC/llvm-ar" rcs "$work/libshadowhook.a" "${objs[@]}"
  ) || { rm -rf "$work"; return 1; }

  log_info "链接 libusign ($abi) ..."
  "$TC/${cc}${api}-clang" -O2 -shared -fPIC \
      -o "$OUT/libusign_${abi}.so" \
      "$SRC" "$work/libshadowhook.a" \
      -I"$SH/include" -llog \
      -Wl,--exclude-libs,ALL \
      -Wl,-z,max-page-size=16384

  rm -rf "$work"
  local sz; sz=$(stat -c%s "$OUT/libusign_${abi}.so" 2>/dev/null || echo 0)
  log_info "✅ libusign_${abi}.so ($sz B)"
}

build_abi arm64 aarch64-linux-android    arm64
build_abi armv7 armv7a-linux-androideabi arm

# ── 自检 ──────────────────────────────────────────────────────────────
for abi in arm64 armv7; do
  f="$OUT/libusign_${abi}.so"
  [ -f "$f" ] || { log_err "产物缺失: $f"; exit 1; }
  if command -v nm >/dev/null 2>&1; then
    nm -D "$f" 2>/dev/null | grep -q Java_com_nc_uncheck_SigFix_nativeHookApkPath \
      || { log_err "$f 缺少 JNI 入口符号"; exit 1; }
    # shadowhook 用 --exclude-libs,ALL 静态链入 → 它的符号在 .symtab（本地）而非 .dynsym。
    # 用 nm（不加 -D）确认代码真的链进去了；只查 .dynsym 会误报。
    nm "$f" 2>/dev/null | grep -q "shadowhook_hook_sym_name" \
      || log_err "⚠️ $f 里找不到 shadowhook_hook_sym_name（静态库没链进去？）"
  fi
done
log_info "自检通过"
log_info "产物目录: $OUT/"
