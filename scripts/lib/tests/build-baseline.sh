#!/usr/bin/env bash
# build-baseline.sh — 按生产参数构建 libnc.so，用于「搬目录前后逐字节对比」
#
# 为什么需要它：搬目录这种重构，唯一可信的验收标准是【产物字节不变】。
# 源码行数/函数名/注释都会变，只有二进制能证明「加密机制没被改动」。
#
# 固定输入（否则每次结果都不同，比对无意义）：
#   · 固定的 sig_hash.h（make-sig-hash.sh 每次 os.urandom(salt)，不固定则永远不等）
#   · 固定的 sig_log_data.h
#   · 生产同款 CFLAGS/LDFLAGS（取自 lib-ndk.sh）
#
# 用法：build-baseline.sh <输出.so> <设施源码目录> <模块源码目录>
set -uo pipefail
OUT="${1:?需要输出路径}"
GUARD_SRC="${2:?设施源码目录}"
MOD_SRC="${3:?模块源码目录}"
ROOT=$(cd "$(dirname "$0")" && pwd)
FIXTURE="$ROOT/fixtures"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# 扁平布局：与 protect.sh 拷进 NDK 工程后的形态一致（jni/ 下全部同级）
cp "$GUARD_SRC"/*.c "$GUARD_SRC"/*.h "$W"/ 2>/dev/null
cp "$MOD_SRC"/*.c "$MOD_SRC"/*.h "$W"/ 2>/dev/null

# 固定输入，保证可复现
cp "$FIXTURE/sig_hash.h" "$W/sig_hash.h"
cp "$FIXTURE/sig_log_data.h" "$W/sig_log_data.h"
[ -f "$FIXTURE/sig_guard2.h" ] && cp "$FIXTURE/sig_guard2.h" "$W/sig_guard2.h"

cd "$W" || exit 2

# 生产同款参数（对齐 lib-ndk.sh 的 LOCAL_CFLAGS / LOCAL_LDFLAGS）
CFLAGS="-fPIC -shared -fvisibility=hidden -fno-ident -Oz \
        -ffunction-sections -fdata-sections -DNC_GUARD_SECTIONED"
{ echo "{"; echo "  global:"; echo "    Java_com_nc_*;"; echo "  local:"; echo "    *;"; echo "};"; } > hide.map

clang $CFLAGS -I. \
    nc_guard_boot.c nc_guard_probe.c nc_guard_jni.c nc_guard_key.c \
    nc_guard_paths.c nc_link.c env_check.c sig_check.c \
    -Wl,--gc-sections -Wl,--build-id=none -Wl,--version-script=hide.map \
    -o out.so 2>build.log
rc=$?
if [ $rc -ne 0 ]; then
    echo "编译失败:" >&2
    head -20 build.log >&2
    exit $rc
fi

# 与生产链一致：先移除 .comment（objcopy 会重排段，必须在锁箱前）
if command -v objcopy >/dev/null 2>&1; then
    objcopy --remove-section=.comment out.so out2.so 2>/dev/null || cp out.so out2.so
else
    cp out.so out2.so
fi
mv out2.so "$OUT"
echo "构建完成: $OUT ($(stat -c%s "$OUT") 字节)"
