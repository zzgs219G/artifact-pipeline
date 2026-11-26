#!/usr/bin/env bash
# uncheck.sh — 去签名校验总控（configs/v2 卡片的执行端）
#
# 契约：<输入.apk> <输出_未签名.apk> [--uncheck]
#
#   --uncheck   唯一的参数。存在即执行，不需要任何子开关 ——
#               用这条流水线就是要去校验，没有"要不要"的问题。
#
# 与 protect.sh 的关系：**完全独立的两条流水线**。
#   protect.sh  → 加固（configs/v1，7 个模块，需要 NDK/Amice/nox）
#   uncheck.sh  → 去校验（configs/v2，1 个动作，纯 Python）
# 刻意不合并：方向相反、依赖天差地别、失败面要隔离。
#
# ⚠️ 产物【一律不签名】。本脚本不接触 keystore。
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WANT_UNCHECK=0
JAVA_ONLY=0
HOOK_LEVEL=6

log_info() { printf '\033[32m[uncheck]\033[0m %s\n' "$*"; }
log_warn() { printf '\033[33m[uncheck]\033[0m %s\n' "$*"; }
log_err()  { printf '\033[31m[uncheck]\033[0m %s\n' "$*" >&2; }

usage() {
  cat >&2 <<'EOF'
用法: uncheck.sh <输入.apk> <输出_未签名.apk> --uncheck

  --uncheck       执行去校验（必填）
  --hook-level N  native hook 分层 1~6（默认 6，需 native 层生效）
                    1 核心(open/fopen/access/stat)
                    2 = 1 + at 家族 + readlink（防 fd 反查）
                    3 = 2（兼容旧值）
                    4 = 3 + openat2
                    5 = 4 + statx
                    6 = 5 + opendir（默认，覆盖最广）
  --java-only     只做 Java 层（不投放 libusign.so）
                  默认是「Java + native」两层。某些 App（尤其 WebView /
                  Capacitor / Flutter 类）被 native 层 libc 重定向影响后
                  会出现网络或图片加载失败 —— 那类 App 多半只用
                  PackageManager 校验，Java 层就够了。

  （原 --full-origin 全量副本参数已于 2026-11-24 移除：该分支从未被
    实现，恒走数据复用打包，见 docs/交接-2026-11-24.md §6.4）
EOF
  exit 2
}

if [[ $# -lt 2 ]]; then usage; fi

IN_APK="$1"; OUT_APK="$2"; shift 2
[[ -f "$IN_APK" ]] || { log_err "输入 APK 不存在: $IN_APK"; exit 1; }
IN_APK="$(cd "$(dirname "$IN_APK")" && pwd)/$(basename "$IN_APK")"
mkdir -p "$(dirname "$OUT_APK")"
OUT_APK="$(cd "$(dirname "$OUT_APK")" && pwd)/$(basename "$OUT_APK")"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uncheck) WANT_UNCHECK=1; shift ;;
    --java-only) JAVA_ONLY=1; shift ;;
    --hook-level) HOOK_LEVEL="${2:-}"; shift 2 ;;
    *) log_err "未知参数: $1"; usage ;;
  esac
done

if [[ $WANT_UNCHECK -eq 0 ]]; then
  log_err "缺少 --uncheck（这条流水线只有这一个动作，不加参数等于什么都不做）"
  exit 1
fi

if [[ $JAVA_ONLY -eq 1 ]]; then
  log_info "注入签名伪造载荷（仅 Java 层：不投放 libusign.so）"
  export USIGN_NO_NATIVE=1
else
  log_info "注入签名伪造载荷（Java + native 两层，hookLevel=$HOOK_LEVEL）"
  export USIGN_HOOK_LEVEL="$HOOK_LEVEL"
fi
python3 "$_HERE/run.py" "$IN_APK" "$OUT_APK"

# ── 产物自检（不签名，只验证结构合法）──────────────────────────────────
log_info "产物自检"
python3 - "$OUT_APK" <<'PY'
import hashlib
import struct
import sys
import zipfile
import zlib

apk = sys.argv[1]
with zipfile.ZipFile(apk) as z:
    names = z.namelist()
    dexes = sorted(n for n in names if n.startswith('classes') and n.endswith('.dex'))
    if not dexes:
        print('❌ 产物里没有任何 classes*.dex', file=sys.stderr)
        sys.exit(1)
    # 载荷分两部分，判据要分开：
    #   · 引导器类 SigFixApp 只在**新建**的 classesN.dex 里（不会被当调用点引用）
    #   · 调用点 Lcom/nc/uncheck/SigFix; 则插在**原** dex 里（必须在原 dex 才执行）
    # 早先只扫 'nc/uncheck/SigFix' 字符串会把调用点误判成载荷位置，
    # 报出「载荷在 classes.dex」——与实际相反（载荷必须在新 dex）。
    payload_in = None
    call_in = []
    for n in dexes:
        blob = z.read(n)
        if blob[:4] != b'dex\n':
            print(f'❌ {n} magic 非法', file=sys.stderr)
            sys.exit(1)
        ck, = struct.unpack_from('<I', blob, 8)
        if ck != (zlib.adler32(blob[12:]) & 0xFFFFFFFF):
            print(f'❌ {n} checksum 不自洽', file=sys.stderr)
            sys.exit(1)
        if blob[12:32] != hashlib.sha1(blob[32:]).digest():
            print(f'❌ {n} SHA-1 签名不自洽', file=sys.stderr)
            sys.exit(1)
        if b'com/nc/uncheck/SigFixApp' in blob and payload_in is None:
            payload_in = n
        if b'com/nc/uncheck/SigFix' in blob:
            call_in.append(n)

if payload_in is None:
    print('❌ 所有 dex 里都找不到引导器类 SigFixApp，注入未生效', file=sys.stderr)
    sys.exit(1)
if not call_in:
    print('❌ 没有任何 dex 含 SigFix 调用点，载荷不会被调用', file=sys.stderr)
    sys.exit(1)

print(f'✅ {len(dexes)} 个 dex 结构均合法')
print(f'   引导器载荷在 {payload_in}')
print(f'   调用点在 {", ".join(call_in)}')
print(f'   dex 清单: {", ".join(dexes)}')
PY

log_info "完成: $OUT_APK"
log_info "产物未签名 —— 请自行签："
log_info "  apksigner sign --ks <你的.jks> --out <最终.apk> $OUT_APK"
