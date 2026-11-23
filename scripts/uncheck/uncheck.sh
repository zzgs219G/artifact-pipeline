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
FULL_ORIGIN=0

log_info() { printf '\033[32m[uncheck]\033[0m %s\n' "$*"; }
log_warn() { printf '\033[33m[uncheck]\033[0m %s\n' "$*"; }
log_err()  { printf '\033[31m[uncheck]\033[0m %s\n' "$*" >&2; }

usage() {
  cat >&2 <<'EOF'
用法: uncheck.sh <输入.apk> <输出_未签名.apk> --uncheck [--full-origin]

  --uncheck       执行去校验（必填）
  --full-origin   origin.apk 用全量副本（回退方案，体积翻倍但兼容性最好）
                  默认走最小化（只留签名块，约 4KB）
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
    --full-origin) FULL_ORIGIN=1; shift ;;
    *) log_err "未知参数: $1"; usage ;;
  esac
done

if [[ $WANT_UNCHECK -eq 0 ]]; then
  log_err "缺少 --uncheck（这条流水线只有这一个动作，不加参数等于什么都不做）"
  exit 1
fi

log_info "注入签名伪造载荷"
if [[ "${FULL_ORIGIN:-0}" -eq 1 ]]; then
  python3 "$_HERE/run.py" "$IN_APK" "$OUT_APK" --full-origin
else
  python3 "$_HERE/run.py" "$IN_APK" "$OUT_APK"
fi

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
    # 载荷在新建的 dex 里（inject.py 强制 n+1），扫所有 dex 找它
    found_in = None
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
        if b'nc/uncheck/SigFix' in blob and found_in is None:
            found_in = n

if found_in is None:
    print('❌ 所有 dex 里都找不到载荷类，注入未生效', file=sys.stderr)
    sys.exit(1)

print(f'✅ {len(dexes)} 个 dex 结构均合法，载荷在 {found_in}')
print(f'   dex 清单: {", ".join(dexes)}')
PY

log_info "完成: $OUT_APK"
log_info "产物未签名 —— 请自行签："
log_info "  apksigner sign --ks <你的.jks> --out <最终.apk> $OUT_APK"
