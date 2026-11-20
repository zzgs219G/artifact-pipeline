#!/usr/bin/env bash
# uncheck.sh — 去签名校验总控（configs/v2 卡片的执行端）
#
# 契约：<输入.apk> <输出_未签名.apk> [选项]
#   --pms              PackageManager 接口层代理（核心能力）
#   --file-redirect    自读 APK 文件的重定向（当前未实现 → fail-fast）
#   --report           出包前体检
#
# 与 protect.sh 的关系：**完全独立的两条流水线**。
#   protect.sh  → 加固（加防御），7 个模块，走 configs/v1
#   uncheck.sh  → 去校验（拆防御），1 个模块，走 configs/v2
# 刻意不合并：
#   · 方向相反，合并后「勾 sigcheck 同时又勾 uncheck」是自相矛盾的配置；
#   · protect.sh 有 20+ 个参数与 NDK/Amice/nox 依赖，去校验一个都用不上；
#   · 合并会让 protect.sh 的 TOTAL 计数、联动校验全部要改，风险远大于收益。
#
# ⚠️ 与 protect.sh 的既有契约一致：产物【一律不签名】。
#   本脚本不接触 keystore，签名由使用者自行完成。
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ROOT="$(dirname "$(dirname "$_HERE")")"

WANT_PMS=0
WANT_FILE_REDIRECT=0
WANT_REPORT=0

log_info() { printf '\033[32m[uncheck]\033[0m %s\n' "$*"; }
log_warn() { printf '\033[33m[uncheck]\033[0m %s\n' "$*"; }
log_err()  { printf '\033[31m[uncheck]\033[0m %s\n' "$*" >&2; }

usage() {
  cat >&2 <<'EOF'
用法: uncheck.sh <输入.apk> <输出_未签名.apk> [--pms] [--file-redirect] [--report]

  --pms             PackageManager 接口层代理（核心能力，建议总是开）
  --file-redirect   自读 APK 文件重定向（当前未实现，仅保留参数位；schema 已移除该选项）
  --report          出包前体检，报告覆盖了哪些、哪些没覆盖
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
    --pms)           WANT_PMS=1; shift ;;
    --file-redirect) WANT_FILE_REDIRECT=1; shift ;;
    --report)        WANT_REPORT=1; shift ;;
    *) log_err "未知参数: $1"; usage ;;
  esac
done

if [[ $((WANT_PMS + WANT_FILE_REDIRECT)) -eq 0 ]]; then
  log_err "未启用任何实际手段（--pms / --file-redirect 至少选一个），产物不会改变校验行为"
  exit 1
fi

# ── 未实现的能力：fail-fast，不静默降级 ─────────────────────────────────
# 静默降级是这类工具最大的坑：用户以为覆盖了「自读 APK」的校验，
# 装上才发现没生效，而且没有任何提示。
if [[ $WANT_FILE_REDIRECT -eq 1 ]]; then
  log_err "--file-redirect 当前版本未实现。"
  log_err "  它需要：把原包副本打进产物 + 重定向 ApplicationInfo.sourceDir +"
  log_err "  可能的 native 文件系统 hook。相关设计见 scripts/uncheck/README.md。"
  log_err "  请先只用 --pms，或等该能力落地。"
  exit 1
fi

# ── 体检（可选）─────────────────────────────────────────────────────────
if [[ $WANT_REPORT -eq 1 ]]; then
  log_info "体检：扫描目标 App 的取签名途径"
  # scan.py 只读、不改；没有它不阻塞出包（但会明确告知降级）
  if [[ -f "$_HERE/scan.py" ]]; then
    python3 "$_HERE/scan.py" "$IN_APK" || {
      log_warn "体检失败（不影响出包，但覆盖情况未知）"
    }
  else
    log_warn "scan.py 不存在，跳过体检（本版尚未实现）"
  fi
fi

# ── 主体：注入载荷 ──────────────────────────────────────────────────────
log_info "注入签名伪造载荷"
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
    bad = [n for n in ('classes.dex',) if n not in names]
    if bad:
        print(f'❌ 产物缺 {bad}', file=sys.stderr)
        sys.exit(1)
    dex = z.read('classes.dex')

if dex[:4] != b'dex\n':
    print('❌ classes.dex magic 非法', file=sys.stderr)
    sys.exit(1)
ck, = struct.unpack_from('<I', dex, 8)
if ck != (zlib.adler32(dex[12:]) & 0xFFFFFFFF):
    print('❌ dex checksum 不自洽', file=sys.stderr)
    sys.exit(1)
if dex[12:32] != hashlib.sha1(dex[32:]).digest():
    print('❌ dex SHA-1 签名不自洽', file=sys.stderr)
    sys.exit(1)

payload = b'nc/uncheck/SigFix'
if payload not in dex:
    print('❌ dex 里找不到载荷类，注入未生效', file=sys.stderr)
    sys.exit(1)

print(f'✅ dex 结构合法，载荷在位，版本 {dex[4:7].decode()}')
PY

log_info "完成: $OUT_APK"
log_info "产物未签名 —— 请自行签："
log_info "  apksigner sign --ks <你的.jks> --out <最终.apk> $OUT_APK"
