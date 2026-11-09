#!/usr/bin/env bash
# identify-combo.sh —— 判断一个 APK 来自哪个模块组合
#
# 为什么本脚本在 apk-protect-action 而不是 dpt-shell：
#   模块组合（勾哪些）由本仓库的 protect.sh 决定；dpt-shell 只是被调用的
#   上游工具，它只要最终走了 --packer 就按同一路径处理，不关心上游勾了什么。
#
# 为什么需要判断组合：不同组合的**故障定位路径完全不同**。
#   脚本挂了时，先知道自己在验什么，才不会往错方向查。
#
# 用法：
#   scripts/verify/identify-combo.sh <apk>
#
# 退出码：0 总是（信息查询，不是断言）
set -uo pipefail

APK="${1:-}"
[[ -n "$APK" ]] || { echo "用法: $0 <apk>" >&2; exit 2; }
[[ -f "$APK" ]] || { echo "❌ APK 不存在: $APK" >&2; exit 2; }
command -v unzip >/dev/null 2>&1 || { echo "❌ 需要 unzip" >&2; exit 2; }

TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT
LIST="$TMPD/entries.txt"
unzip -l "$APK" > "$LIST" 2>/dev/null || { echo "❌ 无法读取 APK 条目" >&2; exit 2; }

# ⚠️ 不要写 `unzip -l ... | grep -q`：grep -q 命中即退出 → SIGPIPE 杀掉
# unzip → 整条管道判失败（实测踩过，全模块包被判成"不是壳包"）。
has() { grep -qE "$1" "$LIST"; }
cnt() { grep -cE "$1" "$LIST" || true; }

echo "APK: $(basename "$APK")"
echo "大小: $(du -h "$APK" | cut -f1)"
echo

# ── 判据 ─────────────────────────────────────────────────────────────
# packer 独有：壳 so / 加密配置 / 载荷 / Manifest 改 Proxy*
XIXIN_SO=$(cnt 'assets/xixin/[^/]+/libxixin[.]so')
XIXIN_CFG=$(cnt 'assets/xixin_config')
XIXIN_DATA=$(cnt 'assets/xixin_data')

# 其他模块产物
LIBNC=$(cnt 'lib/[^/]+/libnc[.]so')          # sigcheck / dex2c / envcheck

# Manifest 是否被改成壳入口
PK_MANIFEST=0
if unzip -p "$APK" AndroidManifest.xml >"$TMPD/mf" 2>/dev/null; then
  if strings "$TMPD/mf" 2>/dev/null | grep -qE 'ProxyApplication|ProxyComponentFactory'; then
    PK_MANIFEST=1
  fi
fi

# stringenc 解密桩：用桩骨架的结构不变量。
# ⚠️ 不能靠类名——桩类名每包随机（实测全模块产物 grep -c strdec = 0）。
STRDEC=0
# ── stringenc 判据：两种桩实现要分别识别（2026-11-09）──────────────
# 为什么旧判据不够：它靠 `strings | grep GAMMA|keyByte|mix64` 认 Java 桩。
# 而 native 桩（--stringenc-native）【刻意】让这些常量不出现在 dex ——
# 算法在 libnc.so 的 .ncx 里。旧判据会把 native 桩产物误判成"没有 stringenc"，
# 进而把整个组合判错（真机上就会被引向错误方向查问题）。
#
#   JAVA 桩：dex 里能找到 GAMMA/keyByte/mix64（算法在 dex）
#   NATIVE 桩：dex 里能找到 nc-strdec-native 标记 + ncDec/ncSetKey 调用，
#              且【找不到】GAMMA/keyByte/mix64（这恰恰是它的正确形态）
STRDEC=0
STRDEC_IMPL=""
if unzip -p "$APK" classes.dex >"$TMPD/dex" 2>/dev/null; then
  if strings "$TMPD/dex" 2>/dev/null | grep -E 'GAMMA|keyByte|mix64' >/dev/null; then
    STRDEC=1; STRDEC_IMPL="java"
  elif strings "$TMPD/dex" 2>/dev/null | grep -qE 'nc-strdec-native|ncSetKey'; then
    STRDEC=1; STRDEC_IMPL="native"
  fi
fi

echo "── 判据 ──"
printf '  assets/xixin/*/libxixin.so : %s   ← packer 独有\n' "$XIXIN_SO"
printf '  assets/xixin_config        : %s   ← packer 独有\n' "$XIXIN_CFG"
printf '  assets/xixin_data          : %s   ← packer 独有\n' "$XIXIN_DATA"
printf '  Manifest 改 Proxy*         : %s   ← packer 独有\n' "$PK_MANIFEST"
printf '  lib/*/libnc.so             : %s   ← sigcheck / dex2c / envcheck\n' "$LIBNC"
printf '  stringenc 解密桩           : %s%s\n' "$STRDEC" \
  "${STRDEC_IMPL:+（实现: $STRDEC_IMPL）}"

IS_PACKER=0
[[ "$XIXIN_SO" -gt 0 && "$XIXIN_CFG" -gt 0 ]] && IS_PACKER=1

# ── 判定 ─────────────────────────────────────────────────────────────
echo
echo "── 判定 ──"
if [[ "$IS_PACKER" -eq 0 ]]; then
  if [[ "$LIBNC" -eq 0 && "$STRDEC" -eq 0 ]]; then
    echo "→ **未加壳，也无模块产物**"
    echo "  可能是原始 APK，或 protect.sh 未成功执行（看 build.log）。"
  elif [[ "$STRDEC" -eq 1 ]]; then
    if [[ "$STRDEC_IMPL" == "native" ]]; then
      echo "→ **字符串加密（纯 C 桩）+ 部分模块，不勾 packer**"
      echo "  预期：加载 libnc.so；字符串由 so 里的 ncDec 解密。"
      echo "  ⚠️ dex 里【不该】出现 GAMMA/keyByte/mix64 —— 那是正确形态"
      echo "     （算法在 .ncx，不在 dex）。若在 dex 里搜到，说明段标记没生效。"
    else
      echo "→ **全模块但不勾 packer**（guard/dex2c/stringenc/envcheck，无壳）"
      echo "  预期：没有 [kl] 日志（壳 so 不存在）；桩仍在业务 dex 里。"
      echo "  测试重点：桩能否正常解字符串（纯 Java，不依赖 so）。"
    fi
    echo "  ⚠️ 这不是壳包：无 .bitcode / 配置 / 载荷抽取，业务 dex 未抽取。"
    echo
    echo "  ⚠️ 用 verify-on-device.sh 跑它会因「无 [kl] 日志」判 FAIL ——"
    echo "     那是**预期的**，不是缺陷。"
  else
    echo "→ **部分模块，不勾 packer**（有 libnc.so，无 stringenc 桩）"
    echo "  常见：仅 sigcheck / 仅 dex2c / sigcheck+dex2c。"
    echo "  预期：没有 [kl] 日志。"
  fi
  exit 0
fi

if [[ "$LIBNC" -gt 0 && "$STRDEC" -eq 1 ]]; then
  echo "→ **全模块（packer + stringenc↔dex2c 联动）**"
  echo "  预期：启动加载 libnc.so；[kl] derive_rc=0；"
  echo "        桩的 SEED 来自 JniBridge.gseed()（壳提供）。"
elif [[ "$LIBNC" -eq 0 && "$STRDEC" -eq 0 ]]; then
  echo "→ **只勾 packer（dpt）**"
  echo "  预期：[kl] derive_rc=0；无 libnc.so 加载。"
  echo "  价值：dpt 自身缺陷在此组合就能复现，与联动无关。"
else
  echo "→ **packer + 部分模块**（libnc=$LIBNC, strdec=$STRDEC）"
fi

# ── 壳载荷强度 ───────────────────────────────────────────────────────
echo
echo "── 壳载荷 ──"
if unzip -o -q "$APK" 'assets/xixin_data' -d "$TMPD" 2>/dev/null \
   && [[ -f "$TMPD/assets/xixin_data" ]]; then
  python3 - "$TMPD/assets/xixin_data" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
try:
    m, v, dc, co, bo, bc, r = struct.unpack_from('<IHHIIII', d, 0)
except struct.error:
    print("  ❌ xixin_data 太短"); raise SystemExit
if m != 0x4F4F4F35:
    print(f"  ❌ magic 不符 0x{m:08x}"); raise SystemExit
print(f"  version={v} dexCount={dc} blockCount={bc} size={len(d)}")
print(f"  含义：{bc} 个载荷块（业务指令已抽取并加密）")
PY
else
  echo "  无 xixin_data（--plain 模式，未抽取指令）"
fi

echo
echo "── 下一步 ──"
echo "  壳包    → scripts/verify/verify-on-device.sh <apk> --device <host:port>"
echo "  非壳包  → 看 build.log，重点在 stringenc/dex2c 自身"
