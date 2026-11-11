#!/usr/bin/env bash
# measure-startup.sh — 测 APK 冷启动耗时（VMP 前后对比用）
#
# 用法: ./measure-startup.sh <包名> <Activity> [次数=10]
#        ./measure-startup.sh com.xixin.box .MainActivity 10
#
# 判据用 `am start -S -W` 的 TotalTime（进程启动→首帧），比 logcat 的
# Displayed 稳定、也不依赖 grep。
#
# ⚠️ 次数别低于 8。实测 A 组前 5 次是 187/200/212/221/253（看着像退化），
#    补到 13 次后中位数落到 184 —— 样本少会得出相反结论。
# ⚠️ 每次必须 force-stop（否则是热启动），且间隔 2~3s 让系统回收。
set -uo pipefail

PKG="${1:?用法: $0 <包名> <Activity> [次数]}"
ACT="${2:?}"
N="${3:-10}"
ACT="${ACT#.}"                       # 容忍传 ".MainActivity" 或 "MainActivity"
D="${ANDROID_SERIAL:-192.168.1.5:45435}"
ADB="${ADB:-adb}"
CMP="$PKG/.$ACT"

echo "=== 冷启动测试: $CMP  ($N 次) ==="

times=()
for i in $(seq 1 "$N"); do
  "$ADB" -s "$D" shell am force-stop "$PKG" >/dev/null 2>&1
  sleep 3
  t=$("$ADB" -s "$D" shell am start -S -W -n "$CMP" 2>/dev/null \
        | awk -F': ' '/TotalTime/{print $2; exit}')
  if [ -n "${t:-}" ]; then
    echo "  第 $i 次: ${t} ms"
    times+=("$t")
  else
    echo "  第 $i 次: 未抓到 TotalTime（Activity 名对么？）"
  fi
  sleep 2
done

echo
if [ ${#times[@]} -eq 0 ]; then
  echo "全部失败，无数据" >&2
  exit 1
fi

printf '%s\n' "${times[@]}" | sort -n | awk '
  { a[NR]=$1; s+=$1 }
  END {
    m = (NR % 2) ? a[(NR+1)/2] : (a[NR/2] + a[NR/2+1]) / 2
    printf "  n=%d  min=%d  中位数=%.1f  mean=%.1f  max=%d ms\n", NR, a[1], m, s/NR, a[NR]
  }'
