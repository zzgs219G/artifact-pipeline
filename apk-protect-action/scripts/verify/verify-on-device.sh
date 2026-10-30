#!/usr/bin/env bash
# verify-on-device.sh —— 真机冒烟验证（dpt-shell 产物）
#
# 目的：把"装机 → 启动 → 抓日志 → 判断死在哪一层"自动化，
#       替代人工截图 + 逐条翻 logcat。
#
# 用法：
#   scripts/dev/verify-on-device.sh <apk> [--device <host:port>] [--pkg <包名>]
#                                    [--activity <.MainActivity>] [--expect-dpt-only]
#
# 示例：
#   scripts/dev/verify-on-device.sh ~/简盒/app_signed.apk --device 192.168.1.5:39963
#
# 退出码：
#   0  通过（进程存活 + 三条链判据全过）
#   1  启动失败 / 崩溃
#   2  参数或环境错误（adb 缺、设备未连、APK 不存在）
#
# 判据来自 docs/基线-v1.3.2-真机验证.md §3：
#   ① [kl] ... derive_rc=0        —— 派生链成功
#   ② 无 "config:" 开头的错误      —— 配置链成功
#   ③ 无 materializeBlock 失败     —— 载荷链成功
set -uo pipefail

APK=""
DEVICE=""
PKG="com.xixin.box"
ACTIVITY=".MainActivity"
WAIT_SEC=12
DPT_ONLY=0

die() { echo "❌ $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --device)   DEVICE="$2"; shift 2 ;;
    --pkg)      PKG="$2"; shift 2 ;;
    --activity) ACTIVITY="$2"; shift 2 ;;
    --wait)     WAIT_SEC="$2"; shift 2 ;;
    --expect-dpt-only) DPT_ONLY=1; shift ;;
    -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
    -*)         die "未知参数: $1" ;;
    *)          APK="$1"; shift ;;
  esac
done

[[ -n "$APK" ]] || die "缺少 APK 路径（--help 看用法）"
[[ -f "$APK" ]] || die "APK 不存在: $APK"
adb version >/dev/null 2>&1 || die "找不到 adb（不在 PATH）"

# ── 前置检查：本脚本只适用于 packer 产物 ─────────────────────────────
#
# 为什么必须检查：全模块但不勾 packer 的产物**不是壳包**，
# 没有壳 so → 不会打 [kl] 日志 → 会被判成"派生链失败"。
# 那是假阳性，会把人引向错误方向（实测：我第一版就漏了这个检查）。
if ! unzip -l "$APK" 2>/dev/null | grep -q 'assets/xixin/.*/libxixin\.so'; then
  echo "⚠️  这不是 dpt 加壳产物（无 assets/xixin/*/libxixin.so）" >&2
  echo "   本脚本只适用于【勾了 packer】的产物。" >&2
  echo "   若你想验证的是 sigcheck/dex2c/stringenc 组合，请改用：" >&2
  echo "     scripts/dev/identify-combo.sh <apk>    # 先确认它是什么组合" >&2
  exit 2
fi

# ── 设备 ─────────────────────────────────────────────────────────────
if [[ -n "$DEVICE" ]]; then
  echo "▶ 连接设备 $DEVICE"
  adb connect "$DEVICE" >/dev/null 2>&1 || true
  export ANDROID_SERIAL="$DEVICE"
fi

STATE="$(adb get-state 2>/dev/null || true)"
[[ "$STATE" == "device" ]] || die "设备未就绪（adb get-state=$STATE）。跑 adb devices 看看。"

echo "▶ 设备: $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')" \
     "/ Android $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')" \
     "/ $(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"

# ── 安装 ─────────────────────────────────────────────────────────────
echo "▶ 安装 $(basename "$APK")"
INSTALL_OUT="$(adb install -r "$APK" 2>&1)"
if ! grep -qi "Success" <<<"$INSTALL_OUT"; then
  echo "$INSTALL_OUT" >&2
  die "安装失败"
fi

# ── 启动 ─────────────────────────────────────────────────────────────
adb logcat -c 2>/dev/null || true
echo "▶ 启动 $PKG/$ACTIVITY"
adb shell am start -n "$PKG/$ACTIVITY" >/dev/null 2>&1 || true

# am start -W 会等启动完成；这里额外等到 WAIT_SEC 秒或进程出现
for _ in $(seq 1 "$WAIT_SEC"); do
  sleep 1
  if adb shell pidof "$PKG" >/dev/null 2>&1; then break; fi
done

sleep 3   # 给 init_array / JNI_OnLoad / 首帧留时间
LOG="$(adb logcat -d 2>/dev/null || true)"
PID="$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')"

# ── 判定 ─────────────────────────────────────────────────────────────
FAILED=0
note() { printf '  %s %s\n' "$1" "$2"; }

echo
echo "── 判据 ──"

# ① 派生链
if grep -q '\[kl\] .*derive_rc=0' <<<"$LOG"; then
  SEEDLINE="$(grep -m1 '\[kl\] ' <<<"$LOG" | sed 's/.*\[kl\] /[kl] /')"
  note "✅" "派生链：$SEEDLINE"
else
  if grep -q '\[kl\] ' <<<"$LOG"; then
    note "❌" "派生链失败：$(grep -m1 '\[kl\] ' <<<"$LOG" | sed 's/.*\[kl\] /[kl] /')"
  else
    note "❌" "派生链：完全没有 [kl] 日志（so 可能未加载 / 未走 init_array）"
  fi
  FAILED=1
fi

# ② 配置链
if grep -qE 'E dpt_native: config:' <<<"$LOG"; then
  note "❌" "配置链失败：$(grep -m1 -E 'E dpt_native: config:' <<<"$LOG" | sed 's/.*config:/config:/')"
  FAILED=1
else
  note "✅" "配置链：无错误"
fi

# ③ 载荷链
if grep -q 'materializeBlock' <<<"$LOG"; then
  note "❌" "载荷链失败：$(grep -m1 'materializeBlock' <<<"$LOG" | sed 's/.*materializeBlock/materializeBlock/')"
  FAILED=1
else
  note "✅" "载荷链：无 inflate 失败"
fi

# ④ JNI 注册（v1.2.8 曾卡在这里）
if grep -q 'java_class == null' <<<"$LOG"; then
  note "❌" "JNI 注册失败：java_class == null"
  FAILED=1
else
  note "✅" "JNI 注册：正常"
fi

# ⑤ 进程存活（最终判据）
if [[ -n "$PID" ]]; then
  note "✅" "进程存活：pid=$PID"
else
  note "❌" "进程已退出（崩溃）"
  CRASH="$(grep -m1 -E 'FATAL EXCEPTION|Fatal signal|Abort message' <<<"$LOG" || true)"
  [[ -n "$CRASH" ]] && note "  " "$CRASH"
  FAILED=1
fi

# ⑥ 可选：确认这次是「只勾 dpt」还是「全模块」
#
# 判据为什么用 APK 内容而不是 logcat：stringenc 的桩类名每包随机，
# 且桩会被搬进壳 dex，logcat 里看不到类名。可靠的办法是查壳 dex 里有没有
# 壳自己的 JniBridge（dpt 必有）+ 有没有 dex2c 的产物特征。
if [[ "$DPT_ONLY" == "1" ]]; then
  MODULE_HINT="$(unzip -p "$APK" classes.dex 2>/dev/null | strings 2>/dev/null       | grep -cE 'Lcom/nc/strdec|strdec' || true)"
  if [[ "${MODULE_HINT:-0}" -gt 0 ]]; then
    note "⚠️ " "--expect-dpt-only：壳 dex 里检出 stringenc 痕迹（$MODULE_HINT 处），组合可能不是纯 dpt"
  else
    note "✅" "--expect-dpt-only：壳 dex 无 stringenc 痕迹，符合纯 dpt 组合"
  fi
fi

# ── 结论 ─────────────────────────────────────────────────────────────
echo
if [[ "$FAILED" == "0" ]]; then
  echo "✅ PASS —— 三条链全部正常，进程存活"
  exit 0
fi

echo "❌ FAIL —— 详见上方判据"
echo
echo "最近 30 行 dpt/jni 相关日志："
grep -E 'dpt_native|dpt-|\[kl\]|materializeBlock|derive|config:' <<<"$LOG" | tail -30 | sed 's/^/  /'
exit 1
