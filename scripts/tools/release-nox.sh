#!/usr/bin/env bash
# release-nox.sh — nox 换版四件套一键化（2026-11-24）
#
# 把"换 tools/nox.zip"的手工流程收敛成一条命令。之前每步都要人工记得，
# 漏任何一步都是静默事故：
#   漏删 tools/nox/  → 静默用旧解压产物（ensure_nox 幂等靠文件存在判断）
#   漏同步登记表     → CI toolkit-version 红（或更糟：以前没这个断言时静默漂移）
#   忘跑消费方回归   → T34/so-lock 的红要等下一轮才发现
#
# 用法：
#   bash scripts/tools/release-nox.sh <nox仓库路径> [版本号]
#
#   版本号省略时从 ../nox/dist/ 里取最新的 zip。前置条件（本脚本会逐项检查）：
#     ① nox 仓库工作区干净
#     ② nox test.sh 全绿（0 失败）
#     ③ dist/ 里有打包产物（make-zip-lib.sh 已跑过；⚠️ 生产 zip 必须带
#        混淆——走 -obf tag 或设 AMICE_BUNDLE，见 AI接手文档 §9 的教训）
set -uo pipefail

NOX_REPO="${1:?用法: release-nox.sh <nox仓库路径> [版本号] | release-nox.sh --zip <zip路径>}"
# --zip 直传模式（2026-11-24 补）：CI 产物在 GitHub release 上，不在本地
# nox/dist/。此时跳过 ① ②（仓库状态/自测已有 CI 背书），只做
# ③(混淆检查) ④(换包) ⑤(同步) ⑥(回归)。
ZIP_DIRECT=""
if [ "$1" = "--zip" ]; then
    ZIP_DIRECT="${2:?--zip 需要 zip 路径}"
    NOX_REPO=""
fi
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

ok()   { echo "  ✅ $*"; }
bad()  { echo "  ❌ $*" >&2; FAILED=1; }
FAILED=0

if [ -n "$ZIP_DIRECT" ]; then
    echo "── ① ② 跳过（--zip 直传：CI 已跑过 test.sh）──"
    ZIP="$ZIP_DIRECT"
else
echo "── ① nox 仓库状态 ──"
cd "$NOX_REPO" || { bad "nox 仓库不存在: $NOX_REPO"; exit 1; }
if [ -n "$(git status --porcelain)" ]; then
    bad "nox 工作区不干净（先 commit）—— tag 必须打在干净树上"
else
    ok "工作区干净 ($(git log --oneline -1 | cut -c1-40))"
fi

echo "── ② nox 自测（0 失败判据）──"
if bash test.sh 2>&1 | grep -qE "失败: [1-9]"; then
    bad "test.sh 有失败——先修再发版"
else
    ok "test.sh 全绿"
fi
fi   # ← ZIP_DIRECT 的 if/else 收尾

echo "── ③ 分发产物 ──"
if [ -z "$ZIP_DIRECT" ]; then
    if [ -n "${2:-}" ]; then
        ZIP="$(ls dist/nox-"$2".zip 2>/dev/null | head -1)"
    else
        # ⚠️ dist/ 里存着历史产物，按文件名排序取"版本号最大"的，不按 mtime
        #    （mtime 是本地打包时间，重打旧版会骗过排序；版本号才是真相）
        ZIP="$(ls dist/nox-*.zip 2>/dev/null | sort -V | tail -1)"
    fi
fi
if [ -z "$ZIP" ] || [ ! -f "$ZIP" ]; then
    bad "dist/ 里没有产物——先跑: bash scripts/make-zip-lib.sh <版本号-obf>"
    bad "⚠️ 版本名必须带 -obf（或设 AMICE_BUNDLE），否则 .a 无混淆（v0.9.48 事故）"
    exit 1
fi
ok "产物: $ZIP ($(stat -c%s "$ZIP") B)"
# T34 同款判据：.a 混淆在位（.ncq 字节码 ≥10KB）
T=$(mktemp -d)
unzip -o -q "$ZIP" 'nox/so-guard/lib/arm64-v8a/libnox.a' -d "$T" 2>/dev/null
SZTOOL=""
for cand in "${ANDROID_NDK_HOME:-/nonexistent}"/toolchains/llvm/prebuilt/*/bin/llvm-size \
            "$(command -v llvm-size || true)" "$(command -v size || true)"; do
    [ -n "$cand" ] && [ -x "$cand" ] && { SZTOOL="$cand"; break; }
done
if [ -n "$SZTOOL" ]; then
    NCQ=$("$SZTOOL" -A "$T/nox/so-guard/lib/arm64-v8a/libnox.a" 2>/dev/null \
          | awk '/^\.ncq /{s+=$2} END {print s+0}')
    if [ "${NCQ:-0}" -ge 10000 ]; then
        ok ".a 混淆在位（.ncq ${NCQ} B）"
    else
        bad ".a 【无混淆】（.ncq ${NCQ:-0} B）—— 不可发布，回 nox 重打 -obf 版"
    fi
else
    echo "  ⚠️ 找不到 llvm-size（设 ANDROID_NDK_HOME 可查），跳过混淆检查（T34 会兜底）"
fi
rm -rf "$T"
[ "$FAILED" -eq 0 ] || { echo "前置检查未过，停止。"; exit 1; }

echo "── ④ 换包（拷 zip + 删旧解压产物）──"
cp "$ZIP" "$ROOT/tools/nox.zip" || exit 1
rm -rf "$ROOT/tools/nox"
ok "tools/nox.zip 已替换"

echo "── ⑤ 登记表自动同步 ──"
python3 "$ROOT/scripts/tools/sync-toolkit-version.py" "$ROOT/tools/nox.zip" || exit 1

echo "── ⑥ 消费方回归（T34 + so-lock 全套）──"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/android-ndk-r29-aarch64/android-ndk-r29}"
bash "$ROOT/scripts/lib/tests/test-so-lock.sh" 2>&1 | grep -E "T34|=== 结果" | sed 's/^/  /'

VER=$(unzip -p "$ROOT/tools/nox.zip" nox/VERSION)
echo
echo "✅ 四件套完成。剩下的收尾（人工）："
echo "   git add tools/nox.zip tools/工具包版本.md && git commit -m 'chore(tools): nox.zip → $VER'"
echo "   git push && 云端出包真机验证（touch 哨兵 → ncguard_log.md）"
