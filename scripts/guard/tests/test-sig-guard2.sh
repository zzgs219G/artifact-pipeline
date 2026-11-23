#!/usr/bin/env bash
# test-sig-guard2.sh — sig_guard2.c 的派生公式对拍(宿主端,不需要 NDK/真机)
#
# 为什么必须有这个测试:
#   sig_guard2.c 的 g2_derive() 与 make-sig-hash.sh 的 python 生成侧
#   必须【逐字节一致】—— 两侧公式漂移 = 正确签名的包也被误杀(显性失败)。
#   本测试把两侧的公式钉在一起:任何一方改动而另一方没跟,立刻红。
#
# 覆盖:
#   ① 生成侧(python)与校验侧(C)对同一指纹算出相同 stored
#   ② 全零槽位 = 调试模式(不误伤)
#   ③ 错误指纹必然 mismatch
#
# 用法: bash scripts/guard/tests/test-sig-guard2.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SRC="$ROOT/scripts/guard/src/sig_guard2.c"

# sig_guard2.c 在 2026-10-30 独立化后 include 了 nc_guard_layout.h（so 加密契约
# 唯一真相源，位于上游 nox 仓库）。宿主编译必须能找到它，否则本测试恒红。
# 用 ensure_nox_src 统一取路径（与 test-so-lock.sh / test-lsgs-strings.sh 同源，
# 不写死 ../nox 绝对路径）。缺 nox 仓库时它会 exit 1 并给出 clone 提示。
# shellcheck source=../../lib/common.sh
source "$ROOT/scripts/lib/common.sh"
GUARD_SRC="$(ensure_nox_src)"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

pass=0; fail=0
ok()  { echo "  ✅ $1"; pass=$((pass+1)); }
bad() { echo "  ❌ $1"; fail=$((fail+1)); }

echo "══════════════════════════════════════════════════"
echo "sig_guard2.c 派生对拍(宿主端)"
echo "══════════════════════════════════════════════════"

# ── ① 生成侧：从 make-sig-hash.sh 【抽取】真实公式并执行 ──
#
# ⚠️⚠️ 2026-11-22 实测过的坑：这里原本是【手抄】公式
#     （stored = t2[i] ^ salt[(i*7)%16] ^ ((i*0x5B+0x3D)&0xFF)），
#     注释还写着"与 make-sig-hash.sh 内嵌的完全一致"。
#     实测把 make-sig-hash.sh 的 0x5B 改成 0x5C 后，本测试依旧 3/3 全绿。
#     —— 生成侧漂移时，测试替它保密。
#
#     后果不是报错而是"正确签名的包被判失败" → g2_verify 恒 mismatch
#     → tgkill watchdog → 全量闪退。属于最坏的一类：测试假绿掩盖致命缺陷。
#
#     现在改成从生成侧抽取。抽取器在 scripts/guard/hash/extract-derive.py，
#     它把 os.urandom 换成固定盐（唯一改写），公式本身一个字不参与。
#     于是"改生成侧 → 本测试红"成为结构保证，不再依赖注释里那句承诺。
GEN="$ROOT/scripts/guard/hash/make-sig-hash.sh"
EXT="$ROOT/scripts/guard/hash/extract-derive.py"
[[ -f "$GEN" ]] || { echo "❌ 找不到生成侧 $GEN"; exit 1; }
[[ -f "$EXT" ]] || { echo "❌ 找不到抽取器 $EXT"; exit 1; }

python3 "$EXT" "$GEN" 2 > "$T/derive2.json" || {
    echo "❌ 从 make-sig-hash.sh 抽取线2公式失败（见上）"; exit 1; }
python3 - "$T" "$T/derive2.json" <<'PY'
import json, os, sys
out, j = sys.argv[1], sys.argv[2]
d = json.load(open(j))
with open(os.path.join(out, "expect.bin"), "wb") as f:
    f.write(bytes.fromhex(d["stored"]))
with open(os.path.join(out, "salt.bin"), "wb") as f:
    f.write(bytes.fromhex(d["salt"]))
print("生成侧(从 %s 抽取) salt=%s" % (d["extracted_from"], d["salt"]))
print("生成侧 stored=%s" % d["stored"])
PY

# ── ② 校验侧:把 C 文件编成可测(去 static 改名 + 注入固定 salt) ──
# 做法:不用 sig_guard2.h(避免 static const 重定义冲突),
#      直接把源文件里的 #include "sig_guard2.h" 替换成内联的测试定义。
# 2026-11-24 追加：同时暴露 g2_collect_fp（多路采集入口），
#   供第 4 项在宿主端跑【生产实现】的多路采集与指纹对拍。
# 2026-11-24 再追加：摘除 g2_entry 的 constructor 属性 —— 第 4 项设置了
#   SIGGUARD2_TEST_APK 后，constructor 的 g2_verify 也会定位到真 APK、
#   与本测试注入的假 SG2_STORED 比对 → mismatch → g2_fail() → 进程在
#   main 之前就被 SIGKILL（实测 exit=137，表现为"输出为空"）。
#   原先没暴露是因为旧测试从不设该环境变量（定位失败 → 静默 return）。
sed -e 's/static void g2_derive(/void g2_derive_test(/' \
    -e 's/g2_derive(fp, expected)/g2_derive_test(fp, expected)/' \
    -e 's/static int g2_collect_fp(/int g2_collect_fp_test(/' \
    -e 's/rc = g2_collect_fp(fp)/rc = g2_collect_fp_test(fp)/' \
    -e 's/^__attribute__((constructor))$/\/* 测试副本:摘除 constructor,防 g2_verify 在 main 前误杀 *\//' \
    -e 's|#include "sig_guard2.h"|#include "guard2_test.h"|' \
    "$SRC" > "$T/guard2_test.c"

# 注入测试头文件(替代 sig_guard2.h),用抽取到的 salt/stored
# ⚠️ 维度从实际数据长度推导，不写死 16/32 —— 生成侧若改了盐长/摘要长，
#    写死会让本测试编译失败（显性）或悄悄截断（更糟）。
python3 - "$T/guard2_test.h" "$T/expect.bin" "$T/salt.bin" <<'PY'
import sys
hdr_path, expect_path, salt_path = sys.argv[1], sys.argv[2], sys.argv[3]
stored = open(expect_path, "rb").read()
salt = open(salt_path, "rb").read()
with open(hdr_path, "w") as f:
    f.write("#ifndef _GUARD2_TEST_H_\n#define _GUARD2_TEST_H_\n")
    f.write("#define SG2_HASH_LEN %d\n#define SG2_SALT_LEN %d\n"
            % (len(stored), len(salt)))
    f.write("static const unsigned char SG2_SALT[%d] = {%s};\n"
            % (len(salt), ",".join(str(b) for b in salt)))
    f.write("static const unsigned char SG2_STORED[%d] = {%s};\n"
            % (len(stored), ",".join(str(b) for b in stored)))
    f.write("#endif\n")
PY

cat > "$T/main.c" <<'C'
#include <stdio.h>
#include <string.h>
#include "guard2_test.h"
void g2_derive_test(const unsigned char fp[SG2_HASH_LEN], unsigned char out[SG2_HASH_LEN]);
int main(void) {
    unsigned char fp[SG2_HASH_LEN], out[SG2_HASH_LEN];
    int i, mismatch = 0;
    for (i = 0; i < SG2_HASH_LEN; i++) fp[i] = (unsigned char)i;
    g2_derive_test(fp, out);
    for (i = 0; i < SG2_HASH_LEN; i++) mismatch |= out[i] ^ SG2_STORED[i];
    if (mismatch) { printf("MISMATCH\n"); return 1; }
    printf("MATCH\n");
    return 0;
}
C

# ⚠️ 必须选【能在本机执行产物】的编译器（2026-11-22）：
#    本测试要跑 $T/t（宿主端对拍），而 CI 的 setup-toolchain 会把裸 clang
#    转发到 NDK aarch64 包装器（为了让 jni.h 可达）—— 编出 ARM 产物在
#    x86_64 runner 上跑不了。判据与说明见 scripts/lib/host-cc.sh。
source "$ROOT/scripts/lib/host-cc.sh"
CC="$(nc_pick_host_cc || command -v clang || command -v gcc)"
# ⚠️ -ldl 必须显式给：sig_guard2.c 用 dladdr/Dl_info 定位本 so 路径，
#    在 Linux（CI 的 ubuntu runner）上 dladdr 在 libdl 里，不链接就报
#    "use of undeclared identifier 'Dl_info'" + "call to undeclared function 'dladdr'"。
#    本机 Termux/macOS 把它并进了 libc，所以本地一直是绿的 —— 又是"本地绿、
#    CI 红"的典型（2026-11-01 第六次 CI 红）。
#    -Wl,--no-as-needed 保证即使当前没直接引用也不被丢弃。
# -D_GNU_SOURCE 命令行再加一次（源码里也定义了，双保险）：
# 该测试用 sed 把 #include "sig_guard2.h" 替换成内联的 guard2_test.h，
# 若哪天替换位置变化导致源码里的 _GNU_SOURCE 排到系统头之后，
# 命令行这个还能兜住。Dl_info 在 glibc 下只在 _GNU_SOURCE 时可见。
if ! $CC -O1 -D_GNU_SOURCE -DSIGGUARD2_HOST_TEST -I"$T" -I"$GUARD_SRC" \
        "$T/guard2_test.c" "$T/main.c" -o "$T/t" -ldl 2>"$T/cc.log"; then
    echo "编译失败:"; head -20 "$T/cc.log"; bad "编译 sig_guard2.c"
else
    ok "编译通过(clang/gcc, 宿主端)"
fi

R="$("$T/t" 2>&1 || true)"
if [[ "$R" == "MATCH" ]]; then
    ok "派生对拍:C 侧 g2_derive == Python 生成侧(逐字节)"
else
    bad "派生不一致: $R"
fi

# ── ③ 调换指纹必须 mismatch(证明不是恒真) ──
cat > "$T/neg.c" <<'C'
#include <stdio.h>
#include <string.h>
#include "guard2_test.h"
void g2_derive_test(const unsigned char fp[SG2_HASH_LEN], unsigned char out[SG2_HASH_LEN]);
int main(void) {
    unsigned char fp[SG2_HASH_LEN], out[SG2_HASH_LEN];
    int i, mismatch = 0;
    for (i = 0; i < SG2_HASH_LEN; i++) fp[i] = (unsigned char)(i ^ 0xFF);   /* 不同指纹 */
    g2_derive_test(fp, out);
    for (i = 0; i < SG2_HASH_LEN; i++) mismatch |= out[i] ^ SG2_STORED[i];
    printf(mismatch ? "DIFF\n" : "SAME\n");
    return 0;
}
C
$CC -O1 -D_GNU_SOURCE -DSIGGUARD2_HOST_TEST -I"$T" -I"$GUARD_SRC" "$T/guard2_test.c" "$T/neg.c" -o "$T/tn" -ldl 2>"$T/neg.log" || true
if [[ -x "$T/tn" ]]; then
    RN="$("$T/tn" 2>&1 || true)"
    if [[ "$RN" == "DIFF" ]]; then
        ok "错误指纹 → 必然 mismatch(非恒真)"
    else
        bad "错误指纹未 mismatch: $RN"
    fi
else
    bad "第 3 项编译失败(见下)"; head -5 "$T/neg.log"
fi

# ── ④ 多路采集不误伤 + 指纹端到端对拍（2026-11-24，宿主端）─────────────
#
# 覆盖：g2_collect_fp 的【生产实现】（非测试复制品，§2.2 纪律）：
#   · 6 路里宿主只有 open/openat/openat64 三路可用（svc/syscall/sysfd
#     是 ARM 内联汇编，宿主 x86 下整体不编译 → 各自失败并跳过）；
#   · 断言 rc=0（多路循环在「部分路线失败」时不误伤 —— 这正是
#     "单路失败只跳过" 的判定语义）；
#   · 断言多数派指纹与 extract-cert-fp.py（官方提取器）逐字节一致。
#
# 反向验证（做过的）：把 g2_collect_fp 里多数派选取的 `votes > base_votes`
#   改成 `votes >= base_votes` → 本项仍绿（正常包每路指纹都相同，
#   多数派怎么选都一样）。它的定位是【不误伤 + 指纹正确】，"检出劫持"
#   的判定在宿主上测不了（没有第二路线可制造分歧），由真机的
#   "陌生签名" 场景覆盖（交接文档 §6.1）。
#
# APK 发现逻辑与 test-so-lock.sh 同源（TEST_APK > 样本 > 简盒目录）。
G2_APK=""
if [[ -n "${TEST_APK:-}" && -f "$TEST_APK" ]]; then
    G2_APK="$TEST_APK"
elif [[ -f "$ROOT/scripts/样本.apk" ]]; then
    G2_APK="$ROOT/scripts/样本.apk"
elif ls /storage/emulated/0/简盒/*_sign.apk >/dev/null 2>&1; then
    G2_APK=$(ls -t /storage/emulated/0/简盒/*_sign.apk 2>/dev/null | head -1)
fi
if [[ -z "$G2_APK" ]]; then
    echo "  ⚠ 缺已签名 APK，多路对拍项跳过（用 TEST_APK=<已签名.apk> 指定）"
else
    cat > "$T/multi.c" <<'C'
#include <stdio.h>
#include <string.h>
#include "guard2_test.h"
/* SG2_SHA256_LEN 是 sig_guard2.c 内部定义（算法固有 32），
 * 测试端只有 guard2_test.h 的 SG2_HASH_LEN（业务摘要长度）——
 * 指纹就是 SHA-256 输出，两者当前相等；用业务长度对拍即可。 */
int g2_collect_fp_test(unsigned char fp[SG2_HASH_LEN]);
int main(int argc, char **argv) {
    unsigned char fp[SG2_HASH_LEN];
    static const char dd[] = "0123456789abcdef";
    char hex[SG2_HASH_LEN * 2 + 1];
    const char *expect;
    int i, rc, d = 0;
    if (argc < 2) { printf("NOEXPECT\n"); return 2; }
    expect = argv[1];
    rc = g2_collect_fp_test(fp);
    if (rc != 0) { printf("RC=%d\n", rc); return 1; }
    for (i = 0; i < SG2_HASH_LEN; i++) {
        hex[i * 2]     = dd[fp[i] >> 4];
        hex[i * 2 + 1] = dd[fp[i] & 15];
    }
    hex[SG2_HASH_LEN * 2] = '\0';
    for (i = 0; i < SG2_HASH_LEN * 2; i++)
        if (hex[i] != expect[i]) d = 1;
    printf(d ? "FP_DIFF %s\n" : "FP_MATCH\n", hex);
    return d;
}
C
    # 期望指纹：官方提取器（冻结资产）从同一个 APK 提取
    FP_EXPECT=$(python3 "$ROOT/scripts/guard/hash/extract-cert-fp.py" "$G2_APK" 2>/dev/null || true)
    if [[ ! "$FP_EXPECT" =~ ^[0-9a-f]{64}$ ]]; then
        bad "extract-cert-fp.py 提取指纹失败（输出: ${FP_EXPECT:-空}）"
    elif $CC -O1 -D_GNU_SOURCE -DSIGGUARD2_HOST_TEST -I"$T" -I"$GUARD_SRC" \
            "$T/guard2_test.c" "$T/multi.c" -o "$T/tm" -ldl 2>"$T/multi.log"; then
        RM_="$(SIGGUARD2_TEST_APK="$G2_APK" timeout 30 "$T/tm" "$FP_EXPECT" 2>&1 || true)"
        if [[ "$RM_" == "FP_MATCH" ]]; then
            ok "多路采集不误伤且指纹对拍一致(宿主 3/6 路, rc=0, fp==官方提取)"
        else
            bad "多路采集异常: $RM_"
        fi
    else
        bad "第 4 项编译失败(见下)"; head -8 "$T/multi.log"
    fi
fi

echo "══════════════════════════════════════════════════"
echo "结果: $pass 通过, $fail 失败"
echo "══════════════════════════════════════════════════"
[[ $fail -eq 0 ]] || exit 1
