#!/usr/bin/env bash
# test-cstrdec.sh — 纯 C 字符串解密桩（csrc/nc_strdec.c）的三方对拍测试
#
# 为什么要对拍而不是"看着对"：
#   本项目历史上的"静默乱码"事故（报错二十二/二十七）全部是
#   "两侧算法各自看起来对，但逐字节不一致"，而症状只有运行期才暴露。
#   故本测试把 C / Python / Java 三方放在一起，逐字节比对：
#     ① C 的 Base64 解码 vs Python base64.b64decode
#     ② C 的密钥流块   vs Python 的 key_byte 参考实现
#     ③ C 的 decrypt    vs Python 的 encrypt 往返
#     ④ C 的 decrypt    vs 现有 Java 桩（StrDec.java 编译后反射调用）
#
# 覆盖的历史雷区（每一条都真炸过）：
#   · offset % 8 != 0（块展开内层 j 起点写错 → 约一半字符串静默解错）
#   · 中文 / emoji（UTF-8 多字节；char[] 是 Latin-1 语义会乱码）
#   · Base64 填充 '=' 的三种长度（len%3 = 0/1/2）
#   · 空串跳过、3 字节 payload 走兜底
#   · 超长串（5188B，历史最长用例）
#
# 依赖：clang（或 cc）、python3、javac/java（Java 桩对拍用，缺失则 skip）
# 不依赖：NDK、android.jar、真机 —— 纯宿主闭环
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"          # scripts/string-enc/tests
SE="$(cd "$HERE/.." && pwd)"                   # scripts/string-enc
ROOT="$(cd "$SE/../.." && pwd)"                # 仓库根
CSRC="$SE/csrc"
CC="${CC:-clang}"
command -v "$CC" >/dev/null 2>&1 || CC=cc

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
bad()  { FAIL=$((FAIL+1)); echo "  ❌ $*" >&2; }
chk()  { if [[ "$2" == "$3" ]]; then ok; else bad "$1（期望 $3，实得 $2）"; fi; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

echo "══ 0. 编译（splitmix64 两档 + ChaCha20）══"
for n in 1 4; do
  # shellcheck disable=SC2086
  if ! "$CC" -std=c99 -O2 -Wall -Wextra -Wpedantic \
      -DNC_STRDEC_NKEYS=$n -DNC_STRDEC_HOST_TEST \
      -I"$CSRC" "$CSRC/nc_strdec.c" "$HERE/host_cstrdec.c" \
      -o "$W/host$n" 2>"$W/cc$n.log"; then
    echo "❌ NKEYS=$n 编译失败:" >&2; cat "$W/cc$n.log" >&2; exit 1
  fi
  [[ -s "$W/cc$n.log" ]] && { echo "❌ NKEYS=$n 有编译警告:" >&2; cat "$W/cc$n.log" >&2; exit 1; }
  echo "   ✅ NKEYS=$n 零警告编译通过"
done
# ChaCha20 档（2026-11-09）：只支持 NKEYS=1（256 位密钥直接当 ChaCha20 key）
if ! "$CC" -std=c99 -O2 -Wall -Wextra -Wpedantic \
    -DNC_STRDEC_NKEYS=1 -DNC_STRDEC_ALGO=2 -DNC_STRDEC_HOST_TEST \
    -I"$CSRC" "$CSRC/nc_strdec.c" "$HERE/host_cstrdec.c" \
    -o "$W/hostchacha" 2>"$W/ccchacha.log"; then
  echo "❌ ChaCha20 编译失败:" >&2; cat "$W/ccchacha.log" >&2; exit 1
fi
[[ -s "$W/ccchacha.log" ]] && { echo "❌ ChaCha20 有编译警告:" >&2; cat "$W/ccchacha.log" >&2; exit 1; }
echo "   ✅ ChaCha20 零警告编译通过"

# ── 1. Base64 解码对拍（C vs Python）──────────────────────────────
echo "══ 1. Base64 解码：C vs Python ══"
python3 - > "$W/b64cases.txt" <<'PY'
import base64, os
cases = []
# 三种填充形态 + 边界长度
for n in list(range(0, 20)) + [63,64,65,127,128,129,255,256,257,1000]:
    cases.append(os.urandom(n))
# 含 0x00 / 0x22 / 0x5C（Base64 存在的理由）
cases.append(bytes([0x00,0x22,0x5c,0x00,0xff,0x7f]))
for c in cases:
    print(base64.b64encode(c).decode() + "\t" + c.hex())
PY
n1=0
while IFS=$'\t' read -r enc want; do
  got="$("$W/host1" b64 <<< "$enc")"
  if [[ "$got" == "$want" ]]; then ok; else bad "b64($enc) → $got，期望 $want"; fi
  n1=$((n1+1))
done < "$W/b64cases.txt"
echo "   $n1 例完成"

# 非法输入必须被拒绝（返回 ERR），而不是静默产出垃圾
echo "══ 1b. Base64 非法输入拒绝 ══"
# ⚠️ 用例选取纪律：只列【Python base64.b64decode 也会拒绝】的形态，
#    否则本测试在断言"比 Python 更严格"，那是另一回事（且会让对拍失去意义）。
#    实测：'QR==' 这类"填充位非零"Python 是接受的（解出 0x41），故不列入。
for bad_case in 'QQ=' 'Q===' '!!!!' 'QQ==QQ==' 'A'; do
  got="$("$W/host1" b64 <<< "$bad_case")"
  chk "非法输入 '$bad_case' 应被拒绝" "$got" "ERR"
done
# 填充位非零：Python 接受，本实现也接受 —— 显式断言这一致性，
# 防止将来有人"顺手加严格校验"把两侧行为改岔。
got="$("$W/host1" b64 <<< 'QR==')"
chk "填充位非零应与 Python 一致接受" "$got" "41"

# ── 2. 密钥流对拍（C vs Python）───────────────────────────────────
echo "══ 2. 密钥流：C vs Python key_byte 参考实现 ══"
for nk in 1 4; do
python3 - "$nk" > "$W/ks_cases.txt" <<'PY'
import sys, os
nk = int(sys.argv[1])
MASK=(1<<64)-1
G=[0x9E3779B97F4A7C15,0x27D4EB2F165667C5,0xC2B2AE3D27D4EB4F,0x165667B19E3779F9]
C1=0xBF58476D1CE4E5B9; C2=0x94D049BB133111EB
def mix64(z):
    z&=MASK
    z=((z^(z>>30))*C1)&MASK
    z=((z^(z>>27))*C2)&MASK
    return (z^(z>>31))&MASK
def block_ks(keys, blk):
    w=mix64((keys[0] + blk*G[0]) & MASK)
    for t in range(1, nk):
        w ^= mix64((keys[t] + (blk+t)*G[t]) & MASK)
    return w
for trial in range(4):
    keys=[int.from_bytes(os.urandom(8),'big') for _ in range(nk)]
    keyhex = b''.join(k.to_bytes(8,'big') for k in keys).hex()
    print(keyhex)
    print("200")
    for b in range(200):
        print("%016x"%block_ks(keys,b))
PY
  # 每个 trial 是 202 行：密钥 + 块数 + 200 个期望值
  total=$(( $(wc -l < "$W/ks_cases.txt") ))
  i=1
  while [[ $i -le $total ]]; do
    keyhex="$(sed -n "${i}p" "$W/ks_cases.txt")"
    i=$((i+1))
    nblk="$(sed -n "${i}p" "$W/ks_cases.txt")"
    i=$((i+1))
    want="$(sed -n "${i},$((i+nblk-1))p" "$W/ks_cases.txt")"
    i=$((i+nblk))
    got="$(printf '%s\n%s\n' "$keyhex" "$nblk" | "$W/host$nk" gen)"
    chk "NKEYS=$nk 密钥流块序列" "$got" "$want"
  done
  echo "   NKEYS=$nk 密钥流对拍完成"
done

# ── 2b. ChaCha20 密钥流（2026-11-09）────────────────────────────────
# 为什么单独一组：ChaCha20 是新增的可选算法（--stringenc-chacha20），
# 它不可逆，能挡住"猜中一条明文 → 反推密钥 → 解全包"。
# 三层验证，缺一层都不算数：
#   ① RFC 8439 官方测试向量 —— 唯一能抓住"轮函数写错"的判据
#      （自己跟自己对拍永远发现不了：两侧都错 = 一致）
#   ② C ↔ Python 逐块对拍 —— 保证构建期加密与运行期解密同源
#   ③ 往返：Python 加密 → C 解密 —— 保证 offset/counter 映射没搞错
echo "══ 2b. ChaCha20 密钥流 ══"

# ① RFC 8439 §2.4.2：全零 key/nonce，counter=0 的块前 8 字节
#    = 76 b8 e0 ad a0 f1 3d 90；counter=1 = 9f 07 e7 be 55 51 38 7a
chk "ChaCha20 RFC 向量 counter=0" \
  "$(printf '%s\n%s\n' "0000000000000000" "2" | "$W/hostchacha" gen \
     | sed -n '1p' | python3 -c "
import sys
w=int(sys.stdin.read().strip(),16)
print(bytes((w>>(i*8))&0xFF for i in range(8)).hex())")" \
  "76b8e0ada0f13d90"
chk "ChaCha20 RFC 向量 counter=1" \
  "$(printf '%s\n%s\n' "0000000000000000" "2" | "$W/hostchacha" gen \
     | sed -n '2p' | python3 -c "
import sys
w=int(sys.stdin.read().strip(),16)
print(bytes((w>>(i*8))&0xFF for i in range(8)).hex())")" \
  "9f07e7be5551387a"

# ② C ↔ Python 逐块对拍（多组随机种子 × 200 块）
SE="$SE" python3 - > "$W/chacha_cases.txt" <<'PY'
import os, sys
sys.path.insert(0, os.environ["SE"])
import importlib.util
spec = importlib.util.spec_from_file_location("es", os.environ["SE"]+"/encrypt-strings.py")
es = importlib.util.module_from_spec(spec); spec.loader.exec_module(es)
for _ in range(4):
    seed = int.from_bytes(os.urandom(8), 'big')
    print("%016x" % seed)
    print("200")
    for b in range(200):
        print("%016x" % es._chacha20_block_head(seed, b))
PY
total=$(wc -l < "$W/chacha_cases.txt"); i=1
while [[ $i -le $total ]]; do
  keyhex="$(sed -n "${i}p" "$W/chacha_cases.txt")"; i=$((i+1))
  nblk="$(sed -n "${i}p" "$W/chacha_cases.txt")"; i=$((i+1))
  want="$(sed -n "${i},$((i+nblk-1))p" "$W/chacha_cases.txt")"; i=$((i+nblk))
  got="$(printf '%s\n%s\n' "$keyhex" "$nblk" | "$W/hostchacha" gen)"
  chk "ChaCha20 C↔Python 密钥流块序列" "$got" "$want"
done
echo "   ChaCha20 密钥流对拍完成"

# ③ 往返 + 关键安全性质：两种算法在同一 offset 的密钥流必须不同
#    （若相同 = 算法切换没生效，安全档形同虚设）
SE="$SE" python3 - > "$W/chacha_rt.txt" <<'PY'
import os, sys, base64
sys.path.insert(0, os.environ["SE"])
import importlib.util
spec = importlib.util.spec_from_file_location("es", os.environ["SE"]+"/encrypt-strings.py")
es = importlib.util.module_from_spec(spec); spec.loader.exec_module(es)
seed = int.from_bytes(os.urandom(8), 'big')
print("%016x" % seed)
plains = ["hello", "中文测试", "emoji\U0001F600test", "x"*300, "a", ""]
for off in (0,1,5,7,8,13,1000):
    for pl in plains:
        pb = pl.encode()
        if not pb:
            continue
        pay = es.encrypt_payload_v2(seed, off, pb, es.ALGO_CHACHA20)
        print("%d\t%s\t%s" % (off, pay, pb.hex()))
PY
seedhex="$(sed -n '1p' "$W/chacha_rt.txt")"
rt_fail=0; rt_n=0
while IFS=$'\t' read -r off pay plainhex; do
  rt_n=$((rt_n+1))
  # dec 模式输出的是【hex】，直接与期望明文的 hex 比
  got="$(printf '%s\n%s\n' "$seedhex" "$pay" | "$W/hostchacha" dec)"
  if [[ "$got" == "$plainhex" ]]; then ok; else
    bad "ChaCha20 往返失败 off=$off payload=${pay:0:24}…（期望 $plainhex 实得 $got）"; rt_fail=1
  fi
done < <(sed -n '2,$p' "$W/chacha_rt.txt")
if [[ $rt_fail -eq 0 ]]; then
  echo "   ChaCha20 往返完成（$rt_n 例）"
fi

# ── 3. 加解密往返（C decrypt vs Python encrypt）────────────────────
echo "══ 3. 加解密往返：Python 加密 → C 解密 ══"
python3 - > "$W/roundtrip.txt" <<'PY'
import os, base64
MASK=(1<<64)-1
G=[0x9E3779B97F4A7C15,0x27D4EB2F165667C5,0xC2B2AE3D27D4EB4F,0x165667B19E3779F9]
C1=0xBF58476D1CE4E5B9; C2=0x94D049BB133111EB
def mix64(z):
    z&=MASK
    z=((z^(z>>30))*C1)&MASK
    z=((z^(z>>27))*C2)&MASK
    return (z^(z>>31))&MASK
def block_ks(keys, blk, nk):
    w=mix64((keys[0]+blk*G[0])&MASK)
    for t in range(1,nk):
        w ^= mix64((keys[t]+(blk+t)*G[t])&MASK)
    return w
def key_byte(keys,i,nk):
    return (block_ks(keys,i>>3,nk)>>((i&7)*8))&0xFF
def encrypt(keys,off,plain,nk):
    body=bytes([b^key_byte(keys,off+k,nk) for k,b in enumerate(plain)])
    raw=bytes([(off>>16)&255,(off>>8)&255,off&255])+body
    return base64.b64encode(raw).decode()

PLAINS=[
  "a", "ab", "abc",
  "https://api.xixin.box/v1/pay/sign",
  "Content-Type", "application/json",
  "yyyy-MM-dd HH:mm:ss",
  "登录失败，请稍后重试",
  "支付订单校验失败，请联系客服",
  "emoji:😀🎉🚀",
  "混合 mixed 中文😀 ascii",
  "\u0000开头含NUL",
  "全角：ＡＢＣ１２３",
  "x"*5188,                      # 历史最长用例
  "".join(chr(0x4e00+i) for i in range(200)),
]
for nk in (1,4):
    keys=[int.from_bytes(os.urandom(8),'big') for _ in range(nk)]
    keyhex=b''.join(k.to_bytes(8,'big') for k in keys).hex()
    # offset 必须覆盖 %8 的全部 8 个 residue —— 这是历史事故的源头
    for residue in range(8):
        off = residue + 8*3
        for p in PLAINS:
            payload=encrypt(keys,off,p.encode('utf-8'),nk)
            print("%d\t%s\t%s\t%s" % (nk, keyhex, payload, p.encode('utf-8').hex()))
PY
nrt=0
while IFS=$'\t' read -r nk keyhex payload want; do
  got="$(printf '%s\n%s\n' "$keyhex" "$payload" | "$W/host$nk" dec)"
  if [[ "$got" == "$want" ]]; then ok; else bad "NKEYS=$nk 往返失败 payload=$payload"; fi
  nrt=$((nrt+1))
done < "$W/roundtrip.txt"
echo "   $nrt 例完成（含 offset%8 全部 residue、emoji、5188B 长串）"

# ── 4. 未设密钥必须 fail-closed ────────────────────────────────────
echo "══ 4. 未设密钥 fail-closed ══"
# 用 nokey 模式，不要试图用空密钥 hex 走 dec 分支 —— dec 会先做密钥长度
# 校验并 exit 2，根本到不了 has_key() 的判定，那样测的是"参数校验"而不是
# "fail-closed 语义"（本测试首版即栽在此，报告 ERR 但原因不对）。
# payload = Base64(offset_be24 || cipher) = Base64(000000 || aa)
# 期望明文由 Python 侧独立算出（seed=0f1e2d3c4b5a6978, offset=0 → 0x73），
# 这里写死是为了让断言自带"第三方答案"，不依赖被测实现自证。
_payload='AAAAqg=='
got="$("$W/host1" nokey <<< "$_payload")"
chk "未设密钥不得产明文" "$got" "ERR"
got="$("$W/host1" dec <<< "$(printf '0f1e2d3c4b5a6978\n%s' "$_payload")")"
chk "设密钥后同一 payload 可解" "$got" "73"

# ── 5b. cfg.h 优先级：构建期注入的算法档必须能覆盖头文件默认值 ──────
# 为什么必须有这条（2026-11-09 真机闪退根因）：
#   nc_strdec.h 里有 `#ifndef NC_STRDEC_ALGO → define 0` 的兜底默认值。
#   若 .c/.jni.c 先 include 头文件、后 include 构建期生成的 nc_strdec_cfg.h，
#   那么 cfg.h 里的 `#ifndef` 守卫整段失效 —— 用户选 ChaCha20 加密，
#   运行期仍按 splitmix64 解密，每条字符串都解错。
#   而 nc_jni_fail() 会静默降级成"原样返回密文"，
#   最终症状是业务代码拿密文当真实值用（实测：getDeclaredField(密文) → 闪退）。
#
# 宿主测试默认不生成 cfg.h，所以这个 bug 只有"造一个假 cfg.h 再编"才能抓到。
# 断言两件事：① 两个 .c 都能在 cfg.h 存在时零警告编译；
#             ② 预处理器实际取到的是 cfg.h 的值，不是头文件默认值。
echo "══ 5b. cfg.h 必须能覆盖 nc_strdec.h 的默认档位 ══"
mkdir -p "$W/cfgtest"
cat > "$W/cfgtest/nc_strdec_cfg.h" <<'CFGEOF'
/* 假的构建期配置头：故意用非默认值（ALGO=2 / NKEYS=1），
 * 若被头文件的 #ifndef 挡住，取到的会是 0 —— 那就是 bug 复现。 */
#ifndef NC_STRDEC_ALGO
#  define NC_STRDEC_ALGO 2
#endif
#ifndef NC_STRDEC_NKEYS
#  define NC_STRDEC_NKEYS 1
#endif
#define NC_STRDEC_KEY_BYTES { 0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78 }
#define NC_STRDEC_STUB_CLASS "tw/qw/ny/la"
CFGEOF
for src in nc_strdec.c nc_strdec_jni.c; do
  hdr="${src%.c}.h"
  # 直接对源文件跑预处理器，取它实际看到的宏值
  got=$("$CC" -E -dM -DNC_STRDEC_HOST_TEST -I"$W/cfgtest" -I"$CSRC" \
        "$CSRC/$src" 2>/dev/null \
        | awk '/^#define NC_STRDEC_ALGO /{a=$3} /^#define NC_STRDEC_NKEYS /{n=$3} END{print a"/"n}')
  chk "$src 取到 cfg.h 的 ALGO/NKEYS（非默认 0）" "$got" "2/1"
done

echo "══ 6. JNI 绑定：必须是短名，不得回退到 RegisterNatives ══"
# 为什么钉死：RegisterNatives 在"桩类 <clinit> 里 loadLibrary"这个场景下
# 必然失败（类初始化未完成 → FindClass 失败），或即使注册成功，ART 也会在
# 类链接阶段就解析 native 方法（那时 so 未加载）→ NoSuchMethodError。
# 真机实测两轮都是硬崩溃，所以这里断言"旧机制不在"。
# 只看代码行（去掉注释），注释里提到这些词是说明用途，不算违规
if grep -vE '^[[:space:]]*(\*|/\*)' "$CSRC/nc_strdec_jni.c" | grep -q 'RegisterNatives'; then
  bad "nc_strdec_jni.c 里出现 RegisterNatives（会崩，见文件头说明）"
else
  ok
  echo "   ✅ 无 RegisterNatives"
fi
if grep -qE '^int nc_strdec_register_natives|^int nc_strdec_bootstrap' "$CSRC/nc_strdec_jni.c"; then
  bad "残留已废弃的注册入口"
else
  ok
  echo "   ✅ 无废弃注册入口"
fi
# 绑定必须由构建期生成的短名封装完成
if grep -q 'Java_\${_jni_cls}_\${_stub_dec_method}' scripts/pipelines/protect.sh; then
  ok
  echo "   ✅ protect.sh 生成短名封装"
else
  bad "protect.sh 未生成短名封装"
fi
# 密钥不得经过 Java：native_stub 生成的桩里不许有 setKey 调用
if grep -vE '^[[:space:]]*#' "$SE/native_stub.py" | grep -q 'ncSetKey'; then
  bad "native_stub.py 仍引用 ncSetKey（密钥会回到 dex）"
else
  ok
  echo "   ✅ 密钥不经 dex（无 ncSetKey 调用）"
fi

# ── 7. 纯 C 桩 ↔ 壳 so 联动（2026-11-10）────────────────────────────
# 目标：证明 nc_strdec 能从"壳 so"取到种子，且取到的密钥与构建期常量
#       逐字节相同（否则构建期加密 / 运行期解密不同源 → 全包乱码）。
#
# 为什么必须在宿主上验：真机验证要整套 APK 流程，而这个契约的核心只有
# 三件事——① 能找到壳 so 的 handle ② 能取到 ncg_strkey ③ 拆出的字节
# 与常量一致。三件都能在宿主上闭环，且改坏时能立刻定位。
echo "══ 7. 纯 C 桩 ↔ 壳 so 联动（ncg_strkey）══"

# 7a. 源码契约：nc_strdec_jni.c 必须用 dl_iterate_phdr 而不是裸 dlsym(RTLD_DEFAULT)
#     原因：Android 的 System.load 走 android_dlopen_ext(RTLD_NOW)，不带
#     RTLD_GLOBAL，所以 dlsym(RTLD_DEFAULT) 搜不到壳 so 的符号。
#     宿主实测：dlopen(RTLD_LOCAL) 后 RTLD_DEFAULT 返回 NULL。
if grep -q 'dl_iterate_phdr' "$CSRC/nc_strdec_jni.c"; then
  ok; echo "   ✅ 用 dl_iterate_phdr 找壳 so 的 handle"
else
  bad "nc_strdec_jni.c 未用 dl_iterate_phdr（裸 dlsym(RTLD_DEFAULT) 在 Android 上找不到壳符号）"
fi
if grep -q 'RTLD_NOLOAD' "$CSRC/nc_strdec_jni.c"; then
  ok; echo "   ✅ 用 RTLD_NOLOAD 取已有 handle（不重复加载）"
else
  bad "未用 RTLD_NOLOAD（会二次加载壳 so）"
fi
if grep -q 'dlclose' "$CSRC/nc_strdec_jni.c"; then
  ok; echo "   ✅ 取完符号后 dlclose 归还引用计数"
else
  bad "未 dlclose（NOLOAD 的引用计数泄漏）"
fi
# 7b. 回退链必须存在：取不到壳 → 用编译期常量
if grep -q 'NC_STRDEC_KEY_BYTES' "$CSRC/nc_strdec_jni.c"; then
  ok; echo "   ✅ 保留编译期常量回退（未包壳的组合作业正常）"
else
  bad "删掉了编译期常量回退 —— 单勾 stringenc-native 时会完全没有密钥"
fi
# 7c. NKEYS 断言必须在 cfg.h/nc_strdec.h 之后（否则读到默认值 1，永真）
if grep -q 'NC_STRDEC_NKEYS != 1' "$CSRC/nc_strdec_jni.c"; then
  ok; echo "   ✅ 有 NKEYS=1 编译期断言"
else
  bad "缺少 NKEYS=1 断言（NKEYS>1 时联动会静默解错）"
fi
# 7d. protect.sh 必须在纯 C 桩 + packer 时写 stub_seed.txt
#     （不写 → dpt 的 stub_seed 保持 0 → ncg_strkey 返回 0 → 回退常量 → 联动失效）
if grep -A3 '_cstub_seed_hex,,.*stub_seed.txt\|stub_seed.txt.*_cstub_seed_hex' \
     "$ROOT/scripts/pipelines/protect.sh" >/dev/null 2>&1 || \
   grep -q '纯 C 桩种子将写入壳 config' "$ROOT/scripts/pipelines/protect.sh"; then
  ok; echo "   ✅ protect.sh 在纯 C 桩路径写 stub_seed.txt"
else
  bad "protect.sh 未在纯 C 桩路径写 stub_seed.txt（联动不会生效）"
fi

# 7d1. 构建期契约：包了壳就必须【不写】编译期常量
#      理由：常量与壳两条密钥来源若同时存在，去掉壳 so 会回退到常量 →
#      照样能解 → 「必须带着壳」失效。所以 protect.sh 必须按 WANT_PACKER
#      分支生成 cfg.h：包壳时只写注释、不 define NC_STRDEC_KEY_BYTES。
# 判定方式：提取 cfg.h 生成处「包壳分支」（protect.sh 第 961 行起）的代码块，
# 确认里面【没有】在 shell 层写 NC_STRDEC_KEY_BYTES。
#
# 为什么不能只 grep 关键词"是否出现"：那样把分支条件改成恒假也照样绿。
# 为什么不能按 `if [[ $WANT_PACKER -eq 1 ]]` 搜第一处：文件里有 5 处同名判断，
# 第一处是 emit-stub-dex 的（protect.sh:343），与 cfg.h 无关 —— 首版就是这么
# 写错的，注入故障没反应，第二次才发现。
# 定位锚点：cfg.h 的第一次写（`cat > ... nc_strdec_cfg.h`）之后最近的那个分支。
_cfg_line="$(grep -n 'cat > "$_cstub_dst/nc_strdec_cfg.h"' "$ROOT/scripts/pipelines/protect.sh" | head -1 | cut -d: -f1)"
if [[ -z "$_cfg_line" ]]; then
  bad "protect.sh 里找不到 cfg.h 生成点"
else
  # 只取「then … else」之间（包壳分支的真身），不含 else 分支 ——
  # else 里本来就该有常量（没包壳的场景）。
  _packer_branch="$(awk -v s="$_cfg_line" '
      NR>=s && /if \[\[ \$WANT_PACKER -eq 1 \]\]; then/ {f=1; next}
      f && /^else$/ {exit}
      f {print}' "$ROOT/scripts/pipelines/protect.sh")"
  if [[ -z "$_packer_branch" ]]; then
    bad "cfg.h 生成点之后找不到「按 WANT_PACKER 分支」的代码块"
  elif printf '%s' "$_packer_branch" | grep -q 'NC_STRDEC_KEY_BYTES'; then
    bad "包壳分支里定义了 NC_STRDEC_KEY_BYTES —— 去掉壳 so 会回退到常量，联动失效"
  else
    ok; echo "   ✅ 包壳分支不编密钥常量（去掉壳 so 才会真的解不开）"
  fi
fi

# 7d2. 跨仓库契约：壳侧必须用 extern "C" 导出 ncg_strkey
#      实测踩过（dpt-shell v1.6.0-strkey）：dpt.cpp 是 C++ 文件，
#      不加 extern "C" 时符号被 mangling 成 _Z10ncg_strkeyv，
#      而本侧 dlsym 找的是字面量 "ncg_strkey" → 永远找不到 →
#      静默回退到编译期常量 → 功能正常但联动失效（最难发现的一类失败）。
#      这里在【源码层】钉：dpt-shell 的 dpt.cpp 里 ncg_strkey 定义前
#      必须有 extern "C"。跨仓库路径可能不存在（只 clone 本仓库时），
#      此时跳过而不判红。
DPT_CPP="$(cd "$ROOT/.." 2>/dev/null && pwd)/dpt-shell/shell/src/main/cpp/dpt.cpp"
if [[ -f "$DPT_CPP" ]]; then
  if grep -B2 'uint64_t ncg_strkey(void)' "$DPT_CPP" | grep -q 'extern "C"'; then
    ok; echo "   ✅ 壳侧 ncg_strkey 有 extern \"C\"（防 C++ mangling）"
  else
    bad "壳侧 ncg_strkey 缺 extern \"C\" —— 会被 mangling 成 _Z10ncg_strkeyv，dlsym 找不到"
  fi
else
  echo "   ⚠ 跳过：未找到 $DPT_CPP（只 clone 本仓库时正常）"
fi

# 7e. 端到端：造一个假壳 so，验证取到的字节与常量一致
if command -v "$CC" >/dev/null 2>&1; then
  mkdir -p "$W/link"
  cat > "$W/link/fakeshell.c" <<'FSEOF'
#include <stdint.h>
__attribute__((used, visibility("default")))
uint64_t ncg_strkey(void){ return 0x0011223344556677ULL; }
FSEOF
  cat > "$W/link/verify.c" <<'VEOF'
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
typedef struct { const char *want; void *handle; } ctx_t;
static int cb(struct dl_phdr_info *i, size_t s, void *d){
    (void)s; ctx_t *c=(ctx_t*)d;
    if(!i->dlpi_name || !i->dlpi_name[0]) return 0;
    if(!strstr(i->dlpi_name, c->want)) return 0;
    c->handle = dlopen(i->dlpi_name, RTLD_NOW|RTLD_NOLOAD);
    return 1;
}
int main(void){
    ctx_t c={"libxixin.so",NULL};
    dl_iterate_phdr(cb,&c);
    if(!c.handle){ printf("NOSHELL\n"); return 2; }
    typedef uint64_t(*fn)(void);
    fn f=(fn)dlsym(c.handle,"ncg_strkey");
    dlclose(c.handle);
    if(!f){ printf("NOSYM\n"); return 3; }
    uint64_t seed=f();
    /* 与 nc_strdec_jni.c 完全同式的拆字节 */
    for(int i=0;i<8;i++) printf("%02x",(unsigned)((seed>>((7-(i%8))*8))&0xFF));
    printf("\n");
    return 0;
}
VEOF
  if "$CC" -shared -fPIC -o "$W/link/libxixin.so" "$W/link/fakeshell.c" 2>/dev/null && \
     "$CC" -O2 -o "$W/link/verify" "$W/link/verify.c" -ldl 2>/dev/null; then
    # ⚠️ 用 $( ) 而不是 $(( ))：后者是【算术展开】，会把输出当表达式求值
    #    （首版写成 $(( )) → 输出 "0011223344556677" 被当十进制数算，
    #      "NOSHELL" 直接报错 → 两条断言静默消失，测试却显示全绿）。
    got="$( cd "$W/link" && LD_PRELOAD=./libxixin.so ./verify 2>/dev/null )"
    chk "有壳 so 时取出的密钥字节" "$got" "0011223344556677"
    # 无壳：应报 NOSHELL（调用方据此回退常量）
    got2="$( cd "$W/link" && ./verify 2>/dev/null )"
    chk "无壳 so 时正确报 NOSHELL（触发常量回退）" "$got2" "NOSHELL"
  else
    bad "联动端到端用例编译失败"
  fi
fi

echo
echo "────────────────────────────────────────"
if [[ $FAIL -eq 0 ]]; then
  echo "✅ 全部通过：$PASS 项断言"
  exit 0
else
  echo "❌ 失败 $FAIL 项 / 通过 $PASS 项" >&2
  exit 1
fi

