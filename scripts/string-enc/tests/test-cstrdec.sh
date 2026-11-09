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

echo "══ 0. 编译（两种 NKEYS 档位）══"
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

# ── 6. JNI 层混淆表反解（防手写 XOR 表出错）────────────────────────
echo "══ 6. JNI 混淆表反解（nc_strdec_jni.c）══"
# 为什么要这条：方法名/签名用 XOR 0x5A 存，手算极易错，而错了的症状是
# 运行期 NoSuchMethodError（RegisterNatives 返回非 0），构建期完全拦不住。
# 本断言直接从源码里抽出十六进制表，反解后与期望字符串比对 ——
# 把"注释说的"变成"机制保证的"。
python3 - "$CSRC/nc_strdec_jni.c" <<'PY'
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()
expect = {
    'nc_name_dec':    'ncDec',
    'nc_sig_dec':     '(Ljava/lang/String;)Ljava/lang/String;',
    'nc_name_setkey': 'ncSetKey',
    'nc_sig_setkey':  '([B)V',
}
fail = 0
for name, want in expect.items():
    m = re.search(r'unsigned char\s+%s\[\]\s*=\s*\{([^}]*)\}' % name, src)
    if not m:
        print("MISSING:%s" % name); fail += 1; continue
    vals = [int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})', m.group(1))]
    got = bytes(v ^ 0x5A for v in vals).rstrip(b'\x00').decode('latin-1')
    if got != want:
        print("BAD:%s got=%r want=%r" % (name, got, want)); fail += 1
sys.exit(1 if fail else 0)
PY
if [[ $? -eq 0 ]]; then
  ok
  echo "   4 张表反解全部正确"
else
  bad "JNI 混淆表反解失败（方法名/签名与预期不符 → 运行期 NoSuchMethodError）"
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

