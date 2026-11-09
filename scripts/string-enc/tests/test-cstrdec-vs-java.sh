#!/usr/bin/env bash
# test-cstrdec-vs-java.sh — C 实现 vs 现有 Java 桩（StrDec.java）的逐字节对拍
#
# 为什么必须单独一套：
#   test-cstrdec.sh 对拍的是"我自己写的 Python 参考实现"——它只能证明
#   C 和 Python 一致，证明不了"和线上正在用的 Java 桩一致"。而这次改动的
#   前提正是【C 实现要能替换现有 Java 桩】，所以必须拿真货对拍：
#   直接编译 stub-src/StrDec.java（唯一源码真相），反射调用它的 dn()，
#   与 C 实现在同一批密文上比对结果。
#
# 关键设计：Java 侧不重新实现算法，而是调 StrDec 的真实方法
#   → 若有人改了 StrDec.java 而没改 C，本测试必红
#   → 这正是本项目历史上最需要的防线（"两侧算法各自看起来都对"）
#
# 依赖：javac / java（缺失则 skip 并 exit 0，与仓库既有约定一致）
#       android.util.Base64 由 tests/shims 顶替（宿主没有 android.jar）
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$SE/../.." && pwd)"
CSRC="$SE/csrc"
CC="${CC:-clang}"
command -v "$CC" >/dev/null 2>&1 || CC=cc

if ! command -v javac >/dev/null 2>&1 || ! command -v java >/dev/null 2>&1; then
  echo "⏭️  跳过：宿主机无 javac/java（本测试需真实 JVM 反射调用 Java 桩）"
  exit 0
fi

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  ❌ $*" >&2; }
chk() { if [[ "$2" == "$3" ]]; then ok; else bad "$1（期望 $3，实得 $2）"; fi; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

echo "══ 1. 编译 C 侧（NKEYS=1，与 Java 桩同档位）══"
"$CC" -std=c99 -O2 -Wall -Wextra -Wpedantic \
  -DNC_STRDEC_NKEYS=1 -DNC_STRDEC_HOST_TEST \
  -I"$CSRC" "$CSRC/nc_strdec.c" "$HERE/host_cstrdec.c" -o "$W/host1" \
  || { echo "❌ C 侧编译失败" >&2; exit 1; }
echo "   ✅ 通过"

echo "══ 2. 编译 Java 侧（真实 StrDec.java，哨兵种子替换为本次密钥）══"
mkdir -p "$W/src/android/util" "$W/cls"
cp "$HERE/shims/android/util/Base64.java" "$W/src/android/util/"
# 用测试密钥替换 SEED 占位行（与 build-stub.sh 同款 sed）
SEED_HEX="0f1e2d3c4b5a6978"
sed "s|private static final long SEED = 0L;.*|private static final long SEED = 0x${SEED_HEX}L;|" \
    "$SE/stub-src/StrDec.java" > "$W/src/StrDec.java"
grep -q "SEED = 0x${SEED_HEX}L;" "$W/src/StrDec.java" \
  || { echo "❌ 哨兵替换失败（StrDec.java 的 SEED 声明行形态变了？）" >&2; exit 1; }

# 驱动：反射调用 dn()（内核，真正干活的那个）并打印 hex
cat > "$W/src/Drv.java" <<'JAVA'
import java.lang.reflect.Method;

public class Drv {
    public static void main(String[] a) throws Exception {
        String mode = a.length > 0 ? a[0] : "dec";
        java.io.BufferedReader r =
            new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
        String line;

        if (mode.equals("utf16")) {
            /* 基准：Java 的 new String(bytes, "UTF-8") 语义。
             * 输出 UTF-16 码元序列（每码元 4 位 hex），供与 C 的
             * nc_strdec_utf8_to_utf16 逐码元比对。这与 StrDec.dn() 里的
             * new String(out, "UTF-8") 完全同源。 */
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                byte[] raw = new byte[line.length() / 2];
                for (int i = 0; i < raw.length; i++) {
                    raw[i] = (byte) Integer.parseInt(
                        line.substring(i * 2, i * 2 + 2), 16);
                }
                String s = new String(raw, "UTF-8");
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < s.length(); i++) {
                    sb.append(String.format("%04x", (int) s.charAt(i)));
                }
                System.out.println(sb);
            }
            return;
        }

        Class<?> c = Class.forName("StrDec");
        Method m = c.getDeclaredMethod("dn", String.class);
        m.setAccessible(true);
        // stdin: 每行一个 payload；输出：明文 UTF-8 的 hex，失败输出 ERR
        while ((line = r.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            try {
                String p = (String) m.invoke(null, line);
                byte[] b = p.getBytes("UTF-8");
                StringBuilder sb = new StringBuilder();
                for (byte x : b) sb.append(String.format("%02x", x & 0xff));
                System.out.println(sb);
            } catch (Throwable t) {
                System.out.println("ERR");
            }
        }
    }
}
JAVA

if ! javac -nowarn -encoding UTF-8 -d "$W/cls" \
      "$W/src/android/util/Base64.java" "$W/src/StrDec.java" "$W/src/Drv.java" \
      >"$W/javac.log" 2>&1; then
  echo "❌ Java 侧编译失败:" >&2; cat "$W/javac.log" >&2; exit 1
fi
echo "   ✅ 通过（真实 StrDec.java，未改动算法）"

echo "══ 3. 生成同批密文（Python 加密，两个实现都解）══"
python3 - "$SEED_HEX" > "$W/cases.txt" <<'PY'
import sys, base64
seed_hex = sys.argv[1]
seed = int(seed_hex, 16)
MASK=(1<<64)-1; GAMMA=0x9E3779B97F4A7C15
C1=0xBF58476D1CE4E5B9; C2=0x94D049BB133111EB
def mix64(z):
    z&=MASK; z=((z^(z>>30))*C1)&MASK; z=((z^(z>>27))*C2)&MASK
    return (z^(z>>31))&MASK
def key_byte(seed,i): return (mix64(seed+(i>>3)*GAMMA)>>((i&7)*8))&0xFF
def encrypt(seed,off,plain):
    body=bytes([b^key_byte(seed,off+k) for k,b in enumerate(plain)])
    return base64.b64encode(bytes([(off>>16)&255,(off>>8)&255,off&255])+body).decode()

PLAINS=[
 "a","ab","abc","abcd",
 "https://api.xixin.box/v1/pay/sign","Content-Type","application/json",
 "yyyy-MM-dd HH:mm:ss","Authorization","/data/data/com.xixin.box/cache",
 "登录失败，请稍后重试","支付订单校验失败，请联系客服","全角：ＡＢＣ１２３",
 "emoji:😀🎉🚀","混合 mixed 中文😀 ascii",
 "\u0000开头含NUL","\u0000\u0000双NUL",
 "x"*5188,
 "".join(chr(0x4e00+i) for i in range(200)),
]
# offset 覆盖 %8 全部 residue —— 历史事故源头
for residue in range(8):
    off = residue + 8*3
    for p in PLAINS:
        print("%s\t%s" % (encrypt(seed, off, p.encode('utf-8')), p.encode('utf-8').hex()))
PY
echo "   $(wc -l < "$W/cases.txt") 条密文"

echo "══ 4. 双方各自解密，逐条比对 ══"
# Java 侧：一次性喂全部 payload
cut -f1 "$W/cases.txt" | java -cp "$W/cls" Drv > "$W/java.out" 2>"$W/java.err" || {
  echo "❌ Java 驱动运行失败:" >&2; cat "$W/java.err" >&2; exit 1
}

# C 侧：逐条（host 程序是单行协议）
: > "$W/c.out"
while IFS=$'\t' read -r payload _want; do
  printf '%s\n%s\n' "$SEED_HEX" "$payload" | "$W/host1" dec >> "$W/c.out"
done < "$W/cases.txt"

n=0
while IFS=$'\t' read -r payload want; do
  n=$((n+1))
  j="$(sed -n "${n}p" "$W/java.out")"
  c="$(sed -n "${n}p" "$W/c.out")"
  if [[ "$j" == "$want" && "$c" == "$want" ]]; then
    ok
  else
    bad "第 $n 条：C=$c Java=$j 期望=$want payload=$payload"
  fi
done < "$W/cases.txt"
echo "   $n 条比对完成"

echo "══ 5. UTF-8 → UTF-16：C vs Java new String(bytes,UTF-8) ══"
# 为什么单独测这一步：
#   dn() 返回 String，C 侧必须自己把 UTF-8 字节转成 UTF-16 再 NewString。
#   这一步若误用 NewStringUTF（它收 modified UTF-8），emoji 会变乱码，
#   而"解出来的字节序列对"掩盖不了这个错误 —— 只有比对码元序列能抓住。
python3 - > "$W/u16cases.txt" <<'PY'
import struct
# ⚠️ 不放空串：Java 驱动按行读、跳过空行，空 hex 会让后续用例整体错位。
#    业务上空串在构建期就被跳过（加密它没有意义），所以不需要覆盖。
cases = [
  "a", "abc",
  "中文", "全角：ＡＢＣ", "混合 mixed 中文 ascii",
  "emoji:\U0001F600\U0001F389\U0001F680", "一个\U0001F600夹在中间",
  "\u0000", "\u0000开头", "中间\u0000夹NUL",
  "\u007f", "\u0080", "\u07ff", "\u0800", "\uffff",
  "\U00010000", "\U0010ffff",
  "".join(chr(0x4e00 + i) for i in range(200)),
  "x" * 5188,
]
for c in cases:
    b = c.encode("utf-8")
    u16 = c.encode("utf-16-le")
    units = struct.unpack("<%dH" % (len(u16) // 2), u16)
    print("%s\t%s" % (b.hex(), "".join("%04x" % w for w in units)))
PY
: > "$W/u16.in"
while IFS=$'\t' read -r hex _want; do printf '%s\n' "$hex" >> "$W/u16.in"; done < "$W/u16cases.txt"
java -cp "$W/cls" Drv utf16 < "$W/u16.in" > "$W/u16.java.out" 2>"$W/u16.err" || {
  echo "❌ Java UTF-16 驱动失败:" >&2; cat "$W/u16.err" >&2; exit 1
}
n16=0
while IFS=$'\t' read -r hex want; do
  n16=$((n16+1))
  c="$("$W/host1" utf16 <<< "$hex")"
  j="$(sed -n "${n16}p" "$W/u16.java.out")"
  if [[ "$c" == "$want" && "$j" == "$want" ]]; then
    ok
  else
    bad "UTF-16 第 $n16 例：C=$c Java=$j 期望=$want"
  fi
done < "$W/u16cases.txt"
echo "   $n16 例完成"

echo "══ 5b. 非法 UTF-8 必须 fail-closed ══"
# Java 侧是 REPLACE 动作（产出 U+FFFD），本实现刻意 fail-closed：
# 损坏时返回 base64 原串（一眼看出坏了），比返回"看起来像正常字符串"的
# 垃圾更安全。这是【已记录的刻意差异】，只在密文损坏时出现。
for bad_hex in 'c080' 'e08080' 'f0808080' 'eda080' 'ff' 'e4b8' 'c2' 'f4908080' 'f8888080'; do
  got="$("$W/host1" utf16 <<< "$bad_hex")"
  chk "非法 UTF-8 '$bad_hex' 应被拒绝" "$got" "ERR"
done
# 合法边界必须接受（防"为了拒绝非法而误杀合法"）
chk "U+10FFFF 应被接受" "$("$W/host1" utf16 <<< 'f48fbfbf')" "dbffdfff"
chk "U+10000 应被接受" "$("$W/host1" utf16 <<< 'f0908080')" "d800dc00"
chk "U+0000 应被接受" "$("$W/host1" utf16 <<< '00')" "0000"
chk "U+D7FF 边界应被接受" "$("$W/host1" utf16 <<< 'ed9fbf')" "d7ff"

echo
echo "────────────────────────────────────────"
if [[ $FAIL -eq 0 ]]; then
  echo "✅ C 实现与现有 Java 桩逐字节一致：$PASS 项"
  exit 0
else
  echo "❌ 失败 $FAIL 项 / 通过 $PASS 项" >&2
  echo "   C 与 Java 不一致 = 不能替换现有桩，禁止进流水线" >&2
  exit 1
fi
