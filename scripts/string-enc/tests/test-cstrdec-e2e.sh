#!/usr/bin/env bash
# test-cstrdec-e2e.sh — native 桩端到端闭环（加密 → 汇编 → 反汇编 → C 解密）
#
# 为什么需要它：test-cstrdec.sh 和 test-cstrdec-vs-java.sh 测的都是
# "算法层"正确性，都不覆盖"流水线真的把 native 桩写进 dex 并让 C 解开"。
# 本套件把 encrypt-strings.py --stub-impl native 的真实产物走完一圈：
#
#   ① 造一个含明文的 smali 类
#   ② encrypt-strings.py --stub-impl native 加密 + 注入 native 桩
#   ③ 从产物 smali 里抠出密文
#   ④ 用 C 实现（csrc/nc_strdec.c）解开，与原始明文逐字节比对
#   ⑤ apktool 真汇编桩 → 反汇编读回，验证结构（native 声明无方法体）
#
# 覆盖的历史雷区：
#   · 桩名每包随机 → 调用点与桩必须指向同一个类（漏一处 = NoClassDefFound）
#   · native 方法不许有方法体（报错三十九：A native method cannot have
#     any instructions，回编阶段才炸）
#   · loadLibrary 必须在 setKey 之前（否则 UnsatisfiedLinkError）
#   · 密钥必须以 array-data 字节形态落盘，不能是明文 hex 字符串
#
# 依赖：clang、python3、java+apktool.jar（缺 apktool 则跳过步骤 ⑤）
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$SE/../.." && pwd)"
CSRC="$SE/csrc"
APKTOOL="$ROOT/tools/apktool.jar"
CC="${CC:-clang}"
command -v "$CC" >/dev/null 2>&1 || CC=cc

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  ❌ $*" >&2; }
chk() { if [[ "$2" == "$3" ]]; then ok; else bad "$1（期望 $3，实得 $2）"; fi; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
SEED=0f1e2d3c4b5a6978

echo "══ 1. 编译 C 侧 ══"
"$CC" -std=c99 -O2 -Wall -Wextra -Wpedantic \
  -DNC_STRDEC_HOST_TEST -I"$CSRC" \
  "$CSRC/nc_strdec.c" "$HERE/host_cstrdec.c" -o "$W/host" \
  || { echo "❌ C 编译失败" >&2; exit 1; }
echo "   ✅ 通过"

echo "══ 2. 造含明文的类并跑 native 桩加密 ══"
mkdir -p "$W/dec/smali/com/demo"
# 多字节 + emoji + 引号转义 + 常见协议串，覆盖不同长度档位
cat > "$W/dec/smali/com/demo/A.smali" <<'SMALI'
.class public Lcom/demo/A;
.super Ljava/lang/Object;

.method public static h()Ljava/lang/String;
    .locals 1
    const-string v0, "支付订单校验失败，请联系客服😀"
    return-object v0
.end method

.method public static u()Ljava/lang/String;
    .locals 1
    const-string v0, "https://api.xixin.box/v1/pay/sign"
    return-object v0
.end method

.method public static e()Ljava/lang/String;
    .locals 1
    const-string v0, "emoji:😀🎉🚀 mixed 中文"
    return-object v0
.end method
SMALI
echo "com.demo.**" > "$W/rules.txt"

python3 "$SE/encrypt-strings.py" "$W/dec" "$W/rules.txt" \
  --stub-impl native --seed-hex "$SEED" --quiet \
  > "$W/enc.log" 2>&1 || { echo "❌ 加密失败:" >&2; cat "$W/enc.log" >&2; exit 1; }
echo "   ✅ 通过"

echo "══ 3. 产物结构断言 ══"
STUB="$(find "$W/dec" -name '*.smali' -path '*nc*' | head -1)"
[[ -z "$STUB" ]] && STUB="$(grep -rl 'nc-strdec-native' "$W/dec" | head -1)"
if [[ -z "$STUB" ]]; then
  bad "找不到 native 桩文件"
else
  ok
  grep -q '\.method public static native .*(Ljava/lang/String;)Ljava/lang/String;' "$STUB" \
    && ok || bad "桩缺 native 解密方法声明"
  # native 方法体必须为空
  if awk '/\.method public static native .*\(Ljava\/lang\/String;\)/{f=1;next} f&&/\.end method/{f=0} f&&NF&&!/^[[:space:]]*#/{print}' "$STUB" | grep -q .; then
    bad "native 方法体内有指令（报错三十九：回编会炸）"
  else
    ok
  fi
  # <clinit> 必须 loadLibrary（so 未加载则 native 方法全部不可用）
  grep -q 'loadLibrary' "$STUB" && ok || bad "桩 <clinit> 缺少 loadLibrary"
  # 密钥【不得】出现在 dex 里（2026-11-09 改设计：编译进 so 的 cfg 头）
  # 这条断言保证"改回把密钥写进 dex"会立刻红。
  if grep -q '\.array-data 1' "$STUB"; then
    bad "桩里出现 array-data（密钥又回到 dex 了 —— 本需求明确禁止）"
  else
    ok
  fi
  # 只看 invoke 指令行（注释里提到 ncSetKey 是在解释"为什么不用它"）
  if grep -E '^[[:space:]]*invoke-.*ncSetKey' "$STUB" >/dev/null; then
    bad "桩里仍调用 ncSetKey（密钥经 Java 注入 —— 会触发 NoSuchMethodError）"
  else
    ok
  fi
  # 桩内不得出现 16 位 hex 字符串（防止有人改回 const-string 形态）
  if grep -qE 'const-string[^,]*,[[:space:]]*"0x[0-9a-fA-F]{16}"' "$STUB"; then
    bad "桩内出现明文 hex 密钥串"
  else
    ok
  fi
fi

# 调用点与桩必须指向同一个类
# 取到第一个 ';' 为止（描述符），不要带后面的方法名
CALL_DESC="$(grep -oh 'invoke-static/range {[^}]*}, [^ ]*' "$W/dec/smali/com/demo/A.smali" \
            | head -1 | sed 's/.*}, //; s/\(;\).*/\1/')"
STUB_CLS="$(grep -o '^\.class public final .*' "$STUB" | sed 's/^\.class public final //')"
chk "调用点与桩类一致" "$CALL_DESC" "$STUB_CLS"

echo "══ 4. 端到端解密闭环（dex 产物 → C 解出原文）══"
n=0
while IFS= read -r payload; do
  n=$((n+1))
  got="$(printf '%s\n%s\n' "$SEED" "$payload" | "$W/host" dec)"
  if [[ "$got" == "ERR" || -z "$got" ]]; then
    bad "第 $n 条密文 C 解不开: $payload"
    continue
  fi
  txt="$(python3 -c "import sys;print(bytes.fromhex('$got').decode('utf-8'))")"
  case "$txt" in
    "支付订单校验失败，请联系客服😀"|"https://api.xixin.box/v1/pay/sign"|"emoji:😀🎉🚀 mixed 中文")
      ok ;;
    *) bad "第 $n 条解出错值: $txt" ;;
  esac
done < <(grep -oh 'const-string v0, "[^"]*"' "$W/dec/smali/com/demo/A.smali" \
         | sed 's/^const-string v0, "//; s/"$//')
echo "   $n 条密文闭环完成"

echo "══ 5. 真汇编往返（apktool SmaliBuilder）══"
if [[ ! -f "$APKTOOL" ]] || ! command -v javac >/dev/null 2>&1; then
  echo "   ⏭️  跳过：缺 apktool.jar 或 JDK"
else
  cat > "$W/D.java" <<'JAVA'
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.writer.builder.DexBuilder;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import brut.androlib.smali.SmaliBuilder;
import java.io.File;
public class D {
  public static void main(String[] a) throws Exception {
    DexBuilder b = new DexBuilder(new Opcodes(26));
    new SmaliBuilder(26).buildFile(new File(a[0]), b);
    b.writeTo(new FileDataStore(new File(a[1])));
  }
}
JAVA
  if javac -cp "$APKTOOL" -d "$W/cls" "$W/D.java" >"$W/javac.log" 2>&1; then
    if java -cp "$W/cls:$APKTOOL" D "$STUB" "$W/stub.dex" >"$W/dex.log" 2>&1; then
      # 注意：$(...) 会剥掉尾随换行，不能直接比 "dex\n"；
      # 改用"前 3 字节 + 非平凡长度"两个断言。
      chk "桩汇编后是合法 dex（魔数）" "$(head -c 3 "$W/stub.dex" 2>/dev/null)" "dex"
      [[ "$(stat -c%s "$W/stub.dex")" -gt 112 ]] && ok || bad "桩 dex 过小（不是合法 dex）"
      echo "   ✅ 真汇编通过（$(stat -c%s "$W/stub.dex") 字节）"
    else
      bad "桩汇编失败（native 声明形态非法？）"; tail -5 "$W/dex.log" >&2
    fi
  else
    echo "   ⏭️  跳过：apktool 驱动编译失败"
    head -3 "$W/javac.log" >&2
  fi
fi

echo
echo "────────────────────────────────────────"
if [[ $FAIL -eq 0 ]]; then
  echo "✅ native 桩端到端闭环通过：$PASS 项"
  exit 0
else
  echo "❌ 失败 $FAIL 项 / 通过 $PASS 项" >&2
  exit 1
fi
