#!/usr/bin/env bash
# protect.sh — 唯一加固总控（勾选式合并版，取代旧三个 pipeline 总控 + run-modules.sh）
#
# 模块契约：<输入.apk> <输出_unsigned.apk> [--sigcheck] [--dex2c [规则文件]]
#           [--stringenc 规则文件] [--envcheck] [--packer] [--packer-smaller] [--anti-diff]
#   - 输入/输出/规则路径一律 normalize 成绝对路径（报错三教训：dex2c 运行时要切目录，
#     相对输出路径会被写进 dex2c 目录）
#   - 主进程 cwd 全程不漂移：dex2c 的 dcc.py 在子 shell 里运行（module_cd_run）
#   - 无论勾选多少模块，apktool 解包/回编只做一次（旧联合方案要两次，这是本次合并
#     的额外收益，对产物无行为差异——sig_check.c 以 constructor 方式并入同一 so）。
#
# 行为对齐（与旧脚本逐一等价）：
#   只 --sigcheck        → 提取指纹 → sig_check.c + nc_link.c 单独成 so → inject-loadlib.py
#                          双保险插桩（<clinit> + onCreate）→ Java 层判决式签名
#                          联动注入(§3.11,判决在 so/杀在 Java,so 缺失即 fail-closed)→ 回编
#   只 --dex2c [规则]      → 规则转 filter → 转译 → mark-native.py 壳替换 → 回编
#   只 --stringenc 规则  → 规则转正则 → 字符串加密(注入 Java 解密桩) → 回编
#   --sigcheck --dex2c       → 提取指纹 → 转译 → sig_check.c 合入同一 NDK 工程 →
#                          mark-native.py 壳替换（不插 loadLibrary：onCreate 已抽进 so，
#                          删 <clinit> 的 loadLibrary 会让 native 壳直接自爆）→ 回编
#   --envcheck           → 环境检测(Frida/Xposed/调试器/libc内存CRC/常驻复查)并入 libnc.so(可与其余模块任意组合)
#   --packer             → 基础加壳(dpt-shell)：必须最后跑，作用于回编并 zipalign
#   --packer-smaller     → 随 --packer 的子选项(体积优化)：dpt --smaller，填料改统一 0x0e
#   --dpt-extra-args 文本 → 通用 dpt 参数通道(空格分隔,随加壳生效;只构成打包参数注入面)
#   --exclude-abi 值      → 带值参数标准件(报错四十四):剔除 ABI 的 so 目录,经环境变量传 packer.sh
#                          之后的成品包；勾了加壳则跳过本脚本的 finish_apk，
#                          由 packer.sh 的产物直接作为最终输出(加壳包不能二次 zipalign)
#
# 转译引擎(2026-10-14 接入;2026-12 旧引擎 dcc 下线,dex2c 成为唯一引擎):
#   --dex2c  引擎 tools/dex2c.zip(源码在父目录 ../Dex2C/,自研 fork 可查;
#            APKEditor 1.4.7 解包、构造函数守卫、Termux/Linux/Windows 跨平台)
#   产出工程包(jni/nc/*.cpp + compiled_methods.txt),mark-native/stringenc 等下游消费方不变
#
# 转译类名来源决策(规则优先,修复联合勾选无视用户规则的 bug):
#   提供了规则(无论是否联合勾选) → 用户规则(rules-to-filter.py)
#   未提供规则 + 联合勾选 sigcheck → 自动抽主类(make-filter-from-apk.py)
#   未提供规则 + 未勾 sigcheck   → 报错退出(fail-fast,无类名来源)
#
# --stringenc [规则文件]   → dex 层字符串常量加密(与 dex2c 同款规则语法,内部复用
#   rules-to-filter.py 的 class_rule_to_filter 做类匹配)。规则必填(没有"自动抽
#   主类"的兜底:字符串加密必须明确范围,否则可能误伤)。加密对象 = const-string
#   字面量 + R8 折叠的 static final String 字段常量;系统类/框架依赖类按硬编码
#   名单排除,规则写 ** 也不突破。产物侧用纯 Java 解密桩 Lcom/nc/strdec/StrDec; 解,
#   不依赖 so。
#
# 固定执行顺序（与勾选顺序无关）：sigcheck → dex2c → stringenc → anti-diff → packer
#
# 前置依赖（由 workflow 安装）: python3 + dex2c requirements、JDK 17、Android NDK、apktool
set -euo pipefail

# ── set -e 静默退出的诊断（2026-10-20 加，源自一次难查的 CI 红）─────────
# 问题：protect.sh 里 set -e 让某条命令非零时【静默退出】，日志里没有任何
#   Error/Traceback，只是凭空停在某行之后。实例：dex2c+sigcheck 组合下
#   inject-javacheck.py 返回 2（native 壳跳过调用点，设计内行为），
#   当时 529 行无保护 → set -e 直接杀掉流水线 → 日志停在"自适应命名"后，
#   无任何线索，只能靠复现才定位到。
# 修法：trap ERR 打出行号 + 命令 + 退出码，让"死在哪"始终可读。
# ⚠️ 不改变任何执行逻辑，只加可观测性；且 ERR trap 只在 set -e 生效时触发，
#    不会捕获 `if ! cmd` / `cmd || true` 这类显式处理过的失败。
_guard_err() {
    local rc=$? line=${1:-?}
    echo "❌ protect.sh 异常退出: rc=$rc 行号=$line 命令=${BASH_COMMAND:-<unknown>}" >&2
    echo "   （set -e 触发。若这是预期内的非致命返回，请用 'cmd || true' 或" >&2
    echo "    'if ! cmd; then ...' 显式处理，别让它冒到 set -e）" >&2
}
trap '_guard_err $LINENO' ERR

# ── 解析勾选（勾选顺序无关，执行顺序由下面 STEP 区硬编码） ────────────
usage() {
  # 打印文件头部的注释块(第 2 行起、到第一条非注释行/代码前为止),
  # 用 awk 动态界定范围 —— 头部注释增删行后不必再改数字(此前写死 2,32p 已踩坑)
  awk 'NR>=2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
  exit 1
}

[[ $# -ge 2 ]] || usage
IN_APK="$1"
OUT_APK="$2"
shift 2
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"    # apk-protect-action 根目录
MODULE_TAG="protect"
# shellcheck source=../lib/common.sh
source "$ROOT/scripts/lib/common.sh"
# shellcheck source=../lib/lib-repack.sh
source "$ROOT/scripts/lib/lib-repack.sh"
# shellcheck source=../lib/lib-ndk.sh
source "$ROOT/scripts/lib/lib-ndk.sh"

DEX2C_DIR=""                                  # dex2c 工具目录(--dex2c 勾选时经 ensure_dex2c 解压填充)
GUARD_SRC=""                                  # so 加密设施目录(经 ensure_nox 从 tools/nox.zip 解压填充)
GUARD_LIB_DIR=""                              # 静态库形态时的 lib 目录；源码形态为空
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

WANT_SIGCHECK=0; WANT_DEX2C=0; WANT_PACKER=0; WANT_ENVCHECK=0; DEX2C_RULES=""
PACKER_SMALLER=0   # 报错四十三:--packer-smaller(体积优化)→ 环境变量传 packer.sh
DPT_EXTRA_ARGS_TEXT=""  # 通用 dpt 参数通道(报错四十三后方向调整):自由文本,空格分隔
EXCLUDE_ABI=""          # 带值参数标准件(报错四十四):--exclude-abi 的值,经环境变量传 packer.sh
WANT_STRINGENC=0; STRING_RULES=""
WANT_ANTIDIFF=0
WANT_DEX2C_STUB=0     # 联动子复选框:把解密桩内核 dn() 也抽进 dex2c(见 STEP2 顺序手术)
# --stringenc-native（2026-11-09）：解密桩改成纯 C 实现。
#   java（默认）：现有 StrDec.java 桩，零漂移
#   native      ：算法在 csrc/nc_strdec.c，编进 libnc.so，dex 侧只有 native 声明
# 与 --dex2c-stub 互斥（那需要 Java 内核才能转译）。
STUB_IMPL="java"
WANT_NATIVE_STUB=0
# Amice 混淆（2026-11-05）：编译期 pass，作用于 so 的 .text。
# 只影响 NDK 编译参数，不影响 dex 层任何步骤。
WANT_OBFUSCATE=0
OBF_MBA=0
OBF_FLATTEN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sigcheck) WANT_SIGCHECK=1; shift ;;
    --dex2c)    WANT_DEX2C=1; shift
                # 规则文件可选(联合勾选 sigcheck 时可省略 → 自动抽主类)
                if [[ $# -ge 1 && "$1" != --* ]]; then
                  DEX2C_RULES="$(normalize_path "$1")"; shift
                fi ;;
    --stringenc) WANT_STRINGENC=1; shift
                # 规则文件必填(字符串加密必须明确范围,不做"自动抽主类"兜底)
                if [[ $# -ge 1 && "$1" != --* ]]; then
                  STRING_RULES="$(normalize_path "$1")"; shift
                fi ;;
    --envcheck) WANT_ENVCHECK=1; shift ;;
    --packer)   WANT_PACKER=1; shift ;;
    --packer-smaller) WANT_PACKER=1; PACKER_SMALLER=1; shift ;;
    --exclude-abi)
      # 带值参数标准件(报错四十四):schema arg_value 子项的值(x86,x86_64),
      # 单 token 无空白(resolver 已校验,此处防御性再验)。经环境变量传 packer.sh。
      if [[ $# -ge 2 ]]; then
        EXCLUDE_ABI="$2"; shift 2
        [[ "$EXCLUDE_ABI" =~ ^[A-Za-z0-9_,.\-]+$ ]] || { log_err "--exclude-abi 值非法: $EXCLUDE_ABI"; exit 1; }
      else
        log_err "--exclude-abi 缺值"; exit 1
      fi ;;
    --dpt-extra-args)
      # 通用 dpt 参数通道:值无条件取下一 token(dpt 参数本身合法地以 -- 开头,
      # 不能套 --stringenc 的 "$1" != --* 守卫);缺值视为空(不附加)。
      # 安全边界:自由文本只构成打包参数注入面,最坏打包失败;secrets 不经此路径。
      if [[ $# -ge 2 ]]; then DPT_EXTRA_ARGS_TEXT="$2"; shift 2; else shift; fi ;;

    --anti-diff) WANT_ANTIDIFF=1; shift ;;
    --dex2c-stub) WANT_DEX2C_STUB=1; shift ;;
    # 纯 C 解密桩（2026-11-09）。隐含 stringenc 开启（没有字符串加密就没有桩）。
    --stringenc-native) WANT_STRINGENC=1; WANT_NATIVE_STUB=1; STUB_IMPL=native; shift ;;
    # Amice 混淆（2026-11-05）。子复选框隐含父模块开启（与 --packer-smaller 同惯例）。
    # 值为空时由 lib-ndk.sh 按"父模块开、子项默认"取默认组合（MBA on / flatten off）。
    --obfuscate) WANT_OBFUSCATE=1; shift ;;
    --obfuscate-mba) WANT_OBFUSCATE=1; OBF_MBA=1; shift ;;
    --obfuscate-flatten) WANT_OBFUSCATE=1; OBF_FLATTEN=1; shift ;;
    *)          log_err "未知参数: $1"; usage ;;
  esac
done

TOTAL=$((WANT_SIGCHECK + WANT_DEX2C + WANT_PACKER + WANT_ENVCHECK + WANT_STRINGENC + WANT_ANTIDIFF + WANT_OBFUSCATE))
if [[ $TOTAL -eq 0 ]]; then
  log_err "未勾选任何模块（--sigcheck / --dex2c [规则] / --obfuscate[mba|flatten] / --stringenc 规则 / --envcheck / --anti-diff / --packer）"
  exit 1
fi

# 联动子复选框的依赖校验(防呆)
# ⚠️ 2026-11-02 架构修正：--dex2c-stub 只需要 --stringenc。
#
# 原代码还要求必须勾 --dex2c，理由是「桩要交给 dex2c 转译」——
# 那把【dex2c 模块】和【dex2c 接口】混为一谈了：
#   · 模块跑在 STEP2（桩尚未注入）→ 看不到桩，勾了也抽不到
#   · 接口由 stringenc 在注入后自己调用 → 这才是真正干活的那条路
# 所以「必须勾 --dex2c」不是需求，是历史误解；照它执行会让
# 「只勾字符串加密 + 解密桩抽 so」这个合法组合直接报错退出。
if [[ $WANT_DEX2C_STUB -eq 1 ]]; then
  if [[ $WANT_STRINGENC -eq 0 ]]; then
    log_err "--dex2c-stub 必须与 --stringenc 同时勾选(没有字符串加密就没有解密桩可抽)"
    exit 1
  fi
fi

# ── 纯 C 桩的前提与互斥（2026-11-09）────────────────────────────────
# 与 --dex2c-stub 互斥：那条路的前提是"Java 内核存在、交给 dex2c 转译"，
# 而 native 桩根本没有 Java 内核。两者同时出现 = 配置自相矛盾，
# fail-fast 好过让其中一条静默失效（历史上"以为防了其实没防"都是这样来的）。
if [[ $WANT_NATIVE_STUB -eq 1 ]]; then
  if [[ $WANT_DEX2C_STUB -eq 1 ]]; then
    log_err "--stringenc-native 与 --dex2c-stub 互斥"
    log_err "    前者把算法编进 libnc.so（无需 dex2c）；后者靠 dex2c 转译 Java 内核。"
    log_err "    两者同时勾 = 没有可转译的对象，请只保留一个。"
    exit 1
  fi
  if [[ $WANT_STRINGENC -eq 0 ]]; then
    log_err "--stringenc-native 必须与 --stringenc 同时勾选"
    exit 1
  fi
fi

# 转译层统一变量:唯一引擎,共用同一套规则来源决策与 STEP3+ 下游(引擎无关)
# ⚠️ 2026-11-02：dex2c_stub 只勾（无 dex2c 模块）时也要启动引擎 —— 那是
# 「stringenc 调 dex2c 接口转译解密桩」这条内部通道，不涉及用户类名规则。
# 用 WANT_ENGINE 表达「引擎要跑」，WANT_TRANSPILE 继续表达「抽用户指定的类」。
WANT_TRANSPILE=$WANT_DEX2C
WANT_ENGINE=0
if [[ $WANT_DEX2C -eq 1 || $WANT_DEX2C_STUB -eq 1 ]]; then WANT_ENGINE=1; fi
TRANSPILE_RULES="$DEX2C_RULES"

# obfuscate 是编译期 pass，必须作用于 so。没有 so 来源时它无事可做。
# 不静默跳过（那会让用户以为混淆生效了），直接 fail-fast。
if [[ $WANT_OBFUSCATE -eq 1 \
      && $WANT_SIGCHECK -eq 0 && $WANT_TRANSPILE -eq 0 && $WANT_ENVCHECK -eq 0 ]]; then
  log_err "勾选了代码混淆（--obfuscate），但没有可混淆的 so"
  log_err "     混淆作用于 libnc.so，请同时勾选其中至少一个："
  log_err "       签名校验(--sigcheck) / Dex2C(--dex2c) / 环境检测(--envcheck)"
  exit 1
fi


# ── 入口契约校验：所有环境假设在开工前 fail-fast ────────────────────
IN_APK="$(normalize_path "$IN_APK")"
OUT_APK="$(normalize_path "$OUT_APK")"
require_file "$IN_APK" "输入 APK"
repack_require_tools
# so 加密设施不在本仓库保存源码，统一从 tools/nox.zip 解压（上游 nox 仓库）。
# 放在入口处一次性解压：protect.sh 的 22 处引用与 4 套回归测试都依赖该路径。
GUARD_SRC="$(ensure_nox)"
require_dir "$GUARD_SRC" "so 加密设施目录"
if [[ $WANT_ENGINE -eq 1 ]]; then
    DEX2C_DIR="$(ensure_dex2c)"             # 从 tools/dex2c.zip 解压(幂等)并取得 Dex2C 目录
    require_dir "$DEX2C_DIR" "dex2c 工具目录"
  # 规则文件:提供了就必须非空;没提供且未联合 sigcheck → 无类名来源,fail-fast
  # ⚠️ 只在【dex2c 模块】勾选时校验；只勾 dex2c_stub 时无用户类名规则可言
  if [[ $WANT_DEX2C -eq 0 ]]; then
    :
  elif [[ -n "$TRANSPILE_RULES" ]]; then
    require_nonempty_file "$TRANSPILE_RULES" "dex2c 规则文件"
  elif [[ $WANT_SIGCHECK -eq 0 ]]; then
    log_err "--dex2c 未提供规则文件且未勾选 --sigcheck,没有类名来源"
    log_err "     (提供规则文件: --dex2c rules.txt;或联合 --sigcheck 自动抽取主类)"
    exit 1
  fi
fi
if [[ $WANT_STRINGENC -eq 1 ]]; then
  if [[ -z "$STRING_RULES" ]]; then
    log_err "--stringenc 必须提供类名规则文件（字符串加密不做自动抽主类的兜底）"
    log_err "     规则语法: com.test.** / com.test.* / 精确类名 /"
    log_err "     activity*(需 --classes) / !com.test.libs.** 排除 / # 注释"
    exit 1
  fi
  require_nonempty_file "$STRING_RULES" "stringenc 规则文件"
fi

log "勾选 $TOTAL 个模块，按固定顺序执行: sigcheck → dex2c → stringenc → anti-diff → packer"

# ── 纯 C 桩：种子必须在 STEP3 之前定下来（2026-11-09）──────────────
# 为什么：C 侧的 RegisterNatives 需要桩类名，而桩名与种子同源生成。
# 种子一旦在 STEP5 才生成，STEP3 就无法预算桩名（实测就是这么失败的）。
# 这里生成一次，STEP3 用它算桩名、STEP5 用同一个种子 + 同一个桩名加密，
# 两侧必然一致。
# ⚠️ 种子是密钥材料：只写进 $WORK（进程结束即删），不打印明细。
if [[ $WANT_NATIVE_STUB -eq 1 ]]; then
  if [[ -n "${CSTUB_SEED_HEX:-}" ]]; then
    if [[ ! "$CSTUB_SEED_HEX" =~ ^[0-9a-fA-F]{16}$ ]]; then
      log_err "CSTUB_SEED_HEX 必须是 16 位 hex（调试/复现用）"
      exit 1
    fi
    printf '%s\n' "${CSTUB_SEED_HEX,,}" > "$WORK/stub_seed_for_decl.txt"
    log_info "纯 C 桩种子: 使用外部指定值（仅调试）"
  else
    python3 -c "import secrets;print(secrets.token_hex(8))" > "$WORK/stub_seed_for_decl.txt"
    log_info "纯 C 桩种子: 已生成（8 字节随机，不落日志）"
  fi
fi

# ── STEP 1: 提取证书指纹，生成 sig_hash.h + sig_guard2.h（仅 --sigcheck） ──
# 2026-10 双线:同时生成第二份【独立】标准答案(sig_guard2.h),供
# sig_guard2.c 使用 —— 两条线的 salt/派生公式/处置路径全独立,
# 攻击者 patch 第一线的 delayed_kill 后,第二线照常判定。
if [[ $WANT_SIGCHECK -eq 1 ]]; then
  log_step 1 6 "提取证书指纹"
  "$ROOT/scripts/guard/hash/make-sig-hash.sh" "$IN_APK" \
      "$WORK/sig_hash.h" "$WORK/sig_guard2.h"
fi

# ── STEP 2: dex2c 转译（--dex2c 勾选时；--no-build 只产出工程包） ─────────
# 联动(stringenc↔dex2c)的顺序手术:
#   dex2c 从【APK】里读 dex(tools/Dex2C/dcc.py compile_dex→auto_vm→androguard),
#   而解密桩是 stringenc 在 STEP5 才注入 smali 的 —— 正常顺序下 STEP2 时
#   APK 里根本没有桩类,filter 写任何名字都转不到它。
#   故勾选 --dex2c-stub 时,先在 STEP2 之前跑一轮 stringenc(解包→加密+注桩
#   →回编成 APK'),dex2c 转译 APK' 就能命中桩;STEP5 再跳过一次 stringenc。
#   代价:apktool 解包/回编从 1 次变 2 次(旧三总控合并时消除过的开销,
#   为联动加回来;dex 8MB 量级约 +30~60s)。
# ⚠️ 2026-11-02 架构修正：dex2c_stub 是【stringenc 调 dex2c 接口】的独立联动，
# 不是「dex2c 模块的修饰符」。
#
# 两种角色的区别（这决定了本条件怎么写）：
#   · dex2c 模块      —— 给客户端用。输入是【未加固的原始 APK】，只能抽
#                        原始 dex 里【已存在】的类；类名由用户规则/主类决定。
#   · dex2c 接口      —— 给我们内部模块用。任意时刻可调，能抽【流水线中途
#                        注入】的类；目标固定，不接受用户类名。
#
# 解密桩就是「流水线中途注入」的典型：它不存在于原始 APK，
# 所以 dex2c 模块（STEP2，跑在注入之前）根本看不到它；
# 而 STEP2 跑完后模块已结束，无法再调。→ 只能由 stringenc 在注入后
# 自己调【接口】完成转译。
#
# 因此本条件【不再要求 WANT_DEX2C】：只勾 dex2c_stub（+ stringenc）时，
# 接口也要启动，只转译桩的 4 个方法。两模块可同时勾，filter 合并。
LINK_STUB=0
if [[ $WANT_STRINGENC -eq 1 && $WANT_DEX2C_STUB -eq 1 ]]; then
  LINK_STUB=1
fi
if [[ $LINK_STUB -eq 1 ]]; then
  log_step 2 6 "字符串加密前置（联动：桩须先于 dex2c 进 APK）"
  repack_unpack "$WORK/pre" "$IN_APK"
  # activity* 需要 Activity 类列表 → 从 Manifest 动态提取(同 STEP5 侧做法)
  if grep -q '^[[:space:]]*activity\*[[:space:]]*$' "$STRING_RULES"; then
    log_info "检测到 activity* 规则,从 Manifest 提取 Activity 列表"
    python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" \
      "$WORK/.placeholder_pre.txt" --classes "$WORK/activity_classes.txt" \
      --on-fail skip || true
  fi
  python3 "$ROOT/scripts/string-enc/encrypt-strings.py" clean "$WORK/pre"
  PRE_ENC_ARGS=()
  [[ -f "$WORK/activity_classes.txt" ]] && PRE_ENC_ARGS+=(--classes "$WORK/activity_classes.txt")
  # 关键差异:前置轮【不传 --exclude-methods】—— 此刻 dex2c 还没跑,
  # 不知道哪些方法会被抽走。后果仅体积(被抽方法里的字符串白加密后随方法
  # 变 native 壳),正确性无碍;STEP5 主轮仍按 compiled_methods 精确跳过。
  #
  # packer 联动（勾了 packer 时）：前置轮【只产出桩 dex，不摘除桩】。
  # 为什么不能在这里摘：紧接着的 dex2c 要靠桩类存在才能把 dn()/mix64()/keyByte()
  # 转译进 libnc.so（--emit-stub-filter 的四个方法必须真实存在于 dex）。
  # 摘除动作放到 STEP 5 解包 pre-encrypted.apk 之后做（见 STEP5 的
  # --remove-stub-only 调用）。
  PRE_ENC_ARGS2=()
  if [[ $WANT_PACKER -eq 1 ]]; then
    # ⚠️ --assume-stub-transpiled（2026-11-02 修）：
    #   本函数（emit_stub_dex）在前置轮调用，那时 dex2c 还没跑、
    #   compiled_methods.txt 还不存在。旧判据 _stub_transpiled() 因此
    #   恒返回 False → 桩永远不 native 化 → 用户勾了「解密桩也抽进 so」
    #   也白勾（CI 41447382614 实证：日志同时出现「桩未被 dex2c 转译」
    #   与「compiled_methods 剔除桩条目 4 条」两句自相矛盾的话）。
    #   走到这里的前提是 LINK_STUB=1，而 LINK_STUB 的定义就是
    #   `WANT_DEX2C && WANT_STRINGENC && WANT_DEX2C_STUB` —— 即 dex2c
    #   必然会转译桩。所以这里传 assume 是【确定事实】而非猜测。
    PRE_ENC_ARGS2+=(--emit-stub-dex "$WORK/stub.dex" --keep-stub-in-dex
                    --stub-seed-from-shell --emit-seed "$WORK/stub_seed.txt"
                    --assume-stub-transpiled)
  fi
  python3 "$ROOT/scripts/string-enc/encrypt-strings.py" \
    "$WORK/pre" "$STRING_RULES" "${PRE_ENC_ARGS[@]}" "${PRE_ENC_ARGS2[@]}" \
    --apk "$IN_APK" \
    --emit-stub-filter "$WORK/stub_filter.txt"
  # 联动前提校验:桩必须真的存在(零加密 + 无旧桩 = 联动空转,fail-fast
  # 而非让用户以为生效)。encrypt-strings 在无桩时写空文件。
  if [[ ! -s "$WORK/stub_filter.txt" ]]; then
    log_err "--dex2c-stub 联动生效前提不成立:本轮 stringenc 没有注入解密桩"
    log_err "     (规则零命中且无旧桩 → 无桩可抽;请检查规则是否命中业务类)"
    exit 1
  fi
  log_info "联动 filter: $(cat "$WORK/stub_filter.txt")"
  repack_build "$WORK/pre" "$WORK/pre-encrypted.apk"
  LINK_APK="$WORK/pre-encrypted.apk"
else
  LINK_APK="$IN_APK"
fi

if [[ $WANT_ENGINE -eq 1 ]]; then
  log_step 2 6 "核心方法转 C（dex2c）"
  # 类名来源决策(规则优先,修复:联合勾选 sigcheck 时无视用户规则的 bug):
  #   0) 只勾 dex2c_stub（无 dex2c 模块）→ 不抽用户类，filter 只有桩（下方追加）
  #   1) 提供了用户规则 → 一律走用户规则(无论是否联合勾选)
  #   2) 未提供规则 + 联合勾选 sigcheck → Manifest 动态解析 LAUNCHER 自动生成 filter
  if [[ $WANT_TRANSPILE -eq 0 ]]; then
    # 只抽桩模式：先放一个空 filter，稍后由 stub_filter 追加。
    # 这是「stringenc 调 dex2c 接口」的内部通道 —— 目标固定为解密桩的
    # 4 个方法，不接受用户类名（用户类名是 dex2c 模块的职责）。
    : > "$WORK/dcc_filter.txt"
    DCC_FILTER="$WORK/dcc_filter.txt"
    log_info "filter 来源: 仅 dex2c_stub（不抽用户类，只转译解密桩）"
  elif [[ -n "$TRANSPILE_RULES" ]]; then
    log_info "filter 来源: 用户规则 $TRANSPILE_RULES"
    python3 "$ROOT/scripts/filter/rules-to-filter.py" "$TRANSPILE_RULES" \
      "$WORK/dcc_filter.txt" --classes "$WORK/activity_classes.txt"
    # activity* 需要 Activity 类列表 → 从 Manifest 动态提取
    if grep -q '^[[:space:]]*activity\*[[:space:]]*$' "$TRANSPILE_RULES"; then
      log_info "检测到 activity* 规则,从 Manifest 提取 Activity 列表"
      python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$LINK_APK" \
        "$WORK/.placeholder_filter.txt" --classes "$WORK/activity_classes.txt" \
        --on-fail skip || true
    fi
    # 全量规则防呆(2026-10-15 排查教训): ** 会被 rules-to-filter.py 转成
    # L.*;.*(全 App 转译)。上游引擎对全量转译明确不支持——混淆过的大方法会
    # 生成引用未声明变量的坏 C,报错形态是 NDK 编译期 undeclared identifier,
    # 极难归因。在源头拦下,报人话(上游 dcc.py 内置护栏只拦字面 .*,拦不住
    # L.*;.*,必须在流水线层补)。
    if grep -qE '^L\.\*;\.\*$|^\.\*$' "$WORK/dcc_filter.txt"; then
      log_err "检测到全量转译规则(**): 会把整个 App 的所有方法抽进 so,上游明确不支持"
      log_err "     (混淆过的大方法会生成坏 C 代码,报错是难排查的 undeclared identifier)"
      log_err "     正确姿势: ①规则留空+勾选签名校验 → 自动抽主类; ②定向规则,如 com.xixin.box.**"
      exit 1
    fi
    DCC_FILTER="$WORK/dcc_filter.txt"
  elif [[ $WANT_SIGCHECK -eq 1 ]]; then
    log_info "filter 来源: 未提供规则,自动抽取主类(make-filter-from-apk)"
    # 动态解析 Manifest 里的 LAUNCHER activity → 自动生成 filter（一行一个类）
    python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$LINK_APK" \
      "$WORK/auto_filter.txt" --classes "$WORK/activity_classes.txt" --on-fail error
    # auto_filter.txt 已是 dcc filter 正则格式(见 make-filter-from-apk.py),
    # 直接使用,不要二次转换 —— 曾经二次转换产生畸形正则导致 no compiled methods
    DCC_FILTER="$WORK/auto_filter.txt"
  fi

  # 只联 --dex2c(唯一引擎):桩名每包随机,规则由 stringenc 前置轮的 --emit-stub-filter 反向产出。
  if [[ $LINK_STUB -eq 1 ]]; then
    cp "$DCC_FILTER" "$WORK/dcc_filter_linked.txt"
    cat "$WORK/stub_filter.txt" >> "$WORK/dcc_filter_linked.txt"
    DCC_FILTER="$WORK/dcc_filter_linked.txt"
    log_info "联动:桩内核已追加进 dex2c filter（$(grep -c . "$WORK/stub_filter.txt") 条: dn/mix64/keyByte）"
  fi

  # 引擎要跑，filter 就不能为空 —— dcc.py 对空 filter 只打
  # `No methods compiled!` 然后不产出工程包，下游 require_file 才报错，
  # 那时错误信息已指向"工程包缺失"而非"filter 为空"，难归因。
  if [[ ! -s "$DCC_FILTER" ]] || ! grep -qv '^[[:space:]]*$' "$DCC_FILTER"; then
    log_err "dex2c filter 为空：无任何类/方法可转译"
    log_err "     勾了 dex2c 请提供类名规则或配合签名校验自动抽主类；"
    log_err "     只勾 dex2c_stub 时应由 stringenc 前置轮产出桩 filter（检查规则是否命中业务类）"
    exit 1
  fi

  # dex2c 的 dcc.py 要在自身目录运行 → 子 shell 隔离，主进程 cwd 不漂移。
  # CLI: -i/-o 旗标式且 -o 必填(no-build 下 -o 不落地产物,传哑值),
  # 另传 --allow-global 对齐规则语义、--disable-signing 防御性关签名(no-build 下本就不执行)。
  #
  # ── --dynamic-register：业务方法名不进 .dynsym（2026-11-02）────────────
  # 不开这个开关时 writer.py:111 生成 `extern "C" JNIEXPORT ... Java_xxx`，
  # 而 JNIEXPORT 自带 visibility("default") → 对 -fvisibility=hidden 免疫 →
  # 业务方法名 + 精确字节数全部躺在 .dynsym 里（实测 7 个导出，含
  # MainActivity.k = 21700 B —— 这个数字本身就是情报，等于告诉逆向者
  # 哪个方法最值得啃）。
  #
  # 开启后 writer.py:106 走另一分支，生成 `void Java_xxx(...)`，【不带
  # JNIEXPORT】→ 恢复受 -fvisibility=hidden 支配 → 变 hidden → 不导出；
  # 改由 DynamicRegister.cpp 的 FindClass + RegisterNatives 表在
  # JNI_OnLoad 里注册（Dex2C.cpp:283 无条件调用）。
  #
  # ⚠️ 曾有前车之鉴（a7d9cbc，2026-10-19 回退动态注册）：那次崩的原因是
  #    【constructor(200) 里调 FindClass】—— dlopen 内部执行，classloader
  #    上下文未建立。本次走 JNI_OnLoad（ART 主动回调，会切到发起 load 的
  #    loader），位置不同。真机实证（Redmi 2602BRT18C / Android 17 /
  #    arm64，loadLibrary 在 <clinit> 里、FindClass 目标就是该 <clinit>
  #    所属类）：EARLY FindClass OK / RegisterNatives -> 0。
  #    不要把 constructor 的失败经验平移到 JNI_OnLoad 上。
  module_cd_run "$DEX2C_DIR" python3 dcc.py -i "$LINK_APK" -o "$WORK/dex2c-no-build.apk" \
    --project-archive "$WORK/dcc-project.zip" \
    --no-build \
    --disable-signing \
    --allow-global \
    --dynamic-register \
    --filter "$DCC_FILTER"

  require_file "$WORK/dcc-project.zip" "dex2c 工程包（filter 可能未命中任何方法）"
fi

# ── STEP 3: 组装 NDK 工程 → 编译 libnc.so ───────────────────────────
# 报错二十三:stringenc 是纯 dex 层模块,不产出/不依赖任何 so。
# 只勾 stringenc(或未来其它纯 dex 组合)时,STEP 3/4 必须整体跳过 ——
# 否则 ndk_write_mk 会往一个从未创建的 jni/ 目录里 cat > Application.mk,
# 报 "No such file or directory"(报错信息里的 tmp.XXX/project/jni 路径即此)。
# 有 so 需求的组合:sigcheck / 转译(--dex2c) / envcheck 任一勾选。
# obfuscate（2026-11-05）也在其列 —— 它是编译期 pass，必须有 so 可编。
# ⚠️ 但单独勾 obfuscate 而不勾任何 so 来源，等于没有可混淆的对象。
#    那种组合在下面有显式 fail-fast（不能静默跑一遍没效果的流程）。
# ⚠️ 2026-11-09 扩条件：$WANT_NATIVE_STUB 也要编 so。
#    纯 C 桩把算法放在 libnc.so 里，不编 so = 桩没有任何实现
#    → 首个加密字符串即 UnsatisfiedLinkError（启动闪退）。
#    这条打破了"纯 stringenc 整体跳过 STEP3/4"（报错二十三）的既有规则，
#    但只对 native 桩这一条新路径生效，Java 桩组合行为完全不变。
if [[ $WANT_SIGCHECK -eq 1 || $WANT_TRANSPILE -eq 1 || $WANT_ENVCHECK -eq 1 \
      || $WANT_NATIVE_STUB -eq 1 ]]; then
log_step 3 6 "组装 NDK 工程"
mkdir -p "$WORK/project"

# 中文流程日志文案表(2026-11 用户需求):扫描 sig_check.c/env_check.c 的
# LSG 标记注释生成 sig_log_data.h(XOR 密文,strings 不泄语义)。
# ⚠️ 2026-10-21 扩条件：boot.c（锁箱设施，见下方拷贝条件）无条件 include
#    本头文件（其 /proc 路径字面量走 LSGS），故只要编 so 就必须生成——
#    原条件"sigcheck 或 envcheck"漏了 transpile-only 组合
#    （dex2c+stringenc-stub 不勾 sigcheck）→ 编译期 file not found。
#    生成器输入仍只扫 sig_check/env_check（boot.c 复用它们的标记，
#    不另立——见 boot.c 头部注释）。
if [[ $WANT_SIGCHECK -eq 1 || $WANT_ENVCHECK -eq 1 || $WANT_TRANSPILE -eq 1 ]]; then
  # ⚠️ 2026-11-08：探针拆到 env_probes.c 后，LSGS 标记分散在两个文件里
  #    （路径/线程名等标记在 env_check.c，特征串在 env_probes.c）。
  #    生成器必须两个都扫 —— 漏扫会让 sig_log_data.h 缺枚举
  #    → 编译期 "undeclared identifier"（fail-fast，比运行期静默好）。
  python3 "$ROOT/scripts/guard/log/make-sig-log.py" \
    "$ROOT/scripts/guard/src/sig_check.c" \
    "$ROOT/scripts/guard/src/env_check.c" \
    "$ROOT/scripts/guard/src/env_probes.c" \
    "$ROOT/scripts/guard/src/sig_guard2.c" \
    "$WORK/sig_log_data.h"
fi

if [[ $WANT_TRANSPILE -eq 1 ]]; then
  unzip -q "$WORK/dcc-project.zip" -d "$WORK/project"
fi

if [[ $WANT_SIGCHECK -eq 1 ]]; then
  # 联合时并入 dcc 工程 jni/nc/；单独时放 jni/ 根 —— ndk_write_mk 的两级
  # wildcard 都收（报错十一/十三教训），两种布局等价
  # nc_link.c = Java 层判决式联动(§3.11):标准值比对在 so 内,零新头文件依赖
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    mkdir -p "$WORK/project/jni/nc"
    SIG_DST="$WORK/project/jni/nc"
  else
    mkdir -p "$WORK/project/jni"
    SIG_DST="$WORK/project/jni"
  fi
  cp "$ROOT/scripts/guard/src/sig_check.c"    "$SIG_DST/"
  cp "$ROOT/scripts/guard/src/nc_link.c"      "$SIG_DST/"
  cp "$ROOT/scripts/guard/src/nc_link_jni.c"  "$SIG_DST/"
  cp "$ROOT/scripts/guard/src/nc_link_jni.h"  "$SIG_DST/"
  cp "$ROOT/scripts/guard/src/sig_guard2.c"   "$SIG_DST/"
  cp "$GUARD_SRC/nc_guard_layout.h"              "$SIG_DST/"
  cp "$WORK/sig_hash.h"                          "$SIG_DST/"
  cp "$WORK/sig_guard2.h"                        "$SIG_DST/"
  cp "$WORK/sig_log_data.h"                      "$SIG_DST/"
fi

# ── NcLink 动态注册的 JNI_OnLoad 归属（2026-11-04）─────────────────────
# 目标：NcLink 的三个 native 入口不再以短名（Java_com_nc_link_NcLink_*）
# 出现在 .dynsym —— 那几个符号名等于告诉逆向者"从这里开始读"。
#
# 一个 so 里只能有一个 JNI_OnLoad：
#   · 勾了 dex2c → Dex2C.cpp 已经提供了（它自己也要注册业务方法），
#                  我们不能重复定义 → 在它的 OnLoad 尾部插一行调用我们的
#                  注册函数（sed 追加，保持幂等）。
#   · 没勾 dex2c → 没人提供 → 由 nc_link_jni.c 提供（宏 NC_LINK_JNI_OWN_ONLOAD）。
# 两种情况都在编译期定死，无运行期分支。
if [[ $WANT_SIGCHECK -eq 1 ]]; then
  _jni_c="$SIG_DST/nc_link_jni.c"
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    # 勾了 dex2c：Dex2C.cpp 会提供唯一 JNI_OnLoad → 关掉本文件自带的那份，
    # 否则同 so 里两个 JNI_OnLoad = 重复符号 = 链接失败。
    # 用源码默认开启 + 这里显式关闭（比"默认关、靠 -D 打开"少一条 mk 注入通道）。
    #
    # ⚠️⚠️ 2026-11-05 修（CI run 42030806689）：
    #   幂等判据原为 `grep -q 'NC_LINK_JNI_NO_ONLOAD'`，而源码自身第 46 行就有
    #   `#if !defined(NC_LINK_JNI_NO_ONLOAD)` —— 恒真 → 永远跳过注入 →
    #   两个 JNI_OnLoad 同时存在 → `ld.lld: error: duplicate symbol: JNI_OnLoad`。
    #   判据必须匹配【我们注入的那行】的完整形态（#define + 值），不能只匹配宏名。
    if ! grep -qE '^#define[[:space:]]+NC_LINK_JNI_NO_ONLOAD[[:space:]]+1' "$_jni_c"; then
      python3 - "$_jni_c" <<'PYEOF2'
import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
anchor = '#include "nc_link_jni.h"\n'
if anchor not in s:
    sys.exit('❌ nc_link_jni.c 里找不到 include 锚点')
s = s.replace(anchor,
              anchor + '\n/* 由 protect.sh 注入（勾了 dex2c）：JNI_OnLoad 由 Dex2C.cpp 提供 */\n'
              '#define NC_LINK_JNI_NO_ONLOAD 1\n', 1)
open(p, 'w', encoding='utf-8').write(s)
print('[jni] nc_link_jni.c 已关闭自带 JNI_OnLoad（改由 Dex2C.cpp 调用注册）')
PYEOF2
    fi
    _dex2c_cpp="$WORK/project/jni/nc/Dex2C.cpp"
    if [[ -f "$_dex2c_cpp" ]] \
       && ! grep -q 'nc_link_register_natives' "$_dex2c_cpp"; then
      # 用 python 而不是 sed：要精确锚定"JNI_OnLoad 函数体内"那一处，
      # 而文件里别处也可能有 return JNI_VERSION_1_6（sed 会全改）。
      #
      # ⚠️⚠️ 2026-11-05 修（CI run 42031354532）：
      #   第一版插入的是
      #     extern int nc_link_register_natives(JNIEnv *env);
      #   而 Dex2C.cpp 是【C++ 文件】—— 函数声明会按 C++ 规则做名称修饰
      #   （mangled），而 nc_link_jni.c 导出的 `nc_link_register_natives` 是
      #   C 符号（未修饰）→ 链接期报
      #     ld.lld: error: undefined symbol: nc_link_register_natives(_JNIEnv*)
      #   （错误信息里带参数类型 = 典型的 mangled name 找不到对应）。
      #   修法：include 头文件（头里有 extern "C" 守卫），不要本地重声明。
      python3 - "$_dex2c_cpp" <<'PYEOF'
import re, sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
i = s.find('JNI_OnLoad')
if i < 0:
    sys.exit('❌ Dex2C.cpp 里找不到 JNI_OnLoad')
tail = s[i:]
m = re.search(r'\n(\s*)return\s+JNI_VERSION_1_6\s*;', tail)
if not m:
    sys.exit('❌ Dex2C.cpp 的 JNI_OnLoad 里找不到 return JNI_VERSION_1_6;')
ind = m.group(1)
# ① 文件级 include（供 extern "C" 生效），插在第一个 #include 之后
inc_anchor = re.search(r'^#include[^\n]*\n', s, re.M)
if inc_anchor is None:
    sys.exit('❌ Dex2C.cpp 里找不到 #include 锚点')
if 'nc_link_jni.h' not in s:
    s = (s[:inc_anchor.end()]
         + '/* 2026-11-05: NcLink 动态注册（避免短名进 .dynsym）。\n'
           ' * 必须 include 头文件而不是本地声明 —— 本文件是 C++，本地声明的\n'
           ' * 函数会按 C++ 规则 mangled，而 nc_link_jni.c 导出的是 C 符号。 */\n'
           '#include "nc_link_jni.h"\n'
         + s[inc_anchor.end():])
    # include 插入改变了偏移，重新定位 JNI_OnLoad
    i = s.find('JNI_OnLoad')
    tail = s[i:]
    m = re.search(r'\n(\s*)return\s+JNI_VERSION_1_6\s*;', tail)
    ind = m.group(1)
ins = ('\n' + ind + '/* 返回值忽略：注册失败不应影响 dex2c 自己的注册结果，\n'
       + ind + ' * NcLink 侧拿不到实现会由 Guard 的 ULE 分支 fail-closed。 */\n'
       + ind + '(void)nc_link_register_natives(env);\n')
pos = i + m.start()
s = s[:pos] + ins + s[pos:]
open(p, 'w', encoding='utf-8').write(s)
print('[jni] Dex2C.cpp 已插入 NcLink 注册调用（include 头文件，非本地声明）')
PYEOF
      if ! grep -q 'nc_link_register_natives' "$_dex2c_cpp"; then
        echo "❌ Dex2C.cpp 注入 NcLink 注册失败——产物会用短名导出，与用户要求不符" >&2
        exit 1
      fi
    else
      echo "[jni] Dex2C.cpp 已含 NcLink 注册调用，跳过（幂等）"
    fi
  else
    # 没勾 dex2c：由 nc_link_jni.c 自己提供 JNI_OnLoad（宏在源码里以
    # 默认开启的方式给出，见下）。这里只做提示。
    echo "[jni] 未勾 dex2c → nc_link_jni.c 提供 JNI_OnLoad"
  fi
fi

# ── 纯 C 解密桩的注册注入（2026-11-09）──────────────────────────────
# 与上面 NcLink 完全同款的问题：一个 so 只能有一个 JNI_OnLoad。
# 本模块【不提供】自己的 OnLoad，而是往"已有的那个"里插一行调用
# nc_strdec_bootstrap()。三种持有者都要覆盖：
#   ① 有 dex2c  → Dex2C.cpp 的 OnLoad
#   ② 无 dex2c 但有 sigcheck → nc_link_jni.c 的 OnLoad
#   ③ 两者都没有（纯 stringenc-native）→ 本段自己生成一个最小 OnLoad
#
# 漏掉 ③ 的症状：so 编出来了、桩也有 native 声明，但没人 RegisterNatives
# → 首个加密字符串即 UnsatisfiedLinkError（启动闪退，且 logcat 只报
#   "No implementation found for ... ncDec"，不指向"没注册"这个真因）。
if [[ $WANT_NATIVE_STUB -eq 1 ]]; then
  _cstub_jni_dst=""
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    _cstub_jni_dst="$WORK/project/jni/nc"
  else
    _cstub_jni_dst="$WORK/project/jni"
  fi

  _injected=0

  # ① 有 dex2c：往 Dex2C.cpp 的 OnLoad 里插
  if [[ $WANT_TRANSPILE -eq 1 && -f "$WORK/project/jni/nc/Dex2C.cpp" ]] \
     && ! grep -q 'nc_strdec_bootstrap' "$WORK/project/jni/nc/Dex2C.cpp"; then
    python3 - "$WORK/project/jni/nc/Dex2C.cpp" <<'PYEOF_CSTUB'
import re, sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
i = s.find('JNI_OnLoad')
if i < 0:
    sys.exit('❌ Dex2C.cpp 里找不到 JNI_OnLoad')
tail = s[i:]
m = re.search(r'\n(\s*)return\s+JNI_VERSION_1_6\s*;', tail)
if not m:
    sys.exit('❌ Dex2C.cpp 的 JNI_OnLoad 里找不到 return JNI_VERSION_1_6;')
inc_anchor = re.search(r'^#include[^\n]*\n', s, re.M)
if inc_anchor is None:
    sys.exit('❌ Dex2C.cpp 里找不到 #include 锚点')
if 'nc_strdec.h' not in s:
    s = (s[:inc_anchor.end()]
         + '/* 2026-11-09: 纯 C 解密桩的 RegisterNatives（桩类名构建期注入）。\n'
           ' * 必须 include 头文件而非本地声明 —— 本文件是 C++，本地声明会\n'
           ' * 按 C++ 规则 mangled，而 nc_strdec_jni.c 导出的是 C 符号。 */\n'
           '#include "nc_strdec.h"\n'
         + s[inc_anchor.end():])
    i = s.find('JNI_OnLoad')
    tail = s[i:]
    m = re.search(r'\n(\s*)return\s+JNI_VERSION_1_6\s*;', tail)
ind = m.group(1)
ins = ('\n' + ind + '/* 纯 C 解密桩：注册 ncDec/ncSetKey 到本次随机桩类。\n'
       + ind + ' * 返回值忽略 —— 注册失败会让解密走 fail-closed（返回密文），\n'
       + ind + ' * 不崩；由真机日志里的"字符串全是密文"暴露。 */\n'
       + ind + 'if (nc_strdec_bootstrap(vm, env) != 0) {\n'
       + ind + '    /* 不返回 JNI_ERR：dex2c 自己的注册可能已经成功，\n'
       + ind + '     * 因桩注册失败而整体 JNI_ERR 会把 dex2c 也一起废掉。 */\n'
       + ind + '}\n')
pos = i + m.start()
s = s[:pos] + ins + s[pos:]
open(p, 'w', encoding='utf-8').write(s)
print('[cstub] Dex2C.cpp 已插入 nc_strdec_bootstrap 调用')
PYEOF_CSTUB
    grep -q 'nc_strdec_bootstrap' "$WORK/project/jni/nc/Dex2C.cpp" && _injected=1
    [[ $_injected -eq 1 ]] && echo "[cstub] 注册注入: Dex2C.cpp 的 JNI_OnLoad"
  fi

  # ② 无 dex2c 但有 sigcheck：往 nc_link_jni.c 的 OnLoad 里插
  if [[ $_injected -eq 0 && $WANT_SIGCHECK -eq 1 ]] \
     && [[ -n "$SIG_DST" && -f "$SIG_DST/nc_link_jni.c" ]] \
     && ! grep -q 'nc_strdec_bootstrap' "$SIG_DST/nc_link_jni.c"; then
    python3 - "$SIG_DST/nc_link_jni.c" <<'PYEOF_CSTUB2'
import re, sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
anchor = '#include "nc_link_jni.h"\n'
if anchor not in s:
    sys.exit('❌ nc_link_jni.c 里找不到 include 锚点')
if 'nc_strdec.h' not in s:
    s = s.replace(anchor, anchor + '#include "nc_strdec.h"\n', 1)
# 找到 JNI_OnLoad 函数体内、nc_link_register_natives 之后插入
m = re.search(r'(\n(\s*)if\s*\(\s*nc_link_register_natives\(env\)[^\n]*\n)', s)
if not m:
    sys.exit('❌ nc_link_jni.c 的 JNI_OnLoad 里找不到 nc_link_register_natives 调用')
ind = m.group(2)
ins = ('\n' + ind + '/* 纯 C 解密桩（2026-11-09）：同一 OnLoad 里顺带注册。\n'
       + ind + ' * 失败不影响 NcLink 的判决 —— 解密侧会 fail-closed。 */\n'
       + ind + '(void)nc_strdec_bootstrap(vm, env);\n')
s = s[:m.end(1)] + ins + s[m.end(1):]
open(p, 'w', encoding='utf-8').write(s)
print('[cstub] nc_link_jni.c 已插入 nc_strdec_bootstrap 调用')
PYEOF_CSTUB2
    grep -q 'nc_strdec_bootstrap' "$SIG_DST/nc_link_jni.c" && _injected=1
    [[ $_injected -eq 1 ]] && echo "[cstub] 注册注入: nc_link_jni.c 的 JNI_OnLoad"
  fi

  # ③ 两者都没有：自己生成最小 OnLoad（纯 stringenc-native 组合）
  if [[ $_injected -eq 0 ]]; then
    cat > "$_cstub_jni_dst/nc_strdec_onload.c" <<'COF'
/* nc_strdec_onload.c — 纯 C 解密桩独有的 JNI_OnLoad（2026-11-09）
 *
 * 何时生成：只勾 --stringenc-native，既没勾 dex2c 也没勾 sigcheck 时。
 * 那条组合里工程中没有任何 JNI_OnLoad（lib-ndk.sh 会扫描源码，
 * 没有定义就不往 version script 里声明），桩的 RegisterNatives 无处安放。
 *
 * 一旦有其他模块提供 OnLoad，本文件不会被生成 —— 一个 so 只能有一个。
 */
#include <jni.h>
#include "nc_strdec.h"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    (void)reserved;
    if (vm == NULL || (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    if (nc_strdec_bootstrap(vm, env) != 0) {
        /* fail-closed：桩注册不上 = 解密能力不存在。
         * 这里返回 JNI_ERR 是刻意的 —— 本组合里没有别的模块需要这个 so，
         * 与其带着"解不了密"的半残状态跑（所有字符串变密文），不如在
         * 加载点就炸（Guard 的 catch(UnsatisfiedLinkError) 会处置）。 */
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
COF
    echo "[cstub] 注册注入: 生成了独立的 JNI_OnLoad（nc_strdec_onload.c）"
  fi
fi
if [[ $WANT_ENVCHECK -eq 1 ]]; then
  # 环境检测(Frida/Xposed/调试器):与 sigcheck 同型并入同一 libnc.so(constructor 天然共存)
  #
  # ⚠️ 2026-11-08：探针拆到 env_probes.c（env_check.c 从 1600+ 行降到 754 行）。
  #    两个 .c + 一个共享头必须一起拷 —— 缺任一个都编不过：
  #      env_check.c    基础设施（日志/syscall/IO/kill/watchdog/调度）
  #      env_probes.c   13 个探针（依赖 env_internal.h 的声明）
  #      env_internal.h 两侧的共享声明
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    mkdir -p "$WORK/project/jni/nc"
    cp "$ROOT/scripts/guard/src/env_check.c" \
       "$ROOT/scripts/guard/src/env_probes.c" \
       "$ROOT/scripts/guard/src/env_internal.h" "$WORK/project/jni/nc/"
  cp "$GUARD_SRC/nc_guard_layout.h" "$WORK/project/jni/nc/"
  else
    mkdir -p "$WORK/project/jni"
    cp "$ROOT/scripts/guard/src/env_check.c" \
       "$ROOT/scripts/guard/src/env_probes.c" \
       "$ROOT/scripts/guard/src/env_internal.h" "$WORK/project/jni/"
  cp "$GUARD_SRC/nc_guard_layout.h" "$WORK/project/jni/"
  fi
  # envcheck 未勾 sigcheck 时也要有文案表(仅勾 envcheck 的组合)
  if [[ $WANT_SIGCHECK -ne 1 ]]; then
    if [[ $WANT_TRANSPILE -eq 1 ]]; then
      cp "$WORK/sig_log_data.h" "$WORK/project/jni/nc/"
    else
      cp "$WORK/sig_log_data.h" "$WORK/project/jni/"
    fi
  fi
fi
# so 静态加固(2026-10-18 自解谜版):开箱代码进 NDK 工程
#
# ⚠️ 本轮改动：nc_guard_unlock.c → nc_guard_boot.c（零冻结路线）
#   unlock.c 仍是冻结资产、保留在仓库，但【不再进 NDK 工程】。
#   boot.c 承接运行期职责：明文 stub(.text) + unlock 本体(.ncxh 密文)。
#   理由：把"开锁器"也锁进箱子，否则 unlock.c 整份逻辑在 .text 明文可读
#   （外部逆向报告 docs/so层防御/简盒-06 §6.2 的实测结论）。
#   不改 unlock.c 本身 = 不动冻结纪律；它以历史存档形式留存。
#
# ndk_write_mk 的两级 wildcard 已收 *.c，放 jni/nc/ 或 jni/ 根都能编入。
# ⚠️ nc_guard_key.c 必须一起拷：boot.c 的 unlock 本体 include 了
#    nc_guard_key.h 并调 khmac_sha256()（HMAC 校验）。漏拷 = ndk-build 就红
#    （fail-fast 反而是好事，比运行期 SIGILL 好定位）。
# ⚠️ nc_guard_layout.h 同理必拷（2026-10-20）：它是 so 加密契约的唯一真相源
#    （段名/尺寸/偏移/magic seed），5 个 .c 都 include 它。漏拷 = 编译期
#    "file not found" —— 比漏同步常量安全得多，那种要等到运行期 SIGILL。
# ⚠️⚠️ 2026-10-21 修真实缺口：锁箱设施的拷贝条件从"jni/nc 目录存在"扩为
#    "jni/nc 存在 或 有转译产物"。
#    原条件只由 guard/envcheck 分支建立 jni/nc → 组合
#    【--dex2c --stringenc --dex2c-stub 且不勾 guard/envcheck】时：
#      标记器（WANT_TRANSPILE 分支）照样把桩的 4 个 JNI 标进 .ncx，
#      但 boot.c 没拷 → 无人解锁 → 桩永为密文 → Java 首次解字符串即
#      踩密文 SIGILL → 包必闪退（且 sig_hash.h 也没人生成，锁箱器
#      会先因缺证书路径失败——两层失败叠加，构建期未必拦得住）。
#    有 .ncx 段就可能存在（转译产物会被标段）就必须有解锁设施——
#    设施跟随【被保护资产】走，不跟随【最先勾了哪个防御模块】走。
if [[ -d "$WORK/project/jni/nc" || $WANT_TRANSPILE -eq 1 ]]; then
  mkdir -p "$WORK/project/jni/nc"
  _guard_dst="$WORK/project/jni/nc"
elif [[ -d "$WORK/project/jni" ]]; then
  _guard_dst="$WORK/project/jni"
else
  _guard_dst=""
fi

# ── 设施落地：按上游分发形态二选一（2026-10-31）──────────────────────
#   ① 源码形态（nox 包里有 .c）→ 拷 .c + .h，由 mk 的 wildcard 编进来
#   ② 静态库形态（nox 包里只有 .h + lib/<abi>/libnox.a）→ 只拷 .h，
#      .a 由 ndk_write_mk 用 --whole-archive 链接
# 两种形态产物等价；差别只在"编译发生在什么时候"。
if [[ -n "$_guard_dst" ]]; then
  # 头文件两种形态都要（契约真相源 + 各 .c include 的接口）
  for _h in nc_guard_key.h nc_guard_layout.h nc_guard_paths.h; do
    cp "$GUARD_SRC/$_h" "$_guard_dst/"
  done
  if nox_guard_has_src "$GUARD_SRC"; then
    cp "$GUARD_SRC/nc_guard_boot.c"  "$_guard_dst/"
    cp "$GUARD_SRC/nc_guard_probe.c" "$_guard_dst/"
    cp "$GUARD_SRC/nc_guard_jni.c"   "$_guard_dst/"
    cp "$GUARD_SRC/nc_guard_key.c"   "$_guard_dst/"
    cp "$GUARD_SRC/nc_guard_paths.c" "$_guard_dst/"
    # nc_guard_xor.c（2026-11-06）：XOR_KEY 重组，从 boot.c 拆出以便单独 VMP。
    # ⚠️ 漏拷的症状是链接缺 ncg_xor_key → 解锁链断 → 真机 fail-closed 杀进程。
    cp "$GUARD_SRC/nc_guard_xor.c"   "$_guard_dst/"
    # nc_guard_crypto.c + nc_guard_internal.h（2026-11-06）：boot_key 派生，
    # 从 boot.c 拆出以便单独 VMP。internal.h 提供 ncg_shdr_t 与跨文件声明。
    # ⚠️ 漏拷 .c 的症状：链接缺 ncg_boot_key → boot_key 算不出 →
    #    .ncks 解不开 → .ncxh 保持密文 → 调用即 SIGILL。
    # ⚠️ 漏拷 .h 的症状：编译期直接报 ncg_shdr_t / ncg_boot_key 未声明（报错早）。
    cp "$GUARD_SRC/nc_guard_crypto.c"  "$_guard_dst/"
    cp "$GUARD_SRC/nc_guard_internal.h" "$_guard_dst/"
    GUARD_LIB_DIR=""      # 源码形态：mk 不需要额外链接 .a
    echo "[nox] 分发形态: 源码（编进 NDK 工程）"
  else
    # 静态库形态：nc_guard_jni.c 提供了 JNI 自检入口，但它不在 .a 里
    #（.a 只含 boot/probe/key/paths 四个固定源文件，见上游 make-zip-lib.sh）。
    # 缺它不影响生产链路 —— 它只是 selftest 入口，protect 不需要。
    GUARD_LIB_DIR="$GUARD_SRC/lib"
    [[ -d "$GUARD_LIB_DIR" ]] || {
      log_err "nox 分发包既无源码也无静态库: $GUARD_SRC"
      log_err "  期望其一: $GUARD_SRC/nc_guard_boot.c 或 $GUARD_LIB_DIR/<abi>/libnox.a"
      exit 1
    }
    echo "[nox] 分发形态: 静态库（链接 $GUARD_LIB_DIR/<abi>/libnox.a）"
  fi
fi

# ── Amice 混淆：解析 bundle 位置并导出环境变量（2026-11-05）──────────
# 三个变量分别解决三件事，缺一即失败（都是 fail-fast，不静默降级）：
#   AMICE_PLUGIN    —— 插件本体路径，写进 -fpass-plugin
#   AMICE_LLVM_LIB  —— host libLLVM.so 所在目录（官方 NDK 不含，必须来自 bundle）
#   AMICE_MBA/FLATTEN —— 编译期被插件读取的功能开关（不是 CFLAGS）
#
# bundle 位置来源（按优先级）：
#   ① 环境变量 AMICE_BUNDLE（CI 里由 workflow 指向解压目录）
#   ② 报错退出 —— 不做"找不到就静默跳过混淆"的降级：
#      用户勾了混淆却没生效，比构建失败危险得多（以为防了其实没防）。
_OBF_SPEC=""
if [[ $WANT_OBFUSCATE -eq 1 ]]; then
  _bundle="${AMICE_BUNDLE:-}"
  if [[ -z "$_bundle" || ! -d "$_bundle/amice" ]]; then
    log_err "勾选了代码混淆，但找不到 Amice bundle"
    log_err "     请设置 AMICE_BUNDLE 指向解压后的 amice-android-ndk-* 目录"
    log_err "     （该目录下应有 amice/lib/libamice.so 与 amice/llvm-lib/）"
    exit 1
  fi
  require_file "$_bundle/amice/lib/libamice.so" "Amice 插件本体"
  [[ -d "$_bundle/amice/llvm-lib" ]] || {
    log_err "bundle 缺 amice/llvm-lib —— 插件依赖的 host libLLVM.so 在此"
    log_err "     官方 NDK 不带它，缺了插件加载必失败"
    exit 1
  }
  export AMICE_PLUGIN="$_bundle/amice/lib/libamice.so"
  export AMICE_LLVM_LIB="$_bundle/amice/llvm-lib"
  # ⚠️ 必须用 bundle 自带的 NDK，不能用预装的 r27d：
  #   插件按 LLVM 主版本编译，与 NDK clang 严格绑定。
  #   实测（CI run 42055440429）：r27d 的 clang 18 加载 r29 插件 → SIGSEGV
  #   （exit code 139，clang frontend crashed）。
  #   bundle 里的 android-ndk-rXX 与插件是配套发布的，不存在错配。
  #
  # 定位：bundle 根目录下唯一名为 android-ndk-* 的子目录。
  _bundle_ndk="$(find "$_bundle" -maxdepth 1 -type d -name 'android-ndk-*' | head -1)"
  if [[ -z "$_bundle_ndk" || ! -x "$_bundle_ndk/ndk-build" ]]; then
    log_err "bundle 里找不到自带的 NDK（期望 <bundle>/android-ndk-rXX/ndk-build）"
    log_err "     插件与 NDK clang 必须配套 —— 用预装 NDK 会段错误（实测）"
    ls -la "$_bundle" | head -10 >&2
    exit 1
  fi
  export AMICE_NDK_HOME="$_bundle_ndk"
  # 子项默认：MBA 开（低风险，默认勾选），flatten 关（高风险，显式才开）。
  # 注意"父模块勾了但没勾任何子项"的情形：schema 里 mba 默认 true，
  # 正常不会发生；但命令行直调时可能出现，此处按"什么都没勾=不开混淆"处理，
  # 并明确报错而不是静默跑一遍没效果的编译。
  if [[ $OBF_MBA -eq 0 && $OBF_FLATTEN -eq 0 ]]; then
    log_err "勾选了代码混淆，但没选任何混淆强度（--obfuscate-mba / --obfuscate-flatten）"
    exit 1
  fi
  [[ $OBF_MBA -eq 1 ]] && _OBF_SPEC="mba"
  [[ $OBF_FLATTEN -eq 1 ]] && _OBF_SPEC="${_OBF_SPEC:+$_OBF_SPEC,}flatten"
  export AMICE_MBA="$([[ $OBF_MBA -eq 1 ]] && echo true || echo false)"
  export AMICE_FLATTEN="$([[ $OBF_FLATTEN -eq 1 ]] && echo true || echo false)"
  log_info "代码混淆: $_OBF_SPEC（AMICE_MBA=$AMICE_MBA AMICE_FLATTEN=$AMICE_FLATTEN）"
  log_info "混淆用 NDK: $AMICE_NDK_HOME（bundle 自带，与插件配套）"
fi

# ── 纯 C 解密桩的源码（2026-11-09）────────────────────────────────
# 放在 ndk_write_mk 之前：mk 用 wildcard 收 *.c，拷晚了不会被编进去
# （报错十一同型：mk 在 include $(BUILD_SHARED_LIBRARY) 那一刻快照源文件列表）。
#
# 两个文件必须一起拷（漏 .c = 链接缺符号；漏 .h = 编译期 file not found）。
# JNI 层单独一个文件，是为将来"桩搬进别处"留的口子 —— 只换 JNI 边界。
if [[ $WANT_NATIVE_STUB -eq 1 ]]; then
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    _cstub_dst="$WORK/project/jni/nc"
  else
    _cstub_dst="$WORK/project/jni"
  fi
  mkdir -p "$_cstub_dst"
  cp "$ROOT/scripts/string-enc/csrc/nc_strdec.c"     "$_cstub_dst/"
  cp "$ROOT/scripts/string-enc/csrc/nc_strdec.h"     "$_cstub_dst/"
  cp "$ROOT/scripts/string-enc/csrc/nc_strdec_jni.c" "$_cstub_dst/"
  # NKEYS 档位必须与 encrypt-strings.py 一致（两侧不同 = 全包乱码）。
  # 这里从 Python 侧抽真值，抽不到即 fail-fast —— 不写死常量。
  _nk="$(python3 -c "
import sys; sys.path.insert(0, '$ROOT/scripts/string-enc')
import native_stub
print(native_stub.NC_STRDEC_NKEYS)
" 2>/dev/null)" || _nk=""
  if [[ -z "$_nk" ]]; then
    log_err "读不到 native_stub.NC_STRDEC_NKEYS —— 纯 C 桩的档位契约无法确认"
    log_err "    （C 侧 NKEYS 与 Python 侧不一致 ⇒ 构建期加密 / 运行期解密不同源）"
    exit 1
  fi
  # ── 桩类描述符：必须【在 STEP3 就算出来】，不能等 STEP5 ────────────
  # 顺序困局（2026-11-09 本地实测踩到）：
  #   C 侧 RegisterNatives 需要真实类名（桩名每包随机）；
  #   而桩是 stringenc 在 STEP5 才注入的，STEP3 时组件标记还不存在。
  # 第一版从 stringenc-components.json 读 → STEP3 必然失败：
  #   "找不到组件标记 ... 无法得知本次的随机桩名"
  #
  # 解法：不搬整个 stringenc（那会破坏 STEP2 的 dex2c 顺序），
  # 只把【桩名】这一个信息提前算出来（emit-stub-decl 子命令）。
  # 名字的生成规则不依赖解包目录内容，所以提前算与 STEP5 再算结果一致 ——
  # 前提是【两边都读到同一个组件标记，或都走同一次随机】。这里用后者：
  # 把算出来的名字写进 $WORK/cstub_decl.txt，STEP5 通过 --stub-name 复用。
  _cstub_seed_hex="$(cat "$WORK/stub_seed_for_decl.txt" 2>/dev/null || true)"
  if [[ -z "$_cstub_seed_hex" ]]; then
    log_err "内部错误：没有本轮的桩种子（stub_seed_for_decl.txt）"
    exit 1
  fi
  _decl_spec=""
  if [[ -n "${CSTUB_FIXED_NAME:-}" ]]; then
    _decl_spec="--stub-name $CSTUB_FIXED_NAME"
  fi
  _decl="$(python3 "$ROOT/scripts/string-enc/encrypt-strings.py" \
             emit-stub-decl "$WORK/decompiled" "$_cstub_seed_hex" $_decl_spec \
           2>&1)" || {
    log_err "emit-stub-decl 失败：$_decl"
    exit 1
  }
  _stub_class="$(printf '%s' "$_decl" | cut -f1)"
  _stub_pkg_dot="$(printf '%s' "$_decl" | cut -f3)"
  _stub_cls_name="$(printf '%s' "$_decl" | cut -f4)"
  if [[ -z "$_stub_class" || "$_stub_class" != */* ]]; then
    log_err "emit-stub-decl 输出无法解析: $_decl（期望 4 个 tab 分隔字段）"
    exit 1
  fi
  # 存下来给 STEP5 的 encrypt-strings.py --stub-name 复用，
  # 保证"C 侧注册的类"与"dex 里实际生成的类"是同一个。
  printf '%s.%s:%s\n' "$_stub_pkg_dot" "$_stub_cls_name" \
    "$(printf '%s' "$_decl" | cut -f2)" > "$WORK/cstub_decl.txt"
  log_info "纯 C 桩类名（构建期预定）: L$_stub_class;"
  # 生成 C 侧的编译期常量头：桩类名 + 档位。与 sig_hash.h 同型
  # （构建期生成、不进 git、由 C 侧 include）。
  cat > "$_cstub_dst/nc_strdec_cfg.h" <<EOF
/* nc_strdec_cfg.h — 由 protect.sh 构建期生成，不进 git（2026-11-09）
 *
 * 为什么必须生成而不是写死：桩类名每包随机（防固定签名），
 * C 侧 RegisterNatives 的 FindClass 需要真名。
 */
#ifndef _NC_STRDEC_CFG_H_
#define _NC_STRDEC_CFG_H_

/* 桩类（斜杠分隔，供 FindClass 用） */
#define NC_STRDEC_STUB_CLASS "$_stub_class"

/* 密钥档位：必须与 native_stub.NC_STRDEC_NKEYS 一致 */
#ifndef NC_STRDEC_NKEYS
#  define NC_STRDEC_NKEYS $_nk
#endif

#endif
EOF
  echo "[cstub] 纯 C 解密桩: 类=$_stub_class NKEYS=$_nk"
fi

ndk_write_mk "$WORK/project/jni" nc "$GUARD_LIB_DIR" "$_OBF_SPEC"   # mk 模板唯一来源（报错十一），模块名固定 nc

# ── 通用段标记（2026-10 设施化第2层）──────────────────────────────
# 让 dex2c 转译产物吃上 .ncx 加密：用规则把 JNI 函数打进加密段。
# 位置必须在 ndk_build 【之前】——标记器改的是源码，编译后才跑就晚了。
#
# 为什么要单独一层：guard/envcheck 的探针是手写 __attribute__ 的
# （env_check.c 冻结，只追加）；dex2c 产物由引擎生成，不该为它改冻结的
# 引擎。有了标记器，加一个消费者 = 加一条规则，谁也不写自己的防御。
# 详见 docs/流程文档.md §3.12 的三层设施说明。
if [[ $WANT_TRANSPILE -eq 1 ]]; then
  echo "[mark] 段标记：dex2c 转译产物 → .ncx"

  # 先数一下源码里到底有多少 JNI 函数头（用于判定"静默失防"）
  JNI_HDRS=$(grep -rlE 'JNIEXPORT[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+JNICALL' \
             "$WORK/project/jni" --include='*.cpp' --include='*.cc' --include='*.c' 2>/dev/null | wc -l)

  python3 "$GUARD_SRC/so_section_mark.py" "$WORK/project/jni" \
    --rule dex2c-jni \
    --exclude nc_guard_jni.c \
    --exclude-func ncVerify \
    --exclude-func heartbeat \
    --exclude-func JNI_OnLoad \
    --exclude-func selftest \
    -v 2>&1 | sed 's/^/  [mark] /' || {
    echo "❌ 段标记失败——dex2c 转译产物未吃上加密（用户明确要求）" >&2
    exit 1
  }

  # 静默失防检测：有 JNI 头却没标上任何一个 → 规则与产物形态脱节
  # （例如 writer.py 改了函数头格式）。此时不能放行——那等于"以为防了
  # 其实没防"，正是本机制最该避免的假绿。
  # ⚠️ 段名必须与 so_section_mark.py 的 SECTION 常量一致（2026-10-19 已改 .ncx）。
  #    这里曾经写死旧段名，段名中性化后漏改 → MARKED=0 → 下面的
  #    "静默失防"守卫 fail-fast（CI 39171457222 实证）。守卫本身是对的，
  #    但漏改段名等于把自己的守卫变成误报源。
  MARKED=$(grep -rc 'section(".ncx")' "$WORK/project/jni" \
           --include='*.cpp' --include='*.cc' --include='*.c' 2>/dev/null \
           | awk -F: '{s+=$2} END {print s+0}')
  if [[ $JNI_HDRS -gt 0 && $MARKED -eq 0 ]]; then
    echo "❌ 检出 $JNI_HDRS 个含 JNIEXPORT 的源文件，但段标记命中 0" >&2
    echo "   → dex2c 的 writer.py 可能改了函数头格式，规则已脱节" >&2
    echo "   → 修 nox 仓库的 so_section_mark.py dex2c-jni 规则，不许静默放行" >&2
    exit 1
  fi
  echo "[mark] 完成：$MARKED 处 .ncx 标记（含探针与转译函数）"

fi

# ── 纯 C 解密桩的段标记（2026-11-09）────────────────────────────────
# 为什么必须做：native 桩的算法就在 nc_strdec.c 里，不标记 = 整份算法
# 以明文躺在 .text，`objdump -d` 直接读出 mix64 常量与密钥流结构，
# 前面所有"dex 侧看不到算法"的努力全部落空。
#
# 标哪些：nc_strdec_jni_decrypt / nc_strdec_jni_set_key（真正的算法入口）
# 不标哪些：nc_strdec_register_natives / nc_strdec_bootstrap
#          —— 它们是 JNI_OnLoad 的调用方，锁进 .ncx 就会"解锁前调用密文"
#             死锁（与 nc_link.c 的 ncVerify/heartbeat 同一条纪律）。
#
# 用 so_section_mark.py 的 --pattern 自定义正则（上游 nox 的通用设施，
# 不新增脚本）：匹配 `jstring nc_strdec_jni_decrypt(` / `void nc_strdec_jni_set_key(`。
# ⚠️⚠️ 标哪个文件是这一步最容易搞错的地方（2026-11-09 自查纠正）：
#   第一版标的是 nc_strdec_jni.c 的 decrypt/set_key，那就是"加密了壳、
#   核留在明文"—— nc_strdec_jni.c 只是 JNI 类型转换与缓存，
#   真正的算法（mix64 常量、密钥流结构、Base64 解码）全在 nc_strdec.c。
#   与被外部实测报告打 2.5 分的那个错误完全同型。
#
# 正确对象（算法层，全在 nc_strdec.c）：
#   nc_strdec_decrypt      解密主流程（块展开 + XOR）
#   nc_block_ks            密钥流块生成（含 splitmix64 与 NKEYS 异或合并）
#   nc_mix64               splitmix64 终混合（算法指纹所在）
#   nc_strdec_b64_decode   Base64 解码
#   nc_strdec_utf8_to_utf16 UTF-8 解码
#
# 不标（调用方 / 门槛函数，标了会死锁或纯属浪费）：
#   nc_strdec_has_key      只是读一个 flag
#   nc_strdec_set_key      只在 <clinit> 调一次
if [[ $WANT_NATIVE_STUB -eq 1 ]]; then
  echo "[mark] 段标记：纯 C 解密桩【算法层】→ .ncx"
  python3 "$GUARD_SRC/so_section_mark.py" "$_cstub_jni_dst/nc_strdec.c" \
    --pattern '^[ \t]*((?:static[ \t]+)?(?:inline[ \t]+)?(?:uint64_t|int)[ \t]+(nc_strdec_decrypt|nc_strdec_b64_decode|nc_strdec_utf8_to_utf16|nc_block_ks|nc_mix64)[ \t]*\()' \
    --section .ncx \
    -v 2>&1 | sed 's/^/  [mark] /' || {
    echo "❌ 纯 C 解密桩段标记失败 —— 算法将以明文留在 .text" >&2
    exit 1
  }
  # 静默失防守卫：算法层 5 个函数必须全部标上。
  # 少标一个 = 那部分算法明文可读，而这不会有任何运行期症状
  # （功能完全正常），属于最难发现的"假绿"。
  # 计数用固定串（-F）：'section(".ncx")' 里的引号/点号在正则下都要转义，
  # 手写正则极易与 so_section_mark.py 的实际输出形式错开（本次就错了：
  # 写成 section("\\.ncx") → grep 收到 \.ncx → 一个都匹配不到 → 假红）。
  _cstub_marked=$(grep -cF 'section(".ncx")' "$_cstub_jni_dst/nc_strdec.c" 2>/dev/null || true)
  _cstub_marked="${_cstub_marked:-0}"
  if [[ -z "$_cstub_marked" || "$_cstub_marked" -lt 5 ]]; then
    echo "❌ 纯 C 桩段标记只命中 ${_cstub_marked:-0} 处（应为 5：decrypt/b64_decode/utf8/block_ks/mix64）" >&2
    echo "   → nc_strdec.c 的函数头形态变了，正则已脱节" >&2
    echo "   → 不许静默放行：那等于算法以明文进产物" >&2
    exit 1
  fi
  echo "[mark] 完成：$_cstub_marked 处 .ncx 标记（纯 C 桩算法层）"
fi

log_step 4 6 "NDK 编译"
ndk_build "$WORK/project"
fi   # 有 so 需求的组合才执行 STEP 3/4(报错二十三:纯 stringenc 组合跳过)

# ── STEP 5: 解包 → smali 处理 → 放 so → 回编（全组合只做这一次） ────
# ── STEP 5: 解包 → smali 处理 → 放 so → 回编（全组合只做这一次） ────
# 联动路径(stringenc↔dex2c)必须解【前置加密后的 APK'】而非原始 IN_APK ——
# stringenc 已在 STEP2 前跑完并回编成 APK',解原始包会把密文+桩全部丢掉,
# 只剩 mark-native 把 dn() 改壳后指向一个不存在的桩类 → UnsatisfiedLinkError。
STEP5_APK="$IN_APK"
if [[ $LINK_STUB -eq 1 ]]; then
  STEP5_APK="$WORK/pre-encrypted.apk"
fi
log_step 5 6 "解包注入重打包"
repack_unpack "$WORK/decompiled" "$STEP5_APK"

# ── packer 联动补做：把桩从业务 dex 摘除（2026-10-26）────────────────
# 为什么在这里而不是前置轮：
#   前置轮（LINK_STUB）必须保住桩让 dex2c 转译内核进 libnc.so，
#   所以那一轮用 --keep-stub-in-dex 只产 dex 不摘除。
#   现在 dex2c 已跑完、解包产物已就位，是摘除的准确时机：
#   早于此 = dex2c 抽不到桩内核；晚于此（回编后）= 桩已经进了产物。
# 只在勾 packer 时做 —— 不勾时没有壳 dex 承载桩，摘除 = 运行期 ClassNotFound。
# 只在【LINK_STUB 路径 + 勾 packer】时做：
#   · LINK_STUB：桩是前置轮注入的、已跨一次回编，这里补做摘除。
#   · 非 LINK_STUB：桩由 STEP5 的 stringenc 主轮注入（在 mark-native 之后），
#     它的摘除由那一轮自己的 --emit-stub-dex 完成，此处不能插手
#     （否则先删后注，顺序反了）。
#   · 不勾 packer：没有壳 dex 承载桩，摘除 = 运行期 ClassNotFound。
if [[ $LINK_STUB -eq 1 && $WANT_PACKER -eq 1 ]]; then
  python3 "$ROOT/scripts/string-enc/encrypt-strings.py" remove-stub "$WORK/decompiled"
  # ⚠️ 必须同步剔除 compiled_methods.txt 里的【桩类】条目（2026-10-26 CI 实测）：
  #    dex2c 已把桩的 d/dn/mix64/keyByte 转译进 libnc.so 并登记在
  #    compiled_methods.txt；桩文件被摘除后 mark-native.py 找不到这些方法
  #    会按设计 exit 3（"有方法没在 smali 里找到"）→ 整条流水线红。
  #    但桩的 native 化本来就【不需要】：它在壳 dex 里、由 libnc.so 提供实现，
  #    业务 dex 里没有它的调用点定义。
  #
  # 精确性要求：只剔除【类描述符 == stub.dex 里的那个类】的行，
  # 绝不用"找不到就删"的启发式 —— 那会把真实的漏保护静默吞掉。
  if [[ $WANT_TRANSPILE -eq 1 && -f "$WORK/project/jni/nc/compiled_methods.txt" && -f "$WORK/stub.dex" ]]; then
    python3 - "$WORK/project/jni/nc/compiled_methods.txt" "$WORK/stub.dex" <<'PY'
import struct, sys
cm_path, stub_dex = sys.argv[1], sys.argv[2]

def class_descs(path):
    """读 dex 的 class_defs，返回类描述符集合。

    ⚠️ string_data_item 的结构是【ULEB128 长度前缀 + MUTF-8 字节 + 0x00】，
    不是裸字符串。直接从 string_data_off 读会把长度前缀（如 '\\r' = 13）
    当成内容，导致 'Lp8/vg/nb/zi;' 变成 '\\rLp8/vg/nb/zi;' 而匹配不上。
    """
    d = open(path, 'rb').read()
    if d[:4] != b'dex\n':
        raise SystemExit(f'❌ 不是合法 dex: {path}')
    n = struct.unpack_from('<I', d, 96)[0]
    cdo = struct.unpack_from('<I', d, 100)[0]
    toff = struct.unpack_from('<I', d, 68)[0]
    soff = struct.unpack_from('<I', d, 60)[0]
    out = set()
    for i in range(n):
        t = struct.unpack_from('<I', d, cdo + i * 32)[0]
        sidx = struct.unpack_from('<I', d, toff + t * 4)[0]
        p = struct.unpack_from('<I', d, soff + sidx * 4)[0]
        # 跳过 ULEB128 长度前缀
        while d[p] & 0x80:
            p += 1
        p += 1
        end = p
        while d[end] != 0:
            end += 1
        out.add(d[p:end].decode('utf-8', 'replace'))
    return out

stub_classes = class_descs(stub_dex)
kept, dropped = [], []
for line in open(cm_path, encoding='utf-8'):
    s = line.rstrip('\n')
    if not s.strip():
        continue
    if any(s.startswith(c) for c in stub_classes):
        dropped.append(s)
    else:
        kept.append(s)
with open(cm_path, 'w', encoding='utf-8') as fp:
    for l in kept:
        fp.write(l + '\n')
print(f'  🧹 compiled_methods 剔除桩条目 {len(dropped)} 条（桩已进壳 dex，无需 native 化）')
for x in dropped:
    print(f'       {x}')
PY
  fi
fi

# ── so 静态加固(2026-12):把 .ncx 段锁成密文（构建期"锁箱"）────────
# 位置在 STEP5 解包后：so 已编译完但【还没进 APK】→ 锁的是即将打包的产物。
# 运行期由 nc_guard_boot.c 的明文 stub 解出 unlock 本体，再由本体解
# .ncx；磁盘上 IDA 读到的 .ncx 是 RC4 密文（现为 4012/2750 字节的
# 12 个 env_check 探针 + dex2c 转译产物）。
# 抄自 XopProtector 的 .bitcode 自解密机制。
# cert 与 package 都由 so-section-lock.py 从 $IN_APK 自己提（定点读 Signing
# Block + AXML 解析），protect.sh 不重复实现 —— 单一职责。
# 换 key 重打包 → cert 变 → k_so 变 → 密文解不开（fail-closed）。
if [[ -d "$WORK/project/libs" ]]; then
  for so in "$WORK"/project/libs/*/libnc.so; do
    [[ -f "$so" ]] || continue
    # ── .comment 段移除（2026-10-21，白嫖清单 #2——实为还债）──────
    # -fno-ident 只去 C 编译器指纹（__FILE__ 等），管不住链接器/工具链
    # 写进 .comment 的版本串（实测：两版 clang 精确版本号明文躺着）。
    # 攻击者据此查该版本已知优化与漏洞行为——情报直接送上门。
    # strip-all 不删 .comment（只删符号表），必须显式移除。
    # ⚠️ 必须在锁箱【之前】：objcopy 重排段布局，锁箱后跑会破坏
    #    slot 里已写好的链接期地址（sh_addr 失配 → 运行期基址计算崩）。
    #
    # ⚠️⚠️ 2026-11-02 修：此前只用 `command -v objcopy` 找 GNU objcopy，
    #    在 GitHub Actions ubuntu runner 上【不存在】（只有 llvm-objcopy），
    #    于是每次都走 else 分支打印一条警告后继续 —— 而 .comment 一直
    #    留在产物里。实测 CI 日志：
    #        [strip] ⚠️ .comment 移除失败（objcopy 异常）——继续但不阻塞
    #    产物 strings 仍能扫出 clang 18.0.4 完整版本串与 LLVM commit hash。
    #    「继续但不阻塞」是刻意设计（不让 strip 失败阻断出包），但它掩盖
    #    了一个【每一版产物都失效】的防护。
    # 修法：按 NDK llvm-objcopy → 系统 llvm-objcopy → GNU objcopy 顺序探测，
    #      并在全部失败时输出 ERROR 级提示（仍不阻塞出包）。
    _objcopy=""
    for _cand in \
        "${ANDROID_NDK_HOME:+$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy}" \
        "${ANDROID_NDK_HOME:+$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-aarch64/bin/llvm-objcopy}" \
        "$(command -v llvm-objcopy 2>/dev/null)" \
        "$(command -v objcopy 2>/dev/null)"; do
      if [[ -n "$_cand" && -x "$_cand" ]]; then _objcopy="$_cand"; break; fi
    done
    if [[ -n "$_objcopy" ]]; then
      if "$_objcopy" --remove-section=.comment "$so" 2>/dev/null; then
        echo "  [strip] .comment 已移除（$(basename "$_objcopy")，工具链指纹归零）"
      else
        echo "  [strip] ❌ .comment 移除失败（$_objcopy 报错）——产物将泄露 clang 版本" >&2
      fi
    else
      echo "  [strip] ❌ 找不到任何 objcopy（llvm-objcopy / objcopy 均不可用）——产物将泄露 clang 版本" >&2
    fi
    # 一级锁箱：.ncx 代码段 + .ncxr 常量表段（共用 k_so/同一个 MAC）
    #
    # 2026-10-19 为什么是两段（实测报告 §8.1 的核心缺陷）：
    #   此前只锁 .ncx，而真正的签名判定函数 nc_verify_t1 与两张表
    #   SIG_SALT/SIG_HASH_STORED 全在明文——加密只保护了 ncVerify 转发壳，
    #   核心留在 .rodata，`od` 一条命令就能读出并反推通过凭据。
    #   现在判定函数进 .ncx（AXR），表进 .ncxr（AWR，不可执行）——
    #   分两段是 clang 的硬约束：const 数据不能进可执行段。
    # ⚠️ 老产物若没有 .ncxr（未定义 NC_GUARD_SECTIONED），锁箱器会
    #   在 --section 列表里找不到它而报错。故此处先探测段是否存在，
    #   不存在则退回单段（向前兼容，且不会静默降级——会打印明确提示）。
    # ⚠️ 段名必须与 nc_guard_boot.c 的宏 / so-section-lock.py 的常量一致。
    # 2026-10-19 段名中性化（.ncguard→.ncx）时漏改这里 → 锁箱报
    # 「段 .ncguard 不存在」→ 构建失败（CI 39176711044 实证）。
    _SECTIONS=".ncx"
    if readelf -SW "$so" 2>/dev/null | grep -q '\.ncxr'; then
      _SECTIONS=".ncx,.ncxr"
    else
      echo "  [lock] ⚠️ 未发现 .ncxr 段（NC_GUARD_SECTIONED 未定义？）" >&2
      echo "  [lock]    → 签名判定函数已加密，但 SIG_SALT/SIG_HASH_STORED 仍在明文" >&2
    fi
    python3 "$GUARD_SRC/so-section-lock.py" "$so" "$so" \
      --section "$_SECTIONS" --from-apk "$IN_APK" \
      2>&1 | sed 's/^/  [lock] /' || {
      echo "❌ .ncx 锁箱失败（段未标记？cert/包名提取失败？）——so 静态加固未生效" >&2
      exit 1
    }
    # 二级锁箱（2026-10-18 自解谜）：把 unlock 本体也锁进 .ncxh。
    # ⚠️ 顺序有依赖：必须先跑一级再跑二级。原因是一级会改 .ncx 内容，
    #    而二级要锁的 .ncxh 是另一个段，本无先后；但若二级先跑，
    #    unlock 本体已变密文，此时一级锁箱器本身不依赖 unlock（纯 Python
    #    读盘），所以其实可交换 —— 但保持"先业务后本体"更易读。
    # ⚠️ 二级失败必须 fail-fast：stub 见 slot 无 magic 会静默放行，
    #    head 段保持明文 → 自解谜没发生 → 静态攻击者照旧读 unlock 本体。
    #    那种"以为防了其实没防"的静默降级正是本机制最该避免的。
    python3 "$GUARD_SRC/so-section-lock.py" "$so" "$so" --lock-head \
      2>&1 | sed 's/^/  [lock2] /' || {
      echo "❌ 二级锁箱失败（.ncxh 未标记？符号被 strip？）——unlock 本体仍可静态读取" >&2
      exit 1
    }
    # ── 元数据清理（2026-11-02）：段与锁箱全部完成后才做 ──────────
    # 删 .eh_frame / .eh_frame_hdr / .comment / .debug_*
    #
    # 为什么必须放在【最后】：
    #   objcopy 会重写 ELF 文件。前面 lock/lock_head 已经往 .nck/.ncks
    #   槽里写了链接期 sh_addr，若 objcopy 挪动它们，运行期基址计算全错。
    #   实测确认 --remove-section 对本产物【不改任何 sh_addr/sh_offset】，
    #   但顺序上仍放在最后最安全（不需要这个前提成立）。
    #
    # 删的价值（实测审计）：
    #   .eh_frame 含 709 个 FDE，每条给出一个函数的精确起止地址 ——
    #   加密了 6 个段，但异常表把 .ncx 里 15 个函数、.ncxh 里 8 个函数
    #   的位置与大小全列出来了。
    #   .comment 含 clang 18.0.4 完整版本串 + LLVM commit + PGO/BOLT/LTO
    #   配置（这一项在 CI 上已失效三个月，见 protect.sh 上文 objcopy 注释）。
    #
    # 代价（如实）：失去 C++ 异常栈回溯。nc_guard/sig_check 全是 C，
    # dex2c 产物的异常用 EX_LandingPad + 显式 goto 分发，不依赖 .eh_frame。
    # 崩溃时 tombstone 的 backtrace 会残缺 —— 排障时用未清理的中间产物。
    python3 "$GUARD_SRC/so-section-lock.py" "$so" "$so" --strip-meta \
      2>&1 | sed 's/^/  [meta] /' || {
      echo "❌ 元数据清理失败 —— 产物将泄露函数边界与工具链指纹" >&2
      exit 1
    }
  done
fi

if [[ $WANT_TRANSPILE -eq 1 ]]; then
  # native 化：把已抽进 so 的方法在 smali 里改成 native 壳，并插 System.loadLibrary("nc")
  # （dcc 原版只在自带重打包路径里做壳替换且不插 loadLibrary，纯成品 APK 后处理必须自动补齐）
  python3 "$ROOT/scripts/repack/mark-native.py" \
    "$WORK/project/jni/nc/compiled_methods.txt" "$WORK/decompiled"
elif [[ $WANT_SIGCHECK -eq 1 || $WANT_ENVCHECK -eq 1 ]]; then
  # 只有 so、没有 dex2c 转译时，必须显式插 loadLibrary("nc") —— 否则
  # so 编出来了但没有任何 Java 代码去 dlopen 它，等于装了个摆设。
  #
  # 双保险插桩:<clinit> + onCreate 各一份。onCreate 里再插一份,
  # 要删两处才失效（联合方案不插：onCreate 已抽进 so,
  # 删 <clinit> 的 loadLibrary 会让 native 壳直接自爆）。幂等:按方法体分别检查。
  # manifest 是二进制 AXML → inject-loadlib 内部走 androguard AXMLPrinter 解析
  #
  # ⚠️⚠️ 2026-11-08 修真实缺口（实测发现）：原条件只有 `WANT_SIGCHECK -eq 1`，
  #    于是【只勾 --envcheck】时两个分支都不进 ——
  #      · so 编出来了（libnc.so 365KB 在包里，系统 logcat 也能看到
  #        nativeLibs1/1:: [..., libnc.so]）
  #      · 但没有任何 Java 代码调 System.loadLibrary("nc")
  #      · → constructor(50) 从不执行 → 13 个探针一行没跑
  #      · → 且完全静默：无崩溃、无日志、包看起来"正常"
  #    真机实测：装包后 logcat 过滤 " nc  *:" 为空，`pm path` 的 dex 里
  #    grep loadLibrary 命中的是 xCrash 自带的那条，不是我们插的。
  #    这是「功能整体失效但构建全绿」——AGENTS.md §3.3 那类最危险的失败。
  #    修法：条件加 `|| $WANT_ENVCHECK -eq 1`。两模块同勾时只跑一次
  #    （脚本本身幂等，但没必要执行两遍）。
  python3 "$ROOT/scripts/inject/inject-loadlib.py" "$WORK/decompiled" \
    --launcher --entrypoints --so-name nc
fi

# ── Java 层判决式签名联动(§3.11,随 --sigcheck 自动生效,无独立勾选) ──
# 两套独立真校验之一:Java 只"量"(PackageManager)并执行杀,标准值与比对全在
# so(nc_link.c) —— 指纹永不过境进 dex;so 缺失 → fail-closed 杀,loadLibrary
# 由"可删开关"变"承重墙"(修复 sigcheck-only 删开关静默绕过的最大缺口)。
# 必须在插桩/loadLibrary 之后、stringenc 之前:新类常量可被 stringenc 顺带加密。
if [[ $WANT_SIGCHECK -eq 1 ]]; then
  # ⚠️⚠️ 2026-10-20 修 CI 红：dex2c + sigcheck 组合下此处曾【必失败】。
  #
  # 根因链（本地已复现，输出与 CI build.log 逐字一致）：
  #   dex2c 把 LAUNCHER activity 的 onCreate 抽成 native 壳
  #     （build.log: `🔧 .../MainActivity.smali: 1 个方法 → native`）
  #   → inject-javacheck.py 按【报错三十九】防线跳过 native 壳上的点
  #     （给 native 方法凭空造方法体 → 回编炸
  #      "A native method cannot have any instructions"）
  #   → sites 为空 → 该脚本 return 2
  #   → 本脚本 set -e(protect.sh:49) 直接杀掉流水线，
  #     日志停在"🏷️ 自适应命名"之后，无任何 Error/Traceback（极难定位）
  #
  # 为什么 dex2c 组合下 return 2 不是缺陷、不该 fail-fast：
  #   inject-loadlib.py:26 已明确——联合方案的 onCreate 兜底【不需要】，
  #   因为 onCreate 进 so 变 native 壳后，攻击者删 loadLibrary 即触发
  #   UnsatisfiedLinkError（fail-closed），壳本身就是承重墙；
  #   且 app 侧 <clinit> 的 loadLibrary 注入点仍在（双保险的另一半）。
  #
  # 故：dex2c 组合 → 记警告放行；非 dex2c 组合 → 仍 fail-fast
  #   （那种场景没有 native 壳保护，注入不到就是真缺口，必须红）。
  #
  # --apk（报错五十九，2026-11-04）：把原始 APK 传进去，让注入器从 dex header
  #   读权威方法数来决定落点。不给也能跑（回落到扫 .method × 1.25 的保守估算），
  #   但给了才能精确判断 classes.dex 是否贴顶——真实大型包经 R8 编译后
  #   classes.dex 常是 65519/65536（余量 17），固定写 smali/ 必炸
  #   "Unsigned short value out of range: 65536"。
  if ! python3 "$ROOT/scripts/guard/javalink/inject-javacheck.py" \
      "$WORK/decompiled" --so-name nc --apk "$STEP5_APK"; then
    if [[ $WANT_TRANSPILE -eq 1 ]]; then
      log_warn "javacheck 无可用调用点 —— dex2c 组合下 onCreate 已是 native 壳（报错三十九防线跳过），放行；app 侧 <clinit> loadLibrary 兜底仍在"
    else
      echo "❌ javacheck 注入失败（非 dex2c 组合，无 native 壳保护 = 真缺口）" >&2
      exit 1
    fi
  fi
fi

# ── 字符串加密（dex 层，与 so 无关；必须在 mark-native 之后） ──────
# 放在 native 化之后的原因:被 dex2c 抽走的方法此时已是 native 壳、没有方法体,
# 字符串加密自然扫不到它们(省体积);同时用 compiled_methods.txt 做精确跳过,
# 避免 dcc 与 mark-native 之间的时序差异导致误加密(报错十三式的布局假设错误)。
#
# 【重要】直接把【用户规则文件】交给 encrypt-strings.py,不要先转成 dcc filter:
# 该脚本内部复用 rules-to-filter.py 的 class_rule_to_filter 做类匹配,输入必须
# 是用户规则(点号通配符)。若喂 rules-to-filter.py 的产物(dcc filter 正则)
# 会被二次转换产生畸形正则(LLcom/.../),filter 那侧的同类坑见流程文档 §2 步骤 3。
if [[ $WANT_STRINGENC -eq 1 && $LINK_STUB -eq 1 ]]; then
  # 联动路径:stringenc 已在 STEP2 前跑完(桩必须先进 APK 才能被 dex2c 转译)。
  # STEP5 再跑一次会二次加密(同一明文被包两层密文)→ 整包乱码,必须跳过。
  log_info "字符串加密已在 STEP2 前置完成（联动路径，此处跳过避免二次加密）"
else
if [[ $WANT_STRINGENC -eq 1 ]]; then
  # activity* 需要 Activity 类列表 → 从 Manifest 动态提取(同 dex2c 侧做法)
  if grep -q '^[[:space:]]*activity\*[[:space:]]*$' "$STRING_RULES"; then
    log_info "检测到 activity* 规则,从 Manifest 提取 Activity 列表"
    python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" \
      "$WORK/.placeholder_string_activity.txt" --classes "$WORK/activity_classes.txt" \
      --on-fail skip || true
  fi

  # 残留清理(幂等):上一轮若留下解密桩但本次一条都没加密,不能把旧桩带进产物
  python3 "$ROOT/scripts/string-enc/encrypt-strings.py" clean "$WORK/decompiled"

  STRING_ENC_ARGS=()
  if [[ -f "$WORK/activity_classes.txt" ]]; then
    STRING_ENC_ARGS+=(--classes "$WORK/activity_classes.txt")
  fi
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    # 被抽进 so 的方法跳过 —— 它们的字符串会在 so 里,dex 侧没必要再加密
    STRING_ENC_ARGS+=(--exclude-methods "$WORK/project/jni/nc/compiled_methods.txt")
  fi
  # ── 纯 C 解密桩（2026-11-09）──────────────────────────────────────
  # 与下面 packer 分支互斥：native 桩没有可搬壳的 Java 类（dex 侧只有
  # 一个 native 声明 + <clinit>，本身就不含算法，搬壳无收益）。
  # 密钥注入走 ncSetKey（<clinit> 里 fill-array-data），不经 Java 静态字段。
  if [[ $WANT_NATIVE_STUB -eq 1 ]]; then
    # ⚠️ 必须传 --seed-hex + --stub-name：
    #   种子与桩名都已在 STEP3 之前定下（C 侧已按它生成注册代码），
    #   这里再随机一次 = 两边的类名/密钥不同 → 解密必失败且不报编译错。
    _cstub_seed_hex="$(cat "$WORK/stub_seed_for_decl.txt")"
    _cstub_spec="$(cat "$WORK/cstub_decl.txt")"
    if [[ -z "$_cstub_seed_hex" || -z "$_cstub_spec" ]]; then
      log_err "内部错误：纯 C 桩的种子/桩名未在 STEP3 之前定下"
      exit 1
    fi
    log_info "纯 C 桩复用构建期桩名: $_cstub_spec"
    python3 "$ROOT/scripts/string-enc/encrypt-strings.py" \
      "$WORK/decompiled" "$STRING_RULES" "${STRING_ENC_ARGS[@]}" \
      --apk "$STEP5_APK" \
      --stub-impl native \
      --seed-hex "$_cstub_seed_hex" \
      --stub-name "$_cstub_spec"
  # ── packer 联动（仅勾了 packer 时）：桩搬进壳 dex ──────────────────
  # ⚠️ 模块化红线：--emit-stub-dex 会【把桩从业务 dex 摘除】。不勾 packer 时
  #    绝不能让这件事发生——那时没有壳 dex 承载桩，摘除 = 运行期 ClassNotFound。
  #    所以只有 WANT_PACKER=1 才传该参数；其余组合与改动前逐字节一致。
  elif [[ $WANT_PACKER -eq 1 ]]; then
    # --compiled-methods：判断桩是否真被 dex2c 转译。不在其中 → 桩保持明文
    # Java（不 native 化）。缺这个参数会导致「dex2c+stringenc+packer 且不勾
    # --dex2c-stub」组合产出声明 native 却无实现的桩 → 启动闪退。
    _CM_ARG=()
    if [[ -f "$WORK/project/jni/nc/compiled_methods.txt" ]]; then
      _CM_ARG=(--compiled-methods "$WORK/project/jni/nc/compiled_methods.txt")
    fi
    python3 "$ROOT/scripts/string-enc/encrypt-strings.py" \
      "$WORK/decompiled" "$STRING_RULES" "${STRING_ENC_ARGS[@]}" \
      --apk "$STEP5_APK" \
      --emit-stub-dex "$WORK/stub.dex" ${_CM_ARG[@]+"${_CM_ARG[@]}"}
  else
    python3 "$ROOT/scripts/string-enc/encrypt-strings.py" \
      "$WORK/decompiled" "$STRING_RULES" "${STRING_ENC_ARGS[@]}" \
      --apk "$STEP5_APK"
  fi
fi
fi

# ── 防对比混淆（dex 层，最后做：等 dcc/stringenc 的改动落定后再上结构噪声） ──
# 放在 stringenc 之后的原因:stringenc 会给选中类插入解密桩并改写 const-string,
# 若 anti-diff 先做、stringenc 后做,stringenc 的改动会让 anti-diff 的"已处理"
# 标记附近继续出现新差异,削弱防对比效果;最后做 anti-diff,全量 smali 一次性
# 盖上标签重命名/块重排/入口垃圾指令噪声,diff 视角即"整包重编译"。
# anti-diff 自带跳过:native 方法(dcc 壳)、<init>/<clinit>(guard/dcc 依赖)。
if [[ $WANT_ANTIDIFF -eq 1 ]]; then
  # 变换 F（shl⇄mul 恒等重编码）已并入模块本体固定开启——原 antidiff.reencode
  # 子复选框（--anti-diff-f）已从 schema 下线（v1.2 回退），此处无条件传 --enable-f
  python3 "$ROOT/scripts/anti-diff/anti-diff.py" "$WORK/decompiled" --enable-f
fi

if [[ $WANT_SIGCHECK -eq 1 || $WANT_TRANSPILE -eq 1 || $WANT_ENVCHECK -eq 1 ]]; then
  repack_install_so "$WORK/decompiled" "$WORK/project/libs"
  # 强制解压 so 加载（本方案唯一允许的 Manifest 修改）——只在有 so 的组合执行;
  # 纯 dex 组合(仅 stringenc)没有 libnc.so,manifest 无需改写(报错二十三)
  repack_force_extractnativelibs "$WORK/decompiled"
  # 2026-11-08：清掉 apktool.yml 里继承来的 doNotCompress 条目（so / dex）。
  # 这是"继承输入 APK 规则"的后果：输入包若把 so/dex 列为"不压缩"，
  # 回编时我们新加的 libnc.so 也会跟着不压缩 —— 白胖约 1MB（双 ABI）。
  #
  # 为什么压缩是安全的：
  #   · so：上面刚强制 extractNativeLibs=true（安装时必解压），
  #         故 APK 内压缩只有收益。
  #   · dex：AOT 编译发生在【安装时、解压之后】，编译产物在
  #         /data/app/<pkg>/oat/，与 APK 内 dex 是否压缩无关。
  #         压缩只影响"读取 APK 时是否要先解压"，不影响 AOT 质量或结果。
  #         实测参照：正式发布的 APK（简盒.apk）本身就是 dex+so 全压缩，
  #         Android 生态里这是常态做法。
  repack_force_compress_payload "$WORK/decompiled"
fi

# ── 强制 debuggable=false（所有组合都做，2026-10-22）────────────────
# 逆向报告 v2 §8 F-11 实证：测试包 Manifest 写着 debuggable=true。
# 带这个标记的 release 包等于从系统层面给攻击者开了后门：
#   · run-as 可进私有目录、dump 内存
#   · 调试器可直接 attach —— 我们那套 ptrace/PR_SET_DUMPABLE 的前提被架空
# 与 extractNativeLibs 不同，这个【所有组合都要做】，包括纯 dex 组合：
# stringenc 的产物同样是 release 包，没有理由保留 debug 标记。
repack_force_debuggable_off "$WORK/decompiled"

# ── dex 局部拆分（2026-11-06）──────────────────────────────────────
# 所有模块都写完 smali 了，回编之前实测一遍：哪个 dex 装不下就只拆哪个。
#
# 为什么放在这里而不是解包后（2026-11-06 实测教出来的）：
#   · 解包时不知道各模块会插多少 —— 实测囧次元勾 stringenc 全量后
#     classes4 从 53398 涨到 53502（+104），因为每个含
#     `static final String` 的类都被加了 1 个 <clinit> 来给字段赋值
#     （编译期内联常量改成运行期解密）。这种增长事前估不出来。
#   · 全量重排会打乱原包 R8 的类聚类（按引用关系分的），重排后
#     method_ids 反而涨（实测 65463 → 73648），越排越炸。
#   · 局部拆分只动装不下的那个，其余 dex 的聚类完全保留。
#
# 耗时：没有超标的 dex 时约 3~5 秒（数一遍 .method + 读 header）。
# 失败不阻断：让 apktool 的报错暴露，不在这里吞掉。
python3 "$ROOT/scripts/repack/dex-rebalance.py" "$WORK/decompiled" \
  --apk "$IN_APK" --split \
  || log_warn "[dex-split] 拆分失败，继续（若回编报 out of range 请查此项）"

repack_build "$WORK/decompiled" "$WORK/unsigned.apk"

# ── 输出 ────────────────────────────────────────────────────────────
# 先把回编产物对齐好，再决定加壳是否接手最后一步（全程不签名，签名由开发者完成）。
#   - 勾加壳：dpt 吃的是"已对齐的成品包"。dpt 内部虽自带 zipalign，但它同时会
#     重写 dex/so/Manifest —— 与其让它对着未对齐的包做一次全量重写，不如先
#     对齐再交壳，失败时也更接近"哪一步坏的"（报错八的定位纪律）。
#   - 不勾加壳：与接入 packer 之前完全一致（finish_apk 直接落到 OUT_APK），
#     保证既有组合零行为变更。
if [[ $WANT_PACKER -eq 1 ]]; then
  ALIGNED="$WORK/aligned.apk"
  finish_apk "$WORK/unsigned.apk" "$ALIGNED"
  log_step 6 6 "基础加壳（dpt-shell）"
  # packer.sh 产物直接作为最终输出：加壳包不能在本脚本再叠一次 finish_apk
  # （加壳已重写 dex/so/Manifest，二次 zipalign 属二次改写）
  # 体积优化(报错四十三):schema 子复选框 packer.smaller → dpt --smaller
  # (方法体填料改统一 0x0e,产物更小);经环境变量传入,packer.sh 两参契约不变
  # 通用通道:--dpt-extra-args 自由文本同经环境变量 DPT_EXTRA_ARGS 传入
  PACKER_SMALLER="$PACKER_SMALLER" DPT_EXTRA_ARGS="$DPT_EXTRA_ARGS_TEXT" \
    EXCLUDE_ABI="$EXCLUDE_ABI" \
    STRINGENC_COMPONENTS="$WORK/decompiled/stringenc-components.json" \
    STUB_DEX="$WORK/stub.dex" \
    STUB_SEED_FILE="$WORK/stub_seed.txt" \
    CERT_SOURCE_APK="$IN_APK" \
    "$ROOT/scripts/packer/packer.sh" "$ALIGNED" "$OUT_APK"
  log_done "完成 ✅ 共 $TOTAL 个模块，产物: $OUT_APK（已加壳，未签名，开发者需自行 apksigner 重签）"
else
  finish_apk "$WORK/unsigned.apk" "$OUT_APK"
  log_done "完成 ✅ 共 $TOTAL 个模块，产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
fi
