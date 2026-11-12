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
#   提供了规则(任何勾选组合) → 用户规则(rules-to-filter.py)
#   未提供规则             → 自动抽主类(make-filter-from-apk.py,只读 APK 的 Manifest)
#
# ⚠️ 2026-11-12 解除对 --sigcheck 的依赖:此前"自动抽主类"被绑在
#    WANT_SIGCHECK 上,但那一步的实际输入只有 $LINK_APK(APK 文件本身),
#    make-filter-from-apk.py 从 AndroidManifest 解析 LAUNCHER activity,
#    不需要 sigcheck 的任何产物。该限制是从 apk-protect-action 迁入时
#    带进来的历史包袱(2026-10-31 4eaa644),已无技术依据。
#    影响:用户勾 --dex2c 且规则留空时必须连带勾 --sigcheck 才能出包。
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
# --stringenc-chacha20（2026-11-09）：纯 C 桩的密钥流算法换成 ChaCha20。
#   （默认）    ：splitmix64 —— 快，但可逆（猜中一条明文可反推密钥解全包）
#   chacha20    ：ChaCha20  —— 不可逆（猜中一条只泄漏那一条），首次解密多算一点
# 只对 --stringenc-native 有意义：Java 桩的算法在 dex 里，换算法要重做整条
# d8→baksmali 链路与 384 项对拍，不在本次范围。
# 必须与 encrypt-strings.py 的 --algo 同源，否则全包乱码（构建期不报错）。
WANT_CHACHA20=0
# Amice 混淆（2026-11-05）：编译期 pass，作用于 so 的 .text。
# 只影响 NDK 编译参数，不影响 dex 层任何步骤。
WANT_OBFUSCATE=0
OBF_MBA=0
OBF_FLATTEN=0
# --dex2c-static-register（2026-11-10）：dex2c 的业务方法改用【静态短名】注册。
#
# 为什么需要这个开关：
#   `--dynamic-register` 会生成 `JNINativeMethod` 表，表里存
#   `(void *)Java_xxx` —— 即【取了业务函数的地址】。而 Amice 的 VMP
#   在 vm_virtualize/mod.rs:1067 的 has_unsupported_function_uses 里规定：
#   除「直接调用」和「@llvm.global.annotations」外，任何函数地址引用都
#   判为 non-call address use → 【静默跳过】该函数（构建照绿，日志无提示）。
#   实测 IR：@tbl = global [1 x %struct] [{ ptr @.str, ptr @.str.1,
#                                        ptr @Java_..._onCreate }]
#   → 4 个 dex2c 业务方法（25.8KB）全部无法上 VMP。
#
#   关掉动态注册后 writer.py:111 生成 `extern "C" JNIEXPORT ... JNICALL
#   Java_xxx(...)`，IR 里只剩一条 define，没有地址引用 → 可虚拟化。
#   实测：check-vmp-eligibility.py 通过。
#
# 代价（如实）：
#   JNIEXPORT 自带 visibility("default")，对 -fvisibility=hidden 免疫 →
#   业务方法名进 .dynsym（`nm -D` 可见）。但实测这些名字本来就从
#   .rodata 的 "onCreate"/"attachBaseContext" 字符串可反推，藏名字
#   只挡 grep 不挡定位 —— 用「藏名字」换「25.8KB 业务逻辑可 VMP」是划算的。
#
# 风险：动态注册有真机实证（见下方 dcc.py 调用处的大段注释），静态短名
#   注册在这条链上【没有】行过真机。开了这个开关必须真机验一遍启动不崩。
WANT_DEX2C_STATIC_REG=0
# --vmp（2026-11-10）：指令级虚拟化，只作用于 .ncx 里被 annotate 的业务函数。
#
# 为什么要它（与 --obfuscate 的分工）：
#   --obfuscate 实测在本项目里几乎是空的 —— NC_OBF 宏没有任何函数在用
#   （三个解密链函数都搬去 VMP 文件了），消费方的 8 个 .c 也是零 annotate，
#   所以只剩全局 MBA 在起作用（算术重写，化简就回来了）。强度很低。
#   --vmp 是函数级强保护：函数体编译成自定义 VM 字节码，解锁后内存里不是
#   明文 ARM64 → 挡住动态 dump（这是 .ncx 锁箱挡不住的那一类）。
#
# 依赖：必须配 --dex2c-static-register（动态注册的 JNINativeMethod 表取了
#   函数地址，Amice 会静默跳过，见该变量处注释）。
WANT_VMP=0
# NC_VMP_CSTUB（2026-11-11）：是否给 stringenc 的【密钥流函数】打 VMP 注解。
# 默认 1 = 打（只打 3 个最值钱的，不是全部 6 个 —— 见下）。
#
# 选哪三个（攻防口径，不是按代码量）：
#   nc_block_ks              splitmix64 密钥流块生成
#   nc_chacha20_keystream64  ChaCha20 密钥流（当前生产档）
#   nc_mix64                 splitmix64 终混合
#   这三个决定「能不能解密全部字符串」—— 拿到密钥流算法 = 全包沦陷。
#   不选的三个不值得：b64_decode / utf8_to_utf16 是公开编码算法，
#   decrypt 只是装配流程（真正的秘密在密钥流里）。
#
# 为什么不一刀切全上（2026-11-11 真机实测）：
#   6 个函数一起 VMP → 启动页 SIGSEGV/SEGV_ACCERR 栈溢出（Amice 的
#   spill frame 是栈分配，ART 线程池线程只有约 1MB 栈）。只挑 3 个密钥流
#   函数（代码短、局部变量少、寄存器需求低）风险小得多。
#
# ⚠️ 这不是「stringenc 不能 VMP」的普适结论 —— nox 自己的解密链 14 个
# 函数全上 VMP 且真机可用。差别在字节码规模：Base64 4-way、UTF-8 解码
# 那几个字节码远长于 nox 那些 19~31 条指令的小函数。
#
# 设 0 可整体关闭（回到"algorithm 层只受锁箱保护"）。
NC_VMP_CSTUB=1
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
    # 密钥流算法（2026-11-09）。隐含 stringenc + native（Java 桩不支持换算法）。
    --stringenc-chacha20) WANT_STRINGENC=1; WANT_NATIVE_STUB=1; STUB_IMPL=native; WANT_CHACHA20=1; shift ;;
    # Amice 混淆（2026-11-05）。子复选框隐含父模块开启（与 --packer-smaller 同惯例）。
    # 值为空时由 lib-ndk.sh 按"父模块开、子项默认"取默认组合（MBA on / flatten off）。
    --obfuscate) WANT_OBFUSCATE=1; shift ;;
    --dex2c-static-register) WANT_DEX2C_STATIC_REG=1; shift ;;
    --vmp) WANT_VMP=1; shift
           # ⚠️ 2026-11-11 调整：不再自动联动 --dex2c-static-register。
           #   原因：dex2c 产物已确认 100% 被 Amice 跳过（寄存器预算），
           #   不给它打注解了。而静态注册的代价是业务方法名进 .dynsym，
           #   既然不再需要它的"让路"效果，就不该无谓付出这个代价。
           #   --vmp 现在保护的是 sigcheck / stringenc 自己的小函数。
           ;;
    --vmp-keep-dynamic-register) WANT_VMP=1; shift ;;   # 历史参数，保留兼容（现等价于 --vmp）
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
  # 规则文件:提供了就必须非空。没提供 → 自动抽主类(只读 APK,不依赖 sigcheck)。
  # ⚠️ 只在【dex2c 模块】勾选时校验；只勾 dex2c_stub 时无用户类名规则可言
  if [[ $WANT_DEX2C -eq 0 ]]; then
    :
  elif [[ -n "$TRANSPILE_RULES" ]]; then
    require_nonempty_file "$TRANSPILE_RULES" "dex2c 规则文件"
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
      log_err "     正确姿势: ①规则留空 → 自动抽主类; ②定向规则,如 com.xixin.box.**"
      exit 1
    fi
    DCC_FILTER="$WORK/dcc_filter.txt"
  else
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
  #
  # ── --dex2c-static-register（2026-11-10）：关掉动态注册以解锁 VMP ────
  # 动态注册的 JNINativeMethod 表存 `(void *)Java_xxx` = 取函数地址 →
  # Amice VMP 判为 non-call address use → 静默跳过（见变量定义处的长注释）。
  # 关掉后走静态短名，IR 里只有 define 没有地址引用 → 可虚拟化。
  _D2C_REG_ARG="--dynamic-register"
  if [[ $WANT_DEX2C_STATIC_REG -eq 1 ]]; then
    _D2C_REG_ARG=""
    echo "[dex2c] 注册方式: 静态短名（为 VMP 让路；业务方法名将进 .dynsym）"
  else
    echo "[dex2c] 注册方式: 动态注册（业务方法名不进 .dynsym，但业务函数无法 VMP）"
  fi
  module_cd_run "$DEX2C_DIR" python3 dcc.py -i "$LINK_APK" -o "$WORK/dex2c-no-build.apk" \
    --project-archive "$WORK/dcc-project.zip" \
    --no-build \
    --disable-signing \
    --allow-global \
    ${_D2C_REG_ARG:+"$_D2C_REG_ARG"} \
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

# ── 纯 C 解密桩的 JNI 绑定方式（2026-11-09 最终形态）────────────────
#
# 用 JNI 【短名绑定】，不用 RegisterNatives。原因（真机实测两轮）：
#
#   ① 桩类在自己的 <clinit> 里 loadLibrary("nc")，此刻该类【正在初始化中】，
#      ART 不允许 FindClass 到未完成初始化的类 → RegisterNatives 失败
#      → 若在 JNI_OnLoad 里 fail-fast 返回 JNI_ERR，启动即
#        UnsatisfiedLinkError: JNI_ERR returned from JNI_OnLoad。
#
#   ② 即使注册成功，ART 对 native 方法的短名解析发生在【类链接阶段】，
#      早于 <clinit> 执行 —— 那时 so 还没加载，ART 记下"方法不存在"，
#      之后调用必抛 NoSuchMethodError（真机日志：at <clinit>:12）。
#
# 短名绑定（Java_<mangled>_<method>）由 ART 在【首次调用时】dlsym，
# 天然满足"so 已加载"这个前提。类名与解密方法名都是每包随机的，
# 所以这个封装文件必须构建期生成。
#
# 代价：这两个符号会出现在 .dynsym（短名绑定的固有代价，与 dex2c 产物同）。
# 名字是随机包名，不含业务语义。
if [[ $WANT_NATIVE_STUB -eq 1 ]]; then
  _cstub_jni_dst=""
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    _cstub_jni_dst="$WORK/project/jni/nc"
  else
    _cstub_jni_dst="$WORK/project/jni"
  fi
  # 本段在下面"C 源拷贝"的 mkdir 之前执行，纯 --stringenc-native 组合下
  # jni/ 还不存在 —— 这里必须先建（否则 cat > 报 No such file，set -e 杀流水线）
  mkdir -p "$_cstub_jni_dst"
  echo "[cstub] JNI 绑定方式: 短名（构建期生成封装，见 nc_strdec_bind.c）"
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
# ── Amice bundle 解析（--obfuscate 与 --vmp 共用，2026-11-10 抽出）──
# 两个开关都需要「插件本体 + host libLLVM + 配套 NDK」这套环境，
# 但需要的 pass 不同：
#   --obfuscate → 全局 MBA / flatten（写法是环境变量，作用于所有编译单元）
#   --vmp       → 只加载插件，靠 annotate("+vm_virtualize") 逐个函数启用
# 抽成一个函数是为了避免两份"找 bundle/校验/定位 NDK"的代码漂移
# （本仓库吃过多次"抄一遍=制造第二份真相"的亏，见 setup-toolchain 的来历）。
resolve_amice_bundle() {
  local _why="$1"          # 出现在报错里，说明是谁需要它
  local _bundle="${AMICE_BUNDLE:-}"
  if [[ -z "$_bundle" || ! -d "$_bundle/amice" ]]; then
    log_err "启用了 $_why，但找不到 Amice bundle"
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
  local _bundle_ndk
  _bundle_ndk="$(find "$_bundle" -maxdepth 1 -type d -name 'android-ndk-*' | head -1)"
  if [[ -z "$_bundle_ndk" || ! -x "$_bundle_ndk/ndk-build" ]]; then
    log_err "bundle 里找不到自带的 NDK（期望 <bundle>/android-ndk-rXX/ndk-build）"
    log_err "     插件与 NDK clang 必须配套 —— 用预装 NDK 会段错误（实测）"
    ls -la "$_bundle" | head -10 >&2
    exit 1
  fi
  export AMICE_NDK_HOME="$_bundle_ndk"
}

if [[ $WANT_OBFUSCATE -eq 1 ]]; then
  resolve_amice_bundle "--obfuscate（代码混淆）"
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

# ── --vmp（2026-11-10）：指令级虚拟化，只作用于 .ncx 里的业务函数 ──────
# 与 --obfuscate 的区别（这是本参数存在的理由）：
#   --obfuscate 是【全局弱混淆】：MBA 重写算术、flatten 重排控制流。
#     实测它在本项目里几乎是空的 —— NC_OBF 宏没有任何函数在用，
#     消费方的 8 个 .c 也零 annotate，所以只剩全局 MBA 在起作用。
#   --vmp 是【函数级强保护】：把函数体编译成自定义 VM 字节码，
#     解锁后内存里不是明文 ARM64 而是字节码 → 挡住动态 dump。
#
# 只加载插件、不设 AMICE_MBA/AMICE_FLATTEN：VMP 由 annotate 逐函数启用，
# 不需要也不想要全局弱混淆掺进来（两者叠加会让体积暴涨而强度增量很小）。
if [[ $WANT_VMP -eq 1 ]]; then
  resolve_amice_bundle "--vmp（指令级虚拟化）"
  export AMICE_MBA=false
  export AMICE_FLATTEN=false
  # ⚠️⚠️ 2026-11-11 修（VMP 空转的真因）：必须设 AMICE_VM_VIRTUALIZE=true。
  #
  #   函数注解（annotate("+vm_virtualize")）只是【函数级覆盖】，
  #   它不能把一个【没启用的 pass】拉起来运行。文档原话
  #   （PassOrder_zh_CN.md）："AMICE_PASS_ORDER 是更外层的 Pass 允许列表：
  #   没有列入的 Pass 不会因为函数注解而重新运行。"
  #   而 AMICE_VM_VIRTUALIZE 默认 false —— 不设它，pass 根本不装，
  #   annotate 写得再对也没人读。
  #
  #   首版只抄了 nox 的 AMICE_VM_PROFILE_PATH 却漏了这个开关，
  #   实测产物：.ncx 只涨 36 字节（annotate 进了 llvm.global.annotations
  #   表，多了个字符串），函数体一条指令都没虚拟化 —— 典型的静默空转。
  #   对照 nox 的 make-zip-lib.sh:163 是
  #       AMICE_VM_VIRTUALIZE=true AMICE_VM_PROFILE_PATH="$prof" "$CC" ...
  #   两个变量必须成对出现。
  export AMICE_VM_VIRTUALIZE=true
  # VM profile：默认用包内自带的 nox-vmp-func（函数级隔离：每函数独立
  # 分派运行时 + 独立 handler 副本）。内置 amice-simple-vmp 是 module 级
  # 共享，攻击者逆一套 VM 语义就能读全部受保护函数。
  #
  # ⚠️ 与 nox 的 make-zip-lib.sh 用同一份 profile，理由一致（见该文件注释）。
  # ⚠️ 用环境变量 AMICE_VM_PROFILE_PATH 而不是 annotate("vm_profile=...")：
  #    annotate 里再塞 profile 路径会和 +vm_virtualize 一起进
  #    llvm.global.annotations，多一个字符串常量引用，不划算且难排查。
  _vmp_prof="$GUARD_SRC/vmp-profile-func"
  if [[ -f "$_vmp_prof/manifest.toml" ]]; then
    export AMICE_VM_PROFILE_PATH="$_vmp_prof"
    log_info "VMP profile: nox-vmp-func（函数级隔离）"
  else
    log_info "VMP profile: 内置 amice-simple-vmp（module 级共享）"
    log_info "   ⚠️ 包内缺 vmp-profile-func/manifest.toml —— 强度降级但功能正常"
  fi
  log_info "VMP 用 NDK: $AMICE_NDK_HOME（bundle 自带，与插件配套）"
  # ── RUST_LOG（2026-11-11）──────────────────────────────────────────
  # 必须开：Amice 的 VMP 遇到不满足条件的函数是【静默跳过】——
  # 只有 RUST_LOG=amice=debug 才会打出
  #     skip function "xxx": function has non-call address uses
  # 这类日志。没有它，构建全绿而 VMP 一个函数都没生效，且无从判断。
  # 这与 nox 的 make-zip-lib.sh:72 同一行配置、同一理由。
  #
  # ⚠️ 不设的话，本参数最核心的失败模式（静默跳过）完全不可观测 ——
  #    那正是 AGENTS.md §3.3 反复记的教训：防护"连续三个月零生效"而
  #    无人发现，因为日志里只有"失败但继续"。
  export RUST_LOG="${RUST_LOG:-amice=debug}"
  log_info "RUST_LOG=amice=debug（用于捕获 VMP 的 skip function 日志）"
  # ── AMICE_VM_ONLY_ANNOTATED（2026-11-11，本 fork 的补丁）─────────────
  # 让 VMP 只处理【带 annotate("+vm_virtualize")】的函数，而不是全部。
  #
  # 为什么必须（实测数据）：AMICE_VM_VIRTUALIZE=true 是全局开关，
  # default_config.enable 会传给每个无注解的函数（amice-macro/src/lib.rs:151），
  # 于是所有函数都成候选。dex2c 引入 87 个引擎辅助函数后：
  #   只 sigcheck+vmp:                .text 180,836 / 43 个函数 / 466KB
  #   sigcheck+dex2c+stringenc+vmp:   .text 648,176 / 130 个函数 / 1,397KB
  # 白涨 467KB，且启动页栈溢出（多余的 runtime 副本 + 深调用链）。
  #
  # 有了这个开关，NC_VMP_CSTUB 之类的"给谁打注解"才真正生效。
  export AMICE_VM_ONLY_ANNOTATED=1
  log_info "VMP 只处理带 annotate 的函数（AMICE_VM_ONLY_ANNOTATED=1）"
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
  cp "$ROOT/scripts/string-enc/csrc/nc_strdec.h"     "$_cstub_dst/"
  cp "$ROOT/scripts/string-enc/csrc/nc_strdec.c"     "$_cstub_dst/"
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
  # 密钥流算法档位（2026-11-09）。同样必须与 encrypt-strings.py 同源。
  # 0 = splitmix64，2 = ChaCha20（见 nc_strdec.h 的 NC_STRDEC_ALGO_*）。
  if [[ $WANT_CHACHA20 -eq 1 ]]; then _algo=2; _algo_name=chacha20; else _algo=0; _algo_name=splitmix64; fi
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
  # 解密方法名也是每包随机的（防固定签名），短名封装必须用它。
  # 漏了它的症状（真机实测）：
  #   No implementation found for java.lang.String il.wd.ct.ae.y9(java.lang.String)
  #   (tried Java_il_wd_ct_ae_y9 ...) —— ART 找的是随机名，而我们只导出了 ncDec
  _stub_dec_method="$(printf '%s' "$_decl" | cut -f2)"
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

/* 密钥流算法：必须与 encrypt-strings.py 的 --algo 一致。
 * 0 = splitmix64（历史实现），2 = ChaCha20（不可逆）。
 * 两侧不同源 = 构建期加密用 A、运行期解密用 B ⇒ 全包乱码，且构建期不报错。 */
#ifndef NC_STRDEC_ALGO
#  define NC_STRDEC_ALGO $_algo
#endif

/* 密钥本体（$_nk 个 uint64，大端字节序），由 bootstrap 直接 set_key。
 * 为什么不经过 dex：见 native_stub.py 里 <clinit> 的说明 —— native 方法
 * 在类链接阶段解析，那时 so 尚未加载 → NoSuchMethodError（真机实测）。
 * 改为编译进 so 后，密钥不出现在 dex 的任何位置（本需求的核心）。
 *
 * ── 包了壳时【故意不定义】（2026-11-10 用户裁决）──────────────────
 *
 * 纯 C 桩的密钥有两个来源（见 nc_strdec_jni.c 的 nc_ensure_key）：
 *   ① 运行期从壳 so 的 ncg_strkey() 取
 *   ② 编译期常量（本宏）兜底
 *
 * 若两者都编进产物，则「去掉壳 so」→ ① 失败 → 退到 ② → **照样能解**，
 * 「必须带着壳运行」这条联动等于白做。
 *
 * 所以：**包了壳就不编常量**。此时去掉壳 so 会让密钥只剩空值 →
 * nc_strdec_has_key() 为 0 → 解密 fail-closed → 字符串原地返回密文 →
 * 业务崩或满屏乱码。这才是"去不掉壳"。
 *
 * 没包壳时仍然编常量（否则单勾 stringenc-native 完全无法工作）。
 */
EOF

# 按是否包壳决定要不要写密钥常量（2026-11-10）
if [[ $WANT_PACKER -eq 1 ]]; then
  cat >> "$_cstub_dst/nc_strdec_cfg.h" <<'EOF'
/* 本包【已加壳】：密钥只从壳 so 的 ncg_strkey() 运行期取，
 * 不提供编译期常量 —— 否则去掉壳仍能解密，联动失效。
 * 详见 nc_strdec_jni.c 的 nc_ensure_key()。 */
EOF
else
  cat >> "$_cstub_dst/nc_strdec_cfg.h" <<EOF
#define NC_STRDEC_KEY_BYTES { $([ "$_nk" = "1" ] && echo "" )$(python3 -c "
import sys
k='$_cstub_seed_hex'
print(', '.join('0x%s' % k[i:i+2] for i in range(0, len(k), 2)))
") }
EOF
fi

cat >> "$_cstub_dst/nc_strdec_cfg.h" <<'EOF'

#endif
EOF
  # ── JNI 短名绑定封装（2026-11-09）────────────────────────────────
  # 为什么不用 RegisterNatives（真机实测踩过）：
  #   桩类在自己的 <clinit> 里 loadLibrary("nc")，此刻该类【正在初始化中】，
  #   ART 不允许 FindClass 到未完成初始化的类 → RegisterNatives 返回非 0
  #   → JNI_OnLoad 返回 JNI_ERR
  #   → UnsatisfiedLinkError: JNI_ERR returned from JNI_OnLoad（真机日志）
  #
  # 改用 JNI 短名绑定：ART 在首次调用 native 方法时按
  #   Java_<包名点换_>_<类名>_<方法名>
  # 去 so 的 .dynsym 里 dlsym —— 不需要 FindClass，也没有初始化时序问题。
  # 类名是构建期已知的（每包随机），所以函数名可以在这里生成。
  #
  # 代价（如实）：这两个符号会出现在 .dynsym（短名绑定的固有代价，
  # 与 dex2c 产物同）。名字是随机包名，不含业务语义。
  _jni_cls="$(printf '%s' "$_stub_class" | tr '/' '_')"
  cat > "$_cstub_dst/nc_strdec_bind.c" <<EOF
/* nc_strdec_bind.c — 由 protect.sh 构建期生成，不进 git（2026-11-09）
 *
 * 作用：把桩类的 native 方法名绑定到 nc_strdec_jni.c 的实现上。
 * 为什么需要它：见 protect.sh 里"JNI 短名绑定封装"那一节的说明 ——
 * RegisterNatives 在类初始化期间会失败，只能走短名。
 *
 * ⚠️ 类名 $_stub_class 是每包随机的，改由构建期注入。
 * ⚠️ 方法名 ncDec / ncSetKey 必须与 nc_strdec_jni.c 的混淆表一致
 *    （那边用 XOR 0x5A 存的就是这两个名字）。
 */
#include <jni.h>
#include "nc_strdec.h"

/* ⚠️ 方法名 ${_stub_dec_method} 是每包随机的（防固定签名），必须与
 * dex 侧桩类里的声明同名 —— 漏用真名会让 ART 找不到实现：
 *   No implementation found for ... ->${_stub_dec_method}(...)
 *   (tried Java_..._${_stub_dec_method} ...)                            */
JNIEXPORT jstring JNICALL
Java_${_jni_cls}_${_stub_dec_method}(JNIEnv *env, jclass clazz, jstring payload)
{
    return nc_strdec_jni_decrypt(env, clazz, payload);
}
EOF
  echo "[cstub] 已生成短名绑定: Java_${_jni_cls}_${_stub_dec_method}"

  echo "[cstub] 纯 C 解密桩: 类=$_stub_class NKEYS=$_nk"
fi

# ── Amice 插件加载规格（2026-11-10）──────────────────────────────────
# ndk_write_mk 的第 4 参数非空 = 往 APP_CPPFLAGS 加 -fpass-plugin。
# 三种情形：
#   --obfuscate        → _OBF_SPEC = "mba" / "mba,flatten"（全局弱混淆）
#   --vmp（只 VMP）    → _OBF_SPEC 为空，但插件仍必须加载 → 传 "vmp"
#   两个都开           → "mba,vmp" 之类，只要非空即加载插件
# 用 "vmp" 这个标记而不是空串，是因为空串会让 mk 完全不加 -fpass-plugin
# → 插件没加载 → annotate("+vm_virtualize") 无人解析 → VMP 静默失效。
_MK_OBF_SPEC="$_OBF_SPEC"
if [[ $WANT_VMP -eq 1 ]]; then
  _MK_OBF_SPEC="${_MK_OBF_SPEC:+$_MK_OBF_SPEC,}vmp"
fi
ndk_write_mk "$WORK/project/jni" nc "$GUARD_LIB_DIR" "$_MK_OBF_SPEC"   # mk 模板唯一来源（报错十一），模块名固定 nc

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

  # 判据：dex2c 产物里【实际存在】的 JNI 函数定义数（用于"静默失防"守卫）。
  #
  # ⚠️ 2026-11-10 修（这是本仓库最严重的一次假绿）：
  #   旧实现数的是 `JNIEXPORT ... JNICALL`，但 protect.sh:467 一直传
  #   `--dynamic-register` → writer.py:106 产出的形态是
  #       void Java_com_xxx_MainActivity_onCreate(JNIEnv *env, ...)
  #   【没有】JNIEXPORT / JNICALL。于是：
  #     · so_section_mark.py 的 dex2c-jni 规则命中 0   → 一个都没标
  #     · 本守卫 JNI_HDRS 也是 0 → `0 > 0` 为假 → 直接放行
  #   「规则」与「守卫」共用同一个失效正则，一起失效，所以两边都安静。
  #
  #   实测后果（protected_unsigned_sign.apk / arm64）：
  #     .ncx  7,908 B（只有 sigcheck/stringenc 的几个小函数）
  #     .text 250,156 B（含 jni.onCreate 4,072 B / jni.k 16,492 B，熵 6.179 = 明文）
  #     → dex2c 抽走的业务逻辑【全部】留在明文段，零加密。
  #
  #   现在按【两种形态都数】判定：静态注册数 JNIEXPORT，动态注册数 Java_ 定义。
  #
  # ⚠️ 2026-11-11 修：两条 grep 必须带 `|| true`。
  #   本脚本开了 `set -euo pipefail`，而 grep 无匹配时退出码是 1 ——
  #   pipefail 让整条管道返回 1 → set -e 直接终止 protect.sh。
  #   实测（CI run 42851661903）：纯 C 桩 + VMP 组合下 jni 目录里没有
  #   动态注册形态的文件 → JNI_DYNAMIC 那条 grep 无匹配 → rc=1 行号 1169
  #   → 整个构建失败。这是"统计数字"的语句，无匹配本就是合法结果（0）。
  JNI_STATIC=$(grep -rhoE 'JNIEXPORT[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+JNICALL' \
               "$WORK/project/jni" --include='*.cpp' --include='*.cc' --include='*.c' 2>/dev/null | wc -l || true)
  JNI_DYNAMIC=$(grep -rhoE '^[[:space:]]*(jboolean|jbyte|jshort|jchar|jint|jlong|jfloat|jdouble|jstring|jobject|jarray|jclass|jthrowable|void|jsize)[[:space:]]+\**[[:space:]]*Java_[A-Za-z0-9_]+[[:space:]]*\(' \
                "$WORK/project/jni" --include='*.cpp' --include='*.cc' --include='*.c' 2>/dev/null | wc -l || true)
  JNI_STATIC=${JNI_STATIC:-0}; JNI_DYNAMIC=${JNI_DYNAMIC:-0}
  JNI_HDRS=$((JNI_STATIC + JNI_DYNAMIC))

  # 两条规则都挂上：静态注册 + 动态注册。
  # 只挂其中一条会在换注册方式时静默失防（本次事故就是这么来的）。
  #
  # ── VMP（2026-11-10）：给业务方法同时打 +vm_virtualize ──────────────
  # 目的：解锁后内存里是 VM 字节码而不是明文 ARM64，挡住动态 dump。
  # 前置条件（四条，缺一即被 Amice 静默跳过）：
  #   ① 函数地址不被「非调用用途」引用 —— vm_virtualize/mod.rs:1067 的
  #      has_unsupported_function_uses 只豁免 direct-call 和
  #      @llvm.global.annotations。所以：
  #        · 动态注册的 JNINativeMethod 表存 (void *)Java_xxx = 取地址 → 跳过
  #          → 必须用 --dex2c-static-register 关掉它（--vmp 已自动联动）
  #        · attribute 里不能带 used / retain（clang 会把它们变成
  #          @llvm.used 表，表里是 ptr @func → 也算地址引用，实测确认）
  #   ② 属性必须在 extern "C" 作用域内，否则 C++ mangling 成 _Z40Java_...
  #      → ART 找不到符号。静态注册形态自带 extern "C"，天然满足。
  #   ③ amice 插件必须真的加载（-fpass-plugin）→ 由 --vmp 负责
  #   ④ 函数得有独立符号（noinline），否则被内联掉就无处虚拟化
  #
  # ⚠️⚠️ 2026-11-11 实测结论：dex2c 产物【不再打 VMP 注解】。
  #
  #   真构建（RUST_LOG=amice=debug）拿到 4 个业务方法的跳过原因，
  #   全是结构性的、改配置解决不了的：
  #     attachBaseContext : register pressure  values=27 vregs=32 free=0
  #     k                 : register pressure  values=27 vregs=32 free=0
  #     onCreate          : register pressure  values=27 vregs=32 free=0
  #     onConfigurationChanged : non-null pointer constants cannot be materialized
  #
  #   根因：Amice 的 VM 只有 x0..x31 共 32 个虚拟寄存器，而 dex2c 生成的
  #   函数把 Dalvik 的每个局部变量映射成一个 C 变量（Dalvik 最多 255 个
  #   局部变量），寄存器需求天生超限。nox 当初的 ncg_stub_recover 也是
  #   这个坑（values=22 就超），靠「拆函数」才过 —— 但 dex2c 产物是引擎
  #   生成的一整个方法，没法为了 VMP 去拆。
  #
  #   留着注解的代价：实测 .so 从 527KB 涨到 1.2MB（Amice 把 profile 和
  #   VM runtime 全编进去了），而 .ncx 一个字节没变、没有函数被虚拟化 ——
  #   纯亏 674KB。所以这里不再打。
  #
  #   要保护 dex2c 产物得换路子（PVM2 在 Dalvik 层虚拟化 / VMPacker 做
  #   二进制级 VMP / 或干脆只做 flatten）。--vmp 现在的实际作用是保护
  #   sigcheck 与 stringenc 自己的小函数（它们的寄存器需求小得多）。
  _MARK_EXTRA=()
  if [[ $WANT_VMP -eq 1 ]]; then
    echo "[mark] VMP: dex2c 产物【不】打注解（实测 4/4 因寄存器预算被跳过，见 protect.sh 注释）"
  fi
  python3 "$GUARD_SRC/so_section_mark.py" "$WORK/project/jni" \
    --rule dex2c-jni \
    --rule dynamic-register-jni \
    --exclude nc_guard_jni.c \
    --exclude-func ncVerify \
    --exclude-func heartbeat \
    --exclude-func JNI_OnLoad \
    --exclude-func selftest \
    "${_MARK_EXTRA[@]}" \
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
    echo "❌ 检出 $JNI_HDRS 个 JNI 函数定义（静态 $JNI_STATIC / 动态 $JNI_DYNAMIC），但段标记命中 0" >&2
    echo "   → dex2c 的 writer.py 的函数头形态变了，两条规则都已脱节" >&2
    echo "   → 修 nox 仓库的 so_section_mark.py（dex2c-jni / dynamic-register-jni），" >&2
    echo "     不许静默放行：那等于 dex2c 抽走的业务逻辑全部以明文留在 .text" >&2
    exit 1
  fi
  # 配对断言：检出的定义数必须与标记数【对得上】。
  # 只查"MARKED==0"不够 —— 3187 个方法里标上 3 个也能通过，实质仍是失防。
  #
  # ⚠️ 2026-11-10 修正分母：必须扣掉【被 --exclude-func 显式排除】的函数。
  #   首版把 JNI_OnLoad 算进分母 → CI 报「检出 8 个，只标上 6 个（要求 ≥7）」
  #   而实际是 100% 覆盖。JNI_OnLoad 是 unlock 的调用方，锁进 .ncx 会
  #   "解锁前执行密文" → 死锁，它【必须】留在明文 .text。
  #   把故意不标的算作漏标，等于把守卫变成误报源 —— 这正是本文件
  #   反复记的那条教训（守卫本身是对的，判据写错就成噪音源）。
  _EXCLUDED=$(grep -rhoE '(JNI_OnLoad|ncVerify|heartbeat|selftest)[[:space:]]*\(' \
              "$WORK/project/jni" --include='*.cpp' --include='*.cc' --include='*.c' 2>/dev/null \
              | sort -u | wc -l || true)
  _EXCLUDED=${_EXCLUDED:-0}
  _EXPECT=$(( JNI_HDRS - _EXCLUDED ))
  [[ $_EXPECT -lt 0 ]] && _EXPECT=0
  if [[ $_EXPECT -gt 0 && $MARKED -lt $_EXPECT ]]; then
    echo "❌ 段标记覆盖不足：应标 $_EXPECT 个（检出 $JNI_HDRS，显式排除 $_EXCLUDED），" >&2
    echo "   实际只标上 $MARKED 个" >&2
    echo "   → 有 dex2c 产物仍在明文 .text，攻击者 objdump 即可读" >&2
    echo "   → 若排除名单（JNI_OnLoad/ncVerify/heartbeat/selftest）与实际不符，先修名单" >&2
    exit 1
  fi
  echo "[mark] 完成：$MARKED 处 .ncx 标记 / 应标 $_EXPECT 个（检出 $JNI_HDRS，排除 $_EXCLUDED）"

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
if [[ $WANT_NATIVE_STUB -eq 1 && "${TMP_NOMARK:-0}" != "1" ]]; then
  echo "[mark] 段标记：纯 C 解密桩【算法层】→ .ncx"
  # ── VMP（2026-11-11）：--vmp 时同时打 +vm_virtualize ──────────────
  # 这 5 个函数是 stringenc 的全部算法（Base64/密钥流/UTF-8），
  # 都不取地址、寄存器需求小，是最可能真正被虚拟化的目标
  # （对照：dex2c 产物因寄存器超限 100% 被跳过）。
  #
  # ⚠️ 走 so_section_mark 的 --annotate 而不是手写 attribute：
  #    它会自动去掉 used/retain（那两个会产生 @llvm.used → Amice 跳过）。
  # ═══ VMP 范围实验开关（2026-11-11）═══════════════════════════════
  # NC_VMP_CSTUB=0（默认）→ 不给 stringenc 算法层打 VMP 注解
  # NC_VMP_CSTUB=1         → 打（旧行为，实测真机栈溢出）
  #
  # 为什么默认关：真机实测（sigcheck+dex2c+stringenc+vmp，两个 algo 档
  # 都试过）应用启动页 SIGSEGV/SEGV_ACCERR，栈溢出：
  #   guard page 0x...e000-0x...f000 权限 ---
  #   崩溃 sp 恰在 guard page 上边界（再压 16B 即越界）
  #   x29 与 sp 相差整整 1.01MB
  # 而同一份代码只 VMP sigcheck（derive_expected）则完全正常。
  #
  # 注意：这不是"stringenc 不能 VMP"的普适结论 —— nox 自己的解密链
  # 14 个函数全上 VMP 且真机可用。差别在字节码规模：这里 5 个函数
  # 含 Base64/UTF-8/密钥流，字节码远长于 nox 那些 19~31 条指令的小函数。
  # 根因待查（dispatcher 内 61 处 bl 回自身，疑似递归分派）。
  if [[ $WANT_VMP -eq 1 && "$NC_VMP_CSTUB" == "1" ]]; then
    echo "[mark] VMP: 密钥流函数稍后单独打注解（NC_VMP_CSTUB=1）"
  elif [[ $WANT_VMP -eq 1 ]]; then
    echo "[mark] VMP: 纯 C 桩算法层【不】打注解（NC_VMP_CSTUB=0，实测真机栈溢出）"
  fi
  # 一次调用同时做两件事（2026-11-11 改）：
  #   --pattern           → 6 个算法函数全部进 .ncx（受锁箱保护）
  #   --annotate-pattern  → 只有 3 个密钥流函数追加 VMP 注解
  #
  # 为什么不分成两次调用：so_section_mark 的幂等判断会认为"已标过段"，
  # 第二次补 annotate 时命中 0 个（实测）。工具明确写着"不做增量补注，
  # 同一函数请一次标全"，所以加了 --annotate-pattern 参数来支持
  # "一次调用、不同函数不同 annotation"。
  _MARK_ARGS=()
  if [[ $WANT_VMP -eq 1 && "$NC_VMP_CSTUB" == "1" ]]; then
    _MARK_ARGS=(
      --annotate '+vm_virtualize'
      --annotate-pattern '^[ \t]*(?:static[ \t]+)?(?:inline[ \t]+)?(?:uint64_t|int)[ \t]+(nc_block_ks|nc_chacha20_keystream64|nc_mix64)[ \t]*\('
    )
  fi
  python3 "$GUARD_SRC/so_section_mark.py" "$_cstub_jni_dst/nc_strdec.c" \
    --pattern '^[ \t]*((?:static[ \t]+)?(?:inline[ \t]+)?(?:uint64_t|int)[ \t]+(nc_strdec_decrypt|nc_strdec_b64_decode|nc_strdec_utf8_to_utf16|nc_block_ks|nc_mix64|nc_chacha20_keystream64)[ \t]*\()' \
    --section .ncx \
    "${_MARK_ARGS[@]+"${_MARK_ARGS[@]}"}" \
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
  if [[ -z "$_cstub_marked" || "$_cstub_marked" -lt 6 ]]; then
    echo "❌ 纯 C 桩段标记只命中 ${_cstub_marked:-0} 处（应为 6：decrypt/b64_decode/utf8/block_ks/mix64/chacha20_keystream64）" >&2
    echo "   → nc_strdec.c 的函数头形态变了，正则已脱节" >&2
    echo "   → 不许静默放行：那等于算法以明文进产物" >&2
    exit 1
  fi
  echo "[mark] 完成：$_cstub_marked 处 .ncx 标记（纯 C 桩算法层）"
fi

log_step 4 6 "NDK 编译"
ndk_build "$WORK/project"

# ── VMP 产物侧断言（2026-11-10）──────────────────────────────────────
# 为什么必须在【产物】上断言而不是看日志：
#   AGENTS.md §3.3 —— "日志里有输出 ≠ 防护生效"。本项目已经付过代价：
#   `.comment` 的"失败但继续"日志让该防护连续三个月零生效没人发现。
#   VMP 的失败模式更隐蔽：Anmice 遇到不满足条件的函数是【静默跳过】，
#   构建全绿、产物正常、只是没虚拟化。所以必须在产物上验。
#
# 判据：VMP 会把函数体换成「VM 运行时 + 字节码」，特征是【代码量暴涨】。
#   实测 nox 单个函数 VMP 前后：1280 B → 22720 B（17 倍）。
#   这里用更宽松的门槛：带 VMP 标记的函数数 ≥1，且 .ncx 段非空。
#   （不做"体积必须涨 N 倍"的硬断言 —— 不同函数差异太大，会变成噪音源。）
#
# ⚠️ 局限（如实）：本断言只能证明"VMP 可能生效"，不能证明每个函数都生效。
#   要精确到函数级必须用 AMICE_VM_EMIT_MARKERS 构建一次（会生成
#   .amice.vm.meta.* 段），那是调试手段，不进生产。
if [[ $WANT_VMP -eq 1 ]]; then
  _so_path="$WORK/project/libs/arm64-v8a/libnc.so"
  if [[ -f "$_so_path" ]]; then
    _ncx_sz=$(python3 - "$_so_path" <<'PYEOF'
import struct,sys
so=open(sys.argv[1],'rb').read()
try:
    shoff=struct.unpack_from('<Q',so,0x28)[0]; shent=struct.unpack_from('<H',so,0x3a)[0]
    shnum=struct.unpack_from('<H',so,0x3c)[0]; shstr=struct.unpack_from('<H',so,0x3e)[0]
    sh=lambda k: struct.unpack_from('<IIQQQQIIQQ',so,shoff+k*shent)
    st=sh(shstr)[4]
    for k in range(shnum):
        s=sh(k); nm=so[st+s[0]:so.index(b'\0',st+s[0])].decode()
        if nm=='.ncx': print(s[5]); break
    else: print(0)
except Exception:
    print(0)
PYEOF
)
    if [[ "${_ncx_sz:-0}" -le 0 ]]; then
      log_err "VMP 已开启，但产物里 .ncx 段为空或不存在 —— VMP 不可能生效"
      log_err "   → 段标记没打上？检查上面 [mark] 的输出"
      exit 1
    fi
    log_info "VMP 产物检查: .ncx = $_ncx_sz 字节（非空，标记已落进加密段）"
    log_info "   ⚠️ 单函数是否真被虚拟化需真机/调试构建确认（AMICE_VM_EMIT_MARKERS）"
  else
    log_err "VMP 已开启，但找不到产物 $_so_path"
    exit 1
  fi
fi
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
    log_info "密钥流算法: $_algo_name"
    # ── 纯 C 桩 ↔ 壳 联动（2026-11-10）──────────────────────────────
    # 把本轮种子写进 stub_seed.txt，供 packer.sh 传给 dpt --stub-seed，
    # 最终落进壳的 shell config；运行期 libnc.so 用 dlsym("ncg_strkey")
    # 从壳取回它当密钥材料。
    #
    # 为什么必须写：不写的话 dpt 的 stub_seed 保持默认 0，壳里的
    # ncg_strkey() 返回 0，libnc.so 侧判定「壳在但没开联动」→ 回退到
    # 编译期常量。表面能跑，但「去掉壳 so 就解不开」这条联动不成立。
    #
    # ⚠️ 与 Java 桩路径的区别：
    #   Java 桩  ：种子经 JniBridge.gseed() 给桩的 <clinit>，桩在 dex 里
    #   纯 C 桩  ：种子经 dlsym 给 nc_strdec.c，桩在 so 里 —— 不经 Java
    #   两条路用的是【同一个】stub_seed.txt 与同一条 dpt --stub-seed 通道，
    #   所以下面写文件的格式必须与 Java 桩路径完全一致（16 位 hex，无换行污染）。
    #
    # ⚠️ 只在勾了 packer 时才写：没有壳就没有 ncg_strkey，写了也没人读，
    #    而且会让 packer 之外的分支误以为"联动已启用"。
    if [[ $WANT_PACKER -eq 1 ]]; then
      printf '%s\n' "${_cstub_seed_hex,,}" > "$WORK/stub_seed.txt"
      log_info "纯 C 桩种子将写入壳 config（供 ncg_strkey 返回）: $_cstub_seed_hex"
    fi
    python3 "$ROOT/scripts/string-enc/encrypt-strings.py" \
      "$WORK/decompiled" "$STRING_RULES" "${STRING_ENC_ARGS[@]}" \
      --apk "$STEP5_APK" \
      --stub-impl native \
      --algo "$_algo_name" \
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

# ⚠️ 2026-11-09 扩条件：纯 C 桩（$WANT_NATIVE_STUB）也必须放 so。
#    漏了它的症状：dex 里 native 声明 + <clinit> 调 loadLibrary("nc")，
#    但 APK 里没有 libnc.so → 启动即
#    UnsatisfiedLinkError: dlopen failed: library "libnc.so" not found
#    （真机实测，本地 .c1 产物复现）。
#    这条与 STEP3/4 的触发条件是同一个前提：native 桩 = 有 so。
if [[ $WANT_SIGCHECK -eq 1 || $WANT_TRANSPILE -eq 1 || $WANT_ENVCHECK -eq 1 \
      || $WANT_NATIVE_STUB -eq 1 ]]; then
  repack_install_so "$WORK/decompiled" "$WORK/project/libs"
  # 强制解压 so 加载（本方案唯一允许的 Manifest 修改）——只在有 so 的组合执行;
  # 纯 dex 组合(仅 stringenc 且用 Java 桩)没有 libnc.so,manifest 无需改写(报错二十三)
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
