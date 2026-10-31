#!/usr/bin/env bash
# common.sh — 加固流水线公共库（被 pipeline/模块脚本 source，不直接执行）
#
# 设计目标（对应历次报错教训）：
#   1. 状态永不依赖 cwd：所有路径在入口处 normalize 成绝对路径（报错三/这次 R2 报错），
#      需要切换目录运行的工具一律放子 shell：module_cd_run <dir> <cmd...>
#   2. 前置条件 fail-fast：require_file / require_dir 在开工前把环境假设全部验掉
#      （apktool.jar 缺失、规则文件为空等）。
#   3. 重复逻辑只写一份：zipalign 输出、日志格式统一在这里。
#
# 约定：调用方 source 本文件后必须已设置 MODULE_TAG（日志前缀），例如 "sigcheck"。

# 防止直接执行（只能 source）
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "❌ common.sh 是公共库，请用 source 引入，不要直接执行" >&2
  exit 1
fi

MODULE_TAG="${MODULE_TAG:-pipeline}"

log()      { echo "━━━ [$MODULE_TAG] $* ━━━"; }
log_step() { echo "━━━ [$MODULE_TAG] $1/$2 $3 ━━━"; }
log_info() { echo "ℹ️ [$MODULE_TAG] $*"; }
log_warn() { echo "⚠️ [$MODULE_TAG] $*"; }
log_err()  { echo "❌ [$MODULE_TAG] $*" >&2; }
log_done() { echo "✅ [$MODULE_TAG] $*"; }

# normalize_path <路径> → 绝对路径（stdout）
# 入口处统一调用；目录必须存在（mkdir_prepare 可先行建好父目录）
normalize_path() {
  local p="$1"
  if [[ -d "$p" ]]; then
    (cd "$p" && pwd)
  else
    local dir base abs
    dir="$(dirname "$p")"; base="$(basename "$p")"
    mkdir -p "$dir"
    abs="$(cd "$dir" && pwd)"
    echo "$abs/$base"
  fi
}

# require_file <文件> [描述] — 不存在即退出
require_file() {
  [[ -f "$1" ]] || { log_err "$2 缺失: $1"; exit 1; }
}

# require_dir <目录> [描述] — 不存在即退出
require_dir() {
  [[ -d "$1" ]] || { log_err "$2 缺失: $1"; exit 1; }
}

# require_nonempty_file <文件> [描述] — 不存在或没有任何有效行（空行/纯空白/
# 以 # 开头的注释行不算）即退出
require_nonempty_file() {
  require_file "$1" "${2:-文件}"
  # 剥注释行再找非空行：'#注释' 是注释(整行 # 开头)，'foo#bar' 是有效内容
  if ! sed 's/^[[:space:]]*#.*//' "$1" | grep -q '[^[:space:]]'; then
    log_err "文件没有任何有效内容（只有空行/注释）: $1"; exit 1
  fi
}

# require_env <变量名> [描述] — 环境变量未设置/为空即退出
require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || { log_err "环境变量 $name 未设置${2:+（$2）}"; exit 1; }
}

# ── dcc 已退役（2026-10-21）────────────────────────────────────────
# dcc.zip 及其解压产物 tools/dcc/ 已删除。原 ensure_dcc() 一并移除——
# 它的两个历史职责各有归宿：
#   · apktool.jar → tools/apktool.jar（git 跟踪的独立文件，见 lib-repack.sh）
#   · androguard  → dex2c.zip 携带（tools/Dex2C/androguard，语义逐字节相同，
#                   见各消费者文件的 _ensure_dcc_dir/ensure 逻辑）
# ensure_dex2c 保留（现役转译引擎）。

# ensure_dex2c [解压根目录，默认 "$ROOT/tools"] → 解压后 Dex2C 目录路径(stdout)
# 唯一转译引擎分发包(--dex2c)。真源 tools/dex2c.zip =
# 父目录 ../Dex2C/ 仓库 Release 资产 Dex2C-<tag>.zip 原样（顶层 Dex2C/），
# 下载后改名即分发包。zip 内顶层是 Dex2C/，解压到 tools/ 得单层 tools/Dex2C/；
# 解压产物不进版本库，由 .gitignore 的 /tools/Dex2C/ 忽略。
# 幂等:目标已存在(dcc.py 可见)则跳过解压,重复调用零开销。
# 换版纪律:删旧解压产物再跑（幂等靠"dcc.py 存在"判断，旧产物在会静默用旧版）。
DEX2C_ZIP="$ROOT/tools/dex2c.zip"  # dex2c 分发包(唯一真源,源码 ../Dex2C/)
ensure_dex2c() {
  local dest="${1:-$ROOT/tools}"
  if [[ -f "$dest/Dex2C/dcc.py" ]]; then
    echo "$dest/Dex2C"
    return 0
  fi
  require_file "$DEX2C_ZIP" "dex2c 分发包"
  mkdir -p "$dest"
  unzip -qo "$DEX2C_ZIP" -d "$dest"
  [[ -f "$dest/Dex2C/dcc.py" ]] || { log_err "dex2c.zip 解压后缺 Dex2C/dcc.py: $dest"; exit 1; }
  echo "$dest/Dex2C"
}

# ensure_nox [解压根目录，默认 "$ROOT/tools"] → 解压后 nox/so-guard 目录路径(stdout)
#
# so 段加密设施（nc_guard_*.c/h、so-section-lock.py、so_section_mark.py）由上游
# nox 仓库分发，本仓库【不再保存源码副本】——上游是唯一真相源，避免双源头漂移。
# 真源 tools/nox.zip = 上游 ../nox/ 的 dist/nox-<ver>.zip 原样（顶层 nox/，
# 不带版本号），解压到 tools/ 得单层 tools/nox/；解压产物不进版本库，
# 由 .gitignore 的 /tools/nox/ 忽略。
#
# ── 上游有两种分发形态，本函数都要认（2026-10-31 起）─────────────────
#   ① 源码形态：so-guard/*.c 存在
#      → protect.sh 把它们 cp 进 NDK 工程一起编译
#   ② 静态库形态：只有 so-guard/*.h + lib/<abi>/libnox.a
#      → protect.sh 只拷头文件，.a 由 lib-ndk.sh 用 --whole-archive 链接
# 判别用 nc_guard_layout.h（两种形态都必有）；具体走哪条路由调用方查
# nox_guard_has_src 决定。
#
# ⚠️ 幂等判据同样要用"两种形态都存在"的文件，否则切换形态后不重新解压。
# 换版纪律：删旧解压产物再跑（幂等靠文件存在判断，旧产物在会静默用旧版）。
NOX_ZIP="$ROOT/tools/nox.zip"           # 生产分发包（静态库形态，上游 ../nox/）
NOX_SRC_ZIP="$ROOT/tools/nox-src.zip"   # 源码包（仅回归测试用，见 ensure_nox_src）

# nox_guard_has_src <guard目录> → 0=源码形态，1=静态库形态
nox_guard_has_src() {
  [[ -f "$1/nc_guard_boot.c" ]] && [[ -f "$1/nc_guard_probe.c" ]]
}

# _unzip_nox <zip文件> <解压根目录> → 解压后 nox/so-guard 路径(stdout)
_unzip_nox() {
  local zip="$1" dest="$2"
  require_file "$zip" "$(basename "$zip") 分发包"
  mkdir -p "$dest"
  unzip -qo "$zip" -d "$dest"
  [[ -f "$dest/nox/so-guard/nc_guard_layout.h" ]] || {
    log_err "$(basename "$zip") 解压后缺 nox/so-guard/nc_guard_layout.h: $dest"
    log_err "  该头文件是 so 加密契约的唯一真相源，两种分发形态都必须有"
    exit 1
  }
  echo "$dest/nox/so-guard"
}

# ensure_nox [解压根目录，默认 "$ROOT/tools"] → 生产设施路径(stdout)
#
# 生产用【静态库形态】（tools/nox.zip）：C 实现不外泄，
# 只给头文件 + Python 工具 + lib/<abi>/libnox.a。
# protect.sh 走这条：只拷头文件，.a 由 lib-ndk.sh 用 --whole-archive 链接。
#
# ⚠️ 若上游改发源码形态（tools/nox.zip 内含 .c），本函数同样工作：
#    调用方用 nox_guard_has_src 判断，源码形态就拷 .c 编。
ensure_nox() {
  local dest="${1:-$ROOT/tools}"
  if [[ -f "$dest/nox/so-guard/nc_guard_layout.h" ]]; then
    echo "$dest/nox/so-guard"
    return 0
  fi
  _unzip_nox "$NOX_ZIP" "$dest"
}

# ensure_nox_src [解压根目录，默认 "$ROOT/tools/nox-src"] → 源码形态设施路径(stdout)
#
# 【仅回归测试用】。test-so-lock.sh 的职责是"源码改对了没有"，
# 其中 T20 要解析 nc_guard_boot.c 的源码常量、T22/T23/T27/T28/T32 要
# 真编译那 5 个 .c —— 静态库形态做不了这些，所以测试必须用源码包。
#
# 为什么解压到 tools/nox-src/（而不是复用 tools/nox/）：
#   两者内容不同（一个有 .c、一个只有 .a），共用一个目录会互相覆盖，
#   且 ensure_nox 的幂等判据会误判成"已解压"。
# 与生产路径分离 = 测试和生产可以同时用，不互相污染。
ensure_nox_src() {
  local dest="${1:-$ROOT/tools/nox-src}"
  if nox_guard_has_src "$dest/nox/so-guard" 2>/dev/null; then
    echo "$dest/nox/so-guard"
    return 0
  fi
  _unzip_nox "$NOX_SRC_ZIP" "$dest"
}

# module_cd_run <目录> <命令...> — 在子 shell 里切目录执行，主进程 cwd 永不漂移
module_cd_run() {
  local dir="$1"; shift
  (cd "$dir" && "$@")
}

# finish_apk <中间产物.apk> <最终输出.apk> — zipalign（有则对齐，无则拷贝）
finish_apk() {
  local src="$1" dst="$2"
  if command -v zipalign >/dev/null 2>&1; then
    zipalign -f 4 "$src" "$dst"
  else
    cp "$src" "$dst"
    log_warn "未找到 zipalign，跳过对齐（apksigner 重签前建议自行 zipalign）"
  fi
}
