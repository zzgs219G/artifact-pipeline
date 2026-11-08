#!/usr/bin/env bash
# packer.sh — 基础加壳模块（dpt-shell 路线）
#
# 模块契约：<输入.apk> <输出.apk>
#   - 输入/输出路径一律 normalize 成绝对路径（与 protect.sh 同一约定，报错三教训）
#   - 主进程 cwd 全程不漂移：dpt.jar 需要在自身目录运行（shell-files/、
#     build-key、keyladder-seed.txt 必须与 jar 同级，见下方契约），一律走
#     module_cd_run 子 shell
#   - 产物不签名（-x），沿用本仓库"未签名包、开发者自行重签"契约
#
# dpt CLI 契约（由 dpt-shell 源码 + --help 实测钉死，勿凭猜测改；dpt-shell 是
# 自研二改项目，源码在父目录 ../dpt-shell/，换版核对直接查源码：
#   CLI 选项 → dpt/src/main/java/com/luoye/dpt/config/Const.java
#   产物命名 → builder/AndroidPackage.buildPackage（-o 传目录 → <base>_unsign.apk）
#   解压布局 → util/FileUtils.getExecutablePath() + shell/build.gradle
# v1.0.0 换版时已逐项复核 -f/-o/-x/-r、产物命名、解压布局均与旧版一致）：
#   java -jar dpt.jar -f <in.apk> -o <outdir> [-x] [-S/--smaller] [-r <rules>] [-c <config>]
#   - PACKER_SMALLER=1(protect.sh --packer-smaller,体积优化) → 追加 --smaller
#   - 环境变量 DPT_EXTRA_ARGS(protect.sh --dpt-extra-args) → 自由文本按空格分词追加
#   - 环境变量 EXCLUDE_ABI(protect.sh --exclude-abi) → 追加 --exclude-abi <值>(报错四十四)
#   - getExecutablePath() = jar 所在目录 → executable/shell-files/、
#     executable/build-key、executable/shell-files/keyladder-seed.txt 必须与
#     executable/dpt.jar 同级，解压布局不能改
#   - 产物文件名 getNewFileName(x, "unsign") 模板为 `_<suffix>.<ext>`
#     → <包名>_unsign.apk，落在 -o 指定的输出目录下
#   - -x / --no-sign：不签名（Builder 默认 sign=1，不传 -x 会用包内
#     assets/dpt.jks 重新签名，与本仓库"产出未签名包"契约冲突）
#   - -r / --rules-file：**不加固**的类名正则名单（注意与 dex2c/stringenc 的
#     规则语义相反，见下方"规则语义警告"），故本模块只吃 dpt 包内自带模板
#
# 规则语义警告（本模块刻意不暴露自定义规则的原因）：
#   dex2c / stringenc：`!com.x.**` = 排除处理（不转译/不加密）
#   dpt -r：           命中的类 = 排除加固（保持明文）
#   两者方向相反，且 dpt 用斜杠正则（Lafzkl/development/.*）、另两者用点号
#   通配符（com.test.**）。共用一份规则必然静默语义反转 → 本模块只提供
#   leaf 开关，规则固定取包内模板，不接受用户输入。
set -euo pipefail

usage() {
  awk 'NR>=2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
  exit 1
}

[[ $# -eq 2 ]] || usage
IN_APK="$1"
OUT_APK="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # apk-protect-action 根目录
MODULE_TAG="packer"
# shellcheck source=../lib/common.sh
source "$ROOT/scripts/lib/common.sh"

IN_APK="$(normalize_path "$IN_APK")"
OUT_APK="$(normalize_path "$OUT_APK")"
require_file "$IN_APK" "输入 APK"

# ── 解压 dpt 分发包（幂等，仿 ensure_dcc 的形态）────────────────────
# tools/dpt-shell.zip 内顶层即 executable/，解压到 <仓库根>/tools/ 得单层
# tools/executable/（与 dcc.zip 的"顶层即 dcc/"形态一致，报错十五：unzip 不
# 自建多级父目录 → 目标父目录必须已存在，tools/ 必然存在）。
# 解压产物不进版本库，由 .gitignore 的 /tools/dcc/ 同类规则忽略（见下方备注）。
DPT_ZIP="$ROOT/tools/dpt-shell.zip"
DPT_EXE_DIR="$ROOT/tools/executable"

ensure_dpt() {
  if [[ -f "$DPT_EXE_DIR/dpt.jar" ]]; then
    return 0
  fi
  require_file "$DPT_ZIP" "dpt-shell 分发包"
  log_info "解压 $DPT_ZIP → $DPT_EXE_DIR"
  unzip -qo "$DPT_ZIP" -d "$ROOT/tools"
  [[ -f "$DPT_EXE_DIR/dpt.jar" ]] \
    || { log_err "dpt-shell.zip 解压后缺 executable/dpt.jar"; exit 1; }
}

ensure_dpt
DPT_JAR="$DPT_EXE_DIR/dpt.jar"
DPT_RULES="$DPT_EXE_DIR/dpt-exclude-classes-template.rules"
require_file "$DPT_JAR" "dpt.jar"
# dpt 的 getExecutablePath() = jar 所在目录，shell-files/、build-key 与
# keyladder-seed.txt 必须与 dpt.jar 同级。解压布局一旦错位（多套一层
# executable/）dpt 会在运行时报一句难懂的缺文件错误；这里提前钉死，比在
# dpt 日志里翻找快得多。
if [[ ! -d "$DPT_EXE_DIR/shell-files" ]]; then
  log_err "解压布局错位：$DPT_EXE_DIR/shell-files 不存在"
  log_err "     dpt 要求 dpt.jar / shell-files/ / build-key / keyladder-seed.txt 同级"
  exit 1
fi
# keyladder-seed.txt（v1.2.3 起）：打包 .bitcode 段时读它，与 C 侧编译宏
# DPT_KL_SEED 必须同一把；缺失说明本地/CI 用的是旧解压产物，拒绝静默跑。
require_file "$DPT_EXE_DIR/shell-files/keyladder-seed.txt" "shell-files/keyladder-seed.txt"
# 规则表随包分发；缺失不静默降级（裸跑会把 android./java./kotlin. 等系统类
# 也塞进壳，加壳后启动失败面显著变大 —— 宁漏勿误伤，故 fail-fast）
require_nonempty_file "$DPT_RULES" "dpt 不加固规则表"

# ── 解密桩必须排除出"抽空"名单（2026-10-26）─────────────────────────
#
# 【问题】dpt 的 extractAllMethods 会抽空所有未被 -r 规则命中的类的所有方法
#   （DexUtils.java:288 `if (matchRules(...)) continue;`）。stringenc 注入的
#   解密桩 d()/dn()/mix64()/keyByte() 一旦被抽空：
#     · d() 变成 native 壳 → 但 libnc.so 里没有对应实现（除非勾 --dex2c-stub）
#     · 即使勾了 --dex2c-stub，桩的方法体也被搬进 xixin_data，壳解密自己
#       的桩 = 鸡生蛋
#   实测后果：App 启动首个加密字符串即 UnsatisfiedLinkError / 解出乱码。
#
# 【修法】把桩描述符动态追加进 dpt 的 -r 规则（命中 = 不抽空，保持明文）。
#   为什么必须动态：桩名是【每包随机】的（防固定签名），规则文件是静态模板，
#   随机名不可能预先写进去。桩名从 stringenc 的组件标记读 —— 那是跨步骤
#   传名的既有通道（报错十八：信息必须在丢失前 save）。
#
# 【模块化】只在"本次真的注入了桩"时追加：
#   不勾 stringenc / 桩不存在 → 规则文件原样用，行为与改动前完全一致。
STUB_EXCLUDE_RULE=""
_components="${STRINGENC_COMPONENTS:-}"
if [[ -n "$_components" && -f "$_components" ]]; then
  # 从组件标记里取桩描述符 Lcom/xxx/StrDec; → dpt 规则要的斜杠正则
  _stub_desc="$(python3 - "$_components" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as f:
        data = json.load(f)
    classes = data.get('classes') or []
    if classes:
        desc = classes[0].get('desc') or ''
        # Lcom/x/y/Str; → Lcom/x/y/Str;
        # dpt -r 是"完整类名正则"，命中=不加固。桩类整体排除即可（含内部类）
        if desc.startswith('L') and desc.endswith(';'):
            print('^' + desc.replace('/', '/') + '.*')
except Exception:
    pass
PY
)"
  if [[ -n "$_stub_desc" ]]; then
    STUB_EXCLUDE_RULE="$_stub_desc"
    log_info "解密桩排除规则: $STUB_EXCLUDE_RULE（桩不被抽空）"
  fi
fi

# ── 执行加壳 ────────────────────────────────────────────────────────
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DPT_OUT="$WORK/dpt-out"
# 预建输出目录：不依赖 dpt 自己去建（不同版本行为不一致，且缺失时报错会指到
# 无关的地方）。建好后再取产物，find 语义也更确定。
mkdir -p "$DPT_OUT"

# 规则文件在工作副本上追加桩排除行（绝不改包内模板）：
#   · 有桩 → 副本 = 模板 + 桩行
#   · 无桩 → 直接用模板（零行为变更）
if [[ -n "$STUB_EXCLUDE_RULE" ]]; then
  DPT_RULES_USE="$WORK/dpt-rules-with-stub.rules"
  { cat "$DPT_RULES"; printf '\n# nc-strdec 解密桩：必须保持明文，否则壳解密自己的桩（鸡生蛋）\n%s\n' "$STUB_EXCLUDE_RULE"; } > "$DPT_RULES_USE"
  require_nonempty_file "$DPT_RULES_USE" "追加桩排除后的规则表"
else
  DPT_RULES_USE="$DPT_RULES"
fi

log_info "加壳: $(basename "$IN_APK") （规则: $(basename "$DPT_RULES_USE")）"

# 双源合并(报错四十三 + 通用通道):
#   源1 专线:PACKER_SMALLER=1(protect.sh --packer-smaller,体积优化)→ --smaller
#   源2 通用:环境变量 DPT_EXTRA_ARGS(protect.sh --dpt-extra-args 自由文本,空格分隔)
# 注意:bash 里环境变量与数组同名会互覆,须先把字符串捕获进独立变量再声明数组。
# 与专线重复(如勾了 smaller 又手填 --smaller)对 dpt 无害(hasOption 幂等),不去重。
# 安全边界:自由文本只构成打包参数注入面,最坏打包失败;secrets 不经此路径。
dpt_extra_from_env="${DPT_EXTRA_ARGS:-}"
DPT_EXTRA_ARGS=()
[[ "${PACKER_SMALLER:-0}" == "1" ]] && DPT_EXTRA_ARGS+=(--smaller)
# 源3 带值参数标准件(报错四十四):EXCLUDE_ABI(protect.sh --exclude-abi)
# → --exclude-abi <值>,剔除 ABI 的 so 目录(如 x86,x86_64 = 只留 arm/arm64)
if [[ -n "${EXCLUDE_ABI:-}" ]]; then
  DPT_EXTRA_ARGS+=(--exclude-abi "$EXCLUDE_ABI")
fi
# 源4 packer 联动(2026-10-26):stringenc 注入的解密桩单独汇编成 dex,
# 由 --extra-dex 合并进【壳 dex】—— 业务 dex 里只留调用点,桩类本身在壳里。
# 不传/文件不存在 = 不合并,行为与改动前完全一致(模块化)。
if [[ -n "${STUB_DEX:-}" && -f "${STUB_DEX}" ]]; then
  DPT_EXTRA_ARGS+=(--extra-dex "$STUB_DEX")
  log_info "解密桩将合并进壳 dex: $(basename "$STUB_DEX") ($(stat -c%s "$STUB_DEX" 2>/dev/null || echo '?') 字节)"
fi
# 源5 packer 联动（2026-10-26）：字符串桩的密钥流种子 → dpt --stub-seed
#   桩的 SEED 已改成运行期调 JniBridge.gseed()（dex 里无字面量），
#   真值经 shell config 提供，运行期由壳返回。两个值必须一致，
#   否则密文解不开 → 整包字符串乱码。
#   文件不存在 = 未走联动（不勾 stringenc 或没开 --stub-seed-from-shell），
#   此时不传参，行为与改动前一致。
if [[ -n "${STUB_SEED_FILE:-}" && -f "${STUB_SEED_FILE}" ]]; then
  _seed="$(tr -d ' \t\r\n' < "$STUB_SEED_FILE")"
  if [[ "$_seed" =~ ^[0-9a-fA-F]{16}$ ]]; then
    DPT_EXTRA_ARGS+=(--stub-seed "$_seed")
    log_info "字符串桩种子将写入壳 config: $_seed"
  else
    log_err "桩种子文件形态非法（需 16 位 hex）: $_seed（$STUB_SEED_FILE）"
    exit 1
  fi
fi
# 源6 段加密证书来源（2026-10-27）：dpt --cert-source
#   为什么需要：dpt 加密壳 so 的 .bitcode 段时，key 里混入 APK 签名证书 DER，
#   运行期从已安装 APK 提 —— 打包侧必须拿到【最终签名会用】的那张证书。
#   而本仓库契约是"全程不签名，开发者用上传时的 keystore 重签"，所以喂给
#   dpt 的 $1 是回编后的【未签名】中间包，里面没有 APK Signing Block，
#   直接让 dpt 从它提证书必然失败（run 40428658987 就是这么红的）。
#   正解：复用流水线已有的锚点 —— 上传的原始 APK（已签名），
#   与 sigcheck 提取指纹同源，也与开发者重签用的一致。
#   不传该变量 = 不追加参数，dpt 退回从输入包提（单机直用行为不变）。
if [[ -n "${CERT_SOURCE_APK:-}" ]]; then
  if [[ -f "$CERT_SOURCE_APK" ]]; then
    DPT_EXTRA_ARGS+=(--cert-source "$CERT_SOURCE_APK")
    log_info "段加密证书来源: $(basename "$CERT_SOURCE_APK")"
  else
    log_err "CERT_SOURCE_APK 指向的文件不存在: $CERT_SOURCE_APK"
    exit 1
  fi
fi
if [[ -n "$dpt_extra_from_env" ]]; then
  read -ra _dpt_extra_words <<< "$dpt_extra_from_env"
  DPT_EXTRA_ARGS+=("${_dpt_extra_words[@]}")
fi

# dpt.jar 需在 executable/ 下运行才能找到 shell-files/ 与 build-key
#
# ⚠️⚠️ 2026-11-08 真事故（CI run 42435473015）：
#    dpt 日志打出 "Zipalign failed!"，但仍然写出一个 0 字节的
#    *_unsign.apk，且 java 进程返回 0 —— 三重都没拦住：
#      ① dpt 自己只打印错误、不非零退出
#      ② 旧版 require_file 只查 [-f] 存在、不查大小
#      ③ CI 没有产物侧断言
#    结果：0 字节包上传 R2，用户在页面上看到"构建成功"。
#    故此处显式检查退出码 + 产物大小（require_file 已加非空检查）。
_DPT_RC=0
module_cd_run "$DPT_EXE_DIR" java -jar "$DPT_JAR" \
  -f "$IN_APK" \
  -o "$DPT_OUT" \
  -x \
  ${DPT_EXTRA_ARGS[@]+"${DPT_EXTRA_ARGS[@]}"} \
  -r "$DPT_RULES_USE" || _DPT_RC=$?
if [[ "$_DPT_RC" -ne 0 ]]; then
  log_err "dpt 加壳失败（退出码 $_DPT_RC）"
  exit 1
fi

# ── 取产物 ──────────────────────────────────────────────────────────
# 不硬编码 <包名>_unsign.apk（包名含点、转文件名易错，且 dpt 版本换名会炸）：
# 只认「后缀」这一个契约，扫描命中多个即 fail-fast。
#
# ⚠️⚠️ 2026-11-08 真事故（CI run 42435473015）：原来只找 `*_unsign.apk`。
#    dpt 的实现（AndroidPackage.java:1119-1133）是：
#        out = new FileOutputStream(unsignedPackagePath);   // 立即创建文件
#        zipalign(unzipalignPackagePath, unsignedPackagePath);
#        // 失败则 zipalignSuccess=false，但那个 FileOutputStream 已经创建了
#        // 一个 0 字节的 *_unsign.apk，且【不会被删除】
#    于是 0 字节的 *_unsign.apk 一直躺在输出目录里，被 find 命中。
#    正确取法（按 dpt 的 resultPath 逻辑）：
#        willSign = zipalignSuccess ? unsigned : unzipalign
#        result   = signed.exists() ? signed : willSign
#    dpt 在 -x（不签名）时会把 willSign 复制成 *_signed.apk，故：
#        · *_signed.apk 存在 → 最优（那是 dpt 认定的最终产物）
#        · 否则退回 *_unzipalign.apk（zipalign 失败时的保底）
#    **绝不能**再挑 *_unsign.apk —— 它在失败路径上是空壳。
_find_dpt_apk() {
  local pattern="$1"
  find "$DPT_OUT" -maxdepth 1 -name "$pattern" -type f -size +100k 2>/dev/null || true
}
produced="$(_find_dpt_apk '*_signed.apk')"
if [[ -z "$produced" ]]; then
  produced="$(_find_dpt_apk '*_unzipalign.apk')"
  if [[ -n "$produced" ]]; then
    log_warn "dpt 未产出 *_signed.apk，退回 *_unzipalign.apk（zipalign 可能失败，包未对齐）"
  fi
fi
if [[ -z "$produced" ]]; then
  log_err "dpt 未产出可用的 APK（输出目录: $DPT_OUT）"
  log_err "     检查：dpt 日志有无 zipalign failed / MergeDex failed"
  log_err "     已知 *_unsign.apk 在 zipalign 失败时是 0 字节空壳，故不作为候选"
  ls -la "$DPT_OUT" 2>/dev/null >&2 || true
  exit 1
fi
count="$(printf '%s\n' "$produced" | grep -c . || true)"
if [[ "$count" -ne 1 ]]; then
  log_err "dpt 产出多个 *_unsign.apk（$count 个），无法判定取哪个："
  printf '%s\n' "$produced" >&2
  exit 1
fi
require_file "$produced" "dpt 加壳产物"

mkdir -p "$(dirname "$OUT_APK")"
cp "$produced" "$OUT_APK"
log_done "加壳完成: $OUT_APK"