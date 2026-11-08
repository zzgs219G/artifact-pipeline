#!/usr/bin/env bash
# lib-repack.sh — apktool 解包/注入/重打包公共库（source 使用，不直接执行）
#
# 抽取自旧 protect-sigcheck.sh / protect-sigcheck-only.sh / protect-dcc.sh 三处
# 几乎相同的"解包 → 放 so → 改 extractNativeLibs → 回编 → zipalign"逻辑
# （2025-09 三总控已合并为 protect.sh，本库继续为其唯一解包/回编实现）。
#
# 依赖：ROOT（仓库根，绝对路径）、MODULE_TAG 已由调用方设置。
# 历次报错教训固定在代码里：
#   - apktool d 不带 --force-manifest（报错五：文本 manifest 回编成灰包）
#   - --no-debug-info（报错八：剥离 debug_info，dex 缩小约 1.8MB）
#   - 二进制 AXML 用 patch-extractnativelibs.py 原位改写（报错五）
#   - apktool.jar 固定路径在开工前 require_file（空目录不被 git 跟踪的教训）

_lib_repack_guard() {
  if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "❌ lib-repack.sh 是公共库，请用 source 引入" >&2
    exit 1
  fi
  : "${ROOT:?使用 lib-repack.sh 前必须设置 ROOT 为仓库根目录}"
}
_lib_repack_guard

# apktool.jar 独立放 tools/apktool.jar（2026-10-21 从 dcc.zip 原样提取，
# sha256 与 zip 内文件逐字节一致）。dcc 引擎连同 dcc.zip 已退役删除——
# apktool 是解包/回编核心链路，不该寄居在已下架引擎的分发包里，
# 且 15MB 的 jar 藏在 zip 里导致每次构建都要解压整个 dcc（23MB）。
# 现为 git 跟踪的独立文件，不再依赖任何解压步骤。
APKTOOL_JAR="$ROOT/tools/apktool.jar"

# repack_require_tools — 开工前校验 apktool.jar 存在
repack_require_tools() {
  require_file "$APKTOOL_JAR" "apktool.jar（tools/ 根下，git 跟踪）"
}

# repack_unpack <输出目录> <输入.apk>
repack_unpack() {
  local out="$1" apk="$2"
  java -jar "$APKTOOL_JAR" d -r -f --no-debug-info -o "$out" "$apk"

  # ⚠️ dex 拆分【不在】这里做 —— 改为回编前局部拆分（protect.sh 的
  # repack_build 之前调 dex-rebalance.py --split）。
  # 原因（2026-11-06 实测）：解包时还不知道各模块会插多少东西，
  # 此时重排等于全量搬 8 万个文件（38 秒）且打乱原包 R8 的类聚类
  # （实测重排后 method_ids 反而从 65463 涨到 73648，回编更炸）。
  # 正确做法是等所有模块写完、回编之前，实测哪些 dex 装不下，
  # 只拆那几个。

  # 报错十八: 回编会把各 dex 版本全部降成 035(原始信息丢失),解包后先记录
  python3 "$ROOT/scripts/repack/patch-dex-version.py" save "$apk" "$out"
}


# repack_install_so <解包目录> <libs根目录> — 把编译产物里所有 ABI 的 .so 拷进解包目录
repack_install_so() {
  local decompiled="$1" libs_root="$2"
  local abi_dir abi
  for abi_dir in "$libs_root"/*; do
    [[ -d "$abi_dir" ]] || continue
    abi="$(basename "$abi_dir")"
    mkdir -p "$decompiled/lib/$abi"
    find "$abi_dir" -maxdepth 1 -name '*.so' -exec cp {} "$decompiled/lib/$abi/" \;
  done
}

# repack_force_extractnativelibs <解包目录> — 二进制 AXML 原位改写 extractNativeLibs=true
repack_force_extractnativelibs() {
  local decompiled="$1"
  python3 "$ROOT/scripts/repack/patch-extractnativelibs.py" "$decompiled/AndroidManifest.xml"
}

# repack_force_compress_payload <解包目录> — 从 apktool.yml 的 doNotCompress 删掉 so / dex
#
# ── 为什么必须做（2026-11-08）─────────────────────────────────────
#   apktool 解包时会把【输入 APK 的实际情况】记进 apktool.yml：
#   若输入的 so/dex 是 STORED（不压缩），就写 `- so` / `- dex`；
#   回编时按这两条把所有 .so/.dex 一律 STORED —— 包括我们新加的 libnc.so。
#
#   实测两个真实输入，差异只来自这条规则：
#     简盒.apk（正式包）  doNotCompress 无 so/dex → 回编产物 dex+so 全压缩
#     demo_1.0.apk（测试包）doNotCompress 有 so/dex → 回编产物全 STORED
#   demo 那条路实测白占：libnc.so 608936 → 608936（双 ABI 约 1.2 MB），
#   classes.dex 1423839 → 1423839（约 700 KB）。
#
# ── 为什么压缩 so 安全 ──────────────────────────────────────────
#   压缩 so 与"能否加载"的唯一冲突点：
#     extractNativeLibs=false 时，系统直接把 APK 内 lib 目录 mmap，
#     此时 so 必须 STORED + 4KB 页对齐；压缩则装不上。
#   而本流水线【无条件强制 extractNativeLibs=true】
#   （repack_force_extractnativelibs，与 repack_install_so 同一步执行），
#   true = 安装时解压到 /data/app/<pkg>/lib/。既然必解压，APK 内就该压缩。
#
# ── 为什么压缩 dex 也安全 ───────────────────────────────────────
#   AOT（dex2oat）发生在【安装时、解压之后】，产物落在
#   /data/app/<pkg>/oat/<abi>/*.odex|*.vdex，与 APK 内 dex 是否压缩无关。
#   压缩只影响"读 APK 时是否要先解压"这一层，不影响 AOT 质量或结果。
#   生态佐证：正式发布的 APK（简盒.apk）本身就是 dex+so 全压缩，
#   市面上绝大多数 APK 也是如此 —— 这是常态，不是特例。
#
# ⚠️ `arsc` / `png` / `webp` / `assets/*.prof` 一律不动：
#     resources.arsc 的不压缩是 AAPT 的硬约束（资源偏移需页对齐）；
#     png/webp 本身已压缩，再压无用且可能影响资源加载。
#
# ⚠️ 幂等：yml 里没有 so/dex 条目时原样返回（输入本来就是压缩的包）。
repack_force_compress_payload() {
  local decompiled="$1"
  local yml="$decompiled/apktool.yml"
  [[ -f "$yml" ]] || return 0
  python3 - "$yml" <<'PY'
import sys, re, io

# 要强制压缩的条目。语义见函数头注释。
TARGETS = ('so', 'dex')

path = sys.argv[1]
with io.open(path, 'r', encoding='utf-8') as f:
    lines = f.read().split('\n')

out = []
in_section = False
removed = {}
for ln in lines:
    if re.match(r'^doNotCompress\s*:', ln):
        in_section = True
        out.append(ln)
        continue
    if in_section:
        # 列表项形如 "- so" / "- dex"；遇到非列表行则离开该段
        m = re.match(r'^\s*-\s*(.+?)\s*$', ln)
        if m is None:
            in_section = False
            out.append(ln)
            continue
        name = m.group(1)
        if name in TARGETS:
            removed[name] = removed.get(name, 0) + 1
            continue          # 丢掉这一行
        out.append(ln)
        continue
    out.append(ln)

if removed:
    with io.open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out))
    detail = ', '.join('%s x%d' % (k, v) for k, v in sorted(removed.items()))
    print('  [repack] doNotCompress: 已移除 %s → 这些条目将被压缩' % detail)
else:
    print('  [repack] doNotCompress: 无 so/dex 条目，保持不变（输入本来就是压缩的）')
PY
}

# repack_build <解包目录> <输出未对齐.apk>
repack_build() {
  local decompiled="$1" out="$2"
  java -jar "$APKTOOL_JAR" b -o "$out" "$decompiled"
  # 报错十八: 回编后按解包时记录的原始版本逐 dex 恢复(只升不降,
  # max(原版本, minSdk 推导下限)),对任意 App/minSdk 组合通用
  python3 "$ROOT/scripts/repack/patch-dex-version.py" restore "$out" "$decompiled"
}

# repack_force_debuggable_off <解包目录> — 强制 debuggable=false
#
# 为什么必须做（见 docs/so层防御/历史结论索引.md §3.1）：
#   实测测试 APK 的 Manifest 写着 debuggable=true。带这个标记的 release 包：
#     · `run-as <pkg>` 可进应用私有目录，读写文件、dump 内存
#     · 调试器可直接 attach —— 我们那套 ptrace(TRACEME) / PR_SET_DUMPABLE
#       全部建立"不许被调试"的前提，debuggable=true 等于从系统层面给开了后门
#     · `am set-debug-app` 等工具链全线可用
#
# ⚠️ 与 extractNativeLibs 不同：debuggable 属性【可能不存在】。
#   不存在时的语义就是 false（Android 默认），所以脚本对"属性不存在"
#   返回成功而非报错 —— 绝大多数正常 App 本来就不写这个属性，
#   若照搬 extractNativeLibs 的"缺则报错"，会让绝大多数包构建失败。
repack_force_debuggable_off() {
  local decompiled="$1"
  local mf="$decompiled/AndroidManifest.xml"
  # 解包可能产出二进制 AXML（-r 模式），也可能被 apktool 转成文本 XML。
  # 文本形态下 patche 方式不同 —— 先探测，避免把文本 XML 喂给二进制解析器。
  if [ ! -f "$mf" ]; then
    log_warn "AndroidManifest.xml 不存在，跳过 debuggable 处理"
    return 0
  fi
  if head -c 4 "$mf" | od -An -tx1 | tr -d ' \n' | grep -q '^03000800$'; then
    python3 "$ROOT/scripts/repack/patch-debuggable.py" "$mf"
  else
    # 文本 XML：apktool 未加 -r 时会解码成文本。用属性替换处理。
    if grep -q 'android:debuggable="true"' "$mf"; then
      sed -i 's/android:debuggable="true"/android:debuggable="false"/g' "$mf"
      log_info "debuggable → false（文本 XML）"
    else
      log_info "debuggable 已是 false 或未设置（文本 XML），跳过"
    fi
  fi
}
