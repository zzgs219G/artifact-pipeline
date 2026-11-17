#!/usr/bin/env python3
"""func-report.py — 生成【函数级】防护报告（构建期）

## 解决什么问题

`ncguard_log.md`（运行期自检）只到【段】粒度：

    .ncx  109.1 KB  r-x  熵 8.098 → 6.872  ✅ 已解密

它能告诉你"这一段解密了"，但回答不了「到底哪个函数被 VMP 了 / 哪个被
混淆了 / 为什么没有」。而 amice 的 skip 日志【只有失败没有成功】，
所以成功清单必须靠产物与源码交叉验证。

本脚本合并四个数据源：

    ① ndk-build.log 的 `[mark]` 行        → 哪些函数被打进 .ncx
    ② ndk-build.log 的 `[amice] ... skip` → 哪些 pass 跳过了谁、为什么
    ③ 源码 `annotate("+vm_virtualize")`   → 哪些函数【本该】被 VMP
    ④ 产物 .ncx 段指令扫描                 → 实际有多少函数起点 / wrapper

③ 是关键：只看 ② 会把"压根没打算 VMP 的函数"误判成"VMP 失败"。
必须从源码读出真实目标清单。

⚠️ 必须在【锁箱之前】调用 —— 锁箱后 .ncx 是密文，指令扫描全废。

## 用法

    python3 func-report.py --build-log ndk-build.log \\
                           --so libs/arm64-v8a/libnc.so \\
                           --src-dir project/jni/nc \\
                           --out protect-report.md [--json-out r.json]

退出码恒 0：报告生成失败不该让构建红（stderr 会说明）。
真正的产物断言在 protect.sh 里。
"""
import argparse
import hashlib
import json
import os
import re
import struct
import zlib
import sys
from collections import OrderedDict, defaultdict

# ── ① [mark] 行 ────────────────────────────────────────────────────
# 实测格式（注意 log 包装会重复 [mark] 前缀）：
#   [mark] 段标记：dex2c 转译产物 → .ncx
#     [mark]   [mark] /tmp/tmp.X/project/jni/nc/foo.c:79  static inline uint64_t nc_mix64(...)
#     [mark]   /tmp/tmp.X/project/jni/nc/foo.c: 6 个函数
#     [mark] 合计 6 个函数 / 1 个文件 → 段 .ncx
RE_MARK_DETAIL = re.compile(
    r'\[mark\]\s+(?P<path>/\S+\.(?:c|cc|cpp|cxx)):(?P<line>\d+)\s+(?P<sig>.*\S)')
RE_MARK_COUNT = re.compile(
    r'\[mark\]\s+(?P<path>/\S+\.(?:c|cc|cpp|cxx)):\s*(?P<n>\d+)\s*个函数')
RE_MARK_SEG = re.compile(r'\[mark\]\s*段标记[：:]\s*(?P<what>.+?)\s*→\s*(?P<seg>\.\w+)')
RE_MARK_TOTAL = re.compile(r'\[mark\]\s*合计\s*(?P<n>\d+)\s*个函数')

# ── ② amice skip ───────────────────────────────────────────────────
RE_VMP_SKIP = re.compile(r'\[amice\]\s+VMP skipped:\s*"(?P<func>[^"]+)"\s*\((?P<reason>.*)\)')
RE_PASS_SKIP = re.compile(r'\[amice\]\s+skip\s+(?P<pass>\w+)\s+for VMP function:\s*"(?P<func>[^"]+)"')
RE_VMFLATTEN = re.compile(r'\(VmFlatten\)\s+fun:\s*"(?P<func>[^"]+)"')

# ── ③ 源码里的 VMP 注解 ────────────────────────────────────────────
# 本项目实际有两种形态，必须都认：
#
# 形态 A（直接注解）：函数定义上直接带 annotate
#     SIG_SEC_MARKED            ← 宏名，它的【定义】里有 +vm_virtualize
#     static int sig_verify(...) { ... }
#
# 形态 B（裸注解）：
#     __attribute__((section(".ncx"), noinline, annotate("+vm_virtualize")))
#     int my_func(void) { ... }
#
# ⚠️ 关键：宏的【定义】里出现 +vm_virtualize 并不意味着哪个函数被 VMP，
#    只有【用法】（宏名后面紧跟函数定义）才算。早期实现按"最近的标识符"
#    猜函数名，会误抓宏定义里的 `defined`、`section` 等词 —— 实测踩过。
RE_ANNOTATE_VMP = re.compile(r'annotate\s*\(\s*"(?:\+vm_virtualize|\+vmp)"')
# 宏定义：`#define NAME` 且其续行块里含 annotate("+vm_virtualize")
# ⚠️ 必须带 re.M —— 否则 ^ 只匹配文件开头，宏一个都找不到（实测踩过）
RE_DEFINE = re.compile(r'^[ \t]*#[ \t]*define[ \t]+(?P<name>[A-Za-z_]\w*)', re.M)
# C 函数定义头（宽松）：返回类型 + 名字 + 参数表开头
RE_FUNC_DEF = re.compile(
    r'^[ \t]*(?:\w[\w \t\*]*?)[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*\(', re.M)

_STOP_WORDS = frozenset((
    'if', 'for', 'while', 'switch', 'return', 'sizeof', 'defined',
    'static', 'inline', 'const', 'void', 'int', 'unsigned', 'signed',
    'char', 'long', 'short', 'float', 'double', 'struct', 'enum', 'union',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t', 'size_t', 'ssize_t',
    'JNIEXPORT', 'JNICALL', 'extern', 'volatile', 'register',
    '__attribute__', 'section', 'used', 'retain', 'noinline', 'aligned',
    'annotate', 'define', 'ifdef', 'ifndef', 'else', 'endif',
))


def norm_path(p):
    """把构建机的临时绝对路径规范化成 project 相对路径。"""
    for marker in ('/project/', '/jni/'):
        i = p.find(marker)
        if i != -1:
            return p[i + len(marker):] if marker == '/project/' else 'jni/' + p[i + len(marker):]
    return os.path.basename(p)


def func_name_from_sig(sig):
    """从 'static inline uint64_t nc_mix64(uint64_t z)' 取 nc_mix64。

    取【第一个后面跟 '(' 的标识符】，跳过类型/修饰词。

    ⚠️ protect.sh 会把签名截断到 ~120 字符，参数表可能没有右括号 ——
       所以不能用"必须以 ')' 结尾"的正则，按 `NAME(` 形态匹配即可。
    """
    s = re.sub(r'__attribute__\s*\(\([^)]*\)\)', '', sig)
    for m in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', s):
        name = m.group(1)
        if name.lower() in _STOP_WORDS:
            continue
        return name
    return None


def resolve_name_from_source(file_rel, line_no, src_root):
    """用日志里的 `path:line` 去源文件读完整函数签名，取出函数名。

    为什么需要这一步：nox 的 so_section_mark.py:249 打印时把签名截到 70 字符
    （`stripped[:70]`），dex2c 的产物签名是
        JNIEXPORT void JNICALL
        Java_com_xixin_box_MainActivity_onCreate__Landroid_os_Bundle_2(...)
    分两行写，截断后只剩 'JNIEXPORT void JNICALL' —— 函数名丢了。

    ⚠️ 不改 nox 那行：so_section_mark.py 是上游冻结设施，改它要重发 tag
       并同步消费方分发包，为了日志好看不值得。源文件本来就在手边。

    做法：从该行起向下拼最多 6 行（跨行函数头），遇到 '(' 即停，再解析名字。
    """
    if not (file_rel and line_no and src_root):
        return None
    # 日志里的路径是 project 相对（jni/nc/foo.c），拼到 src_root 上试试
    cands = [os.path.join(src_root, file_rel),
             os.path.join(src_root, os.path.basename(file_rel))]
    # src_root 可能已是 jni/nc，而 file_rel 是 jni/nc/x.c → 去掉重复前缀
    if file_rel.startswith('jni/'):
        rest = file_rel[len('jni/'):]
        cands += [os.path.join(src_root, rest),
                  os.path.join(os.path.dirname(src_root), file_rel)]
    path = next((c for c in cands if os.path.isfile(c)), None)
    if not path:
        return None
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except OSError:
        return None
    idx = line_no - 1
    if not (0 <= idx < len(lines)):
        return None
    buf = ''
    for k in range(idx, min(idx + 6, len(lines))):
        buf += ' ' + lines[k].strip()
        if '(' in buf:
            break
    return func_name_from_sig(buf.strip())


def parse_build_log(path, src_root=''):
    """→ marks(OrderedDict) / vmp_skips / pass_skips / vmflatten / seg_notes / file_counts"""
    marks = OrderedDict()
    vmp_skips = {}
    pass_skips = defaultdict(set)
    vmflatten = set()
    seg_notes = []
    file_counts = OrderedDict()
    totals = []

    if not path or not os.path.exists(path):
        return marks, vmp_skips, pass_skips, vmflatten, seg_notes, file_counts, totals

    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = RE_MARK_SEG.search(line)
            if m:
                seg_notes.append((m.group('what').strip(), m.group('seg')))
                continue
            m = RE_MARK_TOTAL.search(line)
            if m:
                totals.append(int(m.group('n')))
                continue
            m = RE_MARK_COUNT.search(line)
            if m:
                file_counts[norm_path(m.group('path'))] = int(m.group('n'))
                continue
            m = RE_MARK_DETAIL.search(line)
            if m:
                sig = m.group('sig').strip()
                frel = norm_path(m.group('path'))
                lno = int(m.group('line'))
                # 先按日志签名取；取不到再回源文件读完整签名
                name = func_name_from_sig(sig)
                if not name:
                    name = resolve_name_from_source(frel, lno, src_root)
                rec = {'file': frel, 'line': lno, 'sig': sig, 'name': name}
                key = name or f'<{frel}:{lno}>'
                marks.setdefault(key, rec)

            m = RE_VMP_SKIP.search(line)
            if m:
                vmp_skips[m.group('func')] = m.group('reason').strip()
            m = RE_PASS_SKIP.search(line)
            if m:
                pass_skips[m.group('func')].add(m.group('pass'))
            m = RE_VMFLATTEN.search(line)
            if m:
                vmflatten.add(m.group('func'))

    return marks, vmp_skips, pass_skips, vmflatten, seg_notes, file_counts, totals


def scan_sources_vmp_targets(src_dir):
    """从源码读「本该被 VMP」的函数名集合（权威，不猜日志）。

    两种形态都要认（见上方 ③ 的注释）：

      形态 A  宏携带注解：
          #define SIG_SEC_MARKED ... annotate("+vm_virtualize") ...
          SIG_SEC_MARKED
          static int sig_verify(...) {
        → 先扫出「定义里含 +vm_virtualize 的宏名」，再找这些宏名的【用法】，
          用法后面紧跟的函数定义头才是真正的目标。

      形态 B  裸注解直接贴在函数上：
          __attribute__((..., annotate("+vm_virtualize")))
          int my_func(void) {
        → 从注解位置向后找第一个函数定义头。

    ⚠️ 不要「从注解位置向前取最近的标识符」：宏定义里的 +vm_virtualize
       会让所有宏定义行变成"目标"，实测误抓出 `defined`。
    """
    targets = set()
    files = []
    if src_dir and os.path.isdir(src_dir):
        for root, _dirs, names in os.walk(src_dir):
            for n in names:
                if n.rsplit('.', 1)[-1] in ('c', 'cc', 'cpp', 'cxx', 'h'):
                    files.append(os.path.join(root, n))

    def func_after(text, pos, window=600):
        """从 pos 起向后找第一个函数定义头，返回函数名或 None。"""
        seg = text[pos:pos + window]
        # 跳过预处理行（#define / #endif 之类不是函数）
        for m in RE_FUNC_DEF.finditer(seg):
            nm = m.group('name')
            if nm.lower() in _STOP_WORDS:
                continue
            # 排除"函数调用"：定义头前面通常是行首类型，且不带 '=' 号
            head = seg[max(0, m.start() - 80):m.start()]
            if '=' in head.split('\n')[-1]:
                continue
            return nm
        return None

    for path in files:
        try:
            text = open(path, 'r', encoding='utf-8', errors='replace').read()
        except OSError:
            continue

        # ── 形态 A：定位「定义里含 +vm_virtualize 的宏」──
        vmp_macros = set()
        for m in RE_DEFINE.finditer(text):
            # 宏定义块 = 从 #define 到下一个不以 '\' 结尾的行
            block_start = m.start()
            end = block_start
            while True:
                nl = text.find('\n', end)
                if nl == -1:
                    end = len(text)
                    break
                line = text[end:nl]
                end = nl + 1
                if not line.rstrip().endswith('\\'):
                    break
                if end - block_start > 2000:
                    break
            if RE_ANNOTATE_VMP.search(text[block_start:end]):
                vmp_macros.add(m.group('name'))

        # ── 形态 A 用法：宏名独占一行（或行首），下一行起是函数定义 ──
        for macro in vmp_macros:
            for m in re.finditer(r'^[ \t]*' + re.escape(macro) + r'[ \t]*$', text, re.M):
                nm = func_after(text, m.end())
                if nm:
                    targets.add(nm)

        # ── 形态 B：注解直接贴在函数上（排除属于宏定义的那些）──
        for m in RE_ANNOTATE_VMP.finditer(text):
            line_start = text.rfind('\n', 0, m.start()) + 1
            line = text[line_start:text.find('\n', m.start())]
            if line.lstrip().startswith('#'):
                continue          # 属于宏定义，已由形态 A 处理
            # 注解可能就在函数定义头同一行上（ANNOTATED_ATTR 形态）
            same_line = func_after(text, line_start, window=400)
            if same_line:
                targets.add(same_line)

    return targets


def elf_sections(so_bytes):
    """→ {name: (offset, size, addr, flags)}"""
    out = {}
    if len(so_bytes) < 0x40:
        return out
    try:
        if so_bytes[4] == 2:
            shoff = struct.unpack_from('<Q', so_bytes, 0x28)[0]
            shent = struct.unpack_from('<H', so_bytes, 0x3A)[0]
            shnum = struct.unpack_from('<H', so_bytes, 0x3C)[0]
            shstr = struct.unpack_from('<H', so_bytes, 0x3E)[0]
            fmt, base = '<IIQQQQ', shoff
        elif so_bytes[4] == 1:
            shoff = struct.unpack_from('<I', so_bytes, 0x20)[0]
            shent = struct.unpack_from('<H', so_bytes, 0x2E)[0]
            shnum = struct.unpack_from('<H', so_bytes, 0x30)[0]
            shstr = struct.unpack_from('<H', so_bytes, 0x32)[0]
            fmt, base = '<IIIIII', shoff
        else:
            return out

        def sh(k):
            return struct.unpack_from(fmt, so_bytes, base + k * shent)

        strtab_off = sh(shstr)[4]
        for k in range(shnum):
            name_off, sh_type, flags, addr, off, size = sh(k)
            end = so_bytes.index(b'\0', strtab_off + name_off)
            nm = so_bytes[strtab_off + name_off:end].decode('latin1')
            out[nm] = (off, size, addr, flags, sh_type)
    except (struct.error, IndexError, ValueError):
        return out
    return out


def volume_table(so_bytes, sections):
    """逐段算出「原始 / 压缩后 / 压比」，并给出 so 总计。

    为什么需要（用户原话：『我想知道比如600多kb，有多少被压缩，
    有多少没被压缩，这里也没显示呀』）：
      · 之前报告只有字节数，读者要自己换算单位
      · 更关键：看不到「加密段压不动」这个事实 —— 而它正是所有
        体积决策的依据（.ncx 熵 8.0，zlib 100% 压不动；.text 能压到 51%）

    判据：zlib.compress(data, 9) 后与原大小之比 > 95% → 密文/不可压。
    这不是精确的 APK 内 deflate（那是整包流式压缩），但足以区分
    「加密段」与「明文段」——本项目所有体积决策都基于这个区分。

    返回 (rows, total_raw, total_comp, so_size)
      rows: [(name, raw, comp, ratio_pct, is_cipher), ...] 按 raw 降序
    """
    rows = []
    for name, meta in sections.items():
        off, size, _addr, _flags = meta[0], meta[1], meta[2], meta[3]
        sh_type = meta[4] if len(meta) > 4 else 1
        # ⚠️ SHT_NOBITS(8) = .bss，不占磁盘空间（sh_size 只是运行期需求）
        #    首版把它当实体段算 → 合计 1373.9 KB 超过 so 本身 699 KB（实测假数）
        if sh_type == 8:
            continue
        if size == 0 or name.startswith('.debug') or name in ('.comment',):
            continue
        blob = so_bytes[off:off + size]
        try:
            comp = len(zlib.compress(blob, 9))
        except Exception:
            continue
        ratio = (comp / size * 100.0) if size else 0.0
        rows.append((name, size, comp, ratio, ratio > 95.0))
    rows.sort(key=lambda r: -r[1])
    total_raw = sum(r[1] for r in rows)
    total_comp = sum(r[2] for r in rows)
    return rows, total_raw, total_comp, len(so_bytes)


def scan_ncx(so_bytes, sections):
    """在 .ncx 里估算函数起点与 VMP wrapper 个数。

    判据（只依赖指令编码，无需符号表）：
      ARM64 起点：`sub sp, sp, #imm` 或 `stp x29, x30, [sp, #-N]!`
      ARM32 起点：`push {..., lr}`
      wrapper    ：起点后 20 条内出现 ≥2 个 `bl`（VM 分派调用）

    ⚠️ 估算，不是精确切分：无 .eh_frame/.symtab 时无法 100% 定界。
    ⚠️ 必须在锁箱前调用 —— 锁箱后这里是密文。
    """
    stat = {'ncx_size': 0, 'starts': 0, 'wrappers': 0, 'bl_total': 0,
            'encrypted_guess': False}
    sec = sections.get('.ncx')
    if not sec:
        return stat
    off, size, _addr, _flags = sec[0], sec[1], sec[2], sec[3]
    blob = so_bytes[off:off + size]
    stat['ncx_size'] = len(blob)
    if not blob:
        return stat

    is64 = so_bytes[4] == 2
    starts = []
    ndw = len(blob) // 4
    for i in range(ndw):
        w = struct.unpack_from('<I', blob, i * 4)[0]
        if is64:
            if (w & 0xFF8003FF) == 0xD10003FF:          # sub sp, sp, #imm
                starts.append(i * 4)
            elif (w & 0xFFC07FFF) in (0xA9807BFD, 0xA9BF7BFD):  # stp x29,x30,[sp,#-N]!
                starts.append(i * 4)
        else:
            if (w & 0xFFFF4000) == 0xE92D4000:          # push {..., lr}
                starts.append(i * 4)

    stat['starts'] = len(starts)
    # 密文兜底判据：起点数为 0 且段足够大 → 多半是已锁箱
    if len(starts) == 0 and len(blob) > 4096:
        stat['encrypted_guess'] = True

    for s in starts:
        bl = 0
        for k in range(20):
            p = s + k * 4
            if p + 4 > len(blob):
                break
            w = struct.unpack_from('<I', blob, p)[0]
            if is64:
                if (w & 0xFC000000) == 0x94000000:
                    bl += 1
            else:
                if (w & 0x0F000000) == 0x0B000000:
                    bl += 1
        stat['bl_total'] += bl
        if bl >= 2:
            stat['wrappers'] += 1
    return stat


def redact_reason(reason):
    """把跳过原因里的精确寄存器数值抹掉，只留类别。

    values=15 aggregates=0 temps=5 spilled=3 vregs=32 free=0
       ↓
    register pressure（VM 寄存器预算超限）

    为什么：精确数值等于告诉攻击者「这个函数距离上限还差多少」，
    他可以据此判断"再拆一点就能过"或"差太远不用管"。类别信息
    对内足够定位问题（还要配合构建日志），对外不构成情报。
    """
    if not reason:
        return reason
    low = reason.lower()
    if 'register pressure' in low or 'budget exceeded' in low:
        return '寄存器预算超限（VM 虚拟化跳过）'
    if 'non-call address' in low:
        return '函数地址被非调用用途引用（VM 虚拟化跳过）'
    if 'intrinsic' in low:
        return 'LLVM intrinsic 调用（VM 虚拟化跳过）'
    # 未知类别：只保留前 40 字符，且剥掉所有 =数字 形态
    short = re.sub(r'=\s*-?\d+', '=?', reason)[:40]
    return short


def redact_name(name, salt):
    """函数名 → 稳定短哈希。同一盐同一函数名恒等，便于跨构建对比。"""
    h = hashlib.sha256((salt + '|' + name).encode('utf-8')).hexdigest()[:8]
    return f'func_{h}'


def build_report(marks, vmp_skips, pass_skips, vmflatten, seg_notes, file_counts,
                 totals, scan, sections, vmp_targets, cfg_hint='',
                 redact=True, redact_salt='nc-func-report', volume=None):
    L = []
    A = L.append
    # ⚠️ .nct 的判定必须是【三态】，不能是布尔：
    #    True  = 有解释器段（VMP 生效）
    #    False = 读了 so，确认没有该段（VMP 真没生效）
    #    None  = 没读到 so（sections 为空）→ 无法判断
    #    2026-11-17 踩过：只用布尔时，--so 路径给错会让报告写
    #    「❌ 不存在 —— 消费方 VMP 整个没生效」，而实际 .nct 是有的。
    #    这是典型的「拿不到数据就当失败」假阴性，必须区分。
    has_nct = ('.nct' in sections) if sections else None

    A('# 函数级防护报告（构建期）')
    A('')
    A('> 生成器：`scripts/pipelines/func-report.py`。四个数据源交叉验证：')
    A('> ① `[mark]` 日志（哪些函数进 `.ncx`）② `[amice]` skip 日志（谁被哪个 pass 跳过、为什么）')
    A('> ③ 源码 `annotate("+vm_virtualize")`（哪些函数**本该**被 VMP）④ 产物 `.ncx` 指令扫描（实际有多少函数）')
    A('>')
    A('> **③ 是关键**：只看 ② 会把「压根没打算 VMP 的函数」误判成「VMP 失败」。')
    A('')
    if cfg_hint:
        A(f'**本次配置**：`{cfg_hint}`')
        A('')

    # 统计
    marked = [k for k in marks]
    annotated = [f for f in vmp_targets]
    vmp_bad = [f for f in annotated if f in vmp_skips]
    if has_nct is True:
        vmp_ok = [f for f in annotated if f not in vmp_skips]
    elif has_nct is False:
        vmp_ok = []          # 确认无解释器段 → 一个都没成功
    else:
        vmp_ok = []          # 未知：既不算成功也不算确认失败（见下方措辞）

    A('## 汇总')
    A('')
    A('| 指标 | 值 | 说明 |')
    A('|:---|:---|:---|')
    # ⚠️ 两个标记来源必须分开报，别混成一个"打进 .ncx 的函数"：
    #   ① so_section_mark.py 打的（dex2c 转译产物 / stringenc C 桩）→ 有 [mark] 日志
    #   ② 源码里直接用宏标记的（sig_check.c 的 SIG_SEC_MARKED）→ 没有 [mark] 日志
    #   2026-11-17 实测踩过：只统计 ①，在「只勾 sigcheck+vmp」的构建里
    #   会显示"打进 .ncx 的函数 = 0"，而实际有 11 个函数进了 .ncx。
    #   真相是 sig_check.c 自己带 section 属性，压根不经过 so_section_mark.py。
    A(f'| 源码标注 VMP 的函数 | **{len(annotated)}** | `annotate("+vm_virtualize")`（权威口径）|')
    A(f'| 经 `[mark]` 工具标记的函数 | **{len(marked)}** | 仅覆盖 dex2c/stringenc；'
      f'sig_check.c 自带属性，不在此列 |')
    A(f'| VMP 虚拟化成功 | **{len(vmp_ok)}** | 有注解且未出现在 skip 清单 |')
    A(f'| VMP 被跳过 | **{len(vmp_bad)}** | 有注解但出现在 skip 清单 |')
    if has_nct is True:
        _nct_cell, _nct_note = '✅ 存在', '消费方 VMP 已生成'
    elif has_nct is False:
        _nct_cell, _nct_note = '❌ **不存在**', '消费方 VMP 整个没生效'
    else:
        _nct_cell, _nct_note = '⚠️ 未知', '未读到 so，无法判断（不是失败）'
    A(f'| 第二套 VMP 解释器段 `.nct` | {_nct_cell} | {_nct_note} |')
    A(f'| `.ncx` 段大小 | {scan["ncx_size"]:,} B | |')
    A(f'| `.ncx` 函数起点（估算） | {scan["starts"]} | 指令模式扫描 |')
    A(f'| `.ncx` 疑似 VMP wrapper（估算） | {scan["wrappers"]} | 小帧 + ≥2 个 bl |')
    A('')

    # ── 体积与压缩对照 ────────────────────────────────────────────
    # 用户原话："我想知道比如600多kb，有多少被压缩，有多少没被压缩"
    # 这里逐段给「原始 / 压缩后 / 压比」，并明确标出哪些压不动。
    if volume:
        rows, tot_raw, tot_comp, so_size = volume
        A('## 体积与压缩')
        A('')
        A(f'so 磁盘大小 **{so_size/1024:.1f} KB**，'
          f'其中可统计段合计 **{tot_raw/1024:.1f} KB** → '
          f'压缩后 **{tot_comp/1024:.1f} KB**（压比 **{tot_comp/tot_raw*100:.0f}%**）。')
        A('')
        A('> 判据：逐段 zlib -9 压缩后与原大小之比 > 95% 视为「密文/不可压」。')
        A('> 加密段（熵 8.0）压不动 → 它涨多少，APK 就涨多少；')
        A('> 明文段能压到 20~50% → 体积代价被打折。')
        A('')
        A('| 段 | 原始 | 压缩后 | 压比 | 性质 |')
        A('|:---|--:|--:|--:|:---|')
        for name, raw, comp, ratio, cipher in rows:
            if raw < 512:
                continue
            kind = '🔒 **密文（压不动）**' if cipher else '✅ 明文（可压）'
            A(f'| `{name}` | {raw/1024:.1f} KB | {comp/1024:.1f} KB '
              f'| {ratio:.0f}% | {kind} |')
        A(f'| **合计** | **{tot_raw/1024:.1f} KB** | **{tot_comp/1024:.1f} KB** '
          f'| **{tot_comp/tot_raw*100:.0f}%** | |')
        A('')
        # 明确点出加密段的绝对代价 —— 这是最该被记住的数字
        cipher_raw = sum(r[1] for r in rows if r[4])
        if cipher_raw:
            A(f'> ⚠️ 加密段合计 **{cipher_raw/1024:.1f} KB**，这部分体积'
              f'**无法被压缩吸收**，会原样进入 APK。')
            A('')
        # 明确指出报告覆盖范围（防止"以为都查了"）
        A('> 📋 本报告的段表覆盖以下段：' +
          ' '.join(f'`{r[0]}`' for r in rows if r[1] >= 512) + '。')
        A('> `.eh_frame` / `.comment` 等在构建期已被 `--strip-meta` 删除，故不出现。')
        A('')

    if scan['encrypted_guess']:
        A('> ⚠️ `.ncx` 扫描到 0 个函数起点且段不小 —— 大概率是**已锁箱的密文**。')
        A('> 本脚本必须在锁箱**之前**调用。当前产物应在 `protect.sh` 的')
        A('> `_size_report "编译后"` 之后、`so-section-lock.py` 之前生成报告。')
        A('')

    if annotated and not vmp_ok and has_nct is False:
        A(f'> ❌ **{len(annotated)} 个标注了 VMP 的函数，0 个成功虚拟化。**')
        A('> 常见原因：同时开了 `vm_flatten`（pass priority 960 > VmVirtualize 955，')
        A('> 先摊平 CFG → VMP 拿到的控制流寄存器压力超限 → 整函数跳过）。')
        A('')

    # 段标记说明
    if seg_notes or file_counts:
        A('## 标记阶段')
        A('')
        for what, seg in seg_notes:
            A(f'- {what} → `{seg}`')
        if file_counts and not redact:
            A('')
            A('| 文件 | 标记函数数 |')
            A('|:---|--:|')
            for fn, cnt in file_counts.items():
                A(f'| `{fn}` | {cnt} |')
        A('')

    # 逐函数
    A('## 逐函数明细')
    A('')
    if not marks and not annotated:
        A('> 没有解析到任何函数 —— `ndk-build.log` 缺失，或本次组合不产 so。')
    else:
        A('| 函数 | 源位置 | VMP 目标 | VMP 结果 | 混淆 | 原因 |')
        A('|:---|:---|:---:|:---:|:---|:---|')

        def row(fname, meta=None, is_target=None):
            meta = meta or {}
            is_target = (fname in vmp_targets) if is_target is None else is_target
            shown = redact_name(fname, redact_salt) if redact else fname
            loc = f'`{meta["file"]}:{meta["line"]}`' if meta.get('file') else '—'
            if redact:
                # 脱敏时连文件名都不给 —— 文件名能直接推出是哪个防御模块
                loc = '`(已脱敏)`' if meta.get('file') else '—'
            if not is_target:
                tgt, res, reason = '⬜ 未标注', '—', ''
            else:
                tgt = '🎯'
                if fname in vmp_skips:
                    res = '❌ 跳过'
                    reason = vmp_skips[fname]
                elif has_nct is True:
                    res, reason = '✅', ''
                elif has_nct is False:
                    res = '⚠️ 未生效'
                    reason = '产物无 .nct（VMP pass 未运行）'
                else:
                    res = '❔ 未知'
                    reason = '未读到 so，无法确认是否虚拟化'
            if fname in pass_skips:
                obf = '跳过 ' + '/'.join(sorted(pass_skips[fname]))
            elif fname in vmflatten:
                obf = 'VmFlatten ✅'
            elif pass_skips:
                obf = '未出现在日志'
            else:
                obf = '未启用'
            if redact:
                reason = redact_reason(reason)
            r = reason if len(reason) <= 80 else reason[:77] + '...'
            A(f'| `{shown}` | {loc} | {tgt} | {res} | {obf} | {r} |')

        # 失败项排最前：读报告的人最关心"哪些没保护"
        def sort_key(f):
            return (0 if (f in vmp_targets and f in vmp_skips) else
                    1 if f in vmp_targets else 2, f)

        union = list(OrderedDict.fromkeys(list(marks.keys()) + sorted(vmp_targets)))
        for fname in sorted(union, key=sort_key):
            row(fname, marks.get(fname))
    A('')

    # 未对齐项
    only_annotated = sorted(set(vmp_targets) - set(marks))
    if only_annotated:
        A('## 有 VMP 注解但不在 `.ncx` 标记清单里')
        A('')
        A('> 这些函数被要求虚拟化，但没进加密段 —— 要么段标记漏了，')
        A('> 要么注解落在未拷贝进工程的编译单元里。')
        A('')
        for f in only_annotated:
            r = vmp_skips.get(f, '')
            shown = redact_name(f, redact_salt) if redact else f
            if redact:
                r = redact_reason(r)
            A(f'- `{shown}`' + (f' —— {r[:100]}' if r else ' —— 未出现在 skip 日志（可能已被虚拟化）'))
        A('')

    # 能力边界
    A('## 本报告不包含什么（如实）')
    A('')
    A('| 拿不到的信息 | 为什么 |')
    A('|:---|:---|')
    A('| 每个 pass 对每个函数的**成功**记录 | amice 只打 skip 日志，成功是静默的。'
      '「✅」的判据是「有注解 + 没进 skip 清单 + 产物有 `.nct`」 |')
    A('| 函数边界的精确切分 | 锁箱 + `--strip-all` 后无 `.symtab`/`.eh_frame`，'
      f'只能按指令模式估算（本次估出 {scan["starts"]} 个起点） |')
    A('| 混淆后的**实际强度** | 任何静态报告都给不了 —— 只能评估，不能证明 |')
    A('| 运行期是否真的解密成功 | 那是 `ncguard_log.md`（运行期自检）的职责 |')
    A('')
    A('> 运行期自检看**段**，本报告看**函数**。两者互补，缺一不可。')
    A('')
    return '\n'.join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description='生成函数级防护报告（构建期）')
    ap.add_argument('--build-log', default='')
    ap.add_argument('--so', default='', help='锁箱【前】的 libnc.so（arm64 优先）')
    ap.add_argument('--src-dir', default='', help='C 源码目录，用于读 VMP 注解')
    ap.add_argument('--out', default='', help='输出 .md（留空=stdout）')
    ap.add_argument('--json-out', default='')
    ap.add_argument('--cfg-hint', default='')
    # ── 脱敏（2026-11-17 审核新增）──────────────────────────────────
    # 本仓库是【公开】的，而报告内容是「防护清单 + 弱点清单」：
    #   · 11 个函数成功 0 个 → 攻击者白知道「零虚拟化，不用逆 VM」
    #   · 逐函数的 values=12 vregs=32 free=0 → 精确告诉攻击者边界在哪
    #   · 哪些 pass 被跳过 → 知道这个函数只剩明文逻辑
    # 公开仓库的 Actions artifact 对有 GitHub 账号的人可下载，
    # Step Summary 更是匿名可见。等于给攻击者发路线图。
    #
    # 处理：默认【脱敏】—— 函数名做短哈希、去掉精确寄存器数值、
    #       只保留「N 个目标 / M 个成功 / K 个跳过」这种聚合结论。
    #       运维需要细节时用 --no-redact（CI 里仍会脱敏，本地排查可关）。
    ap.add_argument('--no-redact', action='store_true',
                    help='不脱敏（本地排查用；⚠️ 公开仓库 CI 不要开）')
    ap.add_argument('--redact-salt', default='nc-func-report',
                    help='函数名哈希盐（同一盐同一函数名稳定，便于跨构建对比）')
    args = ap.parse_args(argv)

    (marks, vmp_skips, pass_skips, vmflatten,
     seg_notes, file_counts, totals) = parse_build_log(args.build_log, args.src_dir)

    vmp_targets = scan_sources_vmp_targets(args.src_dir)

    # ── 审核发现（2026-11-17）：src-dir 指错会静默给出"0 个 VMP 目标" ──
    # 危险在哪：把 src-dir 指向一个不含 sig_check.c 的目录（例如只传
    # project/jni 而非 project/jni/nc），报告会显示
    #     「源码标注 VMP 的函数：0」
    # 读报告的人会得出「本次压根没开 VMP」的错误结论，而真相是
    # 「报告找不到源码」。这是本项目最忌讳的【静默降级】。
    # 所以：有 mark 记录却扫不到任何 VMP 注解 → 明确报警，不装没事。
    if args.src_dir and not vmp_targets and marks:
        print(f'[func-report] ⚠️ src-dir 里没扫到任何 annotate("+vm_virtualize")：'
              f'{args.src_dir}', file=sys.stderr)
        print('[func-report]    → 但 ndk-build.log 有标记记录，正常情况下不会两者都空',
              file=sys.stderr)
        print('[func-report]    → 检查 src-dir 是否指向含 sig_check.c 的目录'
              '（通常是 project/jni/nc）', file=sys.stderr)

    sections, scan = {}, {'ncx_size': 0, 'starts': 0, 'wrappers': 0,
                          'bl_total': 0, 'encrypted_guess': False}
    volume = None
    if args.so and os.path.exists(args.so):
        try:
            so_bytes = open(args.so, 'rb').read()
            sections = elf_sections(so_bytes)
            scan = scan_ncx(so_bytes, sections)
            volume = volume_table(so_bytes, sections)
        except OSError as e:
            print(f'[func-report] 读 so 失败: {e}', file=sys.stderr)
    elif args.so:
        print(f'[func-report] so 不存在，跳过段扫描: {args.so}', file=sys.stderr)

    md = build_report(marks, vmp_skips, pass_skips, vmflatten, seg_notes,
                      file_counts, totals, scan, sections, vmp_targets,
                      args.cfg_hint, redact=not args.no_redact,
                      redact_salt=args.redact_salt, volume=volume)

    if args.out:
        try:
            d = os.path.dirname(args.out)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(args.out, 'w', encoding='utf-8') as f:
                f.write(md)
            print(f'[func-report] 已写入 {args.out}', file=sys.stderr)
        except OSError as e:
            print(f'[func-report] 写 {args.out} 失败（改打到 stdout）: {e}', file=sys.stderr)
            print(md)
    else:
        print(md)

    if args.json_out:
        data = {
            'summary': {
                'marked': len(marks),
                'vmp_targets': len(vmp_targets),
                'vmp_ok': len([f for f in vmp_targets if f not in vmp_skips]) if '.nct' in sections else 0,
                'vmp_skipped': len([f for f in vmp_targets if f in vmp_skips]),
                'has_nct': '.nct' in sections,
                'ncx_size': scan['ncx_size'],
                'ncx_starts_est': scan['starts'],
                'ncx_wrappers_est': scan['wrappers'],
                'ncx_looks_encrypted': scan['encrypted_guess'],
            },
            # 体积摘要（供 protect.sh 打一行日志用）
            # 用户口径："600 多 KB 有多少被压缩、多少没被压缩"
            'volume': ({
                'so_kb': round(volume[3] / 1024, 1),
                'raw_kb': round(volume[1] / 1024, 1),
                'comp_kb': round(volume[2] / 1024, 1),
                'ratio_pct': round(volume[2] / volume[1] * 100) if volume[1] else 0,
                'cipher_kb': round(sum(r[1] for r in volume[0] if r[4]) / 1024, 1),
            } if volume else None),
            'functions': [
                {
                    'name': f,
                    'file': marks.get(f, {}).get('file'),
                    'line': marks.get(f, {}).get('line'),
                    'vmp_target': f in vmp_targets,
                    'vmp_skip_reason': vmp_skips.get(f),
                    'passes_skipped': sorted(pass_skips.get(f, [])),
                    'vmflatten_applied': f in vmflatten,
                }
                for f in OrderedDict.fromkeys(list(marks.keys()) + sorted(vmp_targets))
            ],
        }
        try:
            with open(args.json_out, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
            print(f'[func-report] 已写入 {args.json_out}', file=sys.stderr)
        except OSError as e:
            print(f'[func-report] 写 JSON 失败: {e}', file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
