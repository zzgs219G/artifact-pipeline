#!/usr/bin/env python3
"""dex-capacity.py — dex 方法数容量检测 + 注入落点选择（纯 stdlib，零依赖）

背景（报错五十九）：
  注入类（签名校验 Guard/NcLink、字符串解密桩）原本硬编码写进 `smali/`
  （= classes.dex）。真实大型 APK 经 R8/d8 编译后 classes.dex 的方法数
  几乎必然贴顶：

      囤次元包: classes.dex 65519/65536（余量 17）
               classes4.dex 65463/65536（余量 73）
               15 个 dex 里 6 个余量 < 500

  此时任何注入都会把 dex 推过 65536，smali 汇编器报：

      Unsigned short value out of range: 65536
        at InstructionWriter.write(SourceFile:398)      ← Instruction35c（invoke-*）
      Error while writing instruction at code offset 0x2

  报错的类名是"谁最后被写谁中枪"，与我们的改动无关（实测同一个包三次
  运行分别炸在 com/beizi/ad/e$a、androidx/media3/.../Tracks$Group、
  androidx/camera/.../ExifData$WhiteBalanceMode），因此**不能用报错类名定位**。

  修法：写之前先查容量；目标 dex 余量不足就新建 `smali_classes{N+1}/`，
  把本次注入全部写进去（n+1 是注入器通行做法：不碰任何已有 dex，
  不跟别的加固壳抢编号）。apktool 的 `ApkBuilder.buildSources` 按目录名
  生成 dex 文件名（`smali` → classes.dex，`smali_classes5` → classes5.dex），
  新建目录即可，无需改 apktool。

为什么只查方法数，不查字符串数（实测）：
  classes.dex 有 75688 个字符串（超 65535 上限 10152 个），但往其中新增
  1 个类 + 1 条 const-string 的编译**成功**——dexlib2 发现索引超 65535 时
  会自动把 const-string 升级成 const-string/jumbo（32 位索引）。
  原包本身已有 2982 条 jumbo 指令，是常态。故字符串不构成构建期失败条件。

计数来源（性能）：
  方法数在 dex header 的 `method_ids_size`（偏移 0x58 = 88）；
  直接读 APK 内每个 dex 的前 112 字节即可，实测 15 个 dex 共 20.6 ms。
  不解析 class_defs、不反汇编——构建耗时 4~13 分钟，这点开销可忽略。

smali 目录 → dex 文件的映射（以 apktool 字节码为准，勿凭猜）：
  brut.androlib.ApkBuilder.buildSources:
    "smali"                                  → "classes.dex"
    以 "smali_" 开头 → 取首个 '_' 之后的子串 + ".dex"
  注意 `smali_classes2` 的 payload 是 "classes2"，故按"首个下划线"截取，
  不是丢掉整个 "classes" 前缀。
"""
import os
import re
import struct
import zipfile

try:
    import json
except ImportError:  # pragma: no cover
    raise

# 与 inject-loadlib.py / inject-javacheck.py / encrypt-strings.py 同源约定
# （报错七：改一处必须 grep 另外三处；tests 里有断言钉住这份副本一致）
SMALI_DIR_RE = re.compile(r'^smali(?:_classes\d+)?$')

# 本轮自建注入 dex 的标记文件（与 apktool 产物同放解包目录根）。
# 作用：同一条流水线里 javacheck / stringenc 两处注入共用同一个自建 dex，
# 并在回编产物里能被 dex-versions.json 之外的地方识别出来。
MARKER_FILE = 'dex-capacity.json'

# dex header 关键偏移（dex format 035~040 布局一致）
_OFF_STRING_IDS_SIZE = 56   # 0x38
_OFF_METHOD_IDS_SIZE = 88   # 0x58
_HEADER_PROBE = 112         # 读这么多就够拿到两个计数

# 方法与字段索引都是 16 位 → 硬上限 65536 条
DEX_INDEX_LIMIT = 65536

# 安全余量：注入本身只占几十个方法（实测 Guard+NcLink+Guard$Hb = 25 个），
# 但后续同一条流水线里 dex2c native 化、stringenc 桩、调用点插入都会再加方法。
# 余量太小会导致"这次刚好塞下、下次多点就炸"，故留 2000 作为工程余量。
DEFAULT_RESERVE = 2000


def method_count_from_bytes(header: bytes):
    """从 dex header 前若干字节读 (method_ids_size, string_ids_size)。

    非 dex 或字节不足返回 None（调用方据此跳过，不 fail——解包目录里可能
    有非 dex 残留，不该因此中断构建）。
    """
    if len(header) < _HEADER_PROBE or header[:4] != b'dex\n':
        return None
    meth = struct.unpack_from('<I', header, _OFF_METHOD_IDS_SIZE)[0]
    strs = struct.unpack_from('<I', header, _OFF_STRING_IDS_SIZE)[0]
    return meth, strs


def read_apk_dex_counts(apk_path: str) -> dict:
    """读 APK 内每个 dex 的 (方法数, 字符串数)。

    返回 {'classes.dex': (65519, 75688), ...}；只读每个条目的头部 112 字节。
    """
    counts = {}
    with zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            if not name.endswith('.dex'):
                continue
            with z.open(name) as fp:
                got = method_count_from_bytes(fp.read(_HEADER_PROBE))
            if got:
                counts[name] = got
    return counts


def smali_dir_to_dex_name(dir_name: str) -> str:
    """smali 目录名 → apktool 会生成的 dex 文件名（与 ApkBuilder 逐字对齐）。"""
    if dir_name == 'smali':
        return 'classes.dex'
    if dir_name.startswith('smali_'):
        return dir_name.split('_', 1)[1] + '.dex'
    raise ValueError(f'不是 smali 目录名: {dir_name!r}')


def list_smali_dirs(decompiled_dir: str) -> list:
    """列出解包目录下的 smali* 目录名，按 apktool 的生成顺序无关紧要，
    但这里按 dex 序号排序便于日志可读。"""
    dirs = [n for n in os.listdir(decompiled_dir)
            if SMALI_DIR_RE.match(n) and os.path.isdir(os.path.join(decompiled_dir, n))]

    def sort_key(n):
        dex = smali_dir_to_dex_name(n)
        m = re.match(r'^classes(\d*)\.dex$', dex)
        return (int(m.group(1)) if m and m.group(1) else 1)

    return sorted(dirs, key=sort_key)


def next_smali_dir_name(decompiled_dir: str) -> str:
    """下一个可用 smali 目录名 = 现有最大 dex 序号 + 1。

    用"最大+1"而非"填补空缺"：n+1 是注入器通行做法——不碰任何已有 dex，
    也不去猜某个空 dex 是不是被别的壳/加固工具占着位置。
    """
    max_idx = 1                       # classes.dex 视为 1
    for name in list_smali_dirs(decompiled_dir):
        dex = smali_dir_to_dex_name(name)
        m = re.match(r'^classes(\d*)\.dex$', dex)
        if m:
            idx = int(m.group(1)) if m.group(1) else 1
            max_idx = max(max_idx, idx)
        else:
            # classes-foo.dex 这类非常规命名：不下判断，直接抬高序号避开它
            max_idx = max(max_idx, 2)
    return f'smali_classes{max_idx + 1}'


def dir_method_count(smali_dir: str) -> int:
    """统计一个 smali 目录里 `.method` 定义数。

    注意：这只统计"本目录定义的方法"，而 dex 的 method_ids 还包含**引用的
    外部方法**，所以它不等于 dex 的 method_ids_size。本函数只用于：
      · 日志可读
      · 无 APK 可取时的保守兜底（宁可高估占用）
    权威判据始终是 APK 里 dex header 的 method_ids_size。
    """
    total = 0
    for root, _dirs, files in os.walk(smali_dir):
        for fn in files:
            if not fn.endswith('.smali'):
                continue
            try:
                with open(os.path.join(root, fn), encoding='utf-8', errors='replace') as fp:
                    total += sum(1 for line in fp if line.startswith('.method'))
            except OSError:
                continue
    return total


# 引擎估算系数：无原始 APK 时只能数 `.method` 定义数，而 dex 的 method_ids
# 还包含**被引用的外部方法**。实测囤次元包 classes.dex 定义 58214 / 实际
# method_ids 65519（1.126×）、classes4 53398/65463（1.226×）、
# classes3 58283/65425（1.122×）。取 1.25 作保守上界：宁可高估占用
# （提前新建 dex，浪费一个空 dex）也不要低估（撞 65536 直接构建失败）。
SCAN_ESTIMATE_FACTOR = 1.25


def measure(decompiled_dir: str, apk_path: str = None) -> dict:
    """测量解包目录各 smali 目录对应 dex 的占用情况。

    返回 {smali_dir: {'dex': 'classes.dex', 'methods': int,
                      'free': int, 'source': 'apk'|'scan', 'exact': bool}}

    apk_path 给定时从原始 APK 读 header（权威、实测 15 个 dex 共 20.6 ms）；
    否则回落到扫描 `.method` 定义数并乘 SCAN_ESTIMATE_FACTOR 作保守上界。
    """
    apk_counts = read_apk_dex_counts(apk_path) if apk_path and os.path.isfile(apk_path) else {}
    out = {}
    for name in list_smali_dirs(decompiled_dir):
        dex = smali_dir_to_dex_name(name)
        if dex in apk_counts:
            meth = apk_counts[dex][0]
            src, exact = 'apk', True
        else:
            # 新建 dex（APK 里必然没有）→ 扫目录，空目录即 0，精确；
            # 有内容却没 APK 可对照时按系数保守放大。
            raw = dir_method_count(os.path.join(decompiled_dir, name))
            if raw == 0:
                meth, exact = 0, True
            else:
                meth, exact = int(raw * SCAN_ESTIMATE_FACTOR), False
            src = 'scan'
        out[name] = {'dex': dex, 'methods': meth,
                     'free': DEX_INDEX_LIMIT - meth, 'source': src,
                     'exact': exact}
    return out


def _marker_path(decompiled_dir: str) -> str:
    return os.path.join(decompiled_dir, MARKER_FILE)


def _read_marker(decompiled_dir: str) -> str:
    """读本次解包轮次自建的注入 dex 目录名；无标记返回空串。"""
    try:
        with open(_marker_path(decompiled_dir), encoding='utf-8') as fp:
            return (json.load(fp).get('inject_dir') or '').strip()
    except (OSError, ValueError):
        return ''


def _write_marker(decompiled_dir: str, dir_name: str) -> None:
    with open(_marker_path(decompiled_dir), 'w', encoding='utf-8') as fp:
        json.dump({'version': 1, 'inject_dir': dir_name}, fp, indent=1)
        fp.write('\n')


def pick_target_dir(decompiled_dir: str, need_methods: int,
                    apk_path: str = None, reserve: int = DEFAULT_RESERVE,
                    prefer: str = 'smali', log=print) -> str:
    """选择注入落点目录名（纯决策：只读容量、不改文件，除非新建目录并打标记）。

    决策顺序：
      1. 本轮已自建的注入 dex（标记文件记录）仍有足够余量 → 复用它
         （同一条流水线里 javacheck 先建、stringenc 后用，不该各建一个）
      2. 首选目录（默认 smali/）余量 >= need + reserve → 用首选
      3. 都不满足 → 新建 最大序号+1 的目录（n+1），写标记

    ⚠️ 刻意**不去捡现成的空 dex**（如 classes2 常有 6 万空位）：
       用户注入的往往是"已改过的包"，那里的空 dex 可能是某个壳/加固工具
       自己的 dex，动它可能踩到对方对 dex 体积/内容的校验。
       n+1 只增不改，是注入器的通行做法，也是唯一零风险的选择。

    返回目录名（非绝对路径）；第 3 种情形已建好目录。
    """
    stats = measure(decompiled_dir, apk_path)
    need = need_methods + reserve

    # 1) 复用本轮自建的注入 dex
    own = _read_marker(decompiled_dir)
    if own and own in stats and stats[own]['free'] >= need:
        log(f'ℹ️ dex 容量: 落点 {own}/（本轮已建，余量 {stats[own]["free"]}，需 {need}）')
        return own

    # 2) 首选目录够用
    if prefer in stats and stats[prefer]['free'] >= need:
        log(f'ℹ️ dex 容量: 落点 {prefer}/（{stats[prefer]["dex"]} 余量 '
            f'{stats[prefer]["free"]}，需 {need}）')
        return prefer

    # 3) 新建 n+1
    newdir = next_smali_dir_name(decompiled_dir)
    cur = stats.get(prefer)
    cur_desc = (f'{cur["dex"]} 余量仅 {cur["free"]}' if cur else f'缺少 {prefer}/')
    os.makedirs(os.path.join(decompiled_dir, newdir), exist_ok=True)
    _write_marker(decompiled_dir, newdir)
    log(f'ℹ️ dex 容量: {cur_desc}，需 {need} → 新建 {newdir}/'
        f'（{smali_dir_to_dex_name(newdir)}）')
    return newdir


def main(argv):
    import argparse
    import json
    ap = argparse.ArgumentParser(description='dex 方法数容量检测')
    ap.add_argument('decompiled_dir')
    ap.add_argument('--apk', help='原始 APK（给定时从 dex header 取权威计数）')
    ap.add_argument('--need', type=int, default=0, help='本次注入需要的方法数')
    ap.add_argument('--reserve', type=int, default=DEFAULT_RESERVE)
    ap.add_argument('--pick', action='store_true', help='只打印选中的落点目录名')
    args = ap.parse_args(argv)

    if args.pick:
        print(pick_target_dir(args.decompiled_dir, args.need, args.apk,
                              args.reserve))
        return 0

    stats = measure(args.decompiled_dir, args.apk)
    for name in list_smali_dirs(args.decompiled_dir):
        s = stats[name]
        pct = s['methods'] / DEX_INDEX_LIMIT * 100
        flag = '  ← 贴顶' if s['free'] < 500 else ''
        print(f'{name:20s} {s["dex"]:16s} {s["methods"]:6d}/{DEX_INDEX_LIMIT}'
              f'  余量 {s["free"]:6d}  {pct:6.2f}%  [{s["source"]}]{flag}')
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv[1:]))
