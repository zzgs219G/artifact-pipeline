#!/usr/bin/env python3
"""dex-rebalance.py — 重排 smali 目录，让每个 dex 的 method_ids 留足余量（2026-11-06）

## 解决什么问题

大型 App 经 R8/d8 后多个 dex 的方法表贴顶。实测囧次元 1.0.14（16 个 dex）：

    classes.dex    65519/65536  余量 17
    classes3.dex   65425/65536  余量 111
    classes4.dex   65463/65536  余量 73
    classes5.dex   65328/65536  余量 208
    classes6.dex   65419/65536  余量 117
    classes8.dex   65286/65536  余量 250

加固会往 smali 里写东西（sigcheck 注入类、stringenc 每条 const-string
换成 3 行），在余量 73 的 dex 上做这些，回编必炸：

    Exception occurred while writing code_item
    Caused by: Unsigned short value out of range: 65536

**报错类名毫无诊断价值**（谁最后被写谁中枪，三次失败换了三个第三方类：
com/beizi/ad、androidx/media3、com/kwad），所以不能靠"排除某个 SDK"治标。

## 做法（与 MT 管理器「Dex 重新划分」同口径）

关键概念：**dex 的上限是 method_ids，不是 .method 定义数。**
    method_ids = 本 dex 定义的方法 ∪ 所有 invoke 引用的方法（去重）

本脚本两阶段：

  ① 判断要不要重排 —— 读**原 APK 的 dex header**（112 字节/dex，毫秒级）
     拿到真实的 method_ids_size。任一超过阈值才动手。
     ⚠️ 不扫 smali 文件：那是把已算好的数字再数一遍，慢几百倍。

  ② 分配 —— 每个类的"方法数"用 .method 计数（每文件 grep 一次）。
     容量判断用 method_ids = 定义数 × K，其中 K **从原包实测推导**：
         K = max(原包各 dex 的 method_ids_size / 该 dex 的 .method 定义数)
     而不是拍脑袋定一个系数（踩过：先猜 1.45 不够、再猜 1.70 才勉强）。
     取所有原包 dex 里最大的那个比值，再上浮 10% 作安全边际。

## 为什么按「定义数 × 系数」而不是精确算引用

精确算要解析 8 万个 smali 文件里的每条 invoke，实测 3 分钟以上。
而原包已经把"哪些类放在一起时引用去重率多少"这个信息编码在了它自己的
dex 划分里 —— 用原包的最大比值作系数，比精确重算的误差更小、成本低 3 个数量级。

（踩过的两个坏做法，写在这里防止回头：
  · 猜 1.25 —— 来自 dex-capacity.py 注释里的 classes.dex 比值，但那是
    "原包聚类好"的情况；重排后引用去重率下降，实际到 1.63×
  · 猜 1.45/1.70 —— 每次实测打脸再往上加，本质还是猜）

## 用法

    # 只判断（读 APK header，秒出）
    python3 scripts/repack/dex-rebalance.py --check <apk>

    # 重排（需要反编译目录）
    python3 scripts/repack/dex-rebalance.py <反编译目录> --apk <原始apk> [--dry-run]

    # 不给 --apk 时用 DEFAULT_RATIO 兜底（并在日志里标注"未校准"）
    python3 scripts/repack/dex-rebalance.py <反编译目录>

退出码：0 = 无需重排或重排成功；1 = 失败

## ⚠️ 顺序纪律

必须在【任何 smali 改动之前】。重排会搬动所有类文件，若此前已注入桩或
加密字符串，重排后会出现跨 dex 引用 —— apktool 能编出来，但运行期会因
分属不同 dex 的类初始化顺序出问题（且极难排查）。
protect.sh 的 repack_unpack（唯一解包入口）在解包后立刻调本脚本。
"""
import argparse
import os
import re
import shutil
import struct
import sys
import zipfile

# dalvik 硬限：dex header 的 method_ids_size 是 16 位
MAX_METHOD_IDS = 65536

# 留给加固模块的余量：sigcheck 注入约 25 个方法、stringenc 每条
# const-string 换成 3 行可能新增引用。实测注入量 < 100，2000 很宽裕。
SAFETY_MARGIN = 2000

# 触发重排的阈值：任一 dex 的 method_ids 超过它就重排。
# 55000 离硬限留 10536 —— 贴顶的必然触发，余量充足的包不会白搬一遍。
DEFAULT_THRESHOLD = 55000

# 未给 --apk 时的兜底比值（无法从原包实测）。
# 取 1.70：实测重排最坏到 1.632×，再留 4%。
# ⚠️ 会在日志里显式标注"未校准"，提醒这是猜的。
DEFAULT_RATIO = 1.70

SMALI_BASE = 'smali'
SMALI_PREFIX = 'smali_classes'


def log(msg):
    print(msg, flush=True)


# ── 阶段一：读 APK 的 dex header（毫秒级）───────────────────────────
def read_apk_dex_stats(apk_path):
    """返回 {dex名: (method_ids_size, type_ids_size, field_ids_size)}。

    只读 dex header 的前 112 字节，不碰 dex 内容。
    header 布局（小端）：
        0x38  string_ids_size
        0x40  type_ids_size
        0x50  field_ids_size
        0x58  method_ids_size
    """
    out = {}
    with zipfile.ZipFile(apk_path) as z:
        for n in z.namelist():
            if not n.endswith('.dex') or '/' in n:
                continue
            with z.open(n) as f:
                h = f.read(112)
            if len(h) < 112 or h[:4] != b'dex\n':
                continue
            out[n] = (struct.unpack_from('<I', h, 0x58)[0],   # method
                      struct.unpack_from('<I', h, 0x40)[0],   # type
                      struct.unpack_from('<I', h, 0x50)[0])   # field
    return out


def check_only(apk_path, threshold):
    """只判断要不要重排，不碰文件。"""
    stats = read_apk_dex_stats(apk_path)
    if not stats:
        log('✗ APK 里找不到 dex: %s' % apk_path)
        return 1
    log('── %s 的 dex 方法表（读 header，不解析内容）──' % os.path.basename(apk_path))
    need = False
    worst = 0
    for name in sorted(stats, key=lambda s: (len(s), s)):
        mid, tid, fid = stats[name]
        room = MAX_METHOD_IDS - mid
        flag = ''
        if mid > threshold:
            flag = '  ← 超过阈值 %d，需重排' % threshold
            need = True
        if room < worst or worst == 0:
            pass
        log('  %-14s method %5d (余 %5d)  type %5d  field %5d%s'
            % (name, mid, room, tid, fid, flag))
    log('')
    if need:
        log('→ 需要重排（有 dex 的 method_ids 超过 %d）' % threshold)
    else:
        log('✅ 所有 dex 方法表余量充足，无需重排')
    return 0 if not need else 2   # 2 = "需要重排"，供调用方区分


# ── 阶段二：分配 ────────────────────────────────────────────────────
def list_smali_dirs(root):
    out = []
    for name in os.listdir(root):
        p = os.path.join(root, name)
        if not os.path.isdir(p):
            continue
        if name == SMALI_BASE:
            out.append(('', p))
        elif name.startswith(SMALI_PREFIX) and name[len(SMALI_PREFIX):].isdigit():
            out.append((name[len(SMALI_PREFIX):], p))
    out.sort(key=lambda t: (t[0] != '', int(t[0]) if t[0] else 0))
    return out


def count_methods_in_file(path):
    n = 0
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.startswith('.method'):
                    n += 1
    except OSError:
        return 0
    return n


def collect_classes(root):
    """[(相对路径, .method 定义数, 源目录)]。只 grep，不解析 invoke。"""
    classes = []
    for _suffix, d in list_smali_dirs(root):
        for dirpath, _dirnames, filenames in os.walk(d):
            for fn in filenames:
                if not fn.endswith('.smali'):
                    continue
                full = os.path.join(dirpath, fn)
                classes.append((os.path.relpath(full, d),
                                count_methods_in_file(full), d))
    return classes


def calibrate(apk_path, root):
    """从原包实测推导三个池子的比值（method / type / field 相对 .method 定义数）。

    为什么必须三个池子都算（这次的真凶）：
      我一直只控 method_ids，但回编报的是
          InstructionWriter.write(SourceFile:225) + writeCodeItem(SourceFile:1303)
      那不是 method_ids 的写入路径 —— 是 field/type 索引。
      实测原包 classes7.dex：method 39887 但 **field 65357**（field/method
      = 1.64，其他 dex 只有 0.5）—— 字段密集的类聚在一起就爆 field_ids。
      重排把类重新组合后，field_ids 合并去重率下降 → 超 65536。

    ⚠️ 只采样大 dex（定义数 ≥ 10000）：小 dex 的比值天然虚高
    （实测 classes11.dex 94 个定义 → 322 method_ids = 3.43×，
     按它校准会把 dex 数从 16 涨到 29，白折腾）。

    返回 (m_ratio, t_ratio, f_ratio)，都已上浮 10% 作安全边际。
    """
    if not apk_path or not os.path.isfile(apk_path):
        return None
    stats = read_apk_dex_stats(apk_path)
    rows = []
    for suffix, d in list_smali_dirs(root):
        dexname = 'classes.dex' if not suffix else 'classes%s.dex' % suffix
        if dexname not in stats:
            continue
        defs = 0
        for dirpath, _dn, fns in os.walk(d):
            for fn in fns:
                if fn.endswith('.smali'):
                    defs += count_methods_in_file(os.path.join(dirpath, fn))
        if defs < 10000:          # 只采样大 dex，理由见 docstring
            continue
        mid, tid, fid = stats[dexname]
        rows.append((dexname, defs, mid, tid, fid))
    if not rows:
        return None
    rows.sort(key=lambda r: -r[2] / r[1])      # 按 method 比值降序
    log('── 原包实测比值（只采样大 dex，用于容量换算）──')
    log('  %-14s %7s %7s %7s %7s' % ('dex', '定义', 'method', 'type', 'field'))
    for name, defs, mid, tid, fid in rows[:5]:
        log('  %-14s %7d %7d %7d %7d' % (name, defs, mid, tid, fid))
    m = max(r[2] / r[1] for r in rows)
    t = max(r[3] / r[1] for r in rows)
    f = max(r[4] / r[1] for r in rows)
    log('  峰值比值: method %.3f×  type %.3f×  field %.3f×（各上浮 10%%）'
        % (m, t, f))
    return m * 1.10, t * 1.10, f * 1.10


def plan(classes, cap_ids, ratios):
    """顺序填装：按估算的 method_ids 装满一个换下一个。

    与 MT「Dex 重新划分」同做法 —— 不挑类、不排序，灌到满为止。
    粒度是「类」（dalvik 不允许把一个类拆到两个 dex）。
    """
    m_r, t_r, f_r = ratios
    # 三个池子各自的容量（以 .method 定义数为单位），取最紧的那个
    cap_defs = int(min(cap_ids / m_r, cap_ids / t_r, cap_ids / f_r))
    buckets = []
    cur, cur_defs = [], 0
    for rel, cnt, src in classes:
        if cnt > cap_defs:
            log('  ⚠ 类 %s 自身 %d 个方法，超过单 dex 可容纳 %d 个定义'
                ' —— dalvik 不允许拆类，只能单独成包' % (rel, cnt, cap_defs))
            if cur:
                buckets.append((cur, cur_defs)); cur, cur_defs = [], 0
            buckets.append(([(rel, cnt, src)], cnt))
            continue
        if cur_defs + cnt > cap_defs:
            buckets.append((cur, cur_defs))
            cur, cur_defs = [], 0
        cur.append((rel, cnt, src))
        cur_defs += cnt
    if cur:
        buckets.append((cur, cur_defs))
    return [b[0] for b in buckets], [b[1] for b in buckets], cap_defs


def target_dir_name(idx):
    return SMALI_BASE if idx == 0 else '%s%d' % (SMALI_PREFIX, idx + 1)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='重排 smali 目录，让每个 dex 的 method_ids 留足余量')
    ap.add_argument('decompiled', nargs='?', default='',
                    help='apktool 反编译输出目录（--check 模式可省）')
    ap.add_argument('--apk', default='',
                    help='原始 APK：用于读真实 method_ids + 校准换算比值')
    ap.add_argument('--check', action='store_true',
                    help='只判断要不要重排（读 APK header，秒出）')
    ap.add_argument('--threshold', type=int, default=DEFAULT_THRESHOLD,
                    help='dex 的 method_ids 超过它才重排（默认 %d）' % DEFAULT_THRESHOLD)
    ap.add_argument('--dry-run', action='store_true', help='只打印计划，不动文件')
    args = ap.parse_args(argv)

    # ── --check：纯读 header ──
    if args.check:
        if not args.apk:
            log('✗ --check 需要 --apk')
            return 1
        return 0 if check_only(args.apk, args.threshold) in (0, 2) else 1

    if not args.decompiled:
        log('✗ 需要反编译目录（或改用 --check --apk <apk>）')
        return 1
    root = os.path.abspath(args.decompiled)
    if not os.path.isdir(root):
        log('✗ 目录不存在: %s' % root)
        return 1
    dirs = list_smali_dirs(root)
    if not dirs:
        log('✗ 找不到 smali 目录（apktool 反编译输出的根目录？）')
        return 1

    # ── 判断是否需要重排：优先读 APK header（毫秒级）──
    need = False
    if args.apk and os.path.isfile(args.apk):
        rc = check_only(args.apk, args.threshold)
        if rc != 2:
            log('\n✅ 无需重排')
            return 0
        need = True
    else:
        # 没有 APK：只能数 .method 定义，按兜底比值反推
        log('── 未提供 --apk，按 .method 定义数估算（未校准）──')
        for suffix, d in dirs:
            n = 0
            for dirpath, _dn, fns in os.walk(d):
                for fn in fns:
                    if fn.endswith('.smali'):
                        n += count_methods_in_file(os.path.join(dirpath, fn))
            est = int(n * DEFAULT_RATIO)
            if est > args.threshold:
                need = True
                log('  %-18s %6d 定义 → 估 %6d method_ids ← 超阈值'
                    % (os.path.basename(d), n, est))
    if not need:
        return 0

    # ── 校准比值 ──
    ratios = calibrate(args.apk, root) if args.apk else None
    if ratios is None:
        ratios = (DEFAULT_RATIO, DEFAULT_RATIO, DEFAULT_RATIO)
        log('⚠ 无法从原包校准，用兜底比值 %.2f×（未校准，结果偏保守）'
            % DEFAULT_RATIO)

    cap_ids = MAX_METHOD_IDS - SAFETY_MARGIN
    classes = collect_classes(root)
    buckets, loads, cap_defs = plan(classes, cap_ids, ratios)

    log('')
    log('── 重排计划 ──')
    log('  类总数 %d，.method 定义合计 %d'
        % (len(classes), sum(c[1] for c in classes)))
    log('  单 dex 容量 %d 个 method_ids（硬限 %d − 余量 %d）→ 约 %d 个定义'
        % (cap_ids, MAX_METHOD_IDS, SAFETY_MARGIN, cap_defs))
    log('  方案 %d 个 dex：' % len(buckets))
    for i, (b, load) in enumerate(zip(buckets, loads)):
        log('    %-18s %6d 定义 → 估 method %6d / type %6d / field %6d（%d 个类）'
            % (target_dir_name(i) + '/', load,
               int(load * ratios[0]), int(load * ratios[1]),
               int(load * ratios[2]), len(b)))

    if args.dry_run:
        log('\n（dry-run：未改动任何文件）')
        return 0

    # ── 执行 ──
    log('\n── 执行重排 ──')
    tmp_root = os.path.join(root, '__rebalance_tmp')
    if os.path.isdir(tmp_root):
        shutil.rmtree(tmp_root)
    os.makedirs(tmp_root)
    for i, bucket in enumerate(buckets):
        dst_root = os.path.join(tmp_root, target_dir_name(i))
        for rel, _cnt, src in bucket:
            dst_path = os.path.join(dst_root, rel)
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
            try:
                shutil.move(os.path.join(src, rel), dst_path)
            except OSError as e:
                log('  ✗ 搬动失败 %s: %s' % (rel, e))
                log('  旧目录未删，可安全重跑')
                return 1
    for _suffix, d in dirs:
        shutil.rmtree(d, ignore_errors=True)
    for i in range(len(buckets)):
        name = target_dir_name(i)
        os.rename(os.path.join(tmp_root, name), os.path.join(root, name))
    os.rmdir(tmp_root)

    log('\n✅ 重排完成：%d 个 dex' % len(buckets))
    after = collect_classes(root)
    if len(after) != len(classes):
        log('✗ 终检失败：重排前 %d 个类，重排后 %d 个 —— 有类丢失！'
            % (len(classes), len(after)))
        return 1
    log('   终检通过：%d 个类一个不少' % len(after))
    return 0


if __name__ == '__main__':
    sys.exit(main())
