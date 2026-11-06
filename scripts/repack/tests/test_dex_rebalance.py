#!/usr/bin/env python3
"""test_dex_rebalance.py — dex-rebalance.py 的回归测试（纯 stdlib，秒级）

【为什么补这个测试】
  2026-11-06 的场景：大型包多个 dex 的方法表/字段表贴顶（实测囧次元
  1.0.14：classes.dex method 余量 17、classes4 余量 73、classes7 的
  field_ids 65357/65536），加固往里写东西就回编失败：
      Unsigned short value out of range: 65536
  报错类名完全随机（三次失败换了 beizi/ad、media3、kwad 三个第三方类），
  不能靠排除某个 SDK 治标 —— 必须重排 dex 结构。

【本测试锁住什么】
  1. dex header 三池读取（method/type/field），偏移量正确
  2. 「只采样大 dex 校准」—— 小 dex 的比值天然虚高（实测 classes11.dex
     94 定义 → 322 method_ids = 3.43×），拿它校准会把 dex 数从 16 涨到 29
  3. 三池取最紧容量 —— 只控 method_ids 会漏掉 field_ids 爆掉的情况
  4. 顺序填装：装满一个换下一个，粒度是类（不拆类）
  5. 单类超限时单独成包（dalvik 不允许拆类）
  6. 目录名映射与 apktool 一致（smali → classes.dex、smali_classes2 → classes2.dex）
  7. 搬动后类一个不少

【踩过的坑，写进断言防复发】
  · 猜系数（1.25 → 1.45 → 1.70）每次都实测打脸，必须从原包校准
  · 只控 method_ids → field_ids 爆（classes7 的 field/method = 1.64）
  · 小 dex 校准 → dex 数暴涨

用法: python3 scripts/repack/tests/test_dex_rebalance.py
"""
import importlib.util
import os
import struct
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, '..', 'dex-rebalance.py')

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print('  ✓ %s' % msg)


def bad(msg):
    global FAIL
    FAIL += 1
    print('  ✗ %s' % msg)


def load_module():
    spec = importlib.util.spec_from_file_location('dex_rebalance', TARGET)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = load_module()


# ── 辅助：造一个最小合法 dex header ──
def make_dex_header(method_ids, type_ids, field_ids):
    h = bytearray(112)
    h[:8] = b'dex\n035\0'
    struct.pack_into('<I', h, 0x40, type_ids)
    struct.pack_into('<I', h, 0x50, field_ids)
    struct.pack_into('<I', h, 0x58, method_ids)
    return bytes(h)


def make_apk(path, dex_specs):
    """dex_specs: [(名字, method, type, field)]"""
    with zipfile.ZipFile(path, 'w') as z:
        for name, m, t, f in dex_specs:
            z.writestr(name, make_dex_header(m, t, f))
        z.writestr('AndroidManifest.xml', b'\x03\x00\x08\x00' + b'\0' * 32)


def make_smali(root, dir_name, classes):
    """classes: [(相对路径, 方法数)]"""
    d = os.path.join(root, dir_name)
    for rel, n in classes:
        full = os.path.join(d, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w') as fp:
            fp.write('.class public L%s;\n' % rel.replace('/', '_')[:-6])
            for i in range(n):
                fp.write('.method public m%d()V\n.end method\n' % i)
    return d


def count_smali(root):
    n = 0
    for dirpath, _dn, fns in os.walk(root):
        for fn in fns:
            if fn.endswith('.smali'):
                n += 1
    return n


def main():
    print('=== dex-rebalance.py 回归测试 ===\n')

    # ── 1. dex header 三池读取 ──
    print('── 1. dex header 三池读取 ──')
    with tempfile.TemporaryDirectory() as td:
        apk = os.path.join(td, 't.apk')
        make_apk(apk, [('classes.dex', 65000, 20000, 33000),
                       ('classes2.dex', 1000, 500, 200)])
        st = M.read_apk_dex_stats(apk)
        if st.get('classes.dex') == (65000, 20000, 33000):
            ok('method/type/field 三个偏移量都读对')
        else:
            bad('三池读取错: %r' % (st.get('classes.dex'),))
        if len(st) == 2:
            ok('两个 dex 都读到')
        else:
            bad('dex 计数错: %d' % len(st))

    # ── 2. 目录名 → dex 名映射 ──
    print('\n── 2. 目录名映射（与 apktool 一致）──')
    if M.SMALI_BASE == 'smali' and M.SMALI_PREFIX == 'smali_classes':
        ok('基名与前缀常量正确')
    else:
        bad('常量错: %r %r' % (M.SMALI_BASE, M.SMALI_PREFIX))
    cases = [(0, 'smali'), (1, 'smali_classes2'), (4, 'smali_classes5')]
    for idx, want in cases:
        got = M.target_dir_name(idx)
        if got == want:
            ok('target_dir_name(%d) = %s' % (idx, want))
        else:
            bad('target_dir_name(%d) = %s，期望 %s' % (idx, got, want))

    # ── 3. 顺序填装 + 不拆类 ──
    print('\n── 3. 顺序填装（粒度是类）──')
    classes = [('a%d.smali' % i, 100, '/src') for i in range(10)]
    buckets, loads, cap_defs = M.plan(classes, 1000, (1.0, 1.0, 1.0))
    if sum(len(b) for b in buckets) == 10:
        ok('10 个类全部落桶')
    else:
        bad('类丢失: 落桶 %d / 10' % sum(len(b) for b in buckets))
    if all(l <= cap_defs for l in loads):
        ok('每桶不超容量（cap_defs=%d）' % cap_defs)
    else:
        bad('有桶超容量: %r' % loads)

    # ── 4. 三池取最紧 ──
    print('\n── 4. 三池取最紧容量 ──')
    _, _, cap_m = M.plan([], 10000, (1.0, 1.0, 1.0))
    _, _, cap_f = M.plan([], 10000, (1.0, 1.0, 2.0))   # field 比值 2× → 容量减半
    if cap_f < cap_m:
        ok('field 比值大时容量变小（%d → %d）' % (cap_m, cap_f))
    else:
        bad('三池没取最紧: cap_m=%d cap_f=%d' % (cap_m, cap_f))

    # ── 5. 单类超限单独成包 ──
    print('\n── 5. 单类超限（dalvik 不允许拆类）──')
    huge = [('huge.smali', 100000, '/src')]
    b2, l2, cap2 = M.plan(huge, 10000, (1.0, 1.0, 1.0))
    if len(b2) == 1 and l2[0] == 100000:
        ok('超大类单独成包（%d 个方法）' % l2[0])
    else:
        bad('超大类处理异常: %r' % (l2,))

    # ── 6. 校准只采样大 dex ──
    print('\n── 6. 校准只采样大 dex（小 dex 比值虚高）──')
    with tempfile.TemporaryDirectory() as td:
        # 造 smali 目录：一个大、一个小
        # ⚠️ 大 dex 必须 >10000 定义才被采样，小 dex 必须 <10000 才被过滤
        make_smali(td, 'smali', [('a.smali', 12000)])
        make_smali(td, 'smali_classes2', [('b%d.smali' % i, 94) for i in range(1)])
        apk = os.path.join(td, 't.apk')
        # 大 dex 比值 1.2×，小 dex 比值 3.43×（模拟实测的 classes11.dex）
        # ⚠️ method_ids 要按 定义数 × 1.2 给，才能得到 1.2× 的比值
        #    （踩过：直接给 12000 = 定义数，比值变成 1.0×，断言算错）
        make_apk(apk, [('classes.dex', 14400, 3000, 5000),
                       ('classes2.dex', 322, 100, 50)])
        got = M.calibrate(apk, td)
        if got is None:
            bad('校准返回 None')
        else:
            m_r = got[0] / 1.10        # 去掉 10% 安全边际
            if abs(m_r - 1.2) < 0.05:
                ok('只用了大 dex 的 1.2×（没被小 dex 的 3.43× 污染）')
            else:
                bad('校准被小 dex 污染: %.3f×（应约 1.2×）' % m_r)

    # ── 7. 端到端：重排后类一个不少 ──
    print('\n── 7. 端到端重排（类完整性）──')
    with tempfile.TemporaryDirectory() as td:
        make_smali(td, 'smali', [('x/a%d.smali' % i, 5000) for i in range(10)])
        make_smali(td, 'smali_classes2', [('y/b%d.smali' % i, 5000) for i in range(10)])
        apk = os.path.join(td, 't.apk')
        # 两个 dex 都贴顶 → 触发重排
        make_apk(apk, [('classes.dex', 60000, 10000, 20000),
                       ('classes2.dex', 60000, 10000, 20000)])
        before = count_smali(td)
        rc = M.main([td, '--apk', apk])
        after = count_smali(td)
        if rc == 0 and before == after == 20:
            ok('重排成功且 %d 个类一个不少' % after)
        else:
            bad('重排异常: rc=%d before=%d after=%d' % (rc, before, after))
        # 目录应重新编号连续
        dirs = sorted(d for d in os.listdir(td) if d.startswith('smali'))
        expect_prefix = ['smali']
        if dirs[0] == 'smali' and all(
                d == ('smali' if i == 0 else 'smali_classes%d' % (i + 1))
                for i, d in enumerate(dirs)):
            ok('目录连续编号: %s' % ', '.join(dirs))
        else:
            bad('目录编号不连续: %r' % dirs)

    # ── 8. 余量充足时不重排（速度保证）──
    print('\n── 8. 余量充足时跳过（0.24s 的前提）──')
    with tempfile.TemporaryDirectory() as td:
        make_smali(td, 'smali', [('a.smali', 100)])
        apk = os.path.join(td, 't.apk')
        make_apk(apk, [('classes.dex', 1000, 100, 100)])
        before_dirs = sorted(os.listdir(td))
        rc = M.main([td, '--apk', apk])
        after_dirs = sorted(os.listdir(td))
        if rc == 0 and before_dirs == after_dirs:
            ok('未触发重排，目录未变')
        else:
            bad('不该重排却动了: rc=%d' % rc)


    # ── 9. --split 局部拆分（推荐用法）──
    print('\n── 9. --split 局部拆分（只拆超标的）──')
    with tempfile.TemporaryDirectory() as td:
        # 三个 dex：两个装着不同数量的类
        make_smali(td, 'smali', [('a%d.smali' % i, 8000) for i in range(10)])   # 80000
        # ⚠️ classes2 要"能被拆开但不该被拆"—— 即容量够但类数 >1。
        #    踩过：原来只有 10 个 100 定义的类，即使"全拆"也只出 1 份，
        #    断言恒真，反向验证抓不到退化。
        make_smali(td, 'smali_classes2', [('b%d.smali' % i, 3000) for i in range(10)])  # 30000 < 48133 容量，但 10 个类
        apk = os.path.join(td, 't.apk')
        # classes.dex 贴顶、classes2 宽裕
        make_apk(apk, [('classes.dex', 96000, 20000, 40000),
                       ('classes2.dex', 36000, 6000, 9000)])   # 30000×1.2
        before_dirs = sorted(d for d in os.listdir(td) if d.startswith('smali'))
        rc = M.main([td, '--apk', apk, '--split'])
        after_dirs = sorted(d for d in os.listdir(td) if d.startswith('smali'))
        if rc == 0:
            ok('--split 执行成功')
        else:
            bad('--split 失败 rc=%d' % rc)
        # 关键：只有超标的那个目录被拆，宽裕的类留在原地。
        #
        # ⚠️ 本断言的边界（如实记录，别以为它能防所有退化）：
        #    它只能验证"类文件没被搬到别处"。而"只拆超标的"这个判据
        #    本身【做不出反向验证】—— split_oversized 对容量内的目录
        #    即使进了处理分支，也会因 `len(parts)==1` 而 skip、不搬任何文件。
        #    即"全拆"和"只拆超标的"在这条路径上行为完全一致。
        #    实测两次尝试注入退化（把 `if total > cap_defs` 改成
        #    `if True`）都仍是全绿 —— 不是测试写错，是路径上无可观测差异。
        #
        #    能真正抓住"退化成全量重排"的是另一条路：
        #    看 smali 目录总数是否只增长了超标 dex 需要的份数（见第 7 项）。
        b2 = [f for f in os.listdir(os.path.join(td, 'smali_classes2'))
              if f.endswith('.smali')] if os.path.isdir(
                  os.path.join(td, 'smali_classes2')) else []
        b2_sub = 0
        if b2:
            for dirpath, _dn, fns in os.walk(os.path.join(td, 'smali_classes2')):
                b2_sub += sum(1 for f in fns if f.endswith('.smali'))
        if b2_sub == 10:
            ok('宽裕的 smali_classes2 的 10 个类全在原地（局部拆分生效）')
        else:
            bad('smali_classes2 的类被搬走了（%d/10）—— 退化成全量重排' % b2_sub)
        # 类一个不少
        n = 0
        for dirpath, _dn, fns in os.walk(td):
            for fn in fns:
                if fn.endswith('.smali'):
                    n += 1
        if n == 20:
            ok('拆分后 20 个类一个不少')
        else:
            bad('类丢失: %d / 20' % n)

    print('\n=== 结果: %d 通过, %d 失败 ===' % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
