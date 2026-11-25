#!/usr/bin/env python3
"""test-partial-reuse.py —— 部分数据复用（partial-reuse.py）回归

==== 为什么有它 ====
`apktool b` 用 java.util.zip 重写 ZIP，把 origin.apk 从「共享字节」拆成实体副本
→ 加固+去校验产物 119MB。partial-reuse.py 在 apktool 之后手写 ZIP 补回共享布局。
手写 ZIP = 错 1 字节就装不上，而装机失败没有任何诊断信息 → 全靠这里兜住。

==== 覆盖（每条都做反向验证，AGENTS §2.2）====
T1  origin.apk 的数据与输入逐字节一致
T2  「共享」条目（offset 落在 origin 数据区内）确实指向 origin 内部那个 LFH，
    且元数据与该内部条目一致（判断共享不能靠元数据 —— 未共享的条目元数据也相同）
T3  全部条目的元数据与输入一致，且读出的内容 CRC 正确
T4  产物体积真的变小
T5  resources.arsc 与 STORED .so 的**数据起始**满足对齐
T6  共享条目数 == 精确预期（金值，不是阈值）
T7  前置条件不满足时拒绝执行（无 origin.apk / origin 非 STORED）
T8  已知行为钉住：zipfile.testzip() 在复用包上会报 origin.apk —— 这不是 bug，
    是 Python 的 zip-bomb 防护；防止有人把验收改成 testzip()

用法：python3 scripts/repack/tests/test-partial-reuse.py
夹具临时现造，不依赖任何外部 APK。
"""
import importlib.util
import os
import random
import struct
import sys
import tempfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
TOOL = os.path.join(ROOT, "scripts", "repack", "partial-reuse.py")
ORIGIN = "assets/nc_sigfix/origin.apk"

PASS = FAIL = 0
SHARED = ["assets/big.bin", "res/raw/foo.png"]


def ok(m):
    global PASS
    PASS += 1
    print("  ✅ %s" % m)


def bad(m):
    global FAIL
    FAIL += 1
    print("  ❌ %s" % m, file=sys.stderr)


def load_tool():
    spec = importlib.util.spec_from_file_location("pr", TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ── 夹具 ────────────────────────────────────────────────────────────
# src 模拟「加固产物」：含 origin.apk（去校验包）的实体副本，
# 一部分条目与 origin 内容完全相同（apktool 原样搬的），另一部分被加固改过。
def make_fixture(work, tag="", mutate_shared=False, pad_len=0):
    rnd = random.Random(20261125)
    big = bytes(rnd.getrandbits(8) for _ in range(300000))
    shared_blobs = {"assets/big.bin": big, "res/raw/foo.png": b"P" * 5000}

    origin = os.path.join(work, "origin%s.apk" % tag)
    with zipfile.ZipFile(origin, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"M" * 300)
        z.writestr("classes.dex", b"dex\n035\0" + b"D" * 4000)
        for n, b in shared_blobs.items():
            z.writestr(n, b)
        z.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"R" * 600,
                   zipfile.ZIP_STORED)

    src = os.path.join(work, "product%s.apk" % tag)
    with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"M" * 310)
        z.writestr("classes.dex", b"dex\n035\0" + b"D" * 4200)
        z.writestr("classes2.dex", b"dex\n035\0" + b"N" * 900)
        for n, b in shared_blobs.items():
            z.writestr(n, b + (b"\x00" if mutate_shared else b""))
        if pad_len:
            # 长度可控的 STORED 条目：用来把 resources.arsc 顶到任意 mod 4 位置
            zi = zipfile.ZipInfo("res/raw/pad.bin")
            zi.compress_type = zipfile.ZIP_STORED
            z.writestr(zi, b"Z" * pad_len)
        z.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"R" * 650,
                   zipfile.ZIP_STORED)
        # STORED 的 .so：页对齐分支也要能被 T5 覆盖
        zi = zipfile.ZipInfo("lib/arm64-v8a/libfake.so")
        zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, b"S" * 7000)
        zi = zipfile.ZipInfo(ORIGIN)             # 真实流水线里是 STORED
        zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, open(origin, "rb").read())
    return src, origin


# ── 解析（不用 zipfile 读数据：重叠条目会触发它的 zip-bomb 防护）──────
def parse(path):
    raw = open(path, "rb").read()
    e = raw.rfind(b"PK\x05\x06")
    total = struct.unpack_from("<H", raw, e + 10)[0]
    cdoff = struct.unpack_from("<I", raw, e + 16)[0]
    d = {}
    p = cdoff
    for _ in range(total):
        if raw[p:p + 4] != b"PK\x01\x02":
            raise ValueError("中央目录非法 @ %d" % p)
        m = struct.unpack_from("<H", raw, p + 10)[0]
        crc = struct.unpack_from("<I", raw, p + 16)[0]
        cs = struct.unpack_from("<I", raw, p + 20)[0]
        fs = struct.unpack_from("<I", raw, p + 24)[0]
        nl = struct.unpack_from("<H", raw, p + 28)[0]
        el = struct.unpack_from("<H", raw, p + 30)[0]
        cl = struct.unpack_from("<H", raw, p + 32)[0]
        off = struct.unpack_from("<I", raw, p + 42)[0]
        name = raw[p + 46:p + 46 + nl].decode()
        d[name] = (m, crc, cs, fs, off)
        p += 46 + nl + el + cl
    return raw, d


def data_start(raw, off):
    nl, el = struct.unpack_from("<HH", raw, off + 26)
    return off + 30 + nl + el


def entry_bytes(raw, rec):
    m, crc, cs, fs, off = rec
    ds = data_start(raw, off)
    blob = raw[ds:ds + cs]
    return blob if m == 0 else zlib.decompress(blob, -15)


def origin_region(raw, entries):
    """origin.apk 的数据区 [lo, hi)。"""
    rec = entries[ORIGIN]
    lo = data_start(raw, rec[4])
    return lo, lo + rec[2]


def shared_names(raw, entries):
    """offset 落在 origin 数据区内的条目 = 真正共享了的。"""
    lo, hi = origin_region(raw, entries)
    return [n for n, r in entries.items()
            if n != ORIGIN and lo <= r[4] < hi]


# ── 断言 ────────────────────────────────────────────────────────────
def t1_origin_bytes(out, src):
    ra, A = parse(src)
    rb, B = parse(out)
    if ORIGIN not in B or ORIGIN not in A:
        return ["产物或输入里没有 %s" % ORIGIN]
    if entry_bytes(rb, B[ORIGIN]) != entry_bytes(ra, A[ORIGIN]):
        return ["origin.apk 数据与输入不一致"]
    return []


def t2_shared_points_into_origin(out, src):
    rb, B = parse(out)
    if ORIGIN not in B:
        return ["产物里没有 origin.apk"]
    lo, hi = origin_region(rb, B)
    hdr = lo                      # origin 的 LFH 在 offset 0，数据起点 = hdr_len
    with zipfile.ZipFile(io_bytes(entry_bytes(rb, B[ORIGIN]))) as zo:
        inner = {i.filename: (i.compress_type, i.CRC, i.compress_size,
                              i.file_size, i.header_offset)
                 for i in zo.infolist()}
    probs = []
    names = shared_names(rb, B)
    if not names:
        probs.append("没有任何条目落在 origin 数据区（共享完全失效）")
    for n in names:
        m, crc, cs, fs, off = B[n]
        if rb[off:off + 4] != b"PK\x03\x04":
            probs.append("%s 的 offset 处不是 local header" % n)
            continue
        # 指向的必须是 origin 内部对应条目的 LFH（平移 hdr 字节）
        t = inner.get(n)
        if not t:
            probs.append("%s 在 origin 内部不存在，却被指向区内" % n)
            continue
        if off != hdr + t[4]:
            probs.append("%s 的 offset %d != hdr(%d)+origin内offset(%d)"
                         % (n, off, hdr, t[4]))
        if (m, crc, cs, fs) != t[:4]:
            probs.append("%s 的元数据与 origin 内部条目不一致" % n)
    return probs


def t3_meta_and_crc(out, src):
    ra, A = parse(src)
    rb, B = parse(out)
    probs = []
    if set(A) != set(B):
        return ["条目集合不同: %s" % (set(A) ^ set(B))]
    for name, rec in B.items():
        if rec[:4] != A[name][:4]:
            probs.append("%s 元数据与输入不符" % name)
            continue
        try:
            blob = entry_bytes(rb, rec)
        except Exception as ex:
            probs.append("%s 读取失败: %s" % (name, ex))
            continue
        if len(blob) != rec[3]:
            probs.append("%s 长度不符" % name)
        elif zlib.crc32(blob) & 0xFFFFFFFF != rec[1]:
            probs.append("%s CRC 不符" % name)
    return probs


def t4_smaller(out, src):
    a, b = os.path.getsize(src), os.path.getsize(out)
    if b >= a:
        return ["产物没变小（%d -> %d）" % (a, b)]
    return []


def t5_alignment(out, src):
    rb, B = parse(out)
    probs = []
    for name, (m, crc, cs, fs, off) in B.items():
        ds = data_start(rb, off)
        if name == "resources.arsc":
            if m != 0:
                probs.append("resources.arsc 不是 STORED")
            if ds % 4:
                probs.append("resources.arsc 未 4 字节对齐（ds=%d, mod=%d）"
                             % (ds, ds % 4))
        elif m == 0 and name.endswith(".so") and ds % 4096:
            probs.append("%s 未页对齐（ds=%d）" % (name, ds))
    return probs


def t6_shared_count(out, src):
    rb, B = parse(out)
    n = len(shared_names(rb, B))
    if n != len(SHARED):
        return ["共享 %d 条，预期 %d 条" % (n, len(SHARED))]
    return []


def t7_preconditions(work, pr):
    probs = []
    p = os.path.join(work, "no-origin.apk")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", b"a")
    try:
        pr.build_partial(p, os.path.join(work, "x1.apk"))
        probs.append("无 origin.apk 时没有拒绝")
    except SystemExit:
        pass
    p2 = os.path.join(work, "deflated.apk")
    with zipfile.ZipFile(p2, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(ORIGIN, b"x" * 5000)
    try:
        pr.build_partial(p2, os.path.join(work, "x2.apk"))
        probs.append("origin.apk 为 DEFLATE 时没有拒绝")
    except SystemExit:
        pass
    return probs


def t8_testzip_known(out, src):
    """zipfile.testzip() 报 origin.apk 是**预期**行为，不是缺陷。"""
    try:
        with zipfile.ZipFile(out) as z:
            r = z.testzip()
    except Exception as ex:
        msg = str(ex).lower()
        return [] if "overlap" in msg else ["testzip 抛意外异常: %s" % ex]
    if r == ORIGIN:
        return []
    if r is None:
        return ["testzip() 全通过 —— 说明没有重叠，复用失效"]
    return ["testzip() 报的是 %r，预期 %s" % (r, ORIGIN)]


def io_bytes(b):
    import io
    return io.BytesIO(b)


CHECKS = [
    ("T1 origin.apk 数据逐字节一致", t1_origin_bytes),
    ("T2 共享条目指向 origin 内部 LFH", t2_shared_points_into_origin),
    ("T3 元数据 + CRC 全一致", t3_meta_and_crc),
    ("T4 产物体积变小", t4_smaller),
    ("T5 arsc / so 对齐达标", t5_alignment),
    ("T6 共享条目数符合预期", t6_shared_count),
    ("T8 testzip 已知行为", t8_testzip_known),
]


def main():
    print("=== partial-reuse 回归 ===")
    if not os.path.isfile(TOOL):
        bad("找不到 %s" % TOOL)
        return 1
    pr = load_tool()
    work = tempfile.mkdtemp(prefix="preuse-")

    src, _ = make_fixture(work)
    out = os.path.join(work, "out.apk")
    pr.build_partial(src, out)

    print("\n-- 正向 --")
    for label, fn in CHECKS:
        probs = fn(out, src)
        bad("%s: %s" % (label, probs[0])) if probs else ok(label)

    probs = t7_preconditions(work, pr)
    bad("T7 前置条件: %s" % probs[0]) if probs else \
        ok("T7 前置条件不满足时拒绝执行")

    probs = pr.verify(out)
    bad("self-verify: %s" % probs[0]) if probs else ok("self-verify() 全绿")

    # ── 反向验证：每条断言都必须能变红 ──────────────────────────────
    print("\n-- 反向验证 --")

    # ① 改坏 origin 数据区里一个字节 → T1/T3/self-verify 必红
    rb, B = parse(out)
    raw = bytearray(open(out, "rb").read())
    raw[data_start(bytes(raw), B[ORIGIN][4]) + 100] ^= 0xFF
    broken = os.path.join(work, "broken.apk")
    open(broken, "wb").write(raw)
    for label, fn in (("T1", t1_origin_bytes), ("T3", t3_meta_and_crc)):
        bad("%s 反向仍然绿（假断言）" % label) if not fn(broken, src) else \
            ok("%s 反向变红" % label)
    bad("self-verify 反向仍然绿") if not pr.verify(broken) else \
        ok("self-verify 反向变红")

    # ② 把某共享条目的 CD offset +1 → T2 必红（指向区内但不是 LFH）
    raw2 = bytearray(open(out, "rb").read())
    e = raw2.rfind(b"PK\x05\x06")
    cd = struct.unpack_from("<I", raw2, e + 16)[0]
    p = cd
    total = struct.unpack_from("<H", raw2, e + 10)[0]
    targets = set(shared_names(rb, B))
    for _ in range(total):
        nl = struct.unpack_from("<H", raw2, p + 28)[0]
        el = struct.unpack_from("<H", raw2, p + 30)[0]
        cl = struct.unpack_from("<H", raw2, p + 32)[0]
        name = bytes(raw2[p + 46:p + 46 + nl]).decode()
        if name in targets:
            struct.pack_into("<I", raw2, p + 42,
                             struct.unpack_from("<I", raw2, p + 42)[0] + 1)
            break
        p += 46 + nl + el + cl
    shifted = os.path.join(work, "shifted.apk")
    open(shifted, "wb").write(raw2)
    bad("T2 反向仍然绿（假断言）") if not t2_shared_points_into_origin(shifted, src) \
        else ok("T2 反向变红（共享 offset 偏 1 字节）")

    # ③ 让对齐约束失效（monkeypatch 生产函数）→ T5 必红。
    #    ⚠️ 单向不够：夹具尺寸碰巧让 arsc 天然对齐时，关掉约束也测不出来。
    #    所以扫 pad_len 0..3，要求「至少一种尺寸下关掉约束 → T5 变红」，
    #    且「所有尺寸下开着约束 → T5 恒绿」。
    orig_need = pr._align_need
    red_seen = False
    green_all = True
    for pad in range(4):
        s, _ = make_fixture(work, tag="-pad%d" % pad, pad_len=pad)
        good = os.path.join(work, "pad%d-good.apk" % pad)
        pr.build_partial(s, good)
        if t5_alignment(good, s):
            green_all = False
            bad("T5 正向在 pad=%d 时误报: %s" % (pad, t5_alignment(good, s)[0]))
        pr._align_need = lambda name, method: 1
        evil = os.path.join(work, "pad%d-evil.apk" % pad)
        pr.build_partial(s, evil)
        pr._align_need = orig_need
        if t5_alignment(evil, s):
            red_seen = True
    if green_all:
        ok("T5 正向 4 种尺寸全部达标")
    bad("T5 反向仍然绿（关掉对齐约束后 4 种尺寸都看不出问题）") \
        if not red_seen else ok("T5 反向变红（关掉对齐约束）")

    # ④ 夹具里所有条目都被改过 → 无条目可共享 → T4/T6/T8 必红
    src2, _ = make_fixture(work, tag="-allnew", mutate_shared=True)
    out2 = os.path.join(work, "out2.apk")
    try:
        pr.build_partial(src2, out2)
        bad("T6 反向仍然绿（假断言）") if not t6_shared_count(out2, src2) else \
            ok("T6 反向变红（无条目可共享）")
        bad("T8 反向仍然绿（假断言）") if not t8_testzip_known(out2, src2) else \
            ok("T8 反向变红（无重叠时 testzip 全通过）")
    except SystemExit:
        ok("T6/T8 反向：无条目可共享时工具直接拒绝")

    bad("T4 反向仍然绿（假断言）") if not t4_smaller(src, src) else \
        ok("T4 反向变红（输入=输出）")

    print("\n=== 结果: %d 通过, %d 失败 ===" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
