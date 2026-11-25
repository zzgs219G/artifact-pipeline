#!/usr/bin/env python3
"""partial-reuse.py —— 让加固产物里的条目指回 origin.apk 内部偏移（部分数据复用）

`apktool b` 用 `java.util.zip` 重写整个 ZIP，把 `origin.apk` 从「共享字节」拆成
实体副本 —— 加固+去校验产物因此 119MB。本脚本在 apktool 之后补回共享布局：
产物里与 origin.apk 内部条目 (method, CRC, csize, fsize) 全同的条目，在中央目录
里指向 `origin_data_start + 内部offset`，不再存第二份。

```
┌──────────────────────────────────┐ offset 0
│ origin.apk 的 LFH（对齐到 4096）  │
├──────────────────────────────────┤ origin_data_start (= 4096)
│ origin.apk 原字节                 │ ← 共享条目的数据就在这里面
├──────────────────────────────────┤
│ 独有条目（加固改动过的那几条）      │
├──────────────────────────────────┤
│ 中央目录 + EOCD                   │
└──────────────────────────────────┘
```

    python3 partial-reuse.py <含 origin.apk 的产物.apk> <输出.apk>

⚠️ 产物之后**不得再跑 zipalign / apksigner** —— 二者重写整个 ZIP，会把共享布局
拆平（体积回到 119MB）。签名请用 MT 管理器（它手写 ZIP，保留重叠布局）。

⚠️ 验收**不能用** `zipfile.testzip()`：数据复用本身就是条目重叠，Python 的
zip-bomb 防护会报 `origin.apk` 异常。用本文件的 `verify()`。
"""
import io
import struct
import sys
import zipfile
import zlib

LFH_SIG = b'PK\x03\x04'
EOCD_SIG = b'PK\x05\x06'
ORIGIN_NAME = 'assets/nc_sigfix/origin.apk'

# origin.apk 的 LFH 补齐到 4096，让它的数据起点是 4096 的倍数。
# 这样 origin 内部条目的 offset 整体平移 4096 后，4 字节 / 页对齐关系全部保留
# （4096 是 4 与 4096 的公倍数）—— 否则 resources.arsc 会在装机期被拒：
#   Targeting R+ requires the resources.arsc of installed APKs to be stored
#   uncompressed and aligned on a 4-byte boundary
ALIGN = 4096
_EXTRA_ID = b'\x00\x00'


def _lfh_len(name, extra_len=0):
    return 30 + len(name.encode('utf-8')) + extra_len


def _pad_to(off, base_len, align):
    """生成填充 extra，使 (off + base_len + len(extra)) 是 align 的倍数。"""
    if align <= 1:
        return b''
    need = (-(off + base_len)) % align
    if need == 0:
        return b''
    if need < 4:
        need += align
    body = need - 4
    return _EXTRA_ID + struct.pack('<H', body) + b'\x00' * body


def _align_extra(base_len, align=ALIGN):
    """offset 0 处的对齐填充（origin.apk 的 LFH 就在 offset 0）。"""
    return _pad_to(0, base_len, align)


def _dos_time(dt):
    """zipfile 的 date_time 元组 → (mtime, mdate)。"""
    y, mo, d, h, mi, s = dt
    if y < 1980:
        return 0, 0x0021
    return ((h << 11) | (mi << 5) | (s // 2),
            (((y - 1980) << 9) | (mo << 5) | d))


def _make_lfh(name, method, crc, csize, fsize, flags=0, mtime=0, mdate=0x0021,
              extra=b''):
    nb = name.encode('utf-8')
    return (LFH_SIG
            + struct.pack('<H', 20 if method == 8 else 10)
            + struct.pack('<H', flags)
            + struct.pack('<H', method)
            + struct.pack('<HH', mtime, mdate)
            + struct.pack('<I', crc)
            + struct.pack('<I', csize)
            + struct.pack('<I', fsize)
            + struct.pack('<H', len(nb))
            + struct.pack('<H', len(extra))
            + nb
            + extra)


def _make_cd(name, method, crc, csize, fsize, offset, flags=0, mtime=0,
             mdate=0x0021, extra=b''):
    nb = name.encode('utf-8')
    return (b'PK\x01\x02'
            + struct.pack('<H', 20)
            + struct.pack('<H', 20 if method == 8 else 10)
            + struct.pack('<H', flags)
            + struct.pack('<H', method)
            + struct.pack('<HH', mtime, mdate)
            + struct.pack('<I', crc)
            + struct.pack('<I', csize)
            + struct.pack('<I', fsize)
            + struct.pack('<H', len(nb))
            + struct.pack('<H', len(extra))
            + struct.pack('<H', 0)
            + struct.pack('<H', 0)
            + struct.pack('<H', 0)
            + struct.pack('<I', 0)
            + struct.pack('<I', offset)
            + nb
            + extra)


def _data_start(buf, lfh_off):
    """条目的数据起始 = LFH + 30 + name_len + extra_len。

    ⚠️ 对齐判据必须用这个值，不能用 LFH offset（实测 resources.arsc 的
    LFH offset 非 4 倍数但数据起始是对齐的）。
    """
    nl, el = struct.unpack_from('<HH', buf, lfh_off + 26)
    return lfh_off + 30 + nl + el


def _align_need(name, method):
    """该条目在新包里的数据起始至少要满足的对齐（1 = 无要求）。"""
    if method != 0:
        return 1                    # DEFLATE 无对齐要求
    if name == 'resources.arsc':
        return 4                    # Android R+ 硬性要求
    if name.endswith('.so'):
        return ALIGN                # extractNativeLibs=false 时按页映射
    return 4


def _lfh_meta(buf, off):
    """读原包某条目的 LFH 元数据 → (flags, mtime, mdate, extra)。"""
    flags = struct.unpack_from('<H', buf, off + 6)[0] & 0x0800
    mt, md = struct.unpack_from('<HH', buf, off + 10)
    nl, el = struct.unpack_from('<HH', buf, off + 26)
    return flags, mt, md, buf[off + 30 + nl:off + 30 + nl + el]


def build_partial(src_apk, out_apk, origin_name=ORIGIN_NAME):
    """把 src_apk 里 origin.apk 的内容作为共享基础，产出体积更小的 out_apk。

    Returns:
        dict: src_size / out_size / shared / unshared / origin_data / entries
    Raises:
        SystemExit: 输入不满足前提（无 origin.apk / 非 STORED / 条目数或体积超 ZIP32）
    """
    with open(src_apk, 'rb') as f:
        raw = f.read()

    with zipfile.ZipFile(src_apk) as z:
        infos = z.infolist()

    oi = next((i for i in infos if i.filename == origin_name), None)
    if oi is None:
        raise SystemExit('❌ 输入包里没有 %s（没做去校验，无需复用）' % origin_name)
    if oi.compress_type != 0:
        raise SystemExit('❌ %s 不是 STORED（method=%d），无法作为共享基础'
                         % (origin_name, oi.compress_type))

    origin_data = raw[_data_start(raw, oi.header_offset):
                      _data_start(raw, oi.header_offset) + oi.compress_size]

    # origin 内部条目表：name -> (method, crc, csize, fsize, lfh_off, data_off,
    #                            flags, mtime, mdate, extra)
    # ⚠️ CD 里的 offset 必须指向 **LFH**（origin_data 内部的那份），不是数据起始 ——
    # 解析器在该 offset 处期待 PK\x03\x04。data_off 只用来判对齐。
    # ⚠️ 共享条目的 flags/时间戳/extra 必须沿用 origin 那份，否则 CD 与 LFH 不一致。
    omap = {}
    with zipfile.ZipFile(io.BytesIO(origin_data)) as zo:
        for i in zo.infolist():
            omap[i.filename] = (i.compress_type, i.CRC, i.compress_size,
                                i.file_size, i.header_offset,
                                _data_start(origin_data, i.header_offset),
                                *_lfh_meta(origin_data, i.header_offset))

    o_extra = _align_extra(_lfh_len(origin_name))
    hdr_len = _lfh_len(origin_name, len(o_extra))
    assert hdr_len == ALIGN, hdr_len

    out = bytearray()
    out += _make_lfh(origin_name, 0, oi.CRC, oi.compress_size, oi.file_size,
                     flags=oi.flag_bits & 0x0800, mtime=_dos_time(oi.date_time)[0],
                     mdate=_dos_time(oi.date_time)[1], extra=o_extra)
    out += origin_data

    shared = []      # (name, method, crc, csize, fsize, cd_offset, extra, flags, mt, md)
    unshared = []    # 同上
    for i in infos:
        if i.filename == origin_name:
            continue
        flags = i.flag_bits & 0x0800        # bit 11（UTF-8）要保留；bit 3（data
                                            # descriptor）不能保留 —— 我们没写 dd
        mt, md = _dos_time(i.date_time)
        t = omap.get(i.filename)
        if t and t[0] == i.compress_type and t[1] == i.CRC \
                and t[2] == i.compress_size and t[3] == i.file_size:
            # 平移量 hdr_len 是 4096 的倍数，origin 内的对齐在全局同样成立；
            # 唯一要防的是 origin 内部本身就没对齐（那说明原包有问题，不共享）
            need = _align_need(i.filename, i.compress_type)
            if (hdr_len + t[5]) % need == 0:
                shared.append((i.filename, t[0], t[1], t[2], t[3],
                               hdr_len + t[4], t[9], t[6], t[7], t[8]))
                continue

        src_ds = _data_start(raw, i.header_offset)
        blob = raw[src_ds:src_ds + i.compress_size]
        need = _align_need(i.filename, i.compress_type)
        off = len(out)
        base = 30 + len(i.filename.encode('utf-8'))
        extra = _pad_to(off, base, need)
        out += _make_lfh(i.filename, i.compress_type, i.CRC, i.compress_size,
                         i.file_size, flags=flags, mtime=mt, mdate=md,
                         extra=extra)
        assert (off + base + len(extra)) % need == 0
        out += blob
        unshared.append((i.filename, i.compress_type, i.CRC, i.compress_size,
                         i.file_size, off, extra, flags, mt, md))

    cd_start = len(out)
    cd = bytearray()
    cd += _make_cd(origin_name, 0, oi.CRC, oi.compress_size, oi.file_size, 0,
                   flags=oi.flag_bits & 0x0800,
                   mtime=_dos_time(oi.date_time)[0],
                   mdate=_dos_time(oi.date_time)[1], extra=o_extra)
    for (name, method, crc, csize, fsize, off, extra,
         flags, mt, md) in shared + unshared:
        # CD 的 extra 必须与 LFH 那处**字节一致**（长度和内容都算）：
        # zip-reuse.py 实测过，只写 LFH 时解析器读 CD 得到 extra_len=0，
        # 平移量算错 → 没修复对齐。
        cd += _make_cd(name, method, crc, csize, fsize, off, flags=flags,
                       mtime=mt, mdate=md, extra=extra)
    out += cd

    total = 1 + len(shared) + len(unshared)
    if total > 0xFFFF or cd_start > 0xFFFFFFFF or len(out) > 0xFFFFFFFF:
        raise SystemExit('❌ 超出 ZIP32 上限（需要 ZIP64，本脚本不支持）')

    out += EOCD_SIG
    out += struct.pack('<H', 0)
    out += struct.pack('<H', 0)
    out += struct.pack('<H', total)
    out += struct.pack('<H', total)
    out += struct.pack('<I', len(cd))
    out += struct.pack('<I', cd_start)
    out += struct.pack('<H', 0)

    with open(out_apk, 'wb') as f:
        f.write(out)

    return {
        'src_size': len(raw),
        'out_size': len(out),
        'shared': len(shared),
        'unshared': len(unshared),
        'entries': total,
        'origin_data': (hdr_len, hdr_len + len(origin_data)),
    }


def verify(out_apk, origin_name=ORIGIN_NAME):
    """结构自检。返回问题列表（空 = 通过）。"""
    problems = []
    with open(out_apk, 'rb') as f:
        data = f.read()

    eocd_off = data.rfind(EOCD_SIG)
    if eocd_off < 0:
        return ['找不到 EOCD']
    total = struct.unpack('<H', data[eocd_off + 10:eocd_off + 12])[0]
    cd_size, cd_off = struct.unpack('<II', data[eocd_off + 12:eocd_off + 20])

    entries = {}
    p = cd_off
    for _ in range(total):
        if data[p:p + 4] != b'PK\x01\x02':
            problems.append('中央目录条目非法 @ %d' % p)
            break
        method = struct.unpack('<H', data[p + 10:p + 12])[0]
        crc = struct.unpack('<I', data[p + 16:p + 20])[0]
        csize = struct.unpack('<I', data[p + 20:p + 24])[0]
        fsize = struct.unpack('<I', data[p + 24:p + 28])[0]
        namelen = struct.unpack('<H', data[p + 28:p + 30])[0]
        elen = struct.unpack('<H', data[p + 30:p + 32])[0]
        clen = struct.unpack('<H', data[p + 32:p + 34])[0]
        off = struct.unpack('<I', data[p + 42:p + 46])[0]
        name = data[p + 46:p + 46 + namelen].decode('utf-8', 'replace')
        entries[name] = (method, crc, csize, fsize, off)
        p += 46 + namelen + elen + clen

    if len(entries) != total:
        problems.append('解析到 %d 条，EOCD 声明 %d 条' % (len(entries), total))
    if cd_off + cd_size > len(data):
        problems.append('中央目录越界')

    def read_entry(name):
        method, crc, csize, fsize, off = entries[name]
        if data[off:off + 4] != LFH_SIG:
            raise ValueError('%s 的 local header 非法 @ %d' % (name, off))
        blob = data[_data_start(data, off):_data_start(data, off) + csize]
        if method == 0:
            return blob
        return zlib.decompress(blob, -15)

    if origin_name not in entries:
        return problems + ['找不到 %s' % origin_name]

    try:
        origin = read_entry(origin_name)
        m, crc, csize, fsize, off = entries[origin_name]
        if zlib.crc32(origin) & 0xFFFFFFFF != crc:
            problems.append('%s 的数据 CRC 不符（内容被破坏）' % origin_name)
        if len(origin) != fsize:
            problems.append('%s 长度不符（%d != %d）' % (origin_name, len(origin), fsize))
        with zipfile.ZipFile(io.BytesIO(origin)) as oz:
            if not oz.namelist():
                problems.append('origin.apk 里没有任何条目')
    except Exception as e:
        problems.append('origin.apk 读取失败: %s' % e)

    # 除 origin.apk 外，全部条目逐条 CRC 校验（共享条目的数据落在 origin 数据区里，
    # Python 的 zip-bomb 防护会在 read() 时报错 —— 所以只查能读的，其余靠 CRC 抽验）
    bad = 0
    for name in entries:
        if name == origin_name:
            continue
        try:
            blob = read_entry(name)
        except Exception as e:
            problems.append('%s 读取失败: %s' % (name, e))
            bad += 1
            if bad > 5:
                break
            continue
        method, crc, csize, fsize, off = entries[name]
        if zlib.crc32(blob) & 0xFFFFFFFF != crc:
            problems.append('%s CRC 不符' % name)
            bad += 1
            if bad > 5:
                break

    for name, (method, crc, csize, fsize, off) in entries.items():
        ds = _data_start(data, off)
        need = _align_need(name, method)
        if need > 1 and ds % need != 0:
            problems.append('%s 未按 %d 字节对齐（data_start=%d, mod=%d）'
                            % (name, need, ds, ds % need))

    return problems


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    src, dst = argv[1], argv[2]
    st = build_partial(src, dst)
    print('输入      : %d B (%.1f MB)'
          % (st['src_size'], st['src_size'] / 1048576))
    print('输出      : %d B  (%.1f MB)'
          % (st['out_size'], st['out_size'] / 1048576))
    print('共享条目  : %d 条' % st['shared'])
    print('独有条目  : %d 条' % st['unshared'])
    print('origin 数据: %d ~ %d' % st['origin_data'])
    print('节省      : %d B (%.0f%%)'
          % (st['src_size'] - st['out_size'],
             100.0 * (st['src_size'] - st['out_size']) / st['src_size']))

    print('\n=== 自检 ===')
    probs = verify(dst)
    if probs:
        for x in probs:
            print('❌', x)
        return 1
    print('✅ 结构合法 / 全部条目 CRC 一致 / 对齐达标')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
