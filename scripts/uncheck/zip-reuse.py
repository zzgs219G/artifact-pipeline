#!/usr/bin/env python3
"""zip-reuse.py —— 让 origin.apk 与包内其它条目共享物理字节（数据复用）

## 问题

去签名校验要往产物里塞一份 `origin.apk`（原签名 APK 副本），体积直接翻倍。

## FancyBypass 的做法（实测反推自其产物）

```
offset 0     : local header("fancy/origin.apk", 声明 size=197904980)
offset 4096  : ← origin.apk 的"数据"从这里开始
               同时这里也是 APK 第一个普通条目 "AndroidManifest.xml" 的 local header
```

即 **`origin.apk` 的数据区 = 整个 APK 从 4096 到末尾的字节**。
物理上只有一份数据，被两个 ZIP "视图"共享 —— 所以 199MB 的包装得下 197MB 的 origin.apk。

## 本实现的方案（比 fancy 更干净）

fancy 让 origin.apk 缺了前 4096 字节（签名块之前的头），靠"App 只读证书、
证书在文件末尾"这个侥幸前提成立。我们的版本给 origin.apk **完整**的原 APK 字节：

```
输出 APK 布局：
┌────────────────────────────────────────┐
│ origin.apk 的 local header (30+N 字节)  │ offset 0
├────────────────────────────────────────┤
│ 原 APK 的完整字节（逐字节副本）          │ offset = HDR_LEN
│   ↑ 这一段同时就是 origin.apk 的"数据"   │   ← 数据复用点
├────────────────────────────────────────┤
│ 额外条目：payload.dex / *.so / *.json   │
├────────────────────────────────────────┤
│ 中央目录（origin + 原APK所有条目 + 额外）│
├────────────────────────────────────────┤
│ EOCD                                    │
└────────────────────────────────────────┘
```

- 读 `assets/nc_sigfix/origin.apk` → 得到**完整可用的原 APK**
- 读原 APK 的条目（classes*.dex 等）→ 按 `HDR_LEN + 原offset` 读，正常
- 读额外条目 → 按实际 offset 读，正常

代价：原 APK 里那份**旧的**中央目录 + EOCD 会出现在文件中间（作为 origin.apk
内容的一部分）。ZIP 解析器从文件末尾找 EOCD，所以读到的是我们的新 EOCD；
中间那份旧的不会被误用。**已实测 Android 的 ZIP/APK 解析不受影响。**

## 为什么这不违反 ZIP 规范

ZIP 只规定「每个条目由 [local header + 数据] 描述，offset 记录在中央目录」，
**没有任何"条目之间不得重叠"的约束**。两个条目指向重叠区域完全合法。

## 用法

```bash
python3 zip-reuse.py <已含业务补丁的apk（不含origin）> <输出apk>
```
"""
import struct
import sys
import zipfile
import zlib

LFH_SIG = b'PK\x03\x04'
EOCD_SIG = b'PK\x05\x06'
ORIGIN_NAME = 'assets/nc_sigfix/origin.apk'


def _lfh_len(name):
    """local header 长度（固定 30 + 文件名，不含 extra）"""
    return 30 + len(name.encode('utf-8'))


def _make_lfh(name, method, crc, csize, fsize, mtime=0, mdate=0x0021):
    """构造 local file header。mdate 默认 1980-01-01（ZIP 最小合法值）。"""
    nb = name.encode('utf-8')
    return (LFH_SIG
            + struct.pack('<H', 20 if method == 8 else 10)   # version needed
            + struct.pack('<H', 0)                            # flags
            + struct.pack('<H', method)                       # 0=STORED 8=DEFLATE
            + struct.pack('<HH', mtime, mdate)
            + struct.pack('<I', crc)
            + struct.pack('<I', csize)
            + struct.pack('<I', fsize)
            + struct.pack('<H', len(nb))
            + struct.pack('<H', 0)                            # extra len
            + nb)


def _make_cd(name, method, crc, csize, fsize, offset, mtime=0, mdate=0x0021):
    """构造中央目录条目。"""
    nb = name.encode('utf-8')
    return (b'PK\x01\x02'
            + struct.pack('<H', 20)          # version made by
            + struct.pack('<H', 20 if method == 8 else 10)   # version needed
            + struct.pack('<H', 0)           # flags
            + struct.pack('<H', method)
            + struct.pack('<HH', mtime, mdate)
            + struct.pack('<I', crc)
            + struct.pack('<I', csize)
            + struct.pack('<I', fsize)
            + struct.pack('<H', len(nb))
            + struct.pack('<H', 0)           # extra len
            + struct.pack('<H', 0)           # comment len
            + struct.pack('<H', 0)           # disk start
            + struct.pack('<H', 0)           # internal attr
            + struct.pack('<I', 0)           # external attr
            + struct.pack('<I', offset)
            + nb)


def build(src_apk, out_apk, extra_entries=None,
          origin_name=ORIGIN_NAME):
    """把 src_apk 的全字节作为 origin.apk 的数据写进 out_apk，实现数据复用。

    Args:
        src_apk: 输入 APK —— 已含业务补丁/payload/so 等，**不含** origin.apk
        out_apk: 输出 APK
        extra_entries: {name: bytes} 额外的条目（若 src_apk 里已有则不必传）
        origin_name: origin.apk 的条目名
    """
    extra_entries = extra_entries or {}

    with open(src_apk, 'rb') as f:
        src = f.read()

    # ── 1. 收集原 APK 的条目信息（只读中央目录，不复制数据） ──────────
    with zipfile.ZipFile(src_apk) as z:
        infos = z.infolist()
        if any(i.filename == origin_name for i in infos):
            raise SystemExit(f'❌ 输入包里已经有 {origin_name} 了')

    # ── 2. origin.apk 的 header（放在文件最前） ──────────────────────
    # 数据 = 原 APK 全字节，所以 size = len(src)
    origin_crc = zlib.crc32(src) & 0xFFFFFFFF
    origin_csize = len(src)      # STORED，压缩前后相同
    origin_fsize = len(src)
    hdr_len = _lfh_len(origin_name)
    origin_data_start = hdr_len

    # ── 3. 拼装 ─────────────────────────────────────────────────────
    out = bytearray()
    out += _make_lfh(origin_name, 0, origin_crc, origin_csize, origin_fsize)
    assert len(out) == origin_data_start

    out += src          # ← 数据复用：origin.apk 的数据就是这一段
    origin_data_end = len(out)

    # 3a. 额外条目（放在 origin 数据之后，避免污染 origin.apk 的内容）
    extra_meta = []     # (name, method, crc, csize, fsize, offset)
    for name in sorted(extra_entries):
        blob = extra_entries[name]
        crc = zlib.crc32(blob) & 0xFFFFFFFF
        if name.endswith(('.so', '.apk', '.arsc')):
            method, payload, csize = 0, blob, len(blob)
        else:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            payload = co.compress(blob) + co.flush()
            method, csize = 8, len(payload)
        off = len(out)
        out += _make_lfh(name, method, crc, csize, len(blob))
        out += payload
        extra_meta.append((name, method, crc, csize, len(blob), off))

    # ── 4. 中央目录 ─────────────────────────────────────────────────
    cd_start = len(out)
    cd = bytearray()

    # origin.apk 本身
    cd += _make_cd(origin_name, 0, origin_crc, origin_csize, origin_fsize, 0)

    # 原 APK 的所有条目：offset 整体平移 origin_data_start
    for i in infos:
        cd += _make_cd(i.filename, i.compress_type, i.CRC,
                       i.compress_size, i.file_size,
                       i.header_offset + origin_data_start)

    # 额外条目
    for name, method, crc, csize, fsize, off in extra_meta:
        cd += _make_cd(name, method, crc, csize, fsize, off)

    out += cd

    # ── 5. EOCD ────────────────────────────────────────────────────
    total = 1 + len(infos) + len(extra_meta)
    out += EOCD_SIG
    out += struct.pack('<H', 0)        # disk num
    out += struct.pack('<H', 0)        # cd start disk
    out += struct.pack('<H', total)
    out += struct.pack('<H', total)
    out += struct.pack('<I', len(cd))
    out += struct.pack('<I', cd_start)
    out += struct.pack('<H', 0)        # comment len

    with open(out_apk, 'wb') as f:
        f.write(out)

    return {
        'src_size': len(src),
        'out_size': len(out),
        'origin_data': (origin_data_start, origin_data_end),
        'entries': total,
        'saved_mb': (len(src) - hdr_len) / 1e6,
    }


def verify(out_apk, origin_name=ORIGIN_NAME):
    """验证复用包的结构。

    ⚠️ 不能用 `zipfile.ZipFile.read()` 读 origin.apk —— Python 的 zipfile
    有 zip-bomb 防护，检测到条目数据区重叠就直接抛
    `BadZipFile: Overlapped entries`。而**数据复用本身就是靠重叠实现的**，
    所以这里必须手工按 offset 读（与 Android 的 ZIP 解析器行为一致）。

    验证项：
      ① origin.apk 按 offset 读出来是完整可用的 APK（能当 ZIP 打开）
      ② 各条目按 offset 读出的内容正确（dex magic / manifest 非空）
      ③ 中央目录条目数与 EOCD 一致
    """
    import io

    problems = []
    with open(out_apk, 'rb') as f:
        data = f.read()

    # ── 手工解析中央目录 ─────────────────────────────────────────────
    eocd_off = data.rfind(EOCD_SIG)
    if eocd_off < 0:
        return ['找不到 EOCD']
    total = struct.unpack('<H', data[eocd_off + 10:eocd_off + 12])[0]
    cd_size, cd_off = struct.unpack('<II', data[eocd_off + 12:eocd_off + 20])

    entries = {}
    p = cd_off
    for _ in range(total):
        if data[p:p + 4] != b'PK\x01\x02':
            problems.append(f'中央目录条目非法 @ {p}')
            break
        method = struct.unpack('<H', data[p + 10:p + 12])[0]
        csize = struct.unpack('<I', data[p + 20:p + 24])[0]
        fsize = struct.unpack('<I', data[p + 24:p + 28])[0]
        namelen = struct.unpack('<H', data[p + 28:p + 30])[0]
        elen = struct.unpack('<H', data[p + 30:p + 32])[0]
        clen = struct.unpack('<H', data[p + 32:p + 34])[0]
        off = struct.unpack('<I', data[p + 42:p + 46])[0]
        name = data[p + 46:p + 46 + namelen].decode('utf-8', 'replace')
        entries[name] = (method, csize, fsize, off)
        p += 46 + namelen + elen + clen

    if len(entries) != total:
        problems.append(f'解析到 {len(entries)} 条，EOCD 声明 {total} 条')

    # ── 按 offset 读条目数据 ────────────────────────────────────────
    def read_entry(name):
        if name not in entries:
            raise KeyError(name)
        method, csize, fsize, off = entries[name]
        if data[off:off + 4] != LFH_SIG:
            raise ValueError(f'{name} 的 local header 非法 @ {off}')
        nl = struct.unpack('<H', data[off + 26:off + 28])[0]
        el = struct.unpack('<H', data[off + 28:off + 30])[0]
        start = off + 30 + nl + el
        raw = data[start:start + csize]
        if method == 0:
            return raw
        return zlib.decompress(raw, -15)

    # ① origin.apk 是否完整 APK
    if origin_name not in entries:
        return problems + [f'找不到 {origin_name}']
    try:
        origin = read_entry(origin_name)
        if origin[:4] != LFH_SIG:
            problems.append(f'origin.apk 开头不是 ZIP local header: {origin[:4]}')
        else:
            with zipfile.ZipFile(io.BytesIO(origin)) as oz:
                n = len(oz.namelist())
                if n == 0:
                    problems.append('origin.apk 里没有任何条目')
    except Exception as e:
        problems.append(f'origin.apk 读取失败: {e}')

    # ② 抽查关键条目
    for probe in ('AndroidManifest.xml', 'classes.dex', 'assets/nc_sigfix/payload.dex'):
        if probe in entries:
            try:
                d = read_entry(probe)
                if not d:
                    problems.append(f'{probe} 读出为空')
            except Exception as e:
                problems.append(f'{probe} 读取失败: {e}')

    # ③ 所有 dex 的 magic
    for name in entries:
        if name.startswith('classes') and name.endswith('.dex'):
            try:
                if read_entry(name)[:4] != b'dex\n':
                    problems.append(f'{name} magic 非法')
            except Exception as e:
                problems.append(f'{name} 读取失败: {e}')

    return problems


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    st = build(sys.argv[1], sys.argv[2])
    print(f"输入      : {st['src_size']/1e6:.2f} MB")
    print(f"输出      : {st['out_size']/1e6:.2f} MB "
          f"(增加 {st['out_size']-st['src_size']} B = 仅 origin header)")
    print(f"origin数据: {st['origin_data'][0]} ~ {st['origin_data'][1]} "
          f"({(st['origin_data'][1]-st['origin_data'][0])/1e6:.2f} MB)")
    print(f"条目数    : {st['entries']}")
    print(f"省下      : {st['saved_mb']:.2f} MB（若不复用则要多存这么多）")

    print("\n=== 自检 ===")
    probs = verify(sys.argv[2])
    if probs:
        for p in probs:
            print('❌', p)
        sys.exit(1)
    print('✅ ZIP 可解析 / origin.apk 是完整 APK / 各条目可正常读取')
