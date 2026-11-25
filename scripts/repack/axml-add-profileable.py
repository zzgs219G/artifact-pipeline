#!/usr/bin/env python3
"""axml-add-profileable.py — 二进制 AXML 注入 <profileable android:shell="true"/>

用法: axml-add-profileable.py <成品.apk>   （原地改写 manifest 条目）

==== 为什么需要（2026-11-26）====
simpleperf / am profile 对非 debuggable 包默认拒绝（SecurityException:
Process not debuggable, and not profileable by shell）。Manifest 加
<profileable android:shell="true"/>（Android 10+ 官方调试机制）即解锁
函数级 CPU 采样 —— 排障专用，正式产物不要加。

==== 与 axml_edit.py 的关系 ====
axml_edit.py 的能力是给 <application> 加【属性】（展宽 attribute 数组）。
profileable 是【独立元素】，需要：字符串池扩容 + 插入 START/END 元素对。
本文件复用它的池扩容思路，新增元素对插入能力。

==== 实现要点（按踩坑顺序）====
1. 字符串池扩容：offsets 数组变长（+3 条），strsStart 必须从
   28+旧count*4 更新为 28+新count*4 —— 漏更新 = 池全错（aapt 报
   bad string pool）。且旧 offsets 已含在池头区间里，重建池体时
   只取 28B 池头 + 全部新旧 offsets，否则 offsets 重复。
2. START_ELEMENT 结构：16B 头 + attrExt 20B（ns4 name4 attrStart2
   attrSize2 count2 idIndex2 classIndex2）+ attr 数组 20B/条。
   attrStart=20 是【相对 attrExt】的偏移（attr 数组在 chunk+36）。
   漏 idIndex/classIndex 4 字节 = attr 全部错位。
3. profileable 是 <application> 的【子元素】，不是 manifest 直下
   （插错位置 aapt 静默忽略）。
4. 定位 application 闭合：栈匹配（name=='application' 且闭合时
   depth==1）。用『最后一个深度回到 1 的 END』会命中 queries
   （它是 manifest 的最后一个子元素）。
5. attr 的 ns 字段 = 'http://schemas.android.com/apk/res/android'
   的字符串池索引（android: 前缀的 URI），不是 -1。
"""
import struct, sys

def parse_pool(d, pool_off):
    _, hsize, _ = struct.unpack_from('<HHI', d, pool_off)
    (strcount, stylecount, flags, strs_start, styles_start) = struct.unpack_from('<IIIII', d, pool_off+8)
    utf8 = bool(flags & 0x100)
    offs = list(struct.unpack_from(f'<{strcount}I', d, pool_off+28))
    return dict(off=pool_off, hsize=hsize, size=sp_sz, strcount=strcount,
                stylecount=stylecount, flags=flags, strs_start=strs_start,
                styles_start=styles_start, offs=offs, utf8=utf8)

def _inject(mf_path, out_mf=None):
    apk_mf = mf_path
    d = bytearray(open(apk_mf, 'rb').read())
    # 文件头
    _, file_hs, file_sz = struct.unpack_from('<HHI', d, 0)
    pool_off = struct.unpack_from('<I', d, file_hs - 4)[0] if False else None
    # 第一个 chunk 就是 string pool（offset = file header size）
    pool_off = struct.unpack_from('<HHI', d, 0)[1]  # headerSize
    sp = struct.unpack_from('<HHI', d, pool_off)
    assert sp[0] == 0x0001, f"第一个 chunk 不是字符串池: {sp[0]:#x}"
    sp_size = sp[2]
    (strcount, stylecount, flags, strs_start, styles_start) = struct.unpack_from('<IIIII', d, pool_off+8)
    utf8 = bool(flags & 0x100)
    offs = list(struct.unpack_from(f'<{strcount}I', d, pool_off+28))

    def pool_str(i):
        p = pool_off + strs_start + offs[i]
        if utf8:
            u16len = d[p]; q=p+1
            if u16len & 0x80: u16len=((u16len&0x7f)<<8)|d[q]; q+=1
            u8len = d[q]; q+=1
            if u8len & 0x80: u8len=((u8len&0x7f)<<8)|d[q]; q+=1
            return d[q:q+u8len].decode('utf8')
        u16len = struct.unpack_from('<H', d, p)[0]; q=p+2
        if u16len & 0x8000: u16len=((u16len&0x7fff)<<16)|struct.unpack_from('<H',d,q)[0]; q+=2
        return d[q:q+u16len*2].decode('utf-16-le')

    # 找 <application> 的 END_ELEMENT（最后一个 name=application 的 START 之后、
    # 深度回到 1 的 END）—— 简化：从尾向前找第一个 END_ELEMENT，它是 manifest 闭合；
    # 其前面那个 END 就是 application 闭合。
    # 稳妥做法：模拟深度
    depth = 0
    stack = []
    app_end = None
    off = pool_off + sp_size
    t,_,sz = struct.unpack_from('<HHI', d, off)
    if t == 0x0180: off += sz
    while off + 8 <= len(d):
        t, _, sz = struct.unpack_from('<HHI', d, off)
        if t == 0x0102:
            ns, name = struct.unpack_from('<ii', d, off+16)
            stack.append(pool_str(name))
            depth += 1
        elif t == 0x0103:
            depth -= 1
            if stack and stack[-1] == 'application' and depth == 1:
                app_end = off       # application 的闭合（application 是 depth2 层）
            stack.pop()
        off += sz
    assert app_end, "找不到 application 闭合"

    # ── 字符串池扩容：追加 3 条 ──
    new_strs = ['profileable', 'shell', 'true']
    def enc_utf16(s):
        b = s.encode('utf-16-le')
        return struct.pack('<H', len(s)) + b + b'\x00\x00'
    add_blob = b''.join(enc_utf16(s) for s in new_strs)
    # offsets 追加
    last_off = offs[-1]
    last_len = None
    # 最后一条字符串的长度：池 data 区从 strs_start 到池尾
    data_end = sp_size - (styles_start if styles_start else 0) - 0
    # 简单法：池 data 区 = [strs_start, sp_size)（styles 为 0 时）
    data = bytes(d[pool_off+strs_start : pool_off+sp_size])
    # 逐条定位末条长度
    cur = offs[-1]
    p = cur
    u16len = struct.unpack_from('<H', data, p)[0]; p += 2
    if u16len & 0x8000: p += 2
    last_str_end = p + u16len*2 + 2  # 含 NUL
    base = last_str_end
    new_offs = [base]
    for s in new_strs[:-1]:
        base += len(enc_utf16(s))
        new_offs.append(base)
    add_blob = b''.join(enc_utf16(s) for s in new_strs)

    # 新池：strcount+3, offsets+3, data 追加
    new_strcount = strcount + len(new_strs)
    head_pool = bytearray(d[pool_off:pool_off+28])  # 只取池头 28B（offsets 全部重拼）
    struct.pack_into('<I', head_pool, 8, new_strcount)
    offs_blob = b''.join(struct.pack('<I', o) for o in offs) + \
                b''.join(struct.pack('<I', o) for o in new_offs)
    new_data = data + add_blob
    # ⚠️ offsets 数组变长（+3 条），字符串 data 区起点必须后移
    #    strsStart = chunkHeader(28) + offsetsBytes
    import struct as _s
    new_strs_start = 28 + new_strcount * 4
    struct.pack_into('<I', head_pool, 20, new_strs_start)
    new_pool_body = head_pool + offs_blob + new_data
    # 池头大小不变（hsize 固定 28），重写 size
    new_sp_size = len(new_pool_body)
    struct.pack_into('<I', new_pool_body, 4, new_sp_size)

    delta = new_sp_size - sp_size
    # 拼接新文件：头 + 新池 + resource-map(平移) + body(平移)
    idx3 = strcount + 0          # profileable
    idx4 = strcount + 1          # shell
    idx5 = strcount + 2          # true

    # 构造 START_ELEMENT(profileable, shell=true) + END_ELEMENT
    # 属性数组 attrStart=20 attrSize=20
    # 修正：START_ELEMENT 头是 line(4) comment(4) 也在？标准 AXML chunk:
    #   ResXMLTree_node: header(8) + lineNumber(4) + comment(4)
    #   然后 START_ELEMENT: ns(4) name(4) attrStart(2) attrSize(2) attrCount(2)... 
    # 重新构造（含 lineNumber/comment）：
    # 结构 = 16B 头 + attrExt 20B (ns4 name4 attrStart2 attrSize2 count2 idIndex2 classIndex2)
    #        + attr 数组 (20B/条)。attrStart=20（相对 attrExt）。
    def node(ctype, body):
        size = 16 + len(body)
        return struct.pack('<HHIii', ctype, 16, size, 0, -1) + body

    # attr: ns(android=-1 无前缀？—— profileable 的 shell 是 android:shell，
    #   android ns 在 AXML 里 END_NAMESPACE 处理；实际单条 attr 的 ns 字段
    #   指向 android 前缀的 NAMESPACE 索引。看模板 attr ns=203 —— 它是
    #   'android' 之外的？203 对应池里的 android URI。
    # 找池里 android namespace URI 的索引
    android_idx = None
    for i in range(strcount):
        if pool_str(i) == 'http://schemas.android.com/apk/res/android':
            android_idx = i
            break
    print(f"  android ns URI 索引 = {android_idx}")

    attr = (struct.pack('<i', android_idx)          # ns
            + struct.pack('<I', idx4)               # name = shell
            + struct.pack('<I', idx5)               # rawValue = "true"
            + struct.pack('<HBBI', 8, 0, 0x12, 0)      # size=8 res0=0 type=INT_BOOLEAN
            + struct.pack('<I', 0xFFFFFFFF))        # data = true
    se = node(0x0102, struct.pack('<iiHHHHH', -1, idx3, 20, 20, 1,
                                  0, 0) + attr)
    ee = node(0x0103, struct.pack('<ii', -1, idx3))
    inject = se + ee

    # 组装
    head = bytearray(d[:file_hs])
    struct.pack_into('<I', head, 4, file_sz + delta + len(inject))
    rest = bytearray(d[pool_off + sp_size:])
    # 平移 chunk 内的绝对引用？AXML 无绝对偏移引用池外内容（除了池内 offset），安全。
    newdata = head + new_pool_body + bytes(rest) 
    # 插入点 = app_end 平移后
    app_end_new = app_end + delta
    newdata = newdata[:app_end_new] + inject + newdata[app_end_new:]
    # 修文件大小
    struct.pack_into('<I', newdata, 4, len(newdata))
    if out_mf:
        open(out_mf, 'wb').write(newdata)
    else:
        open(apk_mf, 'wb').write(newdata)
    print(f"[profileable] 注入完成: {len(d):,} → {len(newdata):,} B")

def main(apk):
    """入口：吃 APK，原地注入 manifest。"""
    import zipfile as _zf, shutil as _sh, os as _os
    with _zf.ZipFile(apk) as z:
        blob = z.read('AndroidManifest.xml')
    if b'p\x00r\x00o\x00f\x00i\x00l\x00e\x00a\x00b\x00l\x00e\x00' in blob:
        print('[profileable] 已存在，跳过（幂等）')
        return
    tmp = apk + '.mf'
    open(tmp, 'wb').write(blob)
    _inject(tmp)
    new_blob = open(tmp, 'rb').read()
    _os.remove(tmp)
    tmpzip = apk + '.pmf'
    with _zf.ZipFile(apk) as zin, _zf.ZipFile(tmpzip, 'w') as zout:
        for info in zin.infolist():
            if info.filename == 'AndroidManifest.xml':
                zi = _zf.ZipInfo(info.filename, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zout.writestr(zi, new_blob)
            else:
                zout.writestr(info, zin.read(info.filename))
    _sh.move(tmpzip, apk)


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1])
