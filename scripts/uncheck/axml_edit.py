#!/usr/bin/env python3
"""axml_edit.py — 二进制 AXML 改写：给 <application> 加/改 android:name

=== 为什么需要它 ===

我们的去签名校验载荷需要**最早**的执行时机。三个可选挂载点，按时间排序：

    ContentProvider.onCreate  ← 最早（系统先安装 Provider，再初始化 Application）
    Application.attachBaseContext
    Application.onCreate
    Activity.onCreate         ← 最晚（我们目前用的，会漏掉更早的校验）

要挂到「Application」这一级，只有一条路：**改 AndroidManifest 的
android:name**，让它指向我们自己的 Application 子类。
MT / ApkSignatureKiller 就是这么做的 —— 这也是它比「注入 Activity」更稳的根本原因。

本仓库原先只有 patch-extractnativelibs.py，那只能做**等长原位替换**
（false→true，4 字节换 4 字节）。加一个属性会让 START_ELEMENT 块变长，
后续所有 chunk 的偏移都要重算 —— 那是完全不同量级的工作，所以之前没做。

这个文件补上了这个能力。

=== 实现要点（按风险从高到低）===

1. **字符串池扩容**
   新类名字符串要进池。池结构：
       [chunk header 8B][strcount 4B][stylecount 4B][flags 4B]
       [stringsStart 4B][stylesStart 4B][offsets 4B×strcount][...data...]
   追加字符串后：strcount+1、offsets 数组 +4B、stringsStart+4B
   （因为 data 区整体后移 4 字节），各字符串的 offset **不需要改**
   （它们是相对 stringsStart 的）。

2. **所有后续 chunk 后移**
   AXML 的 chunk 之间没有绝对偏移引用，只有各自的 size 字段。
   所以字符串池变长后，后面的 chunk 整体后移即可，不需要逐个修偏移。
   ⚠️ 唯一例外：如果被换的字符串**已经在池里**，就只改属性值，池不动 ——
      优先走这条路（多数 App 的 android:name 值不会重复，但空池槽常有）。

3. **START_ELEMENT 加属性**
   属性结构 20 字节：ns(4) name(4) rawValue(4) typedValue(8)
   插入到 `<application>` 的属性数组末尾，块 size +20，
   同时该 chunk 的 header size 不变（只有 body 变大）。

4. **属性名 "name" 与 resourceId**
   android:name 的属性名在池里是 "name"，其 resourceId 是 0x01010003，
   写在 typedValue.data 里。若池里没有 "name"，也要追加。

=== 安全边界 ===
· 解析失败 / 结构异常 → 直接报错退出，绝不产出畸形 Manifest（灰包）。
· 幂等：已有 android:name 且值相同则跳过。
· 只动 <application>，不碰别的元素。

用法:
    axml_edit.py set-app-name <AndroidManifest.xml> <完整类名>
    axml_edit.py get-app-name <AndroidManifest.xml>
"""
import struct
import sys

# AXML 常量
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_RESOURCE_MAP_TYPE = 0x0180
TYPE_STRING = 0x03
TYPE_REFERENCE = 0x08
ATTR_TYPE_STRING = 0x03
TYPE_REFERENCE = 0x08
NO_INDEX = 0xFFFFFFFF

# android:name 的资源 ID（framework 固定值）
ATTR_ANDROID_NAME_ID = 0x01010003
# android 命名空间 URI
ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AxmlError(Exception):
    pass


# ───────────────────────── 字符串池 ─────────────────────────

class StringPool:
    """AXML 字符串池：解析 + 追加（保持 UTF-8/UTF-16 原编码）。"""

    def __init__(self, data, off):
        self.off = off
        (_ctype, hsize, size) = struct.unpack_from("<HHI", data, off)
        (strcount, stylecount, flags) = struct.unpack_from("<III", data, off + 8)
        (strstart, stylestart) = struct.unpack_from("<II", data, off + 20)
        self.utf8 = bool(flags & 0x100)
        self.strcount = strcount
        self.stylecount = stylecount
        self.flags = flags
        self.strstart = strstart
        self.stylestart = stylestart
        self.offsets = list(struct.unpack_from(f"<{strcount}I", data, off + 28))
        self.base = off + strstart
        self.strings = []
        for o in self.offsets:
            self.strings.append(self._read_string(data, self.base + o))
        self.chunk_size = size
        self.header_size = hsize
        # style 区（多数 Manifest 为空）
        self.style_data = b""
        if stylecount and stylestart:
            self.style_data = bytes(
                data[off + stylestart: off + size])

    def _read_string(self, data, p):
        if self.utf8:
            # utf-16 length（1 或 2 字节），再 utf-8 长度
            n = data[p]
            p += 2 if (n & 0x80) else 1
            n = data[p]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[p + 1]
                p += 2
            else:
                p += 1
            return data[p:p + n].decode("utf-8", "replace")
        else:
            n = struct.unpack_from("<H", data, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                p += 2
            return data[p:p + n * 2].decode("utf-16-le", "replace")

    def _encode(self, s):
        if self.utf8:
            b = s.encode("utf-8")
            out = bytearray()
            if len(s) > 0x7F:
                out.append((len(s) & 0xFF) | 0x80)
                out.append((len(s) >> 8) & 0xFF)
            else:
                out.append(len(s))
            if len(b) > 0x7F:
                out.append((len(b) & 0xFF) | 0x80)
                out.append((len(b) >> 8) & 0xFF)
            else:
                out.append(len(b))
            out.extend(b)
            out.append(0)
            return bytes(out)
        else:
            b = s.encode("utf-16-le")
            out = bytearray()
            n = len(s)
            if n > 0x7FFF:
                out.extend(struct.pack("<H", ((n >> 16) | 0x8000) & 0xFFFF))
            else:
                out.extend(struct.pack("<H", n))
            out.extend(b)
            out.extend(b"\x00\x00")
            return bytes(out)

    def index_of(self, s):
        for i, v in enumerate(self.strings):
            if v == s:
                return i
        return -1

    def add(self, s):
        """追加字符串，返回索引。已存在则直接返回。"""
        idx = self.index_of(s)
        if idx >= 0:
            return idx
        self.strings.append(s)
        self.offsets.append(0)   # 占位，序列化时重算
        self.strcount = len(self.strings)
        return self.strcount - 1

    def serialize(self):
        """重新序列化整个池（body + header）。"""
        # 重算每个字符串的 offset（相对 data 区起点）
        datas = []
        offsets = []
        cur = 0
        for s in self.strings:
            offsets.append(cur)
            e = self._encode(s)
            datas.append(e)
            cur += len(e)
        data_blob = b"".join(datas)
        # 对齐到 4 字节
        pad = (-len(data_blob)) % 4
        data_blob += b"\x00" * pad

        offsets_blob = b"".join(struct.pack("<I", o) for o in offsets)
        styles_blob = self.style_data
        header_size = 28
        strings_start = header_size + len(offsets_blob) + len(styles_blob)
        # stylesStart 用 0 表示无样式（多数 Manifest 如此）
        styles_start = 0 if not styles_blob else strings_start + len(data_blob)

        size = strings_start + len(data_blob)
        out = bytearray()
        out.extend(struct.pack("<HHI", RES_STRING_POOL_TYPE, header_size, size))
        out.extend(struct.pack("<III", self.strcount, self.stylecount, self.flags))
        out.extend(struct.pack("<II", strings_start, styles_start))
        out.extend(offsets_blob)
        out.extend(styles_blob)
        out.extend(data_blob)
        return bytes(out)


# ───────────────────────── chunk 遍历 ─────────────────────────

def iter_chunks(data, start=8):
    """产出 (chunk_type, offset, header_size, size)。

    ⚠️ 默认从 8 开始：AXML 文件最外层是一个 RES_XML_TYPE 容器 chunk
    （head 8 字节，size 覆盖整个文件），真正的字符串池/元素都**在它内部**。
    从 0 开始遍历会被这个容器挡住，只看得到它自己
    （实测踩过：报「找不到字符串池」）。
    """
    off = start
    n = len(data)
    while off + 8 <= n:
        ctype, hsize, size = struct.unpack_from("<HHI", data, off)
        if size < 8 or off + size > n:
            raise AxmlError(f"chunk 尺寸异常 @0x{off:x}: type=0x{ctype:04x} size={size}")
        yield (ctype, off, hsize, size)
        off += size


def find_application_element(data, pool):
    """找 <application> 的 START_ELEMENT，返回 (chunk_off, hsize, size, attr_start, attr_count)。"""
    for (ctype, off, hsize, size) in iter_chunks(data):
        if ctype != RES_XML_START_ELEMENT_TYPE:
            continue
        # START_ELEMENT body: ns(4) name(4) attrStart(2) attrSize(2) attrCount(2) id(2) class(2) style(2)
        ns, name = struct.unpack_from("<II", data, off + hsize)
        attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, off + hsize + 8)
        if pool.strings[name] == "application":
            return (off, hsize, size, attr_start, attr_count, attr_size)
    return None


def read_attrs(data, elem_off, hsize, attr_start, attr_count, attr_size):
    """读出一个 START_ELEMENT 的所有属性，返回 [(ns, name, raw, type, data)]。"""
    out = []
    # 实测：chunk@5064 hsize=16 attrStart=20 →
    #   5064+20=5084 是错的（读到 ns=58），5064+16+20=5100 才对（ns=65）
    base = elem_off + hsize + attr_start
    for i in range(attr_count):
        p = base + i * attr_size
        ns, name, raw = struct.unpack_from("<III", data, p)
        vtype = data[p + 12]
        vdata = struct.unpack_from("<I", data, p + 16)[0]
        out.append((ns, name, raw, vtype, vdata))
    return out


# ───────────────────────── 主逻辑 ─────────────────────────

def get_app_name(path):
    data = open(path, "rb").read()
    if struct.unpack_from("<H", data, 0)[0] != RES_XML_TYPE:
        raise AxmlError("不是二进制 AXML（头不是 0x0003）")
    pool = None
    for (ctype, off, hsize, size) in iter_chunks(data):
        if ctype == RES_STRING_POOL_TYPE:
            pool = StringPool(data, off)
            break
    if pool is None:
        raise AxmlError("找不到字符串池")
    found = find_application_element(data, pool)
    if not found:
        raise AxmlError("找不到 <application> 元素")
    (elem_off, hsize, _size, attr_start, attr_count, attr_size) = found
    for (ns, name, raw, vtype, vdata) in read_attrs(
            data, elem_off, hsize, attr_start, attr_count, attr_size):
        if pool.strings[name] == "name" and pool.strings[ns] == ANDROID_NS:
            return pool.strings[vdata] if raw == NO_INDEX else pool.strings[raw]
    return None


def set_app_name(path, new_class):
    """给 <application> 设置 android:name。就地重写整个文件。"""
    data = bytearray(open(path, "rb").read())
    if struct.unpack_from("<H", data, 0)[0] != RES_XML_TYPE:
        raise AxmlError("不是二进制 AXML（头不是 0x0003）")

    pool_off = None
    chunks = list(iter_chunks(data))
    for (ctype, off, hsize, size) in chunks:
        if ctype == RES_STRING_POOL_TYPE:
            pool_off = off
            break
    if pool_off is None:
        raise AxmlError("找不到字符串池")

    _load_res_map(data)
    pool = StringPool(data, pool_off)
    found = find_application_element(data, pool)
    if not found:
        raise AxmlError("找不到 <application> 元素")
    (elem_off, elem_hsize, elem_size, attr_start, attr_count, attr_size) = found

    name_idx = pool.index_of("name")
    ns_idx = pool.index_of(ANDROID_NS)

    # 先看有没有现成的 android:name
    existing = None
    for i, (ns, name, raw, vtype, vdata) in enumerate(
            read_attrs(data, elem_off, elem_hsize, attr_start, attr_count, attr_size)):
        if pool.strings[name] == "name" and pool.strings[ns] == ANDROID_NS:
            existing = i
            break

    if existing is not None:
        # 已有属性：值相同时跳过；否则只改 value 指向的池索引
        cur_raw = read_attrs(data, elem_off, elem_hsize,
                             attr_start, attr_count, attr_size)[existing][2]
        if cur_raw != NO_INDEX and pool.strings[cur_raw] == new_class:
            print(f"ℹ️ android:name 已是 {new_class}，无需修改")
            return False
        new_idx = pool.add(new_class)
        # 若池变长，需要重排；简单起见统一走"重建"路径
        return _rewrite(path, pool, elem_off, elem_hsize, elem_size, attr_start,
                        attr_count, attr_size, existing, new_idx, new_class)

    # 没有属性 → 追加
    new_idx = pool.add(new_class)
    ns_i = ns_idx if ns_idx >= 0 else pool.add(ANDROID_NS)
    name_i = name_idx if name_idx >= 0 else pool.add("name")
    return _rewrite(path, pool, elem_off, elem_hsize, elem_size, attr_start,
                    attr_count, attr_size, None, new_idx, new_class,
                    extra_attr=(ns_i, name_i))


# resource map：属性 name 索引 → framework 资源 ID。
# 每个 Manifest 都要重新加载（不同包的属性索引不同）。
RES_MAP = {}


def _load_res_map(data):
    """从 0x0180 chunk 读属性名索引 → resourceId 的映射。"""
    global RES_MAP
    RES_MAP = {}
    for (ctype, off, hsize, size) in iter_chunks(data):
        if ctype != RES_XML_RESOURCE_MAP_TYPE:
            continue
        n = (size - hsize) // 4
        ids = struct.unpack_from(f"<{n}I", data, off + hsize)
        for i, rid in enumerate(ids):
            RES_MAP[i] = rid
        break
    return RES_MAP


def _attr_insert_index(pool, new_name_idx, attr_count, rest, attr_base, attr_size):
    """按 resourceId 升序决定新属性插在第几位。

    resource map chunk（0x0180）把属性 name 索引映射到 framework 资源 ID
    （android:name → 0x01010003）。PackageParser 读 <application> 的属性时
    期望按该 ID 升序，乱序会让它提前停止扫描、后面的属性全部丢失
    （实测：追加到末尾时系统读不到 android:name）。

    拿不到 resourceId 的属性（ID 视为最大）排最后。
    """
    new_id = RES_MAP.get(new_name_idx, 0xFFFFFFFF)
    if new_id == 0xFFFFFFFF:
        return attr_count
    for i in range(attr_count):
        p = attr_base + i * attr_size
        ns, nm = struct.unpack_from("<II", rest, p)
        cur_id = RES_MAP.get(nm, 0xFFFFFFFF)
        if new_id < cur_id:
            return i
    return attr_count


def _rewrite(path, pool, elem_off, elem_hsize, elem_size, attr_start, attr_count,
             attr_size, replace_idx, value_idx, new_class, extra_attr=None):
    """统一的重写路径：重建字符串池 + 必要时扩属性数组。"""
    data = bytearray(open(path, "rb").read())
    old_pool_size = pool.chunk_size
    new_pool_blob = pool.serialize()
    delta = len(new_pool_blob) - old_pool_size

    # 拼接：头 8 字节（文件头）+ 新池 + 后续所有 chunk
    head = bytes(data[0:8])
    fsize = struct.unpack_from("<I", data, 4)[0]
    rest = bytes(data[pool.off + old_pool_size:])

    # elem_off 在旧数据中的位置 → 新位置
    elem_off_new = elem_off + delta - pool.off  # 相对 rest 起点
    rest = bytearray(rest)

    if replace_idx is None:
        # 追加一个属性
        (ns_i, name_i) = extra_attr
        # 找到 START_ELEMENT 里的 attrStart/attrCount 位置
        # rest 中 elem 的偏移 = elem_off - (pool.off + old_pool_size)
        e = elem_off - (pool.off + old_pool_size)
        # START_ELEMENT body: ns(4) name(4) attrStart(2) attrSize(2) attrCount(2)
        # 这三项在 chunk 内 headerSize+8 处；attrStart 本身是从 chunk 起点算的偏移
        attr_start_e, attr_size_e, attr_count_e = struct.unpack_from(
            "<HHH", rest, e + elem_hsize + 8)
        if attr_size_e != 20:
            raise AxmlError(f"属性尺寸不是 20（实际 {attr_size_e}），不支持")
        # ⚠️ 插入位置不是"追加到末尾"，而是**按 resourceId 升序插入**。
        #
        # 实测对照（/storage/.../JMComic3v2.1.14_kill.apk，MT 生成）：
        #   MT 把 android:name 插在属性数组的 index 3（最前面），
        #   而不是追加到末尾。原因是 PackageParser 解析 <application>
        #   时按 resourceId 升序读，属性乱序会导致后面的属性被跳过。
        #   android:name 的 resourceId = 0x01010003，是这几个里最小的，
        #   必须放最前。
        #
        # 判定依据：resource map chunk（0x0180）把「属性 name 索引」映射到
        # resourceId。拿不到映射的（如 android:name 之外的普通属性）排在后面。
        ins_index = _attr_insert_index(pool, name_i, attr_count_e,
                                       rest, e + elem_hsize + attr_start_e, attr_size_e)
        ins_at = e + elem_hsize + attr_start_e + ins_index * attr_size_e
        # 属性 20 字节布局（实测自原包 appComponentFactory）：
        #   ns(4) name(4) rawValue(4) size(2) res0(1) dataType(1) data(4)
        #   rawValue = 0xFFFFFFFF(NO_INDEX)：表示"值不在字符串池 raw 里，
        #              请看 typedValue"，这是我们这种生成属性的正确形态
        # ns(4) + name(4) + rawValue(4) + size(2) = 14 字节
        # ⚠️ rawValue 必须是**字符串池索引**，不是 NO_INDEX。
        # 实测 MT（/storage/.../JMComic3v2.1.14_kill.apk）的正确形态：
        #   41000000 03000000 4d000000 0800 00 03 4d000000
        #   ns=65 name=3 raw=0x4d size=8 type=0x03 data=0x4d
        # raw 与 data 相同，都是字符串池索引。
        # 原包里的 appComponentFactory 也是同一形态（raw=0x2e data=0x2e）。
        attr = struct.pack("<IIIH", ns_i, name_i, value_idx, 8)
        # ⚠️ typedValue 必须是 **resourceId + TYPE_REFERENCE(0x08)**，
        # 不能用字符串类型：
        #   系统解析 <application> 的属性时按 resourceId 匹配（android:name
        #   固定是 0x01010003），不看属性名字符串。
        #   写成 type=0x03/data=字符串池索引 → 系统认不出这是 android:name，
        #   当成未知属性丢弃 → 装上后 Application 仍是原类（实测踩过：
        #   dumpsys package 的 applicationInfo 里没有 className）。
        # typedValue 尾部：res0(1) dataType(1) data(4)
        # dataType 用 TYPE_STRING(0x03)，data 是字符串池索引 ——
        # 属性的"身份"由 chunk 0x0180（resource map）里的 name 索引对应关系决定，
        # 不需要把 resourceId 塞进 typedValue（塞了反而解析不出来）。
        attr += bytes([0, TYPE_STRING]) + struct.pack("<I", value_idx)
        rest[ins_at:ins_at] = attr
        # attrCount +1
        struct.pack_into("<H", rest, e + elem_hsize + 8 + 4, attr_count_e + 1)
        # 该 chunk 的 size +20
        chunk_size = struct.unpack_from("<I", rest, e + 4)[0]
        struct.pack_into("<I", rest, e + 4, chunk_size + 20)
    else:
        # 替换已有属性的 raw 与 typedValue.data
        e = elem_off - (pool.off + old_pool_size)
        # START_ELEMENT body: ns(4) name(4) attrStart(2) attrSize(2) attrCount(2)
        # 这三项在 chunk 内 headerSize+8 处；attrStart 本身是从 chunk 起点算的偏移
        attr_start_e, attr_size_e, attr_count_e = struct.unpack_from(
            "<HHH", rest, e + elem_hsize + 8)
        p = e + elem_hsize + attr_start_e + replace_idx * attr_size_e
        # 与 appendAttr 同一形态：rawValue 与 typedValue.data 都是字符串索引
        struct.pack_into("<I", rest, p + 8, value_idx)
        struct.pack_into("<H", rest, p + 12, 8)
        rest[p + 14] = 0
        rest[p + 15] = TYPE_STRING
        struct.pack_into("<I", rest, p + 16, value_idx)

    out = bytearray()
    out.extend(head)
    out.extend(new_pool_blob)
    out.extend(rest)
    struct.pack_into("<I", out, 4, len(out))
    open(path, "wb").write(bytes(out))
    print(f"✅ android:name → {new_class}（池 +{delta}B，文件 {len(out)}B）")
    return True


# ───────────────────────── 高层读取（替代文本 Manifest 解析）─────────────────────────

def _attr_value(pool, data, elem_off, hsize, attr_start, attr_count, attr_size, attr_name):
    """读某个 START_ELEMENT 上指定名字的属性值。"""
    for (ns, name, raw, vtype, vdata) in read_attrs(
            data, elem_off, hsize, attr_start, attr_count, attr_size):
        try:
            if pool.strings[name] == attr_name:
                if raw != NO_INDEX and raw < len(pool.strings):
                    return pool.strings[raw]
                if vtype == ATTR_TYPE_STRING and vdata < len(pool.strings):
                    return pool.strings[vdata]
        except Exception:
            continue
    return None


def parse_manifest(path):
    """解析二进制 AndroidManifest，返回 dict(package, app_class, launchers)。

    与 inject.py 的文本解析同语义，但**直接读 AXML**。
    这样解包时可以保持 Manifest 为二进制（AXML 改写需要），
    不必在"文本"和"二进制"之间来回转换。
    """
    data = open(path, 'rb').read()
    if struct.unpack_from("<H", data, 0)[0] != RES_XML_TYPE:
        raise AxmlError("不是二进制 AXML")
    pool = None
    for (ctype, off, hsize, size) in iter_chunks(data):
        if ctype == RES_STRING_POOL_TYPE:
            pool = StringPool(data, off)
            break
    if pool is None:
        raise AxmlError("找不到字符串池")

    package = None
    app_class = None
    launchers = []

    # 遍历所有 START_ELEMENT，维护一个简单的元素栈，用来判断
    # activity 是否包含 MAIN+LAUNCHER（需要看子元素 <intent-filter>）。
    stack = []
    current_activity = None
    current_activity_ok = False
    has_main = False
    has_launcher = False
    has_not_exported_false = False

    for (ctype, off, hsize, size) in iter_chunks(data):
        if ctype == RES_XML_START_ELEMENT_TYPE:
            (ns, name_i) = struct.unpack_from("<II", data, off + hsize)
            attr_start, attr_size, attr_count = struct.unpack_from(
                "<HHH", data, off + hsize + 8)
            name = pool.strings[name_i] if name_i < len(pool.strings) else ""
            av = lambda n: _attr_value(pool, data, off, hsize,
                                       attr_start, attr_count, attr_size, n)
            if name == "manifest":
                package = av("package")
            elif name == "application":
                app_class = av("name")
            elif name == "activity":
                current_activity = av("name")
                current_activity_ok = (av("enabled") != "false")
                has_main = has_launcher = False
            elif name == "intent-filter":
                pass
            elif name == "action":
                if av("name") == "android.intent.action.MAIN":
                    has_main = True
            elif name == "category":
                if av("name") == "android.intent.category.LAUNCHER":
                    has_launcher = True
            stack.append(name)
        elif ctype == 0x0103:  # END_ELEMENT
            if stack:
                top = stack.pop()
                if top == "activity":
                    if current_activity and current_activity_ok and has_main and has_launcher:
                        launchers.append(current_activity)
                    current_activity = None

    def complete(n):
        if not n or not package:
            return None
        if n.startswith("."):
            return package + n
        if "." not in n:
            return package + "." + n
        return n

    app_desc = None
    if app_class:
        j = complete(app_class)
        app_desc = "L" + j.replace(".", "/") + ";" if j else None

    return {
        "package": package or "",
        "app_class": app_desc,
        "launchers": ["L" + complete(x).replace(".", "/") + ";" for x in launchers],
    }


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "get-app-name":
        try:
            v = get_app_name(argv[2])
            print(v if v else "(无 android:name)")
            return 0
        except AxmlError as e:
            print(f"❌ {e}", file=sys.stderr)
            return 1
    if cmd == "set-app-name":
        if len(argv) != 4:
            print("用法: axml_edit.py set-app-name <manifest> <类名>", file=sys.stderr)
            return 2
        try:
            set_app_name(argv[2], argv[3])
            return 0
        except AxmlError as e:
            print(f"❌ {e}", file=sys.stderr)
            return 1
    print(f"未知命令: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
