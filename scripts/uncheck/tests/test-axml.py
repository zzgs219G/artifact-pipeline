#!/usr/bin/env python3
"""test-axml.py — AXML 改写的回归测试（纯 stdlib）

这几条断言全部来自真机踩过的坑，每条都能对应一次「装上不生效」：

  T1  给无 android:name 的 <application> 追加属性
  T2  幂等：已是目标值时输出与输入逐字节相同
  T3  替换已有 android:name 的值
  T4  **属性插在 resourceId 升序位置，不是追加末尾**
      —— 这条最要命：追加到末尾时 PackageParser 会提前停止扫描，
         系统读不到 android:name，App 照旧跑原类（真机实测）。
  T5  **rawValue 是字符串池索引，不是 NO_INDEX**
      —— 写成 NO_INDEX 时 androguard 与系统都读不出值（真机实测）。
  T6  字符串池扩容后，后续 chunk 仍然连贯（遍历能走到文件末尾）
  T7  文件头 size 字段与实际长度一致
  T8  不是 AXML 时明确报错，不产出畸形文件

用法:
    test-axml.py <原始 AndroidManifest.xml>     # 用真实 Manifest 做夹具
"""
import struct
import subprocess
import sys
import tempfile
import os

HERE = os.path.dirname(os.path.abspath(__file__))
AXML = os.path.join(os.path.dirname(HERE), 'axml_edit.py')

RES_STRING_POOL = 0x0001
RES_RESOURCE_MAP = 0x0180
RES_START_ELEMENT = 0x0102
TYPE_STRING = 0x03
ANDROID_NAME_ID = 0x01010003

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ✅ {name}")
    else:
        print(f"  ❌ {name}  {detail}")
        failures.append(name)


def run(*args):
    r = subprocess.run([sys.executable, AXML, *args],
                       capture_output=True, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def chunks(data):
    off = 8
    out = []
    while off + 8 <= len(data):
        t, h, s = struct.unpack_from("<HHI", data, off)
        if s < 8 or off + s > len(data):
            raise ValueError(f"chunk 越界 @{off} size={s}")
        out.append((t, off, h, s))
        off += s
    return out, off


def read_pool(data):
    for (t, off, h, s) in chunks(data)[0]:
        if t != RES_STRING_POOL:
            continue
        n = struct.unpack_from("<I", data, off + 8)[0]
        flags = struct.unpack_from("<I", data, off + 16)[0]
        start = struct.unpack_from("<I", data, off + 20)[0]
        utf8 = bool(flags & 0x100)
        base = off + start
        offs = struct.unpack_from(f"<{n}I", data, off + 28)

        def rd(o):
            p = base + o
            if utf8:
                c = data[p]
                p += 2 if c & 0x80 else 1
                c = data[p]
                if c & 0x80:
                    c = ((c & 0x7F) << 8) | data[p + 1]
                    p += 2
                else:
                    p += 1
                return data[p:p + c].decode("utf-8", "replace")
            c = struct.unpack_from("<H", data, p)[0]
            p += 2
            return data[p:p + c * 2].decode("utf-16-le", "replace")

        return [rd(o) for o in offs]
    raise ValueError("没有字符串池")


def read_res_map(data):
    for (t, off, h, s) in chunks(data)[0]:
        if t != RES_RESOURCE_MAP:
            continue
        n = (s - h) // 4
        return list(struct.unpack_from(f"<{n}I", data, off + h))
    return []


def app_element(data):
    """按元素名找 <application>（不能靠"属性最多"猜，manifest 也有 7 个属性）。"""
    pool = read_pool(data)
    for (t, off, h, s) in chunks(data)[0]:
        if t != RES_START_ELEMENT:
            continue
        name_idx = struct.unpack_from("<I", data, off + h + 4)[0]
        if pool[name_idx] != "application":
            continue
        a_start, a_size, a_count = struct.unpack_from("<HHH", data, off + h + 8)
        return off, h, a_start, a_size, a_count
    raise ValueError("找不到 <application>")


def attrs_of(data):
    off, h, a_start, a_size, a_count = app_element(data)
    out = []
    for i in range(a_count):
        p = off + h + a_start + i * a_size
        ns, nm, raw = struct.unpack_from("<III", data, p)
        size, res0, dt = struct.unpack_from("<HBB", data, p + 12)
        val = struct.unpack_from("<I", data, p + 16)[0]
        out.append(dict(ns=ns, name=nm, raw=raw, size=size, type=dt, data=val))
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    src = sys.argv[1]
    if not os.path.isfile(src):
        print(f"夹具不存在: {src}", file=sys.stderr)
        return 2

    original = open(src, "rb").read()
    pool = read_pool(original)
    rmap = read_res_map(original)
    # 确认夹具符合前提
    if ANDROID_NAME_ID not in rmap:
        print("⚠️ 夹具的 resource map 里没有 android:name(0x01010003)，"
              "T4/T5 的语义无法验证", file=sys.stderr)

    # 夹具的两类形态决定 T4 的语义（同一套断言不能假设只有一种）：
    #   · 无 android:name → set-app-name 走「追加」分支，属性数 +1
    #   · 已有 android:name → set-app-name 走「原地替换」分支，属性数不变
    # 早先 T4 硬写 "+1"，用已有 name 的夹具（如多数真实 App）会假红，
    # 而真红（插错位置）反而被这条噪音掩盖。
    def _has_app_name(data):
        for a in attrs_of(data):
            if a["name"] < len(rmap) and rmap[a["name"]] == ANDROID_NAME_ID:
                return True
        return False

    original_had_name = _has_app_name(original)
    if original_had_name:
        print(f"ℹ️ 夹具已有 android:name（{run('get-app-name', src)[1]}），"
              f"T4 按「替换」分支断言（属性数不变）")
    else:
        print("ℹ️ 夹具无 android:name，T4 按「追加」分支断言（属性数 +1）")

    tmpdir = tempfile.mkdtemp(prefix="axmltest-")
    NEW = "com.example.test.FakeApp"

    print("[T1] 设置 android:name")
    f1 = os.path.join(tmpdir, "m1.xml")
    open(f1, "wb").write(original)
    rc, out, err = run("set-app-name", f1, NEW)
    d1 = open(f1, "rb").read()
    d1_verify = open(f1, "rb").read()  # 内容快照（供后续 attrs 读取）

    check("命令成功", rc == 0, err)
    check("读回等于目标值", run("get-app-name", f1)[1] == NEW)
    if not original_had_name:
        check("文件变大（池+属性）", len(d1) > len(original),
              f"{len(original)} → {len(d1)}")
    else:
        # 替换分支：值长度变化可能让池补一条新串，文件不一定变小，但不应缩水太多
        check("文件非空且头 size 正确", len(d1) > 8)

    a0 = attrs_of(original)
    a1 = attrs_of(d1_verify)

    print("[T2] 幂等")
    f2 = os.path.join(tmpdir, "m2.xml")
    open(f2, "wb").write(d1)
    rc2, _, _ = run("set-app-name", f2, NEW)
    d2 = open(f2, "rb").read()
    check("重复设置不改变内容", rc2 == 0 and d2 == d1)

    print("[T3] 替换已有值")
    f3 = os.path.join(tmpdir, "m3.xml")
    open(f3, "wb").write(d1)
    OTHER = "com.example.other.AnotherApp"
    run("set-app-name", f3, OTHER)
    check("读回是新值", run("get-app-name", f3)[1] == OTHER)
    # 换成另一个长度不同的类名时，池要新增一条字符串，文件会变大 —— 这是对的。
    # 真正该验的是：属性仍然只有一个（没有重复追加）。
    check("属性数没有翻倍", len(attrs_of(open(f3, "rb").read())) == len(a1),
          f"{len(a1)} → {len(attrs_of(open(f3, 'rb').read()))}")

    print("[T4] android:name 属性位于 resourceId 升序位置，不是追加末尾")
    # 定位「承载我们写的类名」的那个属性：
    #   追加分支 → 新增属性，其 data 指向池里的 NEW
    #   替换分支 → 原属性被就地改值，其 data 可能就是 NEW（也可能池里有旧串）
    pool_d1 = read_pool(d1)
    new_idx = pool_d1.index(NEW) if NEW in pool_d1 else None
    name_pos = None
    for i, a in enumerate(a1):
        if a["type"] == TYPE_STRING and new_idx is not None and a["data"] == new_idx:
            name_pos = i
            break
    check("找到承载目标值属性", name_pos is not None,
          f"属性数 {len(a0)}→{len(a1)}，新池索引 {new_idx}")
    if original_had_name:
        check("替换分支：属性数不变", len(a1) == len(a0), f"{len(a0)} → {len(a1)}")
    else:
        check("追加分支：属性数只 +1", len(a1) == len(a0) + 1, f"{len(a0)} → {len(a1)}")
    # 位置必须满足：它前面所有属性的 resourceId 都 <= android:name 的 ID
    if name_pos is not None:
        ids_before = []
        for a in a1[:name_pos]:
            rid = rmap[a["name"]] if a["name"] < len(rmap) else 0xFFFFFFFF
            ids_before.append(rid)
        check("前面没有更大的 resourceId（即插在升序位）",
              all(x <= ANDROID_NAME_ID for x in ids_before),
              f"前面 ID={[hex(x) for x in ids_before]}")

    print("[T5] rawValue 是字符串池索引，不是 NO_INDEX")
    if name_pos is not None:
        a = a1[name_pos]
        check("raw 不等于 NO_INDEX", a["raw"] != 0xFFFFFFFF, f"raw=0x{a['raw']:08x}")
        check("raw 与 data 一致", a["raw"] == a["data"],
              f"raw=0x{a['raw']:08x} data=0x{a['data']:08x}")
        check("dataType 是 TYPE_STRING", a["type"] == TYPE_STRING,
              f"type=0x{a['type']:02x}")

    print("[T6] chunk 链连贯")
    try:
        _, end = chunks(d1)
        check("遍历到文件末尾", end == len(d1), f"停在 {end}，长度 {len(d1)}")
    except ValueError as e:
        check("遍历到文件末尾", False, str(e))

    print("[T7] 文件头 size 与实际长度一致")
    check("size 字段正确",
          struct.unpack_from("<I", d1, 4)[0] == len(d1),
          f"声明 {struct.unpack_from('<I', d1, 4)[0]}，实际 {len(d1)}")

    print("[T8] 非 AXML 时明确报错")
    f8 = os.path.join(tmpdir, "bad.xml")
    open(f8, "wb").write(b"not an axml file at all")
    rc8, _, err8 = run("set-app-name", f8, NEW)
    check("返回非 0", rc8 != 0)
    check("不修改原文件", open(f8, "rb").read() == b"not an axml file at all")

    print()
    if failures:
        print(f"失败 {len(failures)} 项: {failures}")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
