#!/usr/bin/env python3
"""test_dex_capacity.py — dex-capacity.py 的回归测试（纯 stdlib，秒级）。

【为什么补这个测试】
  报错五十九（2026-11-04）：注入类硬编码写进 smali/（= classes.dex），
  而真实大型包经 R8 编译后 classes.dex 方法数贴顶（实测 65519/65536，
  余量 17），注入直接让 smali 汇编期报
  "Unsigned short value out of range: 65536"（Instruction35c/16 位方法索引）。
  报错落在哪个类完全随机（同包三次分别炸在 beizi/ad/e$a、
  media3/Tracks$Group、camera/ExifData$WhiteBalanceMode），
  所以必须靠容量判定前置拦截，不能等汇编器报错。

【测什么】
  1. dex header 计数读取（真实构造的 dex 字节 + 异常输入）
  2. smali 目录名 → dex 文件名映射（与 apktool ApkBuilder 逐字对齐）
  3. n+1 命名（含不连续序号、非常规命名）
  4. 落点决策三分支：首选够用 / 本轮自建复用 / 新建 n+1
  5. 保守估算系数（无 APK 时不许低估占用）
  6. SMALI_DIR_RE 与其余三份副本一致（报错七铁律）

用法: python3 scripts/repack/tests/test_dex_capacity.py
"""
import importlib.util
import os
import struct
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TARGET = os.path.join(ROOT, "scripts", "repack", "dex-capacity.py")

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  ✅ {msg}")


def bad(msg):
    global FAIL
    FAIL += 1
    print(f"  ❌ {msg}", file=sys.stderr)


def check(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        bad(f"{name}{(' — ' + detail) if detail else ''}")


def load():
    spec = importlib.util.spec_from_file_location("dex_capacity", TARGET)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


DC = load()


def make_dex_header(methods, strings):
    """造一段足够长的假 dex 头部（前 112 字节被本模块读取）。"""
    b = bytearray(112)
    b[0:8] = b'dex\n035\0'
    struct.pack_into('<I', b, 56, strings)
    struct.pack_into('<I', b, 88, methods)
    return bytes(b)


def make_apk(path, dex_specs):
    """dex_specs: {'classes.dex': (meth, str), ...}"""
    with zipfile.ZipFile(path, 'w') as z:
        for name, (meth, strs) in dex_specs.items():
            z.writestr(name, make_dex_header(meth, strs))
        z.writestr('AndroidManifest.xml', b'x')
    return path


def make_decompiled(root, dirs):
    """dirs: {'smali': [方法定义数], ...}"""
    for name, n_methods in dirs.items():
        d = os.path.join(root, name, 'com', 'x')
        os.makedirs(d, exist_ok=True)
        body = []
        for i in range(n_methods):
            body.append(f'.method public static m{i}()V\n    return-void\n.end method\n')
        with open(os.path.join(d, 'C.smali'), 'w', encoding='utf-8') as fp:
            fp.write('.class public Lcom/x/C;\n.super Ljava/lang/Object;\n\n'
                     + '\n'.join(body))
    return root


def main():
    print("[1/6] dex header 计数读取")
    check("正常 dex 头解析出 (方法数, 字符串数)",
          DC.method_count_from_bytes(make_dex_header(65519, 75688)) == (65519, 75688))
    check("非 dex 魔数返回 None",
          DC.method_count_from_bytes(b'PK\x03\x04' + b'\0' * 200) is None)
    check("头部不足 112 字节返回 None",
          DC.method_count_from_bytes(make_dex_header(1, 1)[:80]) is None)
    check("空字节返回 None", DC.method_count_from_bytes(b'') is None)

    print("[2/6] smali 目录名 → dex 文件名（对齐 apktool ApkBuilder）")
    # ApkBuilder: "smali" → classes.dex；其余取【首个 '_' 之后】整体 + ".dex"
    cases = {
        'smali': 'classes.dex',
        'smali_classes2': 'classes2.dex',
        'smali_classes16': 'classes16.dex',
        'smali_classes99': 'classes99.dex',
    }
    for dir_name, want in cases.items():
        got = DC.smali_dir_to_dex_name(dir_name)
        check(f"{dir_name} → {want}", got == want, f"实得 {got}")
    try:
        DC.smali_dir_to_dex_name('lib')
        bad("非 smali 目录名应抛 ValueError")
    except ValueError:
        ok("非 smali 目录名抛 ValueError")

    print("[3/6] n+1 目录命名")
    with tempfile.TemporaryDirectory() as t:
        make_decompiled(t, {'smali': 1, 'smali_classes2': 1, 'smali_classes15': 1})
        check("连续序号 → smali_classes16",
              DC.next_smali_dir_name(t) == 'smali_classes16')

    with tempfile.TemporaryDirectory() as t:
        # 不连续：只有 classes/smali_classes2/smali_classes7
        make_decompiled(t, {'smali': 1, 'smali_classes2': 1, 'smali_classes7': 1})
        check("不连续序号取最大+1 → smali_classes8",
              DC.next_smali_dir_name(t) == 'smali_classes8')

    with tempfile.TemporaryDirectory() as t:
        make_decompiled(t, {'smali': 1})
        check("只有 smali/ → smali_classes2",
              DC.next_smali_dir_name(t) == 'smali_classes2')

    with tempfile.TemporaryDirectory() as t:
        make_decompiled(t, {'smali': 1, 'smali_classes2': 1})
        os.makedirs(os.path.join(t, 'smali_classes3'))
        check("已存在空 classes3 目录仍取最大+1 → smali_classes4"
              "（不捡现成空目录）",
              DC.next_smali_dir_name(t) == 'smali_classes4')

    print("[4/6] 落点决策三分支")
    with tempfile.TemporaryDirectory() as t:
        # classes.dex 还很空 → 用首选 smali/
        make_decompiled(t, {'smali': 100, 'smali_classes2': 10})
        apk = make_apk(os.path.join(t, 'in.apk'),
                       {'classes.dex': (40178, 5000), 'classes2.dex': (10, 10)})
        got = DC.pick_target_dir(t, 25, apk, log=lambda *_: None)
        check("首选余量充足 → 用 smali/", got == 'smali', f"实得 {got}")
        check("未新建多余目录",
              not os.path.isdir(os.path.join(t, 'smali_classes3')))
        check("未写标记文件（复用了原有 dex，无需标记）",
              not os.path.exists(os.path.join(t, DC.MARKER_FILE)))

    with tempfile.TemporaryDirectory() as t:
        # classes.dex 贴顶（真实囤次元包形态）→ 必须新建 classes16
        dirs = {'smali': 10, 'smali_classes2': 1}
        for i in range(3, 16):
            dirs[f'smali_classes{i}'] = 1
        make_decompiled(t, dirs)
        specs = {'classes.dex': (65519, 75688)}
        for i in range(2, 16):
            specs[f'classes{i}.dex'] = (1, 1)
        apk = make_apk(os.path.join(t, 'in.apk'), specs)
        got = DC.pick_target_dir(t, 40, apk, log=lambda *_: None)
        check("classes.dex 贴顶 → 新建 smali_classes16", got == 'smali_classes16',
              f"实得 {got}")
        check("新建目录已落盘", os.path.isdir(os.path.join(t, 'smali_classes16')))
        check("标记文件记录了落点",
              DC._read_marker(t) == 'smali_classes16')

        # 第二轮（同一条流水线的另一处注入）必须复用，不各建一个
        got2 = DC.pick_target_dir(t, 30, apk, log=lambda *_: None)
        check("本轮第二次调用复用同一 dex（不重复新建）",
              got2 == 'smali_classes16', f"实得 {got2}")
        dirs_after = sorted(d for d in os.listdir(t) if d.startswith('smali'))
        check("解包目录里没有多出第二个新建 dex",
              dirs_after.count('smali_classes16') == 1
              and 'smali_classes17' not in dirs_after, str(dirs_after))

    with tempfile.TemporaryDirectory() as t:
        # 空 dex 有 6 万空位，但**不许**去占（可能是别人壳的 dex）
        make_decompiled(t, {'smali': 10, 'smali_classes2': 1})
        apk = make_apk(os.path.join(t, 'in.apk'),
                       {'classes.dex': (65519, 75688), 'classes2.dex': (3, 8)})
        got = DC.pick_target_dir(t, 40, apk, log=lambda *_: None)
        check("空 classes2 不被占用（避免踩别的壳）→ 新建 classes3",
              got == 'smali_classes3', f"实得 {got}")

    print("[5/6] 无 APK 时的保守估算（不许低估占用）")
    with tempfile.TemporaryDirectory() as t:
        make_decompiled(t, {'smali': 1000})
        stats = DC.measure(t, None)
        m = stats['smali']['methods']
        check(f"扫描路径按 ×{DC.SCAN_ESTIMATE_FACTOR} 上浮（1000 → {m}）",
              m == int(1000 * DC.SCAN_ESTIMATE_FACTOR), f"实得 {m}")
        check("扫描结果标记为非精确", stats['smali']['exact'] is False)
        check("实测系数覆盖真实包的上界（1.25 >= 最大实测 1.226）",
              DC.SCAN_ESTIMATE_FACTOR >= 1.226)

    with tempfile.TemporaryDirectory() as t:
        make_decompiled(t, {'smali': 10})
        apk = make_apk(os.path.join(t, 'in.apk'), {'classes.dex': (65519, 1)})
        stats = DC.measure(t, apk)
        check("有 APK 时用 header 精确值", stats['smali']['methods'] == 65519)
        check("精确值标记 exact=True", stats['smali']['exact'] is True)

    with tempfile.TemporaryDirectory() as t:
        make_decompiled(t, {'smali': 5})
        os.makedirs(os.path.join(t, 'smali_classes2'))
        apk = make_apk(os.path.join(t, 'in.apk'), {'classes.dex': (5, 5)})
        stats = DC.measure(t, apk)
        check("新建的空 dex 记为 0（精确，不需上浮）",
              stats['smali_classes2']['methods'] == 0
              and stats['smali_classes2']['exact'] is True)

    print("[6/6] SMALI_DIR_RE 单一真相 + 各消费方一致性（报错七铁律）")
    import re
    # 真相源：inject-loadlib.py 定义正则字面量；其余模块通过 import 复用，
    # 不允许各自再写一份字面量（历史报错七：改写时转义漂移成静默收窄）。
    OWNER = os.path.join(ROOT, 'scripts', 'inject', 'inject-loadlib.py')
    lit = re.compile(r"SMALI_DIR_RE\s*=\s*re\.compile\(r'([^']+)'\)")
    with open(OWNER, encoding='utf-8') as fp:
        m = lit.search(fp.read())
    check("inject-loadlib.py 持有正则字面量（单一真相源）", m is not None)
    truth = m.group(1) if m else None

    consumers = {
        'inject-javacheck.py': os.path.join(ROOT, 'scripts', 'sigcheck', 'javalink',
                                            'inject-javacheck.py'),
        'encrypt-strings.py': os.path.join(ROOT, 'scripts', 'string-enc',
                                           'encrypt-strings.py'),
        'mark-native.py': os.path.join(ROOT, 'scripts', 'repack', 'mark-native.py'),
    }
    for name, path in consumers.items():
        with open(path, encoding='utf-8') as fp:
            text = fp.read()
        dup = lit.search(text)
        if dup:
            # 自带字面量的模块：必须与真相源逐字一致。
            # 报错七的真实形态就是"改写时转义漂移导致静默收窄"
            # （r'\d' → r'\\d'），不是"多写了一份"。
            check(f"{name} 自带字面量与真相源逐字一致",
                  dup.group(1) == truth, f"{dup.group(1)!r} vs {truth!r}")
        else:
            check(f"{name} 通过 import 引用 SMALI_DIR_RE",
                  re.search(r'SMALI_DIR_RE\s*=\s*\w+\.SMALI_DIR_RE', text) is not None)

    check("dex-capacity.py 的正则与真相源逐字一致",
          truth is not None and DC.SMALI_DIR_RE.pattern == truth,
          f"{DC.SMALI_DIR_RE.pattern!r} vs {truth!r}")

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
