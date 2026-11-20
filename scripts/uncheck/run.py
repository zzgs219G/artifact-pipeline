#!/usr/bin/env python3
"""run.py — 一键去签名校验（端到端：APK 进 → 未签名 APK 出）

CLI 契约（与 AGENTS.md §4「模块 = 独立脚本 + <输入> <输出> [参数]」一致）:
  run.py <输入.apk> <输出.apk> [--keep-work DIR] [--api N]

它做的事:
  1. apktool 解包（默认解码 Manifest 为文本，注入器需要）
  2. 调 inject.py：提原证书 → 烘焙 → 选落点 → 插桩
  3. dexlib2 汇编所有 smali → classes.dex
  4. 还原 dex 版本头（原包 035 / 汇编器默认 040，不还原旧系统会崩）
  5. 纯 zip 组装：原包全部条目 + 替换 classes.dex（+ 新增 classesN.dex）
  6. zipalign 对齐
  → 输出未签名 APK，由使用者自行 apksigner 签

为什么第 3 步不用 `apktool b`:
  - apktool b 会重新编译资源（aapt2），在非 x86 环境/精简环境里经常跑不起来；
  - 本模块只改 dex，资源一个字节都没动，没必要重编。
  - 直接替换 classes.dex 是零风险且最快的路径。

为什么第 5 步要「原包全部条目 + 只换 dex」而不是用 apktool 产物:
  - 保持资源、assets、签名块之外的一切逐字节不变；
  - 不引入 apktool 的保真风险（报错八/十八那类）。

⚠️ 产物未签名。装上之前必须自己签（本模块不碰 keystore）。
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
APKTOOL = os.path.join(_ROOT, 'tools', 'apktool.jar')

SMALI_DIR_RE = re.compile(r'^smali(?:_classes\d+)?$')


# ───────────────────────── dex 版本头 ─────────────────────────

def read_dex_version(dex_bytes):
    """返回 (magic8, version:int)。dex 头固定 `dex\\nNNN\\0`。"""
    if len(dex_bytes) < 8 or dex_bytes[:4] != b'dex\n':
        raise ValueError('不是合法 dex（magic 不匹配）')
    ver = dex_bytes[4:7]
    if not ver.isdigit():
        raise ValueError(f'dex 版本字段非法: {ver!r}')
    return dex_bytes[:8], int(ver)


def patch_dex_version(dex_bytes, version):
    """把 dex 版本头改成指定值，并重算 checksum 与 SHA-1 签名。

    dex 头布局（与 scripts/repack/patch-dex-version.py 同语义）：
      0x00 magic(8) | 0x08 checksum(u32, adler32 of [12:]) | 0x0c signature(20, SHA1 of [32:])
    改 magic 后必须重算这两项，否则 ART 直接拒绝加载。
    """
    import hashlib
    import zlib

    buf = bytearray(dex_bytes)
    magic, cur = read_dex_version(buf)
    if cur == version:
        return dex_bytes
    buf[4:7] = f'{version:03d}'.encode('ascii')
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
    struct.pack_into('<I', buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


# ───────────────────────── smali 汇编（dexlib2，不碰 aapt2）─────────────────────────

VERIFIER_DIR = os.path.join(_HERE, 'tools')


def ensure_smali_verifier():
    """编译并缓存 VerifySmali（用 apktool.jar 里的 dexlib2 汇编 smali）。

    为什么需要它：apktool b 会重编资源，在 Termux 等环境跑不起来；
    我们只要 smali → dex 这一步，dexlib2 的 SmaliBuilder 就是 apktool 内部用的那个。
    """
    java_src = os.path.join(VERIFIER_DIR, 'VerifySmali.java')
    cls = os.path.join(VERIFIER_DIR, 'VerifySmali.class')
    if not os.path.isfile(java_src):
        raise RuntimeError(f'缺少 {java_src}（模块自带工具，不应缺失）')
    if os.path.isfile(cls) and os.path.getmtime(cls) >= os.path.getmtime(java_src):
        return cls
    os.makedirs(VERIFIER_DIR, exist_ok=True)
    r = subprocess.run(['javac', '-cp', APKTOOL, '-d', VERIFIER_DIR, java_src],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'编译 VerifySmali 失败:\n{r.stderr}')
    return cls


def assemble_smali(decompiled_dir, out_dex, api):
    """把所有 smali_classesN/ 汇编成一个或多个 dex。

    单 dex 输出（本模块注入量小，原包通常也只有 1 个 dex 需要产出）。
    若原包是多 dex，调用方应只汇编「我们改过的那个 dex 目录」——
    见 run.py 的实际用法：只重编被注入的那个目录。
    """
    cls = ensure_smali_verifier()
    cp = APKTOOL + os.pathsep + VERIFIER_DIR
    r = subprocess.run(
        ['java', '-cp', cp, 'VerifySmali', decompiled_dir, out_dex, str(api)],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'smali 汇编失败:\n{r.stdout}\n{r.stderr}')
    return r.stdout.strip()


# ───────────────────────── zip 组装 ─────────────────────────

def rebuild_apk(src_apk, dst_apk, replace_entries):
    """按原包条目顺序重打包，替换/新增指定条目。

    replace_entries: {entry_name: bytes}

    保留原条目的压缩方式（STORED/DEFLATED）与时间戳 —— dex 若是 STORED，
    保持 STORED 可以维持原对齐假设；改为 DEFLATED 会改变体积但不影响加载。
    """
    with zipfile.ZipFile(src_apk) as zin:
        infos = zin.infolist()
        names = {i.filename for i in infos}
        with zipfile.ZipFile(dst_apk, 'w') as zout:
            for info in infos:
                data = zin.read(info.filename)
                if info.filename in replace_entries:
                    data = replace_entries[info.filename]
                zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.internal_attr = info.internal_attr
                zi.create_system = info.create_system
                zout.writestr(zi, data)
            # 新增条目（原包里没有的）
            for name, data in replace_entries.items():
                if name in names:
                    continue
                zi = zipfile.ZipInfo(name)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(zi, data)


def zipalign(src, dst):
    """对齐。找不到 zipalign 就原样拷，并明确告知（不静默当作已对齐）。"""
    for cand in (shutil.which('zipalign'),
                 os.path.expanduser('~/逆向工具/bin/zipalign'),
                 os.path.expanduser('~/逆向工具/android-tools/zipalign')):
        if cand and os.path.isfile(cand):
            r = subprocess.run([cand, '-f', '4', src, dst], capture_output=True, text=True)
            if r.returncode == 0:
                return cand
            raise RuntimeError(f'zipalign 失败:\n{r.stdout}\n{r.stderr}')
    shutil.copyfile(src, dst)
    return None


# ───────────────────────── 主流程 ─────────────────────────

def run(in_apk, out_apk, keep_work=None, api=30):
    if not os.path.isfile(in_apk):
        raise RuntimeError(f'输入 APK 不存在: {in_apk}')
    if not os.path.isfile(APKTOOL):
        raise RuntimeError(f'缺少 apktool.jar: {APKTOOL}')

    work = keep_work or tempfile.mkdtemp(prefix='uncheck-')
    decompiled = os.path.join(work, 'd')
    os.makedirs(work, exist_ok=True)

    try:
        # 1) 解包（不带 -r：需要文本 Manifest 供注入器解析）
        print('==> 解包')
        r = subprocess.run(
            ['java', '-jar', APKTOOL, 'd', '-f', '-o', decompiled, in_apk],
            capture_output=True, text=True)
        if r.returncode != 0 or not os.path.isdir(decompiled):
            raise RuntimeError(f'apktool 解包失败:\n{r.stdout}\n{r.stderr}')

        # 2) 注入
        print('==> 注入载荷')
        r = subprocess.run(
            [sys.executable, os.path.join(_HERE, 'inject.py'), decompiled, '--apk', in_apk],
            capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            raise RuntimeError(f'注入失败:\n{r.stderr}')

        # 3) 找出被注入的 smali 目录（载荷落在哪个就重编哪个）
        injected_dirs = []
        for entry in sorted(os.listdir(decompiled)):
            if not SMALI_DIR_RE.match(entry):
                continue
            p = os.path.join(decompiled, entry, 'com', 'nc', 'uncheck')
            if os.path.isdir(p):
                injected_dirs.append(entry)
        if not injected_dirs:
            raise RuntimeError('注入后找不到载荷所在 smali 目录（注入逻辑有 bug）')
        if len(injected_dirs) > 1:
            raise RuntimeError(f'载荷跨多个 dex 目录，不支持: {injected_dirs}')
        injected_dir = injected_dirs[0]
        dex_name = 'classes.dex' if injected_dir == 'smali' \
            else 'classes' + injected_dir[len('smali_classes'):] + '.dex'
        print(f'==> 载荷落在 {injected_dir}/ → {dex_name}')

        # 4) 汇编该目录
        print('==> 汇编 smali')
        new_dex = os.path.join(work, dex_name)
        print(assemble_smali(os.path.join(decompiled, injected_dir), new_dex, api))

        # 5) 版本头对齐原 dex
        with zipfile.ZipFile(in_apk) as z:
            if dex_name not in z.namelist():
                raise RuntimeError(
                    f'原包里没有 {dex_name}，但注入落点是 {injected_dir}/。\n'
                    f'  这是「新建 dex」场景，本版未实现（需把新 dex 命名为 n+1 并追加）。')
            orig_dex = z.read(dex_name)
        _, orig_ver = read_dex_version(orig_dex)
        with open(new_dex, 'rb') as f:
            built = f.read()
        _, built_ver = read_dex_version(built)
        if built_ver != orig_ver:
            built = patch_dex_version(built, orig_ver)
            with open(new_dex, 'wb') as f:
                f.write(built)
            print(f'==> dex 版本头 {built_ver:03d} → {orig_ver:03d}（与原始一致）')
        else:
            print(f'==> dex 版本头 {built_ver:03d}（与原始一致，无需改）')

        # 6) 组装
        print('==> 组装 APK')
        tmp_apk = os.path.join(work, 'aligned_in.apk')
        rebuild_apk(in_apk, tmp_apk, {dex_name: built})

        # 7) 对齐
        used = zipalign(tmp_apk, out_apk)
        if used:
            print(f'==> zipalign: {used}')
        else:
            print('⚠️ 未找到 zipalign，产物未对齐（apksigner 签之前请自行 zipalign）')

        print(f'\n✅ 完成: {out_apk} ({os.path.getsize(out_apk)} B)')
        print('   产物未签名 —— 请用你自己的 keystore 签:')
        print(f'   apksigner sign --ks <你的.jks> --out <最终.apk> {out_apk}')
        return out_apk
    finally:
        if keep_work is None:
            shutil.rmtree(work, ignore_errors=True)


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    in_apk, out_apk = argv[1], argv[2]
    keep = None
    api = 30
    i = 3
    while i < len(argv):
        if argv[i] == '--keep-work' and i + 1 < len(argv):
            keep = argv[i + 1]
            i += 2
        elif argv[i] == '--api' and i + 1 < len(argv):
            api = int(argv[i + 1])
            i += 2
        else:
            print(f'未知参数: {argv[i]}', file=sys.stderr)
            return 2
    try:
        run(in_apk, out_apk, keep, api)
    except (RuntimeError, ValueError) as e:
        print(f'❌ {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
