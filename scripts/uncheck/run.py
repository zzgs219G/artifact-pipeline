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
import importlib.util
import json
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

# APK Signing Block（v2/v3）的魔数：位于中央目录前 16 字节
SIG_BLOCK_MAGIC = b'APK Sig Block 42'


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

def _load_module(name, relpath):
    """加载文件名带连字符、不能常规 import 的模块。

    与 inject.py 的同名函数保持一致的语义（路径按本文件位置推算）。
    """
    # relpath 形如 ('scripts', 'uncheck', 'zip-reuse.py')，相对**仓库根**。
    # _HERE = scripts/uncheck，所以往上退两级。
    root = os.path.dirname(os.path.dirname(_HERE))
    path = os.path.join(root, *relpath)
    if not os.path.isfile(path):
        raise RuntimeError(f'找不到依赖模块: {path}')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_sig_block(apk_path):
    """取出 APK 的 APK Signing Block（v2/v3 签名块）原始字节。

    返回 (block_bytes, block_offset) 或 (None, None)。

    ==== 为什么必须保留（2026-11-24 真机 SIGBUS 事故）====
    加固的 libnc.so 用 `k_so = HKDF(master, SHA256(certDER), pkg)` 解 .ncx
    锁箱段，其中 certDER 是从**自己所在 APK 的 Signing Block** 里读的。
    去校验的 libusign.so 又把 `open(base.apk)` 重定向到 origin.apk。

    原先 rebuild_apk 用 zipfile 逐条目重写 → Signing Block 不是条目、
    必然丢失 → origin.apk 没有签名块 → libnc.so 读不到证书 → k_so 错
    → .ncx 解出乱码 → 跳野地址 → SIGBUS（栈上留「不匹配（fail-closed -12）」）。

    注意：Signing Block 里的签名是对**原包内容**签的，放进改过的包并不能
    让包通过系统校验（装机时本来就要重签）。这里保留它，只是为了满足
    「App/native 从自己 APK 里读证书」这条运行期路径 —— 证书 DER 与包内容
    无关，所以取到的值是正确的。
    """
    with open(apk_path, 'rb') as f:
        data = f.read()
    eocd = data.rfind(b'PK\x05\x06')
    if eocd < 0:
        return None, None
    cd_off = struct.unpack_from('<I', data, eocd + 16)[0]
    if cd_off < 32 or cd_off > len(data):
        return None, None
    if data[cd_off - 16:cd_off] != SIG_BLOCK_MAGIC:
        return None, None
    size_total = struct.unpack_from('<Q', data, cd_off - 24)[0]
    if size_total + 8 > cd_off:
        return None, None
    start = cd_off - 8 - size_total
    return data[start:cd_off], start


def rebuild_apk(src_apk, dst_apk, replace_entries):
    """按原包条目顺序重打包，替换/新增指定条目。

    replace_entries: {entry_name: bytes}

    保留原条目的压缩方式（STORED/DEFLATED）与时间戳 —— dex 若是 STORED，
    保持 STORED 可以维持原对齐假设；改为 DEFLATED 会改变体积但不影响加载。

    另外**把原包的 APK Signing Block 原样写回**（中央目录之前）。
    zipfile 无法表达签名块（它不是条目），所以这里手工拼接：
    [条目数据] + [Signing Block] + [中央目录] + [EOCD]。
    见 _extract_sig_block 的注释说明为什么必须保留。
    """
    sig_block, _ = _extract_sig_block(src_apk)

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
                # origin.apk / .so 用 STORED：体积大且运行时需要随机访问
                if name.endswith('.apk') or name.endswith('.so'):
                    zi.compress_type = zipfile.ZIP_STORED
                else:
                    zi.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(zi, data)

    if sig_block:
        # ⚠️ 这里**不能**注入签名块（2026-11-24 实测）：
        #   后续 zipalign 会重写整个 ZIP，把不认识的 Signing Block 丢掉。
        #   正确顺序：zipalign → 再注入（见 inject_sig_block 的调用点）。
        pass


def inject_sig_block(dst_apk, src_apk):
    """从 src_apk 取 Signing Block 并注入 dst_apk（必须在 zipalign 之后调用）。

    返回 True 表示注入了，False 表示源包没有签名块。
    """
    sig_block, _ = _extract_sig_block(src_apk)
    if not sig_block:
        return False
    _inject_sig_block(dst_apk, sig_block)
    return True


def _inject_sig_block(apk_path, sig_block):
    """把 Signing Block 插到中央目录之前，并修正 EOCD 的 CD offset。

    ZIP 布局：[条目...][中央目录][EOCD]
    插入后：  [条目...][Signing Block][中央目录][EOCD]
    → CD 与 EOCD 整体后移 len(sig_block)，EOCD 里的 CD offset 要相应加上。
    """
    with open(apk_path, 'rb') as f:
        data = f.read()
    eocd = data.rfind(b'PK\x05\x06')
    if eocd < 0:
        raise RuntimeError(f'{apk_path}: 找不到 EOCD')
    cd_off = struct.unpack_from('<I', data, eocd + 16)[0]
    if data[cd_off - 16:cd_off] == SIG_BLOCK_MAGIC:
        return          # 已经有签名块（幂等）

    new_cd_off = cd_off + len(sig_block)
    if new_cd_off > 0xFFFFFFFF:
        raise RuntimeError('注入签名块后 CD offset 超出 32 位，暂不支持 >4GB 包')

    out = bytearray()
    out += data[:cd_off]                 # 条目数据
    out += sig_block                     # ← Signing Block
    out += data[cd_off:eocd]             # 原中央目录
    new_eocd = bytearray(data[eocd:])
    struct.pack_into('<I', new_eocd, 16, new_cd_off)
    out += new_eocd

    with open(apk_path, 'wb') as f:
        f.write(out)


def zipalign(src, dst):
    """对齐。找不到 zipalign 就原样拷，并明确告知（不静默当作已对齐）。"""
    for cand in (os.environ.get('SIGFIX_ZIPALIGN'),
                 shutil.which('zipalign'),
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

def run(in_apk, out_apk, keep_work=None, api=30, full_origin=False):
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
            # -r：不反编译资源，**Manifest 保持二进制**。
            # 必须保持二进制的原因：我们要用 axml_edit 改写 android:name，
            # 它只能处理 AXML；apktool 解成文本后还得编回去，而本地没有可用的
            # aapt2（实测 Termux 下 apktool b 会报 aapt2 wrapper 错误）。
            # 代价：注入器不能用正则读文本 Manifest，改用 axml_edit.parse_manifest
            # 直接解析二进制。
            ['java', '-jar', APKTOOL, 'd', '-r', '-f', '-o', decompiled, in_apk],
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

        # inject.py 把自己的解析结果写成 json，供后续步骤使用
        comp_path = os.path.join(decompiled, 'uncheck-components.json')
        with open(comp_path, encoding='utf-8') as f:
            comp = json.load(f)
        cert_b64 = comp.get('certB64', '')
        original_app_java = comp.get('originalApp', '')
        if not cert_b64:
            raise RuntimeError('inject.py 没返回证书（certB64 为空）')

        # 3) 找出「本次被改过的」smali 目录 —— 全部要重新汇编。
        #
        # ⚠️ 这是本模块最严重的一处 bug（2026-11-21 真机实测暴露）：
        #   原实现只汇编「载荷类所在目录」（inject.py 新建的 smali_classesN/），
        #   而 inject.py 同时还会往**原有 smali 目录**里的 LAUNCHER/Application
        #   插调用。那些被插了调用点的目录没有被重新汇编，于是产物里：
        #     · classes.dex  = 原包未修改的旧版本（没有 invoke）
        #     · classes2.dex = 载荷类（没人调用它）
        #   → 载荷完整躺在 APK 里，但永远不会被执行，校验照旧通过/照旧弹警告。
        #   症状极具迷惑性：注入器日志显示「注入 1 个调用点」，
        #   产物自检显示「载荷在位」，装机后却完全没效果。
        #
        #   修法：按「注入标记」而不是按「载荷目录」来判定哪些目录需要重编。
        #   inject.py 在插调用点的同时写了 CALL_MARKER，用它做唯一判据。
        MARKER = '# nc-uncheck-call'
        changed_dirs = []
        for entry in sorted(os.listdir(decompiled)):
            if not SMALI_DIR_RE.match(entry):
                continue
            base = os.path.join(decompiled, entry)
            hit = False
            for root, _dirs, files in os.walk(base):
                for fn in files:
                    if not fn.endswith('.smali'):
                        continue
                    with open(os.path.join(root, fn), encoding='utf-8', errors='ignore') as f:
                        if MARKER in f.read():
                            hit = True
                            break
                if hit:
                    break
            # 载荷目录即使没有标记也要重编（它整个是新增的）
            if not hit and os.path.isdir(os.path.join(base, 'com', 'nc', 'uncheck')):
                hit = True
            if hit:
                changed_dirs.append(entry)

        if not changed_dirs:
            raise RuntimeError(
                '没有任何 smali 目录被改动 —— 注入没有生效，'
                '不要产出「看着成功但什么都没做」的包')

        payload_dirs = [d for d in changed_dirs
                        if os.path.isdir(os.path.join(decompiled, d,
                                                      'com', 'nc', 'uncheck'))]
        if len(payload_dirs) != 1:
            raise RuntimeError(f'载荷应恰好落在一个 dex 目录，实际: {payload_dirs}')
        injected_dir = payload_dirs[0]

        print(f'==> 需要重新汇编的目录: {changed_dirs}')
        print(f'    （载荷在 {injected_dir}/，另有 {len(changed_dirs)-1} 个被插了调用点）')

        # 4) 逐个汇编
        replaced = {}          # {dex_name: built_bytes}
        with zipfile.ZipFile(in_apk) as z:
            src_names = z.namelist()
            orig_dexes = [n for n in src_names
                          if n.startswith('classes') and n.endswith('.dex')]
            if not orig_dexes:
                raise RuntimeError('原包里没有任何 classes*.dex，不是可处理的 APK')
            ref_ver = read_dex_version(z.read(sorted(orig_dexes)[0]))[1]

        print('==> 汇编 smali')
        for d in changed_dirs:
            dex_name = 'classes.dex' if d == 'smali' \
                else 'classes' + d[len('smali_classes'):] + '.dex'
            out = os.path.join(work, dex_name)
            print(f'  · {d}/ → {dex_name}')
            print('    ' + assemble_smali(os.path.join(decompiled, d), out, api))

            with open(out, 'rb') as f:
                built = f.read()
            _, built_ver = read_dex_version(built)
            if built_ver != ref_ver:
                built = patch_dex_version(built, ref_ver)
                print(f'    dex 版本头 {built_ver:03d} → {ref_ver:03d}（与原包一致）')
            replaced[dex_name] = built

        # 6) 投放 payload.dex 到 assets
        #
        # 为什么它必须进 assets 而不是跟 smali 一起编：
        #   payload.dex 里的类要在运行时由 DexFile(String) 让 BootClassLoader
        #   加载，才能拿到"系统域"、反射访问隐藏 API。
        #   如果编进 App 自己的 dex，它就是应用域，反射照样被拦
        #   （实测 Android 17：hook 完全装不上）。
        #   引导器 SigFix 负责在运行时把它取出来写盘再加载。
        assets_dex = os.path.join(_HERE, 'payload', 'payload.dex')
        if not os.path.isfile(assets_dex):
            raise RuntimeError(
                f'缺 payload.dex: {assets_dex}\n'
                f'  先跑 bash scripts/uncheck/payload/build.sh')
        with open(assets_dex, 'rb') as f:
            payload_bytes = f.read()
        if payload_bytes[:4] != b'dex\n':
            raise RuntimeError('payload.dex magic 非法')
        replaced['assets/nc_sigfix/payload.dex'] = payload_bytes
        print(f'==> 投放 assets/nc_sigfix/payload.dex（{len(payload_bytes)} B）')

        # 6aa) native 层 IO 重定向（libusign.so）+ origin.apk
        #
        # 为什么必须加这层：部分 App 在 native 里直接
        # open("/data/app/.../base.apk") 解析 APK Signing Block 取证书，
        # Java 层三层 hook（CREATOR / PMS 代理 / signingInfo）全部无效。
        # 这里用 shadowhook 把 open/open64/openat/openat64 等 base.apk 路径
        # 重定向到 origin.apk（= 原签名 APK 完整副本）。
        lib_dir = os.path.join(_HERE, 'payload', 'lib')
        if os.environ.get('USIGN_NO_NATIVE') == '1':
            print('==> USIGN_NO_NATIVE=1：跳过 libusign.so 投放（诊断用）')
        else:
            for abi, so_name in (('arm64-v8a', 'libusign_arm64.so'),
                                 ('armeabi-v7a', 'libusign_armv7.so')):
                so_path = os.path.join(lib_dir, so_name)
                if os.path.isfile(so_path):
                    with open(so_path, 'rb') as f:
                        replaced[f'lib/{abi}/libusign.so'] = f.read()
                    print(f'==> 投放 lib/{abi}/libusign.so（{os.path.getsize(so_path)} B）')
                else:
                    print(f'⚠️ 缺 {so_path}，native 层不覆盖')

        # 6ab) origin.apk 不再作为普通条目投放 —— 改用数据复用打包
        #
        # 为什么（2026-11-23 实测结论，别重试 min-origin）：
        #   去签名校验需要 origin.apk（原签名 APK 副本），普通投放让体积翻倍。
        #   试过"最小化 origin.apk"（只留签名块 + 中央目录，4KB）→ 真机崩溃
        #   NoClassDefFoundError：IO 重定向会连 ART 的 dex 懒加载一起劫持，
        #   min-origin 的 ZIP 骨架合法但条目全空，ART 以为拿到正确 APK 却读不到
        #   内部 dex。详见 docs/签名校验接手文档.md §6 待办 2。
        #
        # 正解 = 数据复用（FancyBypass 的做法，实测反推）：
        #   origin.apk 的数据区与"整个 APK 的字节"共享，物理上只存一份。
        #   本文件的 origin 投放改为标记，由 zip-reuse.py 在最后一步完成，
        #   见下方「数据复用打包」段。
        need_origin_reuse = True


        # 6a) 投放配置文件：证书 + 原 Application 类名。
        #
        # 这些是**唯一的目标相关数据**，全部集中在这份小 JSON 里。
        # dex 因此完全静态（不含任何证书/类名），可复用、可下载、可缓存。
        import json as _json
        cfg = {
            'cert': cert_b64,
            'originalApp': original_app_java or '',
        }
        if os.environ.get('USIGN_NO_SIGFIX') == '1':
            cfg['cert'] = ''   # 诊断：让 SigFix.install 读不到证书而提前 return（Java hook 全禁）
        cfg_bytes = _json.dumps(cfg, ensure_ascii=False).encode('utf-8')
        replaced['assets/nc_sigfix/sigfix.json'] = cfg_bytes
        print(f'==> 投放 assets/nc_sigfix/sigfix.json'
              f'（cert {len(cert_b64)} 字符，originalApp='
              f'{original_app_java or "(无)"}）')

        # 6b) 把解包目录里**改写过的 AndroidManifest.xml** 写回产物。
        #
        # ⚠️ 这一步漏了会怎样（实测踩过）：签名后的包里 Manifest 仍是原内容，
        #    系统照旧实例化原 Application，我们的 SigFixApp 形同虚设，
        #    日志里完全没有 SigFixApp 的输出，只有注入的 onCreate 在跑。
        #    inspect 产物时表现为 get-app-name 返回原类名。
        mf = os.path.join(decompiled, 'AndroidManifest.xml')
        if not os.path.isfile(mf):
            raise RuntimeError(f'解包目录里没有 AndroidManifest.xml: {mf}')
        with open(mf, 'rb') as f:
            mf_bytes = f.read()
        if mf_bytes[:2] != b'\x03\x00':
            raise RuntimeError(
                '解包出的 AndroidManifest.xml 不是二进制 AXML。\n'
                '  改 Manifest 的流程要求 apktool 解包时带 -r（保持二进制）。')
        if os.environ.get('USIGN_NO_MANIFEST') == '1':
            print('==> USIGN_NO_MANIFEST=1：不写回 Manifest（保持原 Application，SigFixApp 代理禁用）')
        else:
            replaced['AndroidManifest.xml'] = mf_bytes
            print(f'==> 写回改写后的 AndroidManifest.xml（{len(mf_bytes)} B）')

        # 7) 组装
        #
        # 分两步：
        #   a) 先用常规方式产出「不含 origin.apk 的中间包」（业务补丁/payload/so 都在里面）
        #   b) 再用 zip-reuse 把中间包的全字节作为 origin.apk 的数据共享进去
        #
        # 为什么不在 rebuilt 里直接加 origin：常规 ZIP 写入器无法让两个条目
        # 共享同一片物理字节，只能复制一份 → 体积翻倍。
        print('==> 组装 APK')
        tmp_apk = os.path.join(work, 'aligned_in.apk')
        rebuild_apk(in_apk, tmp_apk, replaced)
        for name in sorted(replaced):
            kind = '替换' if name in src_names else '新增'
            print(f'    {kind} {name}（{len(replaced[name])} B）')

        if need_origin_reuse:
            # 复用前先对齐中间包：zipalign 会重写 ZIP，必须在"还没被
            # 重叠共享"的时候做。复用之后只改 offset 表、不动数据，
            # 对齐属性自然保留。
            aligned_in = os.path.join(work, 'aligned_before_reuse.apk')
            used = zipalign(tmp_apk, aligned_in)
            if used:
                print(f'==> zipalign（复用前）: {used}')
                tmp_apk = aligned_in
            else:
                # ⚠️ 不能"警告后继续"：未对齐的中间包 + 数据复用平移，
                # resources.arsc 必然落在非 4 倍数 → 装机被拒。
                # 这是必需依赖，缺了就该在构建期失败，不要产出一个装不上的包。
                raise RuntimeError(
                    '找不到 zipalign —— 无法保证 resources.arsc 的 4 字节对齐。\n'
                    '  Android R+ 装机要求：resources.arsc 必须 STORED 且 4 字节对齐。\n'
                    '  修复：安装 Android build-tools 并确保 zipalign 在 PATH，\n'
                    '        或用 SIGFIX_ZIPALIGN=<path> 指定。')

            # ⚠️ Signing Block 必须在 zipalign **之后**注入：
            #    zipalign 重写整个 ZIP，会丢掉它不认识的 Signing Block
            #    （2026-11-24 实测：先在 rebuild_apk 里注入 → zipalign 后消失）。
            #    注入点选在这里，是因为 origin.apk 的数据区 = 中间包字节，
            #    必须在复用**之前**注入，origin.apk 里才会带上签名块。
            if inject_sig_block(tmp_apk, in_apk):
                print('==> 注入 APK Signing Block（origin.apk 需要它读证书）')
            else:
                print('⚠️ 输入包没有 APK Signing Block（v1-only？），origin.apk 将不含签名块')

            print('==> 数据复用打包（origin.apk 与整包共享字节）')
            reuse_mod = _load_module('zip_reuse', ('scripts', 'uncheck', 'zip-reuse.py'))
            reused = os.path.join(work, 'reused.apk')
            st = reuse_mod.build(tmp_apk, reused)
            print(f'    中间包 {st["src_size"]/1e6:.2f} MB '
                  f'→ 复用包 {st["out_size"]/1e6:.2f} MB '
                  f'（仅增加 {st["out_size"]-st["src_size"]} B 头开销）')
            probs = reuse_mod.verify(reused)
            if probs:
                raise RuntimeError('数据复用自检失败: ' + '; '.join(probs))
            print('    自检通过：origin.apk 是完整 APK，各条目可读')
            tmp_apk = reused

        # 8) 输出
        #
        # ⚠️ 数据复用包**绝不能 zipalign**。
        #
        # 实测（2026-11-23）：zipalign 会重写整个 ZIP，把"重叠共享"的字节
        # 展开成两份独立数据 —— 127.96MB 的复用包被撑回 255.6MB，
        # 数据复用完全失效。
        #
        # 对齐已在**中间包**阶段做过（rebuild_apk 后的 tmp_apk 若需要对齐，
        # 由 zipalign 在复用前处理）；复用只是改 ZIP 的 offset 表，
        # 条目数据本身没有移动，对齐属性保留。
        #
        # 若 --full-origin（不复用），则照常对齐。
        if need_origin_reuse:
            shutil.copyfile(tmp_apk, out_apk)
            print('==> 数据复用包跳过 zipalign（对齐会破坏重叠共享结构）')
        else:
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
    full_origin = False
    i = 3
    while i < len(argv):
        if argv[i] == '--keep-work' and i + 1 < len(argv):
            keep = argv[i + 1]
            i += 2
        elif argv[i] == '--api' and i + 1 < len(argv):
            api = int(argv[i + 1])
            i += 2
        elif argv[i] == '--full-origin':
            # origin.apk 用全量副本（回退方案）：体积翻倍，但兼容任何读法
            full_origin = True
            i += 1
        else:
            print(f'未知参数: {argv[i]}', file=sys.stderr)
            return 2
    try:
        run(in_apk, out_apk, keep, api, full_origin)
    except (RuntimeError, ValueError) as e:
        print(f'❌ {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
