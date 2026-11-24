#!/usr/bin/env python3
"""test-e2e.py — uncheck 端到端回归（夹具 = scripts/样本.apk，git 跟踪资产）

==== 为什么存在（2026-11-25，方案二）====
run.py/inject.py/zip-reuse.py 是 uncheck 的全部核心逻辑，但此前只有
test-axml.py（8 组 AXML 断言）——注入链路没有任何自动化回归，
改动只能靠手跑一次全流程（本次清理死参数时即如此）。
更深的动机：v0.9.50/v0.9.51 两个"构建绿真机炸"的教训说明，
**产物结构断言必须在构建期就有，而不是等真机首验**。

==== 覆盖（全链路 + 产物结构）====
T1  产物产出且 ≠ 原包（字节级）
T2  全部 dex 结构自洽（magic / adler32 checksum / SHA-1 签名）
T3  引导器 SigFixApp 在【新建】dex；调用点 SigFix 在【原有】dex
    （uncheck.sh 自检的同款判据——方向反了=注入没生效）
T4  Manifest android:name → SigFixApp（axml_edit 独立读回）
T5  数据复用包可解析（zip-reuse.verify：origin.apk 完整、条目可读、
    resources.arsc STORED 且 4 字节对齐 —— v0.9.51 教训面）
T6  APK Signing Block 已注入产物（锁箱/证书派生依赖它，v0.9.51 教训面）

==== 反向验证（已做，记录在案）====
改坏 inject.py 的 `SIGFIX_DESC = 'Lcom/nc/uncheck/SigFixX;'` → T3 红
（"调用点缺失"）；恢复 → 绿。产物级断言对注入逻辑的破坏是敏感的。

==== 依赖与 skip 纪律 ====
java + apktool.jar（仓库自带）+ zipalign（Android R+ 装机硬要求）。
缺任何一项 → **skip 并打印修复指引**，绝不静默假绿（AGENTS §3.3）。
耗时本地实测 ~90s（apktool 解包占大头）。
"""
import os
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))  # tests→uncheck→scripts→仓库根
RUNPY = os.path.join(os.path.dirname(HERE), "run.py")   # tests 的上一级 = uncheck/
SAMPLE = os.path.join(ROOT, "scripts", "样本.apk")
PASS, FAIL, SKIP = 0, 0, 0


def ok(m):
    global PASS
    PASS += 1
    print(f"  ✅ {m}")


def bad(m):
    global FAIL
    FAIL += 1
    print(f"  ❌ {m}", file=sys.stderr)


def skip(m):
    global SKIP
    SKIP += 1
    print(f"  ⚠️ 跳过：{m}")


def which_zipalign():
    import shutil
    for cand in (os.environ.get("SIGFIX_ZIPALIGN"),
                 shutil.which("zipalign"),
                 os.path.expanduser("~/逆向工具/bin/zipalign"),
                 os.path.expanduser("~/逆向工具/android-tools/zipalign")):
        if cand and os.path.isfile(cand):
            return cand
    return None


def _load(relpath, name):
    import importlib.util
    path = os.path.join(ROOT, *relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def extract_sig_block_bytes(data):
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        return None
    cd = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd < 32 or cd > len(data):
        return None
    if data[cd - 16:cd] != b"APK Sig Block 42":
        return None
    total = struct.unpack_from("<Q", data, cd - 24)[0]
    return data[cd - 8 - total:cd]


def extract_sig_block(apk):
    """与 run.py:_extract_sig_block 同语义（独立实现，防 run.py 漂移）。"""
    with open(apk, "rb") as f:
        data = f.read()
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        return None
    cd = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd < 32 or cd > len(data):
        return None
    if data[cd - 16:cd] != b"APK Sig Block 42":
        return None
    total = struct.unpack_from("<Q", data, cd - 24)[0]
    return data[cd - 8 - total:cd]


def main():
    print("=== uncheck 端到端回归 ===")
    # ── 依赖探测（skip 纪律：缺就明说，不假绿）──
    if not os.path.isfile(SAMPLE):
        skip(f"缺夹具 {SAMPLE}（git 跟踪资产，请确认仓库完整）")
        return 0
    import shutil
    if not shutil.which("java"):
        skip("缺 java（JDK 17）—— uncheck 依赖它解包/汇编")
        return 0
    if not os.path.isfile(os.path.join(ROOT, "tools", "apktool.jar")):
        skip("缺 tools/apktool.jar")
        return 0
    za = which_zipalign()
    if not za:
        skip("缺 zipalign（Android R+ 装机硬要求）。修复：装 build-tools 或 "
             "export SIGFIX_ZIPALIGN=<path>。CI 的 test job 已配置 build-tools")
        return 0
    ok(f"依赖就绪（zipalign={os.path.basename(za)}）")

    work = tempfile.mkdtemp(prefix="uncheck-e2e-")
    out_apk = os.path.join(work, "out-unsigned.apk")
    r = subprocess.run(
        [sys.executable, RUNPY, SAMPLE, out_apk],
        capture_output=True, text=True,
        env={**os.environ, "SIGFIX_ZIPALIGN": za})
    if r.returncode != 0:
        bad(f"run.py 失败（rc={r.returncode}）:\n{r.stdout[-800:]}\n{r.stderr[-400:]}")
        return 1

    # ── T1 产物产出且 ≠ 原包 ──
    if not os.path.isfile(out_apk) or os.path.getsize(out_apk) == 0:
        bad("产物不存在或为空")
        return 1
    ok(f"产物 {os.path.getsize(out_apk)} B（原包 {os.path.getsize(SAMPLE)} B）")
    if os.path.getsize(out_apk) == os.path.getsize(SAMPLE):
        bad("产物与原包等大——注入可能没生效")
        return 1

    # ── T2/T3 dex 结构与载荷位置 ──
    import zlib
    import hashlib
    dexes = {}
    with zipfile.ZipFile(out_apk) as z:
        for n in z.namelist():
            if n.startswith("classes") and n.endswith(".dex"):
                dexes[n] = z.read(n)
    if not dexes:
        bad("产物里没有任何 dex")
        return 1
    t2_ok = True
    for n, blob in sorted(dexes.items()):
        if blob[:4] != b"dex\n":
            bad(f"{n} magic 非法")
            t2_ok = False
            continue
        ck, = struct.unpack_from("<I", blob, 8)
        if ck != (zlib.adler32(blob[12:]) & 0xFFFFFFFF):
            bad(f"{n} checksum 不自洽")
            t2_ok = False
        if blob[12:32] != hashlib.sha1(blob[32:]).digest():
            bad(f"{n} SHA-1 不自洽")
            t2_ok = False
    if t2_ok:
        ok(f"{len(dexes)} 个 dex 结构自洽（magic/checksum/SHA-1）")

    payload_in = [n for n, b in sorted(dexes.items())
                  if b"com/nc/uncheck/SigFixApp" in b]
    call_in = [n for n, b in sorted(dexes.items())
               if b"com/nc/uncheck/SigFix;" in b and n not in payload_in]
    if not payload_in:
        bad("引导器 SigFixApp 未注入（载荷不在任何 dex）")
    elif len(payload_in) != 1:
        bad(f"引导器应恰好在一个新 dex，实际 {payload_in}")
    else:
        ok(f"引导器载荷在 {payload_in[0]}（新建 dex）")
    if not call_in:
        bad("没有任何 dex 含 SigFix 调用点（载荷不会被调用）")
    else:
        ok(f"调用点在 {', '.join(call_in)}（原 dex）")

    # ── T4 Manifest 指向（axml_edit 独立读回）──
    with zipfile.ZipFile(out_apk) as z:
        mf = z.read("AndroidManifest.xml")
    tmp_mf = os.path.join(work, "AndroidManifest.xml")
    open(tmp_mf, "wb").write(mf)
    axml = _load(("scripts", "uncheck", "axml_edit.py"), "ue_axml")
    name = axml.get_app_name(tmp_mf)
    if name == "com.nc.uncheck.SigFixApp":
        ok("Manifest android:name → SigFixApp（独立读回一致）")
    else:
        bad(f"Manifest android:name = {name!r}（应 SigFixApp）")

    # ── T5 数据复用完整性（zip-reuse.verify 走生产校验函数）──
    reuse = _load(("scripts", "uncheck", "zip-reuse.py"), "ue_reuse")
    probs = reuse.verify(out_apk)
    if not probs:
        ok("数据复用自检通过（origin.apk 完整 / 条目可读 / arsc 对齐）")
    else:
        for q in probs:
            bad(f"zip-reuse.verify: {q}")

    # ── T6 Signing Block：origin.apk 内必须保留（锁箱/证书派生依赖）──
    # ⚠️ 断言对象是【产物内的 origin.apk 条目】而不是产物本体：
    #    块注入在中间包（zipalign 后），数据复用后位于 origin.apk 视图内
    #    —— native hook 重定向后 libnc/libusign 读的就是它。
    #    产物本体是"未签名产物"，安装时由用户重签产生自己的块 ——
    #    本体无块是设计内形态（v0.9.51 教训：先注入会被 zipalign 丢弃）。
    reuse2 = _load(("scripts", "uncheck", "zip-reuse.py"), "ue_reuse2")
    with open(out_apk, "rb") as f:
        raw = f.read()
    eocd = raw.rfind(b"PK\x05\x06")
    blk = None
    origin_entry = None
    if eocd >= 0:
        total = struct.unpack("<H", raw[eocd + 10:eocd + 12])[0]
        cd_size, cd_off = struct.unpack("<II", raw[eocd + 12:eocd + 20])
        q = cd_off
        for _ in range(total):
            if raw[q:q + 4] != b"PK\x01\x02":
                break
            nl = struct.unpack("<H", raw[q + 28:q + 30])[0]
            el = struct.unpack("<H", raw[q + 30:q + 32])[0]
            nm = raw[q + 46:q + 46 + nl].decode("utf-8", "replace")
            if nm == "assets/nc_sigfix/origin.apk":
                off = struct.unpack("<I", raw[q + 42:q + 46])[0]
                csz = struct.unpack("<I", raw[q + 24:q + 28])[0]
                nl2 = struct.unpack("<H", raw[off + 26:off + 28])[0]
                el2 = struct.unpack("<H", raw[off + 28:off + 30])[0]
                start = off + 30 + nl2 + el2
                # ⚠️ 必须按 CD 记录的 compress_size 精确切：多切一字节就会
                #    把 origin 之后的"新 CD/EOCD"包进来，rfind 找到外层
                #    EOCD → 误判"无块"（首版踩过）。
                origin_entry = raw[start:start + csz]
                break
            q += 46 + nl + el + struct.unpack("<H", raw[q + 32:q + 34])[0]
    if origin_entry is None:
        bad("产物内找不到 origin.apk 条目")
    else:
        blk = extract_sig_block_bytes(origin_entry)
        blk_src = extract_sig_block_bytes(open(SAMPLE, "rb").read())
        if blk is None:
            bad("origin.apk 丢失 Signing Block（锁箱读证书会失败）")
        elif blk_src and blk != blk_src:
            bad("origin.apk 的 Signing Block 与原包不一致")
        else:
            ok(f"origin.apk 保留 Signing Block（{len(blk)} B，与原包一致）")

    print(f"=== 结果: {PASS} 通过, {FAIL} 失败, {SKIP} 跳过 ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
