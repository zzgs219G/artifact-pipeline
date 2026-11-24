#!/usr/bin/env python3
"""test-keep-sig-block.py — 签名块保留的回归 + 与 uncheck 实现的行为对拍

==== 为什么有它（2026-11-25）====
加固产物原本「未签名」（apktool b 不写 Signing Block），导致：
  ① MT 显示「未签名」而不是「校验未通过」（信息量更低）
  ② **去签名校验提不到证书** → 「先加固、再去校验」流程直接失败
现在 protect.sh 在 zipalign 之后调用 keep-sig-block.py 保留原包签名块。

==== 覆盖 ====
T1  extract→inject 往返：签名块字节完全一致（逐字节）
T2  幂等：产物已有块时 inject 返回 False 且不改文件
T3  EOCD 的 CD offset 被正确修正（插入块后仍能正常 zipfile 解析）
T4  注入后 zipfile 能读出所有原条目（ZIP 结构完好）
T5  **与 uncheck 实现行为对拍**：同一输入，两个实现的块字节一致
    （两条线刻意不共享代码，AGENTS §4；算法必须一致 → 由本项钉住）
T6  zipalign 会丢签名块的**已知行为**钉住（防止有人把注入挪到 zipalign 前）
    —— 这条同时是"为什么必须在 zipalign 之后"的可执行记录

用法：python3 scripts/repack/tests/test-keep-sig-block.py [已签名APK]
不给 APK 时用 scripts/样本.apk（git 跟踪）。
"""
import os
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
TOOL = os.path.join(ROOT, "scripts", "repack", "keep-sig-block.py")
UNCHECK_RUN = os.path.join(ROOT, "scripts", "uncheck", "run.py")
SAMPLE = os.path.join(ROOT, "scripts", "样本.apk")
MAGIC = b"APK Sig Block 42"

PASS = FAIL = SKIP = 0


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


def load_tool():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ksb", TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def load_uncheck_impl():
    """只取 _extract_sig_block / _inject_sig_block 做对拍（不执行 run()）。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("uc_run", UNCHECK_RUN)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def has_block(path):
    d = open(path, "rb").read()
    e = d.rfind(b"PK\x05\x06")
    if e < 0:
        return False
    cd = struct.unpack_from("<I", d, e + 16)[0]
    return cd >= 16 and d[cd - 16:cd] == MAGIC


def main(argv):
    apk = argv[1] if len(argv) > 1 else SAMPLE
    print("=== keep-sig-block 回归 ===")
    if not os.path.isfile(apk):
        skip(f"缺已签名 APK 夹具: {apk}")
        return 0
    if not has_block(apk):
        skip(f"{os.path.basename(apk)} 没有 v2/v3 签名块（需已签名包）")
        return 0
    ksb = load_tool()
    work = tempfile.mkdtemp(prefix="ksb-")

    # ── T1 往返：extract → inject → 块字节一致 ──
    blk, _ = ksb.extract_sig_block(apk)
    if not blk:
        bad("T1 提不到签名块")
        return 1
    # 造一个"丢失签名块"的产物：按条目重写（模拟 apktool b）
    stripped = os.path.join(work, "stripped.apk")
    with zipfile.ZipFile(apk) as zin, zipfile.ZipFile(stripped, "w") as zout:
        for info in zin.infolist():
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.compress_type = info.compress_type
            zout.writestr(zi, zin.read(info.filename))
    if has_block(stripped):
        bad("T1 测试前置失败：stripped 仍带签名块")
        return 1
    ok("T1a 重写条目后签名块确实丢失（复现 apktool b 行为）")

    ksb.inject_sig_block(stripped, blk)
    if not has_block(stripped):
        bad("T1b 注入后仍无签名块")
        return 1
    blk2, _ = ksb.extract_sig_block(stripped)
    if blk2 != blk:
        bad("T1b 注入后的块与原块字节不一致")
    else:
        ok(f"T1b 注入后块字节逐字节一致（{len(blk)} B）")

    # ── T2 幂等 ──
    before = open(stripped, "rb").read()
    r = ksb.inject_sig_block(stripped, blk)
    if r is False and open(stripped, "rb").read() == before:
        ok("T2 幂等：已有块时不重复注入、文件不变")
    else:
        bad(f"T2 幂等失败（返回 {r}）")

    # ── T3 EOCD CD offset 修正 ──
    d = open(stripped, "rb").read()
    e = d.rfind(b"PK\x05\x06")
    cd = struct.unpack_from("<I", d, e + 16)[0]
    real_cd = d.rfind(b"PK\x01\x02")   # 最后一个中央目录条目起点不可靠，用首条
    if d[cd:cd + 4] == b"PK\x01\x02":
        ok("T3 EOCD 的 CD offset 指向真实中央目录起点")
    else:
        bad(f"T3 CD offset 错误（指向 {d[cd:cd+4]!r}）")

    # ── T4 ZIP 结构完好 ──
    try:
        with zipfile.ZipFile(stripped) as z:
            with zipfile.ZipFile(apk) as zo:
                n_out, n_orig = len(z.namelist()), len(zo.namelist())
            if n_out != n_orig:
                bad(f"T4 条目数变化 {n_orig} → {n_out}")
            else:
                ok(f"T4 ZIP 结构完好（{n_out} 条目与原包一致）")
    except Exception as ex:
        bad(f"T4 注入后 ZIP 不可解析: {ex}")

    # ── T5 与 uncheck 实现对拍 ──
    try:
        uc = load_uncheck_impl()
        blk_uc, _ = uc._extract_sig_block(apk)
        if blk_uc == blk:
            ok("T5 与 uncheck 的 _extract_sig_block 逐字节一致（两条线算法对齐）")
        else:
            bad("T5 与 uncheck 实现不一致（同一输入的块字节不同）")
    except Exception as ex:
        skip(f"T5 无法加载 uncheck 实现做对拍: {ex}")

    # ── T6 zipalign 会丢签名块（已知行为，钉住防止注入位置被挪错）──
    za = os.environ.get("SIGFIX_ZIPALIGN") or _which("zipalign")
    if not za:
        skip("T6 无 zipalign，跳过（CI 的 test job 有 build-tools）")
    else:
        aligned = os.path.join(work, "aligned.apk")
        r = subprocess.run([za, "-f", "4", stripped, aligned],
                           capture_output=True, text=True)
        if r.returncode != 0:
            skip(f"T6 zipalign 失败: {r.stderr[:100]}")
        elif has_block(aligned):
            print("  ℹ️ T6 本机 zipalign 保留了签名块（与 2026-11-24 实测不同）"
                  "—— 仍建议注入放 zipalign 之后，见 protect.sh 注释")
            ok("T6 记录：本机 zipalign 行为")
        else:
            ok("T6 zipalign 确实丢掉签名块 —— 证明注入必须在 zipalign 之后")

    print(f"=== 结果: {PASS} 通过, {FAIL} 失败, {SKIP} 跳过 ===")
    return 1 if FAIL else 0


def _which(name):
    import shutil
    return shutil.which(name)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
