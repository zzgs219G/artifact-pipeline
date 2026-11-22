#!/usr/bin/env python3
"""test-sigblock-bounds.py — APK Signing Block 解析的【边界回绕】回归测试。

【为什么需要它】
  2026-11-22 审核 sig_guard2.c 时发现（编译器早在报警，但没人处理）：

      block_size = g2_rd64le(sz8);        /* 8 字节完全来自 APK 文件内容 */
      if ((off_t)(block_size + 8) > cd_off) return -1;
      block_start = (off_t)cd_off - 8 - (off_t)block_size;

  两个可利用问题：
    ① 整数回绕：block_size = 0xFFFFFFFFFFFFFFFF 时 `block_size + 8`
       回绕成 7，检查 "7 > cd_off" 恒假 → 边界检查被绕过。
    ② 有符号/无符号混比：`(off_t)x > cd_off`，cd_off 是 unsigned long long，
       off_t 是 signed → 按 C 规则转无符号比，负数变巨正数。

  后果：block_start 变负数 → 后续 g2_read_at 拿到非法偏移 → 越界读。
  越界读通常表现为"指纹算错 → 签名不过"，排查者会往证书方向找，
  离真实原因很远。这是最坏的一类：**能被恶意构造的 APK 触发，
  而且症状指向错误方向**。

【测什么】
  用【构造的恶意 APK】打 g2_extract_cert()：
    B1 block_size = UINT64_MAX（回绕候选）→ 必须拒绝
    B2 block_size = UINT64_MAX - 7（+8 正好回绕成 0）→ 必须拒绝
    B3 block_size 略大于文件（不回绕，但超界）→ 必须拒绝
    B4 certs_len = 0 → 必须拒绝（certs 区不能为空）
    B5 certs_len 超出 signer 区 → 必须拒绝（本次新加的那条检查）
    B6 正常签名块 → 必须成功（防"修过头把合法包也拒了"）

  B6 是关键：只测"拒绝"会让实现可以无脑 return -1 全过。
  必须同时证明合法输入仍然被接受。

用法: python3 scripts/guard/tests/test-sigblock-bounds.py
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
SRC = os.path.join(ROOT, 'scripts', 'guard', 'src', 'sig_guard2.c')

PASS = 0
FAIL = 0


def ok(m):
    global PASS
    PASS += 1
    print(f"  ✅ {m}")


def bad(m):
    global FAIL
    FAIL += 1
    print(f"  ❌ {m}", file=sys.stderr)


def check(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        bad(f"{name}{(' — ' + detail) if detail else ''}")


# ── APK Signing Block 构造 ────────────────────────────────────────────
# 布局（APK v2 规范）：
#   [size:8][pairs...][size:8][magic:16]
#   pair = [len:8][id:4][value:len-4]
# id 0x7109871a = v2 signer 块；其 value 形如：
#   [signer_len:4][signer]
#   signer = [sd_len:4][signer_data]
#   signer_data = [digests_len:4][digests][certs_len:4][certs]
#   certs = [cert_len:4][cert_der]
# 注意：本测试不需要"真实签名"，只需要结构合法到能走到边界判断。

MAGIC = b'APK Sig Block 42'


def build_block(block_size_override=None, certs_len_override=None,
                cert_len_override=None, cert=b'\x30\x82\x02\x00' + b'A' * 512):
    """构造一个 Signing Block。返回 (block_bytes, cd_off_offset)。"""
    certs = struct.pack('<I', len(cert)) + cert
    if cert_len_override is not None:
        certs = struct.pack('<I', cert_len_override) + cert

    certs_field = struct.pack('<I', len(certs)) + certs
    if certs_len_override is not None:
        certs_field = struct.pack('<I', certs_len_override) + certs

    digests = struct.pack('<I', 0)          # 空 digests，结构合法
    sd = struct.pack('<I', len(digests)) + digests + certs_field
    signer = struct.pack('<I', len(sd)) + sd
    value = struct.pack('<I', len(signer)) + signer

    pair = struct.pack('<Q', len(value) + 4) + struct.pack('<I', 0x7109871a) + value

    # size 字段 = pairs 长度 + 尾部 8 字节 size + 16 字节 magic
    real_size = len(pair) + 8 + 16
    size = real_size if block_size_override is None else block_size_override

    # ⚠️⚠️ Signing Block 有【两个】size 字段：
    #   头部 [size:8] ... [size:8][magic:16]
    # 解析器读的是【尾部】那个（cd_off-24 处，见 sig_guard2.c:457）。
    # 第一版本只改了头部，于是 block_size 仍是正常值，
    # 回绕用例根本没被触发 —— 测试全绿但什么都没测到。
    # 这是"构造不严谨导致断言测不到东西"的第二次踩坑（第一次在
    # test-derive-extract.py 的 PYEOF 构造上）。两个 size 必须一起改。
    block = struct.pack('<Q', size) + pair + struct.pack('<Q', size) + MAGIC
    return block


def make_apk(path, block):
    """把 Signing Block 插到 ZIP 的 EOCD 之前（符合 v2 规范位置）。

    ⚠️ EOCD 的 cd_off 字段（偏移 16）必须填【真实的中央目录偏移】。
    第一版这里写了 0，导致 g2_extract_cert 的 `cd_off == 0 → return -1`
    直接拒绝 —— 于是"拒绝"类用例全部假绿（它们本来就该被拒，但拒的理由
    与用例想测的毫无关系）。**这是本测试自己也差点变成"假绿"的现场记录**：
    B6（合法样例必须通过）就是为抓这种情况而设计的。
    """
    local = b'PK\x03\x04' + b'\x00' * 26          # 假 local header（30 字节）
    cd = b''                                      # 空中央目录
    # ⚠️ Signing Block 位于【local header 与中央目录之间】，
    #    所以 cd_off = local + block 的长度，不是只有 local。
    #    第一版写成 len(local)，导致 magic 位置对不上 → 合法样例被拒。
    cd_off = len(local) + len(block)
    # EOCD: sig(4) disk(2) cddisk(2) n_this(2) n_total(2) cd_size(4) cd_off(4) cmt(2)
    eocd = (b'PK\x05\x06' + b'\x00' * 4 + b'\x00' * 4
            + b'\x00' * 4 + b'\x00' * 2)
    eocd = (b'PK\x05\x06'
            + struct.pack('<H', 0)      # disk number
            + struct.pack('<H', 0)      # cd start disk
            + struct.pack('<H', 0)      # entries on this disk
            + struct.pack('<H', 0)      # total entries
            + struct.pack('<I', len(cd))   # cd size
            + struct.pack('<I', cd_off)    # cd offset  ← 关键
            + struct.pack('<H', 0))        # comment len
    with open(path, 'wb') as f:
        f.write(local)
        f.write(cd)
        f.write(block)
        f.write(eocd)


def main():
    if not os.path.isfile(SRC):
        print(f"❌ 找不到 {SRC}", file=sys.stderr)
        return 1

    sys.path.insert(0, os.path.join(ROOT, 'scripts', 'lib'))
    # 选能在本机执行的宿主编译器（CI 的裸 clang 可能是 NDK 转发器）
    host_cc = None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'hostcc', os.path.join(ROOT, 'scripts', 'lib', 'host-cc.sh'))
        # host-cc.sh 是 bash，不是 python —— 直接走 shell 拿
    except Exception:
        pass
    out = subprocess.run(
        ['bash', '-c',
         f'source "{ROOT}/scripts/lib/host-cc.sh"; nc_pick_host_cc'],
        capture_output=True, text=True)
    host_cc = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ''
    if not host_cc:
        host_cc = shutil.which('clang') or shutil.which('gcc')
    if not host_cc:
        print("❌ 找不到宿主编译器", file=sys.stderr)
        return 1

    T = tempfile.mkdtemp()
    try:
        # 生成 sig_guard2.h / nc_guard_layout.h 等依赖
        gen_dir = os.path.join(T, 'gen')
        os.makedirs(gen_dir)
        apk = os.path.join(ROOT, 'scripts', '样本.apk')
        if not os.path.isfile(apk):
            print(f"⚠️ 跳过：缺样本 APK {apk}（CI 上正常）")
            return 0
        r = subprocess.run(
            ['bash', os.path.join(ROOT, 'scripts', 'guard', 'hash',
                                  'make-sig-hash.sh'),
             apk, os.path.join(gen_dir, 'sig_hash.h'),
             os.path.join(gen_dir, 'sig_guard2.h')],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(f"⚠️ 跳过：sig_hash.h 生成失败\n{r.stderr[:300]}")
            return 0

        # 把被测函数从 static 改成外部可见（与 test-sig-guard2.sh 同手法）
        with open(SRC, encoding='utf-8') as f:
            src = f.read()
        # ⚠️ 定义【和调用点】都要改名 —— 只改定义会让 g2_collect_fp 里的
        #    调用变成"隐式声明"，C99+ 直接编译失败。
        patched = src.replace('static int g2_extract_cert(int fd,',
                              'int g2_extract_cert_test(int fd,')
        patched = patched.replace('g2_extract_cert(fd, &der, &der_len)',
                                  'g2_extract_cert_test(fd, &der, &der_len)')
        if 'g2_extract_cert_test(fd, &der, &der_len)' not in patched:
            bad("无法把 g2_extract_cert 改成可测（函数定义/调用形态变了？）")
            return 1

        # ── 探针注入（只在临时副本上，生产文件一字不改）─────────────
        # 目的：区分"边界检查主动拒绝"与"后续 IO 失败兜底"。
        # 前者是修复生效，后者是侥幸 —— 反向验证时发现两者都表现为 rc=-1，
        # 只看 rc 的话回退修复也测不出来。
        #
        # ⚠️ 声明必须放在【所有被插桩的函数之前】。
        #    2026-11-22：g2_extract_cert 拆成三段后，边界检查搬进了
        #    g2_read_v2block（在文件里更靠前），原来"插在 g2_extract_cert
        #    前面"的写法就变成了"在使用点之后声明"→ 编译报
        #    undeclared identifier。改成插在第一个 #include 之后。
        probe = 'const char *g2_last_reject = "other";\n'
        _inc_end = patched.find('\n', patched.find('#include'))
        # 找到最后一个连续的 #include 行之后
        last_inc = 0
        for m in re.finditer(r'^#include\s.*$', patched, flags=re.M):
            last_inc = m.end()
        if last_inc == 0:
            bad("探针注入失败：找不到 #include 锚点")
            return 1
        patched = patched[:last_inc] + '\n' + probe + patched[last_inc:]
        # 边界检查打 "bounds" 标记
        marked = patched.replace(
            'if (block_size > (uint64_t)cd_off) return -1;',
            'if (block_size > (uint64_t)cd_off) { g2_last_reject = "bounds"; return -1; }')
        marked = marked.replace(
            'if (block_size + 8 > (uint64_t)cd_off) return -1;',
            'if (block_size + 8 > (uint64_t)cd_off) { g2_last_reject = "bounds"; return -1; }')
        if marked == patched:
            bad("探针注入失败：源码里找不到修复后的边界检查 —— "
                "如果检查被改回旧形态，本测试的 REASON 判据会失效")
            return 1
        # certs 区长度检查打 "certs" 标记。
        # ⚠️ 2026-11-22：g2_extract_cert 拆成三段后，这段从 goto fail
        #    改成了 return -1（拆出的 g2_parse_cert 用 return，不用 label）。
        #    锚点要跟着源码形态走 —— 这里加了个兜底：两种形态都认，
        #    但只命中一个，避免"改了形态测试静默失效"。
        before_certs = marked
        for old_form, new_form in (
            ('if (certs_len == 0 || sd + certs_len > end) goto fail;',
             'if (certs_len == 0 || sd + certs_len > end) '
             '{ g2_last_reject = "certs"; goto fail; }'),
            ('if (certs_len == 0 || sd + certs_len > end) return -1;',
             'if (certs_len == 0 || sd + certs_len > end) '
             '{ g2_last_reject = "certs"; return -1; }'),
        ):
            if old_form in marked:
                marked = marked.replace(old_form, new_form, 1)
                break
        if marked == before_certs:
            bad("探针注入失败：找不到 certs_len 的边界检查 —— "
                "如果该检查被删掉或改成别的形态，本测试的 REASON 判据会失效，"
                "必须同步更新锚点而不是让测试静默通过")
            return 1
        patched = marked
        tsrc = os.path.join(T, 'sg2_test.c')
        with open(tsrc, 'w', encoding='utf-8') as f:
            f.write(patched)

        driver = os.path.join(T, 'driver.c')
        with open(driver, 'w', encoding='utf-8') as f:
            f.write(r'''
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
int g2_extract_cert_test(int fd, unsigned char **out_der, size_t *out_len);
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { printf("OPEN_FAIL\n"); return 2; }
    unsigned char *der = NULL; size_t n = 0;
    extern const char *g2_last_reject;
    int rc = g2_extract_cert_test(fd, &der, &n);
    close(fd);
    free(der);
    printf("rc=%d REASON=%s\n", rc, g2_last_reject);
    return rc == 0 ? 0 : 1;
}
''')

        layout = None
        for cand in (os.path.join(ROOT, 'tools', 'nox', 'so-guard',
                                  'nc_guard_layout.h'),
                     os.path.join(os.path.dirname(ROOT), 'nox', 'scripts',
                                  'so-guard', 'nc_guard_layout.h')):
            if os.path.isfile(cand):
                layout = os.path.dirname(cand)
                break
        if layout is None:
            print("⚠️ 跳过：找不到 nc_guard_layout.h（需 ../nox 或 tools/nox）")
            return 0

        binp = os.path.join(T, 't')
        r = subprocess.run(
            [host_cc, '-O1', '-D_GNU_SOURCE', '-DSIGGUARD2_HOST_TEST',
             '-I' + gen_dir, '-I' + layout, '-I' + os.path.dirname(SRC),
             tsrc, driver, '-o', binp, '-ldl'],
            capture_output=True, text=True)
        if r.returncode != 0:
            bad(f"编译失败\n{r.stderr[:600]}")
            return 1
        ok("编译通过（含被测 g2_extract_cert）")

        # ── B6 先跑正常样例：必须成功 ──
        good = os.path.join(T, 'good.apk')
        make_apk(good, build_block())
        r = subprocess.run([binp, good], capture_output=True, text=True)
        check("B6 合法 Signing Block → rc=0（防修过头误杀正常包）",
              'rc=0' in r.stdout, r.stdout.strip() + r.stderr.strip()[:200])

        cases = [
            ('B1 block_size=UINT64_MAX（+8 回绕成 7）',
             build_block(block_size_override=0xFFFFFFFFFFFFFFFF)),
            ('B2 block_size=UINT64_MAX-7（+8 回绕成 0）',
             build_block(block_size_override=0xFFFFFFFFFFFFFFF8)),
            ('B3 block_size 略超文件（不回绕但超界）',
             build_block(block_size_override=0x100000)),
            ('B4 certs_len=0',
             build_block(certs_len_override=0)),
            ('B5 certs_len 超出 signer 区',
             build_block(certs_len_override=0x7FFFFFFF)),
        ]
        for name, blk in cases:
            p = os.path.join(T, 'bad.apk')
            make_apk(p, blk)
            r = subprocess.run([binp, p], capture_output=True, text=True,
                               timeout=20)
            got = r.stdout.strip()
            # 必须拒绝。
            #
            # ⚠️ 光看"被拒"不够 —— B1/B2 即使把修复回退掉也会被拒，
            #    因为 block_start 变负数后 pread 失败、循环 break，
            #    最后由 found<0 兜住。那是**侥幸**，不是边界检查。
            #    真正的判据是：修复后应该在【边界检查那一步】主动拒绝，
            #    而不是靠后续 IO 失败兜底。
            #
            #    所以驱动额外输出 "REASON=<行标记>"，见 driver.c：它用
            #    __builtin_return_address 拿不到行号，改用更朴素的办法 ——
            #    让被测函数把拒绝位置写进一个全局变量（见 driver 里的
            #    g2_last_reject）。这里断言 REASON 是 "bounds"。
            rejected = ('rc=0' not in got) and ('OPEN_FAIL' not in got)
            check(f"{name} → 必须拒绝", rejected, f"实得 {got}")
            if rejected:
                # 区分"主动边界拒绝"与"IO 失败兜底"。
                # B1~B3 期望走 block_size 边界检查（bounds）；
                # B4~B5 期望走 certs 区长度检查（certs）。
                want = 'certs' if name.startswith(('B4', 'B5')) else 'bounds'
                check(f"{name} → 在该检查处主动拒绝（非 IO 兜底）",
                      f'REASON={want}' in got,
                      f"实得 {got}：说明是后续读失败兜住的，"
                      f"边界检查本身没拦住")
    finally:
        shutil.rmtree(T, ignore_errors=True)

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
