#!/usr/bin/env python3
"""verify_text_crc_ready.py — 校验 .text 是否满足「代码自绑定」的前提。

【为什么需要这个脚本】
  nox 的锁箱链有 CRC 自绑定（so-section-lock.py:1195）：
    锁箱期把 .text 的 sh_addr/sh_size 写进 .ncks 的 code_addr/code_len；
    运行期 ncg_stub_recover 对这段算 CRC32，异或进 k_stub。
    改代码一位 → CRC 变 → k_stub 变 → .ncxh 解出乱码 → SIGILL。

  这条链能自洽的前提是：**锁箱期按文件算的 CRC 与运行期按内存算的完全一致**。
  它成立需要两个条件，缺一不可：
    ① .text 内【无重定位】—— 有的话加载后内容与文件不同，CRC 对不上
    ② sh_addr == sh_offset —— 按文件偏移取字节，按虚拟地址算区间

  为什么要在混淆之后专门验一次：Amice 的 MBA/flatten 会大幅改写 .text，
  虽然理论上不该引入重定位，但这是**整条锁箱链的单点前提**——
  一旦破，产物在真机上必 SIGILL，而静态检查（段表/熵值）全都正常，
  极难定位。宁可多一条断言。

【判据】
  通过：.text 存在、size > 0、addr == off、区间内重定位数 == 0
  失败：任一不满足，打印具体原因与落在 .text 内的重定位示例

用法: python3 scripts/verify_text_crc_ready.py <so路径>
退出码: 0 通过 / 1 不满足 / 2 用法错误
"""
import re
import struct
import subprocess
import sys


def read_sections(d):
    """解析 ELF section header，返回 {name: {addr, off, size, type}}。"""
    e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', d, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', d, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', d, 0x3e)[0]
    if e_shoff == 0 or e_shnum == 0:
        raise ValueError('无 section header table')

    def sh(i):
        return struct.unpack_from('<IIQQQQIIQQ', d, e_shoff + i * e_shentsize)

    stroff = sh(e_shstrndx)[4]
    out = {}
    for i in range(e_shnum):
        s = sh(i)
        end = d.index(b'\0', stroff + s[0])
        name = d[stroff + s[0]:end].decode('latin1')
        if s[1] == 8:                       # SHT_NOBITS (.bss) 跳过
            continue
        out[name] = {'addr': s[3], 'off': s[4], 'size': s[5], 'type': s[1]}
    return out


def reloc_offsets(so_path):
    """返回该 so 的全部重定位目标偏移（十进制）。

    用 readelf -rW 而不是自己解析 .rela.dyn —— R_AARCH64_RELATIVE 等
    重定位在 ELF32/ELF64 下格式不同，交给 binutils 更稳。
    """
    try:
        out = subprocess.run(['readelf', '-rW', so_path],
                             capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None                     # 没有 readelf → 调用方决定怎么处理
    # 行首十六进制偏移（8~16 位）后跟类型/符号列
    return [int(m.group(1), 16)
            for m in re.finditer(r'^([0-9a-fA-F]{8,16})\s+\S+\s+\S+', out.stdout, re.M)]


def main(argv):
    if len(argv) != 1:
        print(__doc__)
        return 2
    so = argv[0]
    try:
        with open(so, 'rb') as f:
            d = f.read()
    except OSError as e:
        print(f'❌ 读不到 {so}: {e}')
        return 2

    if d[:4] != b'\x7fELF':
        print(f'❌ 不是 ELF: {so}')
        return 2
    if d[4] != 2:
        print(f'ℹ️ 这不是 ELF64（class={d[4]}）—— 本脚本只支持 64 位产物')
        return 2

    try:
        segs = read_sections(d)
    except ValueError as e:
        print(f'❌ {e}')
        return 2

    text = segs.get('.text')
    if text is None:
        print('❌ 找不到 .text 段 —— 自绑定无法成立')
        return 1

    bad = 0
    print(f"  .text: addr=0x{text['addr']:x} off=0x{text['off']:x} "
          f"size={text['size']}")

    if text['size'] == 0:
        print('  ❌ .text 为空')
        bad = 1
    if text['addr'] != text['off']:
        # 这不是必然失败（部分 so 布局确实不等），但会破坏"按文件偏移取字节"
        # 的假设，必须显式报警让人确认。
        print(f"  ❌ .text 的 addr(0x{text['addr']:x}) != off(0x{text['off']:x})"
              f" —— 自绑定按文件偏移算，前提不成立")
        bad = 1

    rels = reloc_offsets(so)
    if rels is None:
        print('  ⚠️ 无 readelf，跳过重定位检查（无法确认自绑定前提）')
    else:
        lo, hi = text['addr'], text['addr'] + text['size']
        inside = [x for x in rels if lo <= x < hi]
        print(f"  重定位: 全 .so 共 {len(rels)} 条，落在 .text 内 {len(inside)} 条")
        if inside:
            print('  ❌ .text 内有重定位 —— 加载后内容与文件不同，'
                  '锁箱期 CRC 与运行期 CRC 对不上')
            for x in inside[:8]:
                print(f'      0x{x:x}')
            if len(inside) > 8:
                print(f'      ...（共 {len(inside)} 条）')
            bad = 1

    if bad:
        print('❌ CRC 自绑定前提不满足')
        return 1
    print('✅ CRC 自绑定前提成立（.text 非空、addr==off、零重定位）')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
