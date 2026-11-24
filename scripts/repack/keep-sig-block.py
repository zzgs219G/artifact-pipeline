#!/usr/bin/env python3
"""keep-sig-block.py — 重打包后把原包的 APK Signing Block 写回去

==== 为什么需要（2026-11-25，用户需求）====
`apktool b` 重打包只写 ZIP 条目，而 APK Signing Block（v2/v3）**不是条目**
（它是中央目录前的独立结构）→ 加固产物必然「未签名」。

对比 MT 管理器的行为：它原地改字节，签名块原样保留 → MT 显示
「校验未通过」（有签名但内容变了）。两种状态的差别很实际：

  MT 式（保留签名块）    → 证书可读、MT 说"校验未通过"
  apktool 式（丢掉签名块）→ 证书不可读、MT 说"未签名"

**证书可读这件事有真实用途**：
  ① 去签名校验（scripts/uncheck）要从输入包提证书 → 没有签名块就提不到，
     「先加固、再去校验」这条流程直接失败（实测报错：
      未找到 APK Signing Block（无 v2/v3 签名））
  ② 目标 App 自己从 APK 读证书时能读到正确值

⚠️ 保留的签名**不合法**：它是对原包内容签的，而包已被改动。
   装之前必须重签（apksigner）。这里保留它只为「证书 DER 可读」——
   证书与包内容无关，所以读出来的值是正确的。

==== 用法 ====
  keep-sig-block.py <原包.apk> <加固产物.apk>

幂等：产物已有签名块时不动（保留已有的）。

==== 与 uncheck 的对应实现 ====
scripts/uncheck/run.py 的 `_extract_sig_block` / `_inject_sig_block` 是同一
算法的成熟版本（2026-11-24 起用于 origin.apk）。本文件是【独立实现】：
按 AGENTS.md §4 模块化契约，加固侧不 import 去校验模块的内部函数
（两条线刻意不共享代码）。两者算法必须一致 → 由 tests/test-keep-sig-block.py
做行为对拍。
"""
import os
import struct
import sys

SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def extract_sig_block(apk_path):
    """取签名块原始字节。返回 (block_bytes, start_off) 或 (None, None)。"""
    with open(apk_path, "rb") as f:
        data = f.read()
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        return None, None
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd_off < 32 or cd_off > len(data):
        return None, None
    if data[cd_off - 16:cd_off] != SIG_BLOCK_MAGIC:
        return None, None
    size_total = struct.unpack_from("<Q", data, cd_off - 24)[0]
    if size_total + 8 > cd_off:
        return None, None
    start = cd_off - 8 - size_total
    return data[start:cd_off], start


def inject_sig_block(apk_path, sig_block):
    """把签名块插到中央目录之前，并修正 EOCD 的 CD offset。幂等。"""
    with open(apk_path, "rb") as f:
        data = f.read()
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise RuntimeError("%s: 找不到 EOCD（不是合法 ZIP）" % apk_path)
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd_off >= 16 and data[cd_off - 16:cd_off] == SIG_BLOCK_MAGIC:
        return False    # 已有签名块（幂等）
    new_cd_off = cd_off + len(sig_block)
    if new_cd_off > 0xFFFFFFFF:
        raise RuntimeError("注入后 CD offset 超 32 位（>4GB 包不支持）")
    out = bytearray()
    out += data[:cd_off]
    out += sig_block
    out += data[cd_off:eocd]
    new_eocd = bytearray(data[eocd:])
    struct.pack_into("<I", new_eocd, 16, new_cd_off)
    out += new_eocd
    with open(apk_path, "wb") as f:
        f.write(out)
    return True


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    src, dst = argv[1], argv[2]
    if not os.path.isfile(src):
        print("❌ 原包不存在: %s" % src, file=sys.stderr)
        return 1
    if not os.path.isfile(dst):
        print("❌ 产物不存在: %s" % dst, file=sys.stderr)
        return 1
    blk, _ = extract_sig_block(src)
    if not blk:
        print("⚠️ 原包没有 APK Signing Block（v1-only 或未签名）——"
              "产物将保持未签名（证书不可读，uncheck 无法从中提证书）")
        return 0
    if not inject_sig_block(dst, blk):
        print("ℹ️ 产物已有签名块，跳过（幂等）")
        return 0
    print("✅ 已保留原包 Signing Block（%d B）—— 签名本身无效（内容已改），"
          "但证书 DER 可读；装前仍需 apksigner 重签" % len(blk))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
