#!/usr/bin/env python3
"""gen-paths.py — 生成 nc_guard_paths.c 的密文常量表（一次性工具，可重跑）

用途：so-guard 独立化后不再依赖主项目的 sig_log_data.h，改为自带两条
/proc 路径的密文。本脚本产出那些密文字节，贴进 nc_guard_paths.c。

⚠️ 这是【混淆】不是【加密】：
  密钥写死在本脚本与 nc_guard_paths.c 里，攻击者反汇编即可还原。
  目标只是让 `strings` 扫不到明文路径，与既有 lsg_s 的定位一致。
  不要据此高估防御强度。

密钥流（与 nc_guard_paths.c 的 ncg_path_ctr_xor 逐字节一致）：
  ks_i = SHA256(key[16] || msg_id_be32 || counter_be64)
  cipher = plain XOR ks            (counter 从 0 起，每块 32 字节)

与 make-sig-log.py 的差异（并存，不是副本）：
  生成器用 32 字节 key；此处 16 字节。二者是不同用途的两套表，
  不要要求逐字节对拍。
"""
import hashlib
import struct

# 16 字节固定密钥。这是混淆层，公开无妨（见文件头说明）。
KEY = bytes([0x4F, 0x1C, 0x8A, 0x73, 0xD5, 0x26, 0xE9, 0x0B,
             0x37, 0xC4, 0x6F, 0x92, 0xA1, 0x58, 0xED, 0x30])

# msg_id 做域分离：两条路径的密钥流互相独立，
# 避免"已知一条明文就能推另一条"（两段共用密钥流 = two-time pad）。
PATHS = [
    (0, "cmdline", b"/proc/self/cmdline"),
    (1, "maps", b"/proc/self/maps"),
]


def keystream(msg_id: int, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(
            KEY + struct.pack('>I', msg_id) + struct.pack('>Q', ctr)
        ).digest()
        ctr += 1
    return bytes(out[:n])


def enc(msg_id: int, data: bytes) -> bytes:
    ks = keystream(msg_id, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def c_array(name: str, data: bytes, indent: str = "    ") -> str:
    lines = []
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        lines.append(indent + ", ".join("0x%02X" % b for b in chunk) + ",")
    return "static const uint8_t %s[] = {\n%s\n};" % (name, "\n".join(lines))


def main() -> int:
    print("/* ── 由 gen-paths.py 生成，勿手改（重跑即可）───────────────")
    print(" * KEY 与两张表必须与 nc_guard_paths.c 的 ncg_path_key 一致。 */")
    print("static const uint8_t ncg_path_key[16] = {")
    print("    " + ", ".join("0x%02X" % b for b in KEY) + ",")
    print("};")
    print()
    for msg_id, name, plain in PATHS:
        cipher = enc(msg_id, plain)
        print("/* msg_id=%d  len=%d  明文长度=%d */" % (msg_id, len(cipher), len(plain)))
        print(c_array("ncg_path_%s" % name, cipher))
        print()
    print("/* 自检（生成期，不落产物）： */")
    print("/* %s */" % "  ".join(
        "%s -> %s" % (n, enc(i, p).hex()[:16] + "...") for i, n, p in PATHS))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
