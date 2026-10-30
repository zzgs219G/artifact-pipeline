/* nc_guard_paths.c — 路径密文表 + 解密（设施自包含，2026-10-30）
 *
 * 背景与强度边界见 nc_guard_paths.h 的文件头。此处只写实现要点。
 *
 * 密钥流结构（与 gen-paths.py 逐字节一致）：
 *     ks_i    = SHA256(key[16] || msg_id_be32 || counter_be64)
 *     cipher  = plain XOR ks          counter 从 0 起，每块 32 字节
 *
 * 域分离（msg_id）为什么必要：
 *   两条路径若共用同一段密钥流，即构成 two-time pad —— 已知一条明文
 *   （"/proc/self/maps" 极好猜）就能 XOR 出另一条。主项目的
 *   make-sig-log.py 有同样的设计，且实测过"相同前缀 → 相同密文"
 *   从 6/6 降到 0/6。这里沿用同一思路。
 *
 * ⚠️ 本文件【不加段标记】，故编译进 .text（明文段）。这是必须的：
 *   ncg_boot_key() 要对整个 .text 算 CRC 做代码自绑定，而它调用的
 *   任何函数都必须在 .text 里（stub 纪律：stub 只能调 .text 的函数）。
 *   若把本文件标进 .ncxh，就是"用密文解密文"——本文件已踩过两次的坑。
 *
 * ⚠️ 本文件被 ncg_boot_key 的 CRC 区间覆盖是【好事】：
 *   攻击者改这里的解密代码 → CRC 变 → k_stub 变 → .ncxh 解不开。
 */
#include <stdint.h>
#include <string.h>

#include "nc_guard_paths.h"
#include "nc_guard_key.h"    /* ksha256（已在 .text，且被 khmac 复用）*/

/* ── 由 gen-paths.py 生成的密文常量 ──────────────────────────────────
 * 重跑 `python3 scripts/so-guard/gen-paths.py` 可重新生成。
 * 改动本区块必须同步 gen-paths.py 的 KEY / PATHS，否则解出乱码。 */

static const uint8_t ncg_path_key[16] = {
    0x4F, 0x1C, 0x8A, 0x73, 0xD5, 0x26, 0xE9, 0x0B,
    0x37, 0xC4, 0x6F, 0x92, 0xA1, 0x58, 0xED, 0x30,
};

/* msg_id=0  明文 "/proc/self/cmdline"（18 字节） */
static const uint8_t ncg_path_blob_cmdline[] = {
    0x0C, 0x5E, 0x07, 0x23, 0x1B, 0x38, 0x49, 0x0B, 0xB4, 0x5A, 0x06, 0x60,
    0xCB, 0x28, 0x90, 0x5E, 0x99, 0xF6,
};

/* msg_id=1  明文 "/proc/self/maps"（15 字节） */
static const uint8_t ncg_path_blob_maps[] = {
    0x34, 0x1E, 0x51, 0xB5, 0x66, 0x52, 0x68, 0x5B, 0x45, 0x7C, 0xC8, 0x1F,
    0x90, 0x6A, 0xBC,
};

/* 表：与 ncg_path_id 一一对应。顺序必须与枚举一致。 */
static const struct {
    const uint8_t *blob;
    uint8_t        len;
} ncg_path_tab[NCG_PATH_COUNT] = {
    { ncg_path_blob_cmdline, (uint8_t)sizeof(ncg_path_blob_cmdline) },
    { ncg_path_blob_maps,    (uint8_t)sizeof(ncg_path_blob_maps) },
};

/* ── 密钥流解密（就地写入调用方缓冲）───────────────────────────────
 *
 * 为什么复用 ksha256 而不是另写一个哈希：
 *   项目纪律是"密码学原语必须复用仓内已验证实现，不重造轮子"——
 *   nc_guard_key.c 的 ksha256 已被三组 NIST 向量钉死，且已在 .text。
 *   自己再写一份等于引入第二个可能出错的实现（历史上手写 SHA-256
 *   压缩函数出过错："abc" 应 ba7816bf，实得 554144d9）。
 *
 * 为什么不用 RC4：
 *   RC4 需要 256 字节 S 盒初始化循环，那是"这是 RC4"的活招牌，且会
 *   撑大 .text 里攻击者唯一能直读的部分。SHA-256 已在本 so 里
 *   （签名校验/证书派生都在用），加它不暴露任何新线索。
 *
 * ⚠️ 与 ncg_ctr_xor（nc_guard_boot.c，用于 .ncxh 解密）的区别：
 *   那个是 21(16+1+4) 字节消息、dom 用 1 字节；这里是 28(16+4+8) 字节
 *   消息、msg_id 4 字节 + counter 8 字节。两者【故意不同】，因为它们
 *   保护的对象不同，且混用会削弱域分离。不要"统一"它们。 */
__attribute__((noinline))
static void ncg_path_ctr_xor(const uint8_t *blob, uint8_t msg_id, uint8_t n,
                             char *out) {
    uint8_t msg[28];
    uint8_t ks[32];
    uint32_t i = 0;

    memcpy(msg, ncg_path_key, 16);

    while (i < n) {
        uint32_t blk = i / 32;          /* 块号 = counter */
        uint32_t off = i % 32;          /* 块内偏移 */

        /* 消息 = key[16] || msg_id_be32 || counter_be64 */
        msg[16] = 0;
        msg[17] = 0;
        msg[18] = 0;
        msg[19] = msg_id;
        msg[20] = (uint8_t)(blk >> 24);
        msg[21] = (uint8_t)(blk >> 16);
        msg[22] = (uint8_t)(blk >> 8);
        msg[23] = (uint8_t)blk;
        msg[24] = 0;
        msg[25] = 0;
        msg[26] = 0;
        msg[27] = 0;
        ksha256(msg, sizeof(msg), ks);

        for (; off < 32 && i < n; off++, i++)
            out[i] = (char)(blob[i] ^ ks[off]);
    }

    /* 密钥材料用完即毁（与 ncg_wipe 同样的动机：避免栈上残留）。
     * 这里用 volatile 写，防止 -Oz 把"死存储"优化掉。 */
    {
        volatile uint8_t *p = ks;
        size_t k;
        for (k = 0; k < sizeof(ks); k++) p[k] = 0;
        p = msg;
        for (k = 0; k < sizeof(msg); k++) p[k] = 0;
    }
}

/* ── 对外接口（语义与 lsg_s 一致，便于原地替换调用点）─────────────── */
const char *ncg_path_s(int id, char *buf, size_t cap) {
    uint8_t n;

    if (!buf || cap == 0) return NULL;
    if (id < 0 || id >= NCG_PATH_COUNT) return NULL;

    n = ncg_path_tab[id].len;
    /* 需要 n+1 空间放结尾 NUL；不足则不写，避免截断出一个假路径
     * （截断的路径会被 open() 当成合法但不存在的文件，问题更难查）。 */
    if ((size_t)n + 1 > cap) return NULL;

    ncg_path_ctr_xor(ncg_path_tab[id].blob, (uint8_t)id, n, buf);
    buf[n] = '\0';
    return buf;
}
