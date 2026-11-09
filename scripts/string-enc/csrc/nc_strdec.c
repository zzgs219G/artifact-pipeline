/* nc_strdec.c — 纯 C 字符串解密桩（2026-11-09）
 *
 * 契约、密文形态、安全边界、强度档位说明全部在 nc_strdec.h 的文件头。
 * 本文件只做三件事：Base64 解码 → 密钥流 XOR → 输出 UTF-8 字节。
 * 【不含 JNI】—— JNI 边界在后续步骤单独加，宿主测试因此不需要 JVM。
 *
 * 与 Java/Python 侧的一致性由 scripts/string-enc/tests/test-cstrdec.sh
 * 三方对拍锁定（C ↔ Python 逐字节，C ↔ Java 反射调用）。
 * 任何一方改动都必须让该测试重新变绿。
 */

#include "nc_strdec.h"

#include <string.h>

/* ── 各 key 的块步进增量 ──────────────────────────────────────────────
 *
 * 索引 0 必须是 splitmix64 的黄金分割增量 —— 这是 NKEYS=1 时与现有
 * Java/Python 实现逐字节兼容的锚点。不要为了"看起来更随机"改掉它。
 *
 * 其余项全部为奇数：奇数在 mod 2^64 加法群上是生成元性质的前提，
 * 保证 (blk * gamma) 在 blk 递增时遍历而非提前循环。
 */
#if NC_STRDEC_NKEYS == 1
const uint64_t nc_strdec_gamma[NC_STRDEC_NKEYS] = {
    0x9E3779B97F4A7C15ULL,
};
#elif NC_STRDEC_NKEYS == 4
const uint64_t nc_strdec_gamma[NC_STRDEC_NKEYS] = {
    0x9E3779B97F4A7C15ULL,   /* [0] 与 Java/Python 侧 GAMMA 同值 */
    0x27D4EB2F165667C5ULL,
    0xC2B2AE3D27D4EB4FULL,
    0x165667B19E3779F9ULL,
};
#else
#  error "NC_STRDEC_NKEYS 只支持 1 或 4（见 nc_strdec.h 的强度档位说明）"
#endif

/* ── 密钥状态 ────────────────────────────────────────────────────────
 *
 * 只在类初始化/首次解密前写入一次，读侧无锁。
 * volatile 防 -Oz 把"读一次存局部"之外的优化做过头（与 env_check.c
 * 的 heartbeart 变量同一理由）。
 *
 * 不主动擦除：本实现要在整个进程生命周期内反复使用密钥，
 * 用完即擦是 unlock 链（一次性密钥）的做法，不适用于这里。
 */
static uint64_t nc_key[NC_STRDEC_NKEYS];
static volatile int nc_key_ready = 0;

/* splitmix64 终混合。
 * 与 StrDec.java 的 mix64()、encrypt-strings.py 的 _mix64() 逐字节等价：
 *   z ^= z >>> 30; z *= C1; z ^= z >>> 27; z *= C2; return z ^ (z >>> 31)
 * long 溢出天然等于 mod 2^64，C 侧用无符号整型同样是定义良好的模运算。 */
static inline uint64_t nc_mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * NC_STRDEC_C1;
    z = (z ^ (z >> 27)) * NC_STRDEC_C2;
    return z ^ (z >> 31);
}

/* 第 blk 个密钥流块（8 字节）。
 *
 * NKEYS=1：mix64(key[0] + blk*GAMMA)  ← 与现有实现完全一致
 * NKEYS=4：四个 mix64 异或合并
 *
 * 为什么 4 个而不是"更多轮 mix64"：轮数叠加仍是可逆双射，攻击者照样
 * 一步反演（详见 nc_strdec.h 的安全边界）。异或合并则把未知数从 1 个
 * 提到 4 个 —— 一个方程四个未知数，才真正无解。
 */
static inline uint64_t nc_block_ks(uint64_t blk)
{
    uint64_t w = nc_mix64(nc_key[0] + blk * nc_strdec_gamma[0]);
#if NC_STRDEC_NKEYS > 1
    /* 每个 key 用不同的块偏移与步进，避免四个分量之间出现线性相关：
     * 若都用 blk 且步进相同，则 blk 递增时四个分量同步平移，
     * 异或结果的差分性质会退化。 */
    for (int t = 1; t < NC_STRDEC_NKEYS; t++) {
        w ^= nc_mix64(nc_key[t] + (blk + (uint64_t)t) * nc_strdec_gamma[t]);
    }
#endif
    return w;
}

void nc_strdec_set_key(const uint8_t *key)
{
    if (key == NULL) {
        nc_key_ready = 0;
        return;
    }
    /* 大端序读取：与 Java 的 0x…L 字面量、Python 的 int.from_bytes(..,'big')
     * 三方一致。改字节序 = 两侧密钥不一致 = 全包乱码，且不会在构建期报错。 */
    for (int t = 0; t < NC_STRDEC_NKEYS; t++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) {
            v = (v << 8) | (uint64_t)key[t * 8 + b];
        }
        nc_key[t] = v;
    }
    nc_key_ready = 1;
}

int nc_strdec_has_key(void)
{
    return nc_key_ready ? 1 : 0;
}

/* ── Base64 ────────────────────────────────────────────────────────── */

/* 单字符 → 6 位值。非法返回 -1。
 * 用一张 256 字节查表而不是算术比较：这是解码热路径，每次调用要处理
 * 上千字符。
 * ⚠️ 表必须 const（进 .rodata），不能是可变全局 —— 否则每次调用都要
 *    判断"初始化了没有"，那点分支在热路径上是实打实的开销。 */
static const int8_t nc_b64_tbl[256] = {
    /* 0x00-0x0F */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /* 0x10-0x1F */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /* 0x20-0x2F */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    /* 0x30-0x3F */ 52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    /* 0x40-0x4F */ -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    /* 0x50-0x5F */ 15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    /* 0x60-0x6F */ -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    /* 0x70-0x7F */ 41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    /* 0x80-0xFF 全部非法（payload 恒为 ASCII） */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

int nc_strdec_b64_decode(const char *s, size_t n, uint8_t *out, size_t outcap)
{
    if (s == NULL || out == NULL) {
        return -1;
    }

    size_t i = 0;
    size_t o = 0;

    /* ── 4 字符一组：24 位正好 3 字节，无需任何中间状态 ─────────────
     *
     * 对比逐字符实现（每次 1 字符：移位塞入 + 判断攒够 8 位没有 +
     * 处理跨字节拆包）：实测真实负载下 4-way 快约 20 倍
     * （1.11 ms → 0.05 ms / 1.3 万条），而 Base64 解码是整条解密链路里
     * 最大的一笔开销，比密钥流生成本身大一个数量级。
     *
     * 等价性：两者输出逐字节相同，由 tests/test-cstrdec.sh 对拍锁定。 */
    while (i + 4 <= n) {
        int v0 = nc_b64_tbl[(uint8_t)s[i]];
        int v1 = nc_b64_tbl[(uint8_t)s[i + 1]];
        int v2 = nc_b64_tbl[(uint8_t)s[i + 2]];
        int v3 = nc_b64_tbl[(uint8_t)s[i + 3]];

        if (v0 < 0 || v1 < 0) {
            return -1;
        }

        /* 填充只可能出现在最后一组，且必须是字符串末尾。
         * 出现 '=' 却后面还有内容 = 非法输入。 */
        if (s[i + 2] == '=' && s[i + 3] == '=') {
            if (i + 4 != n || o + 1 > outcap) {
                return -1;
            }
            out[o++] = (uint8_t)((v0 << 2) | (v1 >> 4));
            return (int)o;
        }
        if (s[i + 3] == '=') {
            if (v2 < 0 || i + 4 != n || o + 2 > outcap) {
                return -1;
            }
            uint32_t v = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12)
                       | ((uint32_t)v2 << 6);
            out[o++] = (uint8_t)(v >> 16);
            out[o++] = (uint8_t)(v >> 8);
            return (int)o;
        }
        if (v2 < 0 || v3 < 0) {
            return -1;
        }
        if (o + 3 > outcap) {
            return -1;
        }

        uint32_t v = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12)
                   | ((uint32_t)v2 << 6) | (uint32_t)v3;
        out[o++] = (uint8_t)(v >> 16);
        out[o++] = (uint8_t)(v >> 8);
        out[o++] = (uint8_t)v;
        i += 4;
    }

    /* 残留不足 4 字符：Python 侧 b64encode 产出的长度恒为 4 的倍数，
     * 出现这种情况说明输入被截断或不是本模块的产物 → 拒绝。 */
    if (i != n) {
        return -1;
    }
    return (int)o;
}

/* ── 单条解密 ──────────────────────────────────────────────────────── */

int nc_strdec_decrypt(const char *b64, size_t b64len, uint8_t *out, size_t outcap)
{
    if (!nc_strdec_has_key()) {
        /* fail-closed：没设密钥就绝不解密。返回 -1 让上层原样返回密文。
         * 不要改成"用全零密钥试一下" —— 那会产出乱码明文，
         * 比原样返回密文危险得多（乱码会被当成合法值写进字段/URL）。 */
        return -1;
    }

    int raw = nc_strdec_b64_decode(b64, b64len, out, outcap);
    if (raw < 4) {
        /* 合法密文最短是 3 字节 offset + 1 字节正文 = 4 字节。
         * 更短的只可能是空串（构建期已跳过）或损坏 → 走失败兜底。 */
        return -1;
    }

    const uint32_t off = ((uint32_t)out[0] << 16)
                       | ((uint32_t)out[1] << 8)
                       | (uint32_t)out[2];
    const size_t len = (size_t)raw - 3;

    /* ── 块展开：一次 mix64 产出 8 字节密钥流 ─────────────────────
     *
     * 内层 j 必须从 (off + k) & 7 起，不能固定从 0 —— off 未必是 8 的倍数。
     * 这是历史事故（offset%8≠0 的每条字符串全部静默解错，不崩不报错，
     * 只是文案/URL 全烂）。README「密钥流定义」的易错点 2。
     *
     * 就地解密的安全性：第 k 轮写 out[k]，读 out[k+3]。
     * 此前只写过 out[0..k-1]，而 k-1 < k+3 恒成立 → 读到的永远是原始密文。
     * 调用方传同一块缓冲也安全。 */
    size_t k = 0;
    while (k < len) {
        const uint32_t pos = off + (uint32_t)k;
        const uint64_t w = nc_block_ks((uint64_t)(pos >> 3));
        unsigned j = (unsigned)(pos & 7u);
        for (; j < 8 && k < len; j++, k++) {
            out[k] = (uint8_t)(out[k + 3] ^ (uint8_t)(w >> (j * 8)));
        }
    }

    return (int)len;
}

/* ── UTF-8 → UTF-16 ──────────────────────────────────────────────────
 *
 * 契约与拒绝规则见头文件。这里只强调两处易错点：
 *
 * ① 代理对（补充平面）：U+10000..U+10FFFF 在 UTF-16 里是两个码元
 *    （高位 D800-DBFF + 低位 DC00-DFFF）。少写这一步，emoji 会变成
 *    两个"看似合法"的代理字符，Java 侧 new String 出来是乱码。
 *
 * ② overlong 编码必须拒绝：比如 0xC0 0x80 表示 U+0000 的 2 字节形态，
 *    虽然"数值上"能解出 NUL，但它是非法的（modified UTF-8 就用它表示 NUL）。
 *    放过它意味着我们的解码器会接受 modified UTF-8，语义就变形了。
 *    判据：每个长度档位都有"最小合法值"（见下方 min 表）。
 */
int nc_strdec_utf8_to_utf16(const uint8_t *in, size_t len,
                           uint16_t *out, size_t outcap)
{
    if (in == NULL || out == NULL) {
        return -1;
    }

    size_t i = 0;
    size_t o = 0;

    while (i < len) {
        const uint8_t b0 = in[i];
        uint32_t cp;
        size_t need;

        if (b0 < 0x80) {
            cp = b0;
            need = 0;
        } else if ((b0 & 0xE0) == 0xC0) {
            cp = b0 & 0x1Fu;
            need = 1;
        } else if ((b0 & 0xF0) == 0xE0) {
            cp = b0 & 0x0Fu;
            need = 2;
        } else if ((b0 & 0xF8) == 0xF0) {
            cp = b0 & 0x07u;
            need = 3;
        } else {
            return -1;              /* 0x80-0xBF 起始 / 0xF8+ 非法 */
        }

        if (need > 0 && i + need >= len) {
            return -1;              /* 截断：续字节不够 */
        }
        for (size_t k = 1; k <= need; k++) {
            const uint8_t bk = in[i + k];
            if ((bk & 0xC0) != 0x80) {
                return -1;          /* 续字节必须是 10xxxxxx */
            }
            cp = (cp << 6) | (uint32_t)(bk & 0x3Fu);
        }

        /* overlong 检查：每个长度档位的最小合法码点 */
        static const uint32_t min_cp[4] = { 0u, 0x80u, 0x800u, 0x10000u };
        if (cp < min_cp[need]) {
            return -1;
        }
        /* 代理区（U+D800..U+DFFF）在 UTF-8 里不允许直接出现 */
        if (cp >= 0xD800u && cp <= 0xDFFFu) {
            return -1;
        }
        if (cp > 0x10FFFFu) {
            return -1;
        }

        i += need + 1;

        if (cp <= 0xFFFFu) {
            if (o + 1 > outcap) {
                return -1;
            }
            out[o++] = (uint16_t)cp;
        } else {
            /* 补充平面 → 代理对 */
            if (o + 2 > outcap) {
                return -1;
            }
            cp -= 0x10000u;
            out[o++] = (uint16_t)(0xD800u | (cp >> 10));
            out[o++] = (uint16_t)(0xDC00u | (cp & 0x3FFu));
        }
    }

    return (int)o;
}

/* ── 宿主测试钩子 ────────────────────────────────────────────────────
 * 只在 NC_STRDEC_HOST_TEST 下导出，生产构建不进符号表。
 * 用途：与 Python 侧的 key_byte()/block 值逐 64 位对拍，
 * 把"两侧算法一致"从注释变成断言。 */
#ifdef NC_STRDEC_HOST_TEST
uint64_t nc_strdec_block_ks(uint64_t blk)
{
    return nc_block_ks(blk);
}
#endif
