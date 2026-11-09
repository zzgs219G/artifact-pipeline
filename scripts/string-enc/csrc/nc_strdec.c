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

/* 构建期生成的配置头（protect.sh 写进 NDK 工程目录，不进 git）。
 *
 * ⚠️⚠️ 必须在 "nc_strdec.h" **之前** include（2026-11-09 真机闪退根因）：
 *   头文件里有 `#ifndef NC_STRDEC_ALGO` 的兜底默认值（0=splitmix64）。
 *   若先包含头文件，构建期注入的算法档就会被默认值挡住 → 加密用 A、
 *   解密用 B → 每条字符串都解错，而且构建期零报错、运行期只是静默
 *   降级成"返回密文"（nc_jni_fail）。
 *   本文件与 nc_strdec_jni.c 都必须这样做 —— 两个 TU 各编一遍算法，
 *   宏不同源 = 链接期也不报错、运行期行为诡异。
 *
 * 用 __has_include 而非无条件 include：宿主测试
 * （tests/test-cstrdec.sh 的 host 程序）不生成 cfg.h。 */
#if defined(__has_include)
#  if __has_include("nc_strdec_cfg.h")
#    include "nc_strdec_cfg.h"
#  endif
#endif

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
 * long 溢出天然等于 mod 2^64，C 侧用无符号整型同样是定义良好的模运算。
 *
 * ⚠️ ChaCha20 档不用它，但 nc_strdec_gamma 等 splitmix 常量还在。
 *    条件编译掉函数体（而非整段）以保持文件结构可读；
 *    不加这层会让 -Wunused-function 在 ChaCha20 档报警告，
 *    而本项目的测试判据是"零警告"（见 test-cstrdec.sh 的编译断言）。 */
#if NC_STRDEC_ALGO != NC_STRDEC_ALGO_CHACHA20
static inline uint64_t nc_mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * NC_STRDEC_C1;
    z = (z ^ (z >> 27)) * NC_STRDEC_C2;
    return z ^ (z >> 31);
}
#endif

/* ── ChaCha20（RFC 8439）密钥流 ──────────────────────────────────────
 *
 * ## 为什么按 64 字节块算，而不是 8 字节
 *
 * ChaCha20 的一次 20 轮运算天然产出 **64 字节**密钥流。本文件最初的写法
 * 为了套用 splitmix64 的「一个 uint64 = 8 字节」契约，每 8 字节就重跑一次
 * 20 轮 —— 等于算了 64 字节只用 8 字节，**浪费 8 倍**。
 *
 * 实测（宿主 aarch64 Cortex-A720，64 MiB 密钥流）：
 *     按 8 字节块调用：63 MB/s（126 ns / 8 字节）
 *     按 64 字节块输出：见下方 NC_STRDEC_ALGO_SEC 的性能记录
 *
 * 因此解密主循环对 ChaCha20 走独立的块号语义：
 *     splitmix64 : 块号 = pos >> 3，块内取第 (pos & 7) 字节
 *     ChaCha20   : 块号 = pos >> 6，块内取第 (pos & 63) 字节
 * 两者的 offset（密文头 3 字节）语义完全不变、密文长度不变，
 * 只有"虚拟密钥流的块边界"不同 —— 构建期与运行期必须同源，见 key_byte_algo()。
 *
 * ## 状态布局（RFC 8439 §2.3）
 *   c[0..3]   常量 "expa" "nd 3" "2-by" "te k"
 *   c[4..11]  key（32 字节，小端 8 个 uint32）
 *   c[12]     counter 低 32 位
 *   c[13..15] nonce（全零 —— counter 已是全包唯一，见调用处注释）
 *
 * counter 32 位够用：全包密钥流按 64 字节/块计，2^32 块 = 256 GiB，
 * 远超单包字符串总量（最大实测 ~1.2 万条 × 数百字节 ≈ 数 MiB）。
 */
#if NC_STRDEC_ALGO == NC_STRDEC_ALGO_CHACHA20

/* QUARTERROUND（RFC 8439 §2.1）
 *   a += b; d ^= a; d = ROTL32(d, 16);
 *   c += d; b ^= c; b = ROTL32(b, 12);
 *   a += b; d ^= a; d = ROTL32(d,  8);
 *   c += d; b ^= c; b = ROTL32(b,  7);
 *
 * ⚠️ 必须是【循环】左移，不是普通左移 —— 普通 `<<` 会把高位丢掉，
 * 结果完全错且不报错。这道 bug 只有对 RFC 测试向量才会暴露，
 * 自己跟自己对拍永远发现不了（两侧都错 = 一致）。 */
static inline uint32_t nc_rotl32(uint32_t v, int n)
{
    return (v << n) | (v >> (32 - n));
}

#define NC_QR(a, b, c, d)                          \
    do {                                           \
        a += b; d ^= a; d = nc_rotl32(d, 16);      \
        c += d; b ^= c; b = nc_rotl32(b, 12);      \
        a += b; d ^= a; d = nc_rotl32(d, 8);       \
        c += d; b ^= c; b = nc_rotl32(b, 7);       \
    } while (0)

/* 256 位密钥的 uint32 形态。由 nc_strdec_set_key() 从 nc_key 小端展开，
 * 与 Python 侧 struct.pack('<8I', ...) 必须逐字节一致。 */
static uint32_t nc_chacha20_key[8];
static int nc_chacha20_key_ready = 0;

static void nc_chacha20_derive_key(void)
{
    for (int i = 0; i < NC_STRDEC_NKEYS && i < 4; i++) {
        nc_chacha20_key[i * 2]     = (uint32_t)(nc_key[i] & 0xFFFFFFFFu);
        nc_chacha20_key[i * 2 + 1] = (uint32_t)(nc_key[i] >> 32);
    }
    nc_chacha20_key_ready = 1;
}

/* 核心：counter=blk 的 20 轮，输出 16 个 uint32（= 64 字节密钥流）。
 *
 * ## 为什么写成一大串局部变量，而不是 uint32_t x[16] + 循环
 *
 *   · 用数组时 `NC_QR(x[0], x[4], x[8], x[12])` 的每次读写都是内存访问 ——
 *     编译器无法证明不同下标互不别名，只能老实 load/store。
 *   · 换成 16 个独立局部变量后全部落寄存器（aarch64 有 31 个通用寄存器），
 *     整个 20 轮不碰内存。
 *   · 双轮刻意展开成 10 次而非 for 循环：循环变量会让编译器保守处理
 *     寄存器分配。实测 941 条 add/eor/ror（理论最少 960，无浪费）。
 *
 * ## 为什么不做 SIMD（4×uint32x4）
 *
 * 理论上还能再快 3~4 倍，但本项目 `APP_ABI := armeabi-v7a arm64-v8a`：
 * v7a 的 NEON 是可选扩展，不能假设存在；且 AI接手文档 §8.4.1 记录过
 * v7a/arm64 因 SIMD 栈布局差异导致的 22 字节偏移问题（至今未查清）。
 * 为 1ms 去碰这个坑不划算 —— 保持标量实现，一套代码两个 ABI 都对。
 */
static void nc_chacha20_core(uint32_t counter, uint32_t out[16])
{
    /* 初始状态：常量 4 字 + key 8 字 + counter + nonce(3 字，全零) */
    const uint32_t s0  = 0x61707865u, s1  = 0x3320646Eu;
    const uint32_t s2  = 0x79622D32u, s3  = 0x6B206574u;
    const uint32_t s4  = nc_chacha20_key[0], s5  = nc_chacha20_key[1];
    const uint32_t s6  = nc_chacha20_key[2], s7  = nc_chacha20_key[3];
    const uint32_t s8  = nc_chacha20_key[4], s9  = nc_chacha20_key[5];
    const uint32_t s10 = nc_chacha20_key[6], s11 = nc_chacha20_key[7];
    const uint32_t s12 = counter;
    const uint32_t s13 = 0, s14 = 0, s15 = 0;

    uint32_t x0 = s0,  x1 = s1,  x2 = s2,  x3 = s3;
    uint32_t x4 = s4,  x5 = s5,  x6 = s6,  x7 = s7;
    uint32_t x8 = s8,  x9 = s9,  x10 = s10, x11 = s11;
    uint32_t x12 = s12, x13 = s13, x14 = s14, x15 = s15;

#define NC_DBLROUND                                            \
    NC_QR(x0, x4, x8,  x12);  NC_QR(x1, x5, x9,  x13);         \
    NC_QR(x2, x6, x10, x14);  NC_QR(x3, x7, x11, x15);         \
    NC_QR(x0, x5, x10, x15);  NC_QR(x1, x6, x11, x12);         \
    NC_QR(x2, x7, x8,  x13);  NC_QR(x3, x4, x9,  x14)
    NC_DBLROUND; NC_DBLROUND; NC_DBLROUND; NC_DBLROUND; NC_DBLROUND;
    NC_DBLROUND; NC_DBLROUND; NC_DBLROUND; NC_DBLROUND; NC_DBLROUND;
#undef NC_DBLROUND

    /* RFC 是「工作状态 + 初始状态」相加（不是异或），别写错。 */
    out[0]  = x0  + s0;   out[1]  = x1  + s1;
    out[2]  = x2  + s2;   out[3]  = x3  + s3;
    out[4]  = x4  + s4;   out[5]  = x5  + s5;
    out[6]  = x6  + s6;   out[7]  = x7  + s7;
    out[8]  = x8  + s8;   out[9]  = x9  + s9;
    out[10] = x10 + s10;  out[11] = x11 + s11;
    out[12] = x12 + s12;  out[13] = x13 + s13;
    out[14] = x14 + s14;  out[15] = x15 + s15;
}

/* 取整块 64 字节密钥流。返回 1 成功 / 0 无密钥（fail-closed）。 */
static int nc_chacha20_keystream64(uint64_t blk, uint8_t ks[64])
{
    if (!nc_chacha20_key_ready) {
        return 0;
    }
    uint32_t w[16];
    nc_chacha20_core((uint32_t)blk, w);
    for (int i = 0; i < 16; i++) {
        ks[i * 4 + 0] = (uint8_t)(w[i]);
        ks[i * 4 + 1] = (uint8_t)(w[i] >> 8);
        ks[i * 4 + 2] = (uint8_t)(w[i] >> 16);
        ks[i * 4 + 3] = (uint8_t)(w[i] >> 24);
    }
    return 1;
}

/* 单块前 8 字节 —— 供宿主对拍与基准（生产解密走 keystream64）。 */
static uint64_t nc_chacha20_block_head(uint64_t blk)
{
    uint8_t ks[64];
    if (!nc_chacha20_keystream64(blk, ks)) {
        return 0;
    }
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | (uint64_t)ks[i];
    }
    return v;
}

#endif /* NC_STRDEC_ALGO == CHACHA20 */


/* 第 blk 个密钥流块（8 字节）。
 *
 * NKEYS=1：mix64(key[0] + blk*GAMMA)  ← 与现有实现完全一致
 * NKEYS=4：四个 mix64 异或合并
 * ALGO=2：ChaCha20 第 blk 个 64 字节块的前 8 字节
 *
 * 为什么 4 个而不是"更多轮 mix64"：轮数叠加仍是可逆双射，攻击者照样
 * 一步反演（详见 nc_strdec.h 的安全边界）。异或合并则把未知数从 1 个
 * 提到 4 个 —— 一个方程四个未知数，才真正无解。
 */
static inline uint64_t nc_block_ks(uint64_t blk)
{
#if NC_STRDEC_ALGO == NC_STRDEC_ALGO_CHACHA20
    /* ChaCha20 用 blk 当 counter、key 当 256 位密钥、nonce 全零。
     *
     * 为什么 nonce 可以全零：counter 本身就是全包唯一的（= 块号），
     * 它已保证每条密文、每个位置都用不同的 (key, counter) 组合，
     * ChaCha20 的安全性前提（同一 key 下 counter 不重复）已满足。
     * 换独立随机 nonce 要多存 8~12 字节/条，而用户要求体积不涨。
     *
     * 取前 8 字节而非全部 64：上层按 8 字节粒度取密钥流
     * （keyByte(i) = block_ks(i>>3) 的第 (i&7) 字节），契约不变，
     * 因此解密主循环、offset 分配、密文格式全部零改动。 */
    return nc_chacha20_block_head(blk);
#else
    uint64_t w = nc_mix64(nc_key[0] + blk * nc_strdec_gamma[0]);
#  if NC_STRDEC_NKEYS > 1
    /* 每个 key 用不同的块偏移与步进，避免四个分量之间出现线性相关：
     * 若都用 blk 且步进相同，则 blk 递增时四个分量同步平移，
     * 异或结果的差分性质会退化。 */
    for (int t = 1; t < NC_STRDEC_NKEYS; t++) {
        w ^= nc_mix64(nc_key[t] + (blk + (uint64_t)t) * nc_strdec_gamma[t]);
    }
#  endif
    return w;
#endif
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
#if NC_STRDEC_ALGO == NC_STRDEC_ALGO_CHACHA20
    /* ChaCha20 需要 8 个 uint32 形态。必须在 nc_key 填好之后派生 ——
     * 顺序反了会拿全零密钥算出错误密钥流（构建期不报错，运行期全包乱码）。 */
    nc_chacha20_derive_key();
#endif
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

    /* ── 密钥流展开：两种算法的块粒度不同 ─────────────────────────
     *
     *   splitmix64 : 块 8 字节  → 块号 pos>>3，块内偏移 pos&7
     *   ChaCha20   : 块 64 字节 → 块号 pos>>6，块内偏移 pos&63
     *
     * 为什么 ChaCha20 要单独一条路径（2026-11-09）：它一次 20 轮天然产出
     * 64 字节。若硬套 8 字节契约，每 8 字节都重跑一次 20 轮，等于算了
     * 64 字节只用 8 字节，浪费 8 倍（实测 63 MB/s vs 500+ MB/s）。
     *
     * ⚠️ 两条路径的块边界必须与 encrypt-strings.py 的 key_byte_algo() 完全同源，
     *    否则构建期加密与运行期解密用不同的密钥流 → 全包乱码，且构建期不报错。
     *
     * ⚠️ 内层起始偏移必须从 (pos & mask) 起，不能固定从 0 —— off 未必对齐。
     *    这是历史事故（offset 不对齐的每条字符串全部静默解错，不崩不报错，
     *    只是文案/URL 全烂）。README「密钥流定义」的易错点 2。
     *
     * 就地解密的安全性：第 k 轮写 out[k]，读 out[k+3]。
     * 此前只写过 out[0..k-1]，而 k-1 < k+3 恒成立 → 读到的永远是原始密文。
     * 调用方传同一块缓冲也安全。 */
#if NC_STRDEC_ALGO == NC_STRDEC_ALGO_CHACHA20
    {
        /* 当前缓存的 64 字节密钥流块（blk_cached 无效时重算） */
        uint8_t ks[64];
        uint64_t blk_cached = ~(uint64_t)0;
        size_t k = 0;
        while (k < len) {
            const uint32_t pos = off + (uint32_t)k;
            const uint64_t blk = (uint64_t)(pos >> 6);
            if (blk != blk_cached) {
                if (!nc_chacha20_keystream64(blk, ks)) {
                    return -1;              /* fail-closed：无密钥绝不出明文 */
                }
                blk_cached = blk;
            }
            unsigned j = (unsigned)(pos & 63u);
            for (; j < 64 && k < len; j++, k++) {
                out[k] = (uint8_t)(out[k + 3] ^ ks[j]);
            }
        }
    }
#else
    {
        size_t k = 0;
        while (k < len) {
            const uint32_t pos = off + (uint32_t)k;
            const uint64_t w = nc_block_ks((uint64_t)(pos >> 3));
            unsigned j = (unsigned)(pos & 7u);
            for (; j < 8 && k < len; j++, k++) {
                out[k] = (uint8_t)(out[k + 3] ^ (uint8_t)(w >> (j * 8)));
            }
        }
    }
#endif

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

/* 虚拟密钥流第 i 个字节（与解密主循环里取密钥流的方式完全一致）。
 * 只给宿主基准用 —— 让 benchmark 测的是真实路径，不是另写一份等价逻辑
 * （另写就会测到"我以为的路径"，与产物里跑的代码脱节）。 */
uint8_t nc_strdec_key_byte_at(uint64_t i)
{
    const uint64_t w = nc_block_ks(i >> 3);
    return (uint8_t)(w >> ((i & 7) * 8));
}
#endif
