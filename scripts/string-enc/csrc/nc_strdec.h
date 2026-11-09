/* nc_strdec.h — 纯 C 字符串解密桩的【契约真相源】（2026-11-09）
 *
 * 这是什么：
 *   string-enc 模块的运行期解密实现，用 C 写，替代 stub-src/StrDec.java
 *   的 dn() 内核（Base64 解码 + splitmix64 密钥流 XOR + UTF-8 输出）。
 *
 * 为什么要有它（与 Java 桩的分工）：
 *   · Java 桩（StrDec.java）的算法可被 apktool 反编译成明文 smali；
 *     dex2c 联动能把它转译进 so，但要吃一次额外的 apktool 往返（+30~60s）
 *     且依赖 dex2c 引擎。
 *   · 本文件是手写的纯 C，不依赖任何引擎，可直接编进 libnc.so，
 *     并由 so_section_mark 标进 .ncx 加密段。
 *   · 目标不是"更强的算法"，是【算法不在 dex 里】+【不依赖 dex2c】。
 *
 * ⚠️ 安全边界（如实记录，别高估）：
 *   本文件实现的是"防静态可见性"级别的流密码，不是密码学安全的加密。
 *   已知边界：NKEYS=1 时，攻击者若已知算法 + 猜中任意一条明文，
 *   可反推出种子（splitmix64 与 XOR 均可逆）。这就是 NKEYS>1 存在的
 *   原因——它把"未知数个数"从 1 提到 4，使反推退化成一维搜索。
 *   详见 docs/流程文档.md §3.7 与本模块 README。
 *
 * ⚠️ 密文形态与 Java 侧必须逐字节一致（由 tests/test-cstrdec.sh 对拍锁定）：
 *     payload   = Base64( offset_be24 || cipher )
 *     offset    = 该条明文 UTF-8 字节在"全包虚拟密钥流"里的起始下标
 *     cipher[k] = plain_utf8[k] ^ keyByte(offset + k)
 *     keyByte(i) = (block_ks(i >> 3) >> ((i & 7) * 8)) & 0xFF
 *
 *   block_ks(blk) = XOR over t in [0,NKEYS):
 *                     mix64(key[t] + blk * gamma[t])
 *
 *   NKEYS=1 时退化为 block_ks(blk) = mix64(key[0] + blk*0x9E3779B97F4A7C15)，
 *   与 StrDec.java / encrypt-strings.py 的现有实现逐字节等价。
 *
 * 编码约束（为什么用 Base64 而不是原始字节）：
 *   payload 要落进 smali 的字符串字面量（const-string），原始字节可能含
 *   0x00 / 0x22(") / 0x5C(\) / 控制字符，会破坏语法。Base64 把任意字节
 *   映射到 64 个安全字符。代价是体积 +37%，换来语法安全 —— 这笔交易是
 *   必要的，不要为了省体积去掉它。
 */

#ifndef _NC_STRDEC_H_
#define _NC_STRDEC_H_

#include <stddef.h>
#include <stdint.h>

/* ── JNI 类型的前置声明 ────────────────────────────────────────────────
 *
 * ⚠️ 不直接 #include <jni.h>：本头文件被纯算法侧（nc_strdec.c）和宿主
 *    测试共同包含，而宿主/CI 环境未必装了 JNI 头。用条件包含 +
 *    前置声明让"只编算法"的场景零 JNI 依赖。
 *
 * 触发条件：只有真正在编 JNI 层（nc_strdec_jni.c）或宿主明确要求时才拉
 * <jni.h>。宿主测试走 NC_STRDEC_HOST_TEST 但不需要 JNI 声明，故也排除。
 */
#if !defined(NC_STRDEC_HOST_TEST) && !defined(NC_STRDEC_NO_JNI)
#  include <jni.h>
#endif
#if defined(NC_STRDEC_HOST_TEST) || defined(NC_STRDEC_NO_JNI)
/* 极简前置声明：只声明 nc_strdec_register_natives 用到的三个类型。
 * 不定义完整 JNI 接口表 —— 本头文件的调用者要么有真 jni.h，
 * 要么根本不会调用这些函数。 */
typedef struct JNIEnv_ JNIEnv;
typedef struct JavaVM_ JavaVM;
#endif

/* ── 强度档位（构建期常量，必须与 encrypt-strings.py 侧一致）─────────
 *
 * 1 = 与现有 Java/Python 实现逐字节兼容（用于分阶段验证，见文件头说明）
 * 4 = 256 位秘密，猜中一条明文只能解出那一条
 *
 * ⚠️ 改这个值必须同时改 scripts/string-enc/encrypt-strings.py 的
 *    NC_STRDEC_NKEYS，否则构建期加密与运行期解密不一致 → 全包乱码。
 *    两侧一致性由 tests/test-cstrdec.sh 对拍锁定。
 */
#ifndef NC_STRDEC_NKEYS
#  define NC_STRDEC_NKEYS 1
#endif

#define NC_STRDEC_KEYLEN (NC_STRDEC_NKEYS * 8)   /* 字节数：NKEYS 个 uint64 */

/* ── 密钥流算法档位（构建期常量，必须与 encrypt-strings.py 侧一致）───────
 *
 * 与 NKEYS 一样是【编译期】常量，不是运行期开关：它决定密钥流怎么算，
 * 构建期加密与运行期解密必须用同一档，否则全包乱码且构建期不报错。
 *
 *   1 = splitmix64（默认，历史实现）  block_ks(blk) = mix64(key + blk*γ)
 *   4 = splitmix64 × 4 个密钥         XOR 合并四个分量（未知数 1→4）
 *   2 = ChaCha20                      block_ks 取 64 字节块的前 8 字节
 *
 * 为什么 ChaCha20 是"安全"档而 splitmix64 是"速度"档：
 *   splitmix64 与 XOR 都可逆 → 猜中任意一条明文即可反解种子 → 全包沦陷。
 *   ChaCha20 的密钥流是 PRF 输出 → 猜中一条只泄漏那一条，解不出密钥。
 *   两者体积完全相同（offset 直接当 nonce，不额外存 nonce）。
 */
#ifndef NC_STRDEC_ALGO
#  define NC_STRDEC_ALGO 0   /* 0 = 沿用 NKEYS 决定（历史行为） */
#endif
#define NC_STRDEC_ALGO_SPLITMIX 0
#define NC_STRDEC_ALGO_CHACHA20 2

#if NC_STRDEC_ALGO != 0 && NC_STRDEC_ALGO != NC_STRDEC_ALGO_CHACHA20
#  error "NC_STRDEC_ALGO 只支持 0（splitmix64，按 NKEYS 分档）或 2（ChaCha20）"
#endif
#if NC_STRDEC_ALGO == NC_STRDEC_ALGO_CHACHA20 && NC_STRDEC_NKEYS != 1
#  error "ChaCha20 档只支持 NKEYS=1（256 位密钥直接当 ChaCha20 key，不做异或合并）"
#endif


/* splitmix64 终混合常量（与 Java/Python 同源，勿改） */
#define NC_STRDEC_C1 0xBF58476D1CE4E5B9ULL
#define NC_STRDEC_C2 0x94D049BB133111EBULL

/* 各 key 的块步进增量。全为奇数（保证 mod 2^64 上的满周期步进）。
 * 索引 0 恒为 splitmix64 的黄金分割增量 —— 这是 NKEYS=1 兼容性的锚点。 */
extern const uint64_t nc_strdec_gamma[NC_STRDEC_NKEYS];

/* ── API ───────────────────────────────────────────────────────────── */

/* 设置密钥。key 长度必须是 NC_STRDEC_KEYLEN，按大端序解释：
 *   key[0..7] → key[0]，key[8..15] → key[1]，依此类推。
 * 大端序与 Java 侧 SEED 字面量（0x…L）和 Python 侧 int.from_bytes(..,'big')
 * 一致。线程安全：只在 <clinit> / 首次解密前调用一次。 */
void nc_strdec_set_key(const uint8_t *key);

/* 当前是否已设置密钥（0 = 未设置，1 = 已设置）。
 * 未设置时 decrypt 一律返回 -1（fail-closed，绝不返回"假明文"）。 */
int nc_strdec_has_key(void);

/* Base64 解码，4 字符一组（一次吃 4 字符出 3 字节，无分支、无中间状态）。
 *
 * 为什么不用逐字符版：实测逐字符实现在真实负载下比 4-way 慢约 20 倍
 * （1.11ms vs 0.05ms / 1.3 万条），而它是整条解密链路里最大的一笔开销，
 * 比密钥流生成本身大一个数量级。算法等价性由对拍测试锁定。
 *
 * 支持标准 Base64 字母表与 '=' 填充（NO_WRAP 形态）。
 * 返回：写入 out 的字节数（>=0）；-1 = 输入含非法字符或 out 容量不足。 */
int nc_strdec_b64_decode(const char *s, size_t n, uint8_t *out, size_t outcap);

/* 单条解密：Base64 payload → 明文 UTF-8 字节。
 *
 * 就地解码：先把整个 payload 解码进 out（需要 outcap >= 解码后长度），
 * 再从 out[3..] 读出密文、把明文写回 out[0..len)。调用方按
 * outcap >= b64len * 3 / 4 + 4 分配即可。
 *
 * 返回：明文长度（>0）；-1 = 失败。
 *
 * 失败语义（与 Java 桩的 catch 兜底等价）：任何失败都返回 -1，
 * 调用方（JNI 层）必须【原样返回传入的 payload 对象】，不抛异常、
 * 不崩溃、不缓存。这是"密文损坏 → 降级为原样返回"的历史契约，
 * 不要改成抛异常（会把解密问题变成闪退）。
 *
 * ⚠️ 返回 0 是合法值吗：不是。明文为空串的记录在构建期就被跳过了
 *    （空串无信息量，且 3 字节 payload 会走"原样返回"兜底）。
 *    因此 len==0 一律按失败处理。 */
int nc_strdec_decrypt(const char *b64, size_t b64len, uint8_t *out, size_t outcap);

/* ── UTF-8 → UTF-16 转换 ──────────────────────────────────────────────
 *
 * 为什么必须自己做，不能用 JNI 的 NewStringUTF：
 *   NewStringUTF 接收的是 **modified UTF-8**，不是标准 UTF-8：
 *     · U+0000 必须编码成 0xC0 0x80（而不是 0x00）
 *     · 补充平面字符（emoji U+10000+）必须编码成 CESU-8 的两个 3 字节代理
 *   把标准 UTF-8 直接喂给它，emoji 会变成乱码或抛异常。
 *   而现有 Java 桩用的是 new String(bytes, "UTF-8")（标准 UTF-8 语义）。
 *   要逐字节等价，只能自己解码成 jchar 数组，再 NewString。
 *
 * 语义对齐 new String(byte[], "UTF-8")：
 *   · 合法 UTF-8 → 相同的 UTF-16 序列（含 U+0000，NewString 允许内嵌 NUL）
 *   · 非法输入 → 本实现返回 -1（fail-closed，调用方原样返回密文）；
 *     Java 的 CharsetDecoder 是 REPLACE 动作，会产出 U+FFFD。
 *     ⚠️ 这是【已知的、刻意的行为差异】：只在密文损坏时出现，
 *     正常路径（构建期加密的都是合法 UTF-8）两者完全一致。
 *     选 fail-closed 的理由：损坏时返回 base64 原串（一眼看出坏了），
 *     比返回含 U+FFFD 的"看起来像正常字符串"的垃圾更安全。
 *     由 tests/test-cstrdec-vs-java.sh 断言"合法输入两侧一致"。
 *
 * 拒绝的情况（RFC 3629）：overlong 编码、代理区 U+D800..U+DFFF、
 *   > U+10FFFF、截断序列、非法起始字节。
 *
 * 返回：写入 out 的 UTF-16 码元数（>=0）；-1 = 非法或容量不足。 */
int nc_strdec_utf8_to_utf16(const uint8_t *in, size_t len,
                           uint16_t *out, size_t outcap);

/* ── JNI 层（实现在 nc_strdec_jni.c，本头文件只给注册入口）──────────
 *
 * 为什么单独一个文件：nc_strdec.c 是纯算法（宿主测试不需要 JVM），
 * JNI 类型转换、缓存、异常处置都在 .c 之外。将来若把桩搬进别的 so
 * （如 dpt 壳），只需重写这一层。
 */

/* ── JNI 层（实现在 nc_strdec_jni.c）───────────────────────────────
 *
 * 本头文件【不】暴露注册入口：绑定由构建期生成的 nc_strdec_bind.c
 * 用 JNI 短名完成（Java_<mangled>_<method>），不需要 RegisterNatives，
 * 也不需要 JNI_OnLoad。原因见 nc_strdec_jni.c 顶部说明。
 */

/* ── JNI 实现本体（供构建期生成的 nc_strdec_bind.c 转调）────────────
 *
 * 本头文件在宿主侧不 include <jni.h>，故只在有 jni.h 时声明。
 * 重复声明必须与定义逐字一致，否则报 conflicting types（实测踩过）。
 */
#if !defined(NC_STRDEC_HOST_TEST) && !defined(NC_STRDEC_NO_JNI)
jstring nc_strdec_jni_decrypt(JNIEnv *env, jclass clazz, jstring payload);
void    nc_strdec_jni_set_key(JNIEnv *env, jclass clazz, jbyteArray key);
#endif

/* ── 仅供宿主测试（NC_STRDEC_HOST_TEST）─────────────────────────────
 * 暴露单块密钥流，便于与 Python/Java 侧逐值对拍。
 * 生产构建不导出符号（static linkage），不进 .dynsym。 */
uint64_t nc_strdec_block_ks(uint64_t blk);
/* 虚拟密钥流第 i 个字节（与解密主循环取密钥流的方式一致）。
 * 用途：宿主基准测两种算法的真实吞吐，避免另写一份等价逻辑而测错路径。 */
uint8_t  nc_strdec_key_byte_at(uint64_t i);

#endif /* _NC_STRDEC_H_ */
