/*
 * sig_guard2.c — 签名校验第二独立线(2026-10)
 *
 * 【为什么存在】
 *   第一线 sig_check.c 的所有失败路径最终汇聚到单个 delayed_kill()。
 *   实测(2026-10):把该函数入口 4 字节改成 ret,整条杀链即失效,重签名包
 *   可正常运行。单点 = 改一处全废。
 *   本模块提供【完全独立】的第二线:独立取指纹来源、独立派生公式、独立
 *   标准答案(sig_guard2.h)、独立处置路径。攻击者改掉第一线,本线照跑。
 *
 * 【与 sig_check.c 的关系】
 *   - 零代码共享:不复用其函数、不 include sig_hash.h
 *     (共享标准答案 = 单点:改一处两线同废)
 *   - 同源指纹:两份答案都由 make-sig-hash.sh 从同一 APK 生成
 *   - 各自挂 constructor,互不感知
 *
 * 【派生公式(与第一线不同,与 make-sig-hash.sh 生成侧逐字节一致)】
 *   t2       = SHA256(b"G2" || fp)                    轮1:域分隔
 *   stored[i]= t2[i] ^ salt2[(i*7)%16] ^ ((i*0x5B+0x3D)&0xFF)
 *
 * 【处置:两条路径,互不依赖】
 *   路径 A(明杀):syscall(__NR_tgkill, SIGKILL) —— SIGKILL 不可捕获
 *   路径 B(反制):校验失败后起 watchdog;若 N 秒后进程仍活着,说明杀路径
 *                 被 patch 了 —— 再走一条完全不同的路径(exit_group)
 *
 * 【误报兜底】任一步 I/O/解析异常 → 视为"未检出",绝不误伤。
 *   全零标准答案 = 调试模式(流水线未注入) → 跳过。
 *
 * 【性能】构造期一次解析 + SHA-256;watchdog 线程睡眠不耗 CPU。
 *   正常运行路径零开销。
 */
/*
 * _GNU_SOURCE 必须是文件里【第一个】生效的宏，且早于任何系统头文件。
 * 原因（2026-11-01，CI 上暴露）：路径②用 Dl_info + dladdr() 反推本 so 路径，
 * 而 Dl_info 在 glibc 里受 __USE_GNU 保护（只在 _GNU_SOURCE 下可见）。
 * Android bionic / Termux / macOS 默认暴露它，所以本机总是能编过；
 * 一旦在 glibc（ubuntu CI 的宿主端 clang 测试）上编译就报
 *   error: use of undeclared identifier 'Dl_info'
 *   error: call to undeclared function 'dladdr'
 *
 * ⚠️ 位置不能挪到 <dlfcn.h> 前面就算完：glibc 的 feature-test 宏在
 *    【第一个系统头文件】被包含时就已经定型，之后定义无效。
 *    所以必须在 <stdio.h> 之前 —— 第一次改就栽在这里。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/syscall.h>

#include "sig_guard2.h"

/* ── SHA-256 的【固有】输出长度 vs 业务摘要长度 ──────────────────────
 *
 * 2026-11-22 审核发现的一处混用：本文件里数组维度写死 [32]，
 * 而循环上界用 SG2_HASH_LEN。两者当前都是 32 所以没暴露，
 * 但只要有人把 SG2_HASH_LEN 改小（或生成侧改摘要长度），
 * 比对循环就只覆盖前 SG2_HASH_LEN 字节，
 * 【后 32 - SG2_HASH_LEN 字节的差异被静默忽略】—— 签名校验静默变弱。
 *
 * 实测：把 SG2_HASH_LEN 设成 16，循环停在 i=16，后 16 字节不参与比较。
 *
 * 区分两个概念：
 *   SG2_SHA256_LEN  SHA-256 的输出长度，由算法决定，永远 32，不可改
 *   SG2_HASH_LEN    业务用到的摘要长度，由生成侧写入（当前等于 32）
 * 数组都按 SG2_SHA256_LEN 开（容量足够），循环上界用 SG2_HASH_LEN（业务语义），
 * 并在下面加 _Static_assert 挡住"业务长度 > 算法能力"的误配。 */
#define SG2_SHA256_LEN 32

_Static_assert(SG2_HASH_LEN <= SG2_SHA256_LEN,
               "SG2_HASH_LEN 超过 SHA-256 输出长度 —— "
               "生成侧与 sig_guard2.c 的摘要长度契约不一致");
#include "nc_guard_layout.h"  /* 契约常数单一真相源：段名/尺寸/偏移
                               * 2026-10-28 T5b：本文件此前没 include 它，
                               * 因为没有段标记需求；现在 G2_SEC_MARKED 要用
                               * NC_SEC_CODE，故补上。零依赖头，任何工具链可编。 */
/* LSGS 密文表（2026-10-19 补）：本文件此前不在 make-sig-log.py 的扫描
 * 清单里，导致 .rodata 字符串全明文（复测报告实测命中 2 处）。 */

/*LSGS:G2_BLOCK_MAGIC|APK Sig Block 42*/
/* 路径 ①② 用到的字面量（2026-10-22 补）。
 * 实测报告（2026-10-22）明确点名这批串：
 *   "apk path from maps: %s" / "/data/app" / "base.apk" …
 *   报告说"相当于把校验流程的伪代码印在了 .rodata 里"。
 * 本文件此前只做了 magic，路径串漏了 —— 复测实测 so 里仍可 strings 到。 */
/*LSGS:G2_SUFFIX_APK|base.apk*/
/*LSGS:G2_DIR_LIB|/lib/*/
/* 注：/proc/self/maps 复用 sig_check.c 已定义的 LSGS_PATH_MAPS2，
 * 不另立标记（同内容两条标记会因生成器的宏名唯一性检查而 fail-fast）。
 *
 * /proc/%d/root%s（路径 ② 的 SELinux 绕行前缀）：这个格式串无法整体密文化
 * ——它含 %d/%s 占位符，且拆开后会暴露 "root" 这个语义关键词。改为
 * 运行期由两段密文拼装（见 g2_root_prefix()）。 */
/*LSGS:G2_PATH_PROC|/proc/*/
/*LSGS:G2_PATH_ROOT|root*/

/* ── .rodata 字符串密文化（2026-10-19）─────────────────────────
 * 本文件是独立的第二签名校验线（与 sig_check.c 双线互备），
 * 上一轮 LSGS 改造漏了它 —— 复测报告实测：
 *   APK Sig Block 42 仍在 .rodata 明文（2 处）
 *   /proc/self/maps   仍在 .rodata 明文
 * 攻击者 strings 一遍即知道「这里有第二条签名校验线」。
 * 标记格式见 make-sig-log.py（此处不写其字面形态，防嵌套注释）。
 * ⚠️ 需同步 make-sig-log.py 的扫描清单与 protect.sh 的传参。 */

/* ── 日志:纯 logcat,零文件 I/O(与第一线解耦,也不受其哨兵开关影响) ──
 * ⚠️ 2026-11-24 补 SIGGUARD2_HOST_TEST 豁免：多路化后 g2_collect_fp /
 *    g2_verify 里有 G2LOG 调用，而 test-sig-guard2.sh 会在宿主【链接并
 *    运行】本文件 —— Termux 的 clang 定义 __ANDROID__，G2LOG 变成真调用，
 *    链接报 undefined symbol: __android_log_print（宿主没有 liblog）。
 *    宿主测试只验证派生公式，不需要 logcat，退化为空操作。 */
#if defined(__ANDROID__) && !defined(SIGGUARD2_HOST_TEST)
#include <android/log.h>
#define G2LOG(...) __android_log_print(ANDROID_LOG_INFO, "nc", __VA_ARGS__)
#else
#define G2LOG(...) do { } while (0)
#endif

/* LSGS 密文表：路径字面量与签名块 magic 走它解码。
 * ⚠️ 条件包含（与仓库既有的 SIGGUARD2_HOST_TEST 约定一致）：
 *    宿主测试只验证派生公式，不构建 sig_log_data.h（流水线产物），
 *    此时退化为明文字面量。测试环境不需要密文，只需要公式对。 */
#ifndef SIGGUARD2_HOST_TEST
#  include "sig_log_data.h"
#  define G2_HAVE_LSGS 1
#endif

/* ── T5b（2026-10-28）：第二签名校验线主干进加密段 ──────────────────
 *
 * 为什么补这一处：T5 首轮只标了 sig_check.c 的 4 个函数，测 CI 产物时
 * 发现 .text 里仍有 2 处 v2/v3 block id 装载 —— 追查到本文件。
 * sig_guard2.c 是【独立的第二签名校验线】，自带一份完整流程：
 *   g2_find_apk / g2_extract_cert / g2_derive / g2_verify
 * 一行段标记都没有，整条线是明文。逆向报告（外部实测报告结论汇总.md §三 3.1）早就
 * 点名过这一点（"相当于把校验流程的伪代码印在了 .rodata 里"），
 * 上一轮只做了 .rodata 字符串密文化，代码仍在明文。
 *
 * ⚠️ g2_entry 是 constructor，【绝不能】标段 —— 它是 unlock 的调用方，
 *    标进去 = 解锁前执行密文 = 死锁。
 * ⚠️ 条件化 SIGGUARD2_HOST_TEST：宿主测试没有解锁设施，标了读到密文 → 假红。
 *    与 sig_check.c 的 SIG_SEC_MARKED 同一纪律。 */
#if defined(NC_GUARD_SECTIONED) && !defined(SIGGUARD2_HOST_TEST)
/* ── 2026-11-17：第二道防线补 VMP ────────────────────────────────────
 *
 * 背景：本文件是【独立第二线】（与 sig_check.c 零代码共享，独立证书
 * 派生 + 独立处置路径 g2_kill_hard/tgkill + watchdog）。设计意图是
 * "第一线被破了还有第二道"。
 *
 * 但此前 G2_SEC_MARKED 只有段标记、没有 annotate("+vm_virtualize")，
 * 于是 4 个标记函数全部只吃 Flatten+Mba —— 而第一线对应的
 * derive_expected / sig_compare_fp 是有 VMP 的。结果：攻击者破了第一线
 * 之后，第二线的判定逻辑是"可读状态机"，第二线价值掉一半。
 *
 * 修法：判定点补 VMP，支撑函数保持只有段（吃混淆）。
 * 与 sig_check.c 同一纪律：链式依赖里只有判定点需要 VMP。
 *
 *   需要 VMP（判定点）：
 *     g2_derive —— 第二套派生公式（对应第一线的 derive_expected）
 *     g2_verify —— 比对 + 处置调度（对应 sig_compare_fp + sig_verify）
 *   不需要 VMP（支撑函数，改了只会导致失败）：
 *     g2_find_apk / g2_extract_cert / 各种 g2_sha_* / g2_rd* / watchdog
 *
 * ⚠️ g2_entry 是 constructor，【绝不能】标段 —— 它是 unlock 的调用方，
 *    标进去 = 解锁前执行密文 = 死锁。
 * ⚠️ 条件化 SIGGUARD2_HOST_TEST：宿主测试没有解锁设施，标了读到密文 → 假红。
 *    与 sig_check.c 的 SIG_SEC_MARKED 同一纪律。 */
#  if defined(NC_AMICE_VMP)
#    define G2_SEC_MARKED \
       __attribute__((section(NC_SEC_CODE), retain, used, noinline, \
                      annotate("+vm_virtualize")))
#    define G2_SEC_MARKED_NOVMP \
       __attribute__((section(NC_SEC_CODE), retain, used, noinline))
#  else
#    define G2_SEC_MARKED \
       __attribute__((section(NC_SEC_CODE), retain, used, noinline))
#    define G2_SEC_MARKED_NOVMP \
       __attribute__((section(NC_SEC_CODE), retain, used, noinline))
#  endif
#else
#  define G2_SEC_MARKED
#  define G2_SEC_MARKED_NOVMP
#endif

/* ═══════════════════════ SHA-256(公共域精简实现,自包含) ═══════════════════════ */
typedef struct {
    unsigned int state[8];
    unsigned long long bitlen;
    unsigned char data[64];
    unsigned int datalen;
} g2_sha_ctx;

static const unsigned int g2_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define G2_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define G2_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define G2_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define G2_EP0(x) (G2_ROTR(x,2) ^ G2_ROTR(x,13) ^ G2_ROTR(x,22))
#define G2_EP1(x) (G2_ROTR(x,6) ^ G2_ROTR(x,11) ^ G2_ROTR(x,25))
#define G2_SG0(x) (G2_ROTR(x,7) ^ G2_ROTR(x,18) ^ ((x) >> 3))
#define G2_SG1(x) (G2_ROTR(x,17) ^ G2_ROTR(x,19) ^ ((x) >> 10))

static void g2_transform(g2_sha_ctx *c, const unsigned char d[64]) {
    unsigned int m[64], a,b,cc,e,f,g,h,t1,t2;
    int i;
    for (i = 0; i < 16; i++)
        m[i] = ((unsigned int)d[i*4] << 24) | ((unsigned int)d[i*4+1] << 16) |
               ((unsigned int)d[i*4+2] << 8) | (unsigned int)d[i*4+3];
    for (i = 16; i < 64; i++)
        m[i] = G2_SG1(m[i-2]) + m[i-7] + G2_SG0(m[i-15]) + m[i-16];
    a=c->state[0]; b=c->state[1]; cc=c->state[2]; e=c->state[3];
    f=c->state[4]; g=c->state[5]; h=c->state[6]; /* state[7] 暂存 */
    {
        unsigned int dd = c->state[3];
        unsigned int ee = c->state[4], ff = c->state[5], gg = c->state[6], hh = c->state[7];
        unsigned int aa = c->state[0], bb = c->state[1], ccc = c->state[2];
        for (i = 0; i < 64; i++) {
            t1 = hh + G2_EP1(ee) + G2_CH(ee,ff,gg) + g2_k[i] + m[i];
            t2 = G2_EP0(aa) + G2_MAJ(aa,bb,ccc);
            hh=gg; gg=ff; ff=ee; ee=dd+t1; dd=ccc; ccc=bb; bb=aa; aa=t1+t2;
        }
        c->state[0]+=aa; c->state[1]+=bb; c->state[2]+=ccc; c->state[3]+=dd;
        c->state[4]+=ee; c->state[5]+=ff; c->state[6]+=gg; c->state[7]+=hh;
    }
    (void)a;(void)b;(void)cc;(void)e;(void)f;(void)g;(void)h;
}

static void g2_sha_init(g2_sha_ctx *c) {
    c->datalen = 0; c->bitlen = 0;
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
}

static void g2_sha_update(g2_sha_ctx *c, const unsigned char *d, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        c->data[c->datalen++] = d[i];
        if (c->datalen == 64) { g2_transform(c, c->data); c->bitlen += 512; c->datalen = 0; }
    }
}

static void g2_sha_final(g2_sha_ctx *c, unsigned char out[SG2_SHA256_LEN]) {
    unsigned int i = c->datalen;
    int j;
    c->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) c->data[i++] = 0;
        g2_transform(c, c->data);
        i = 0;
    }
    while (i < 56) c->data[i++] = 0;
    c->bitlen += (unsigned long long)c->datalen * 8;
    for (j = 7; j >= 0; j--) c->data[56 + (7 - j)] = (unsigned char)(c->bitlen >> (j * 8));
    g2_transform(c, c->data);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (unsigned char)(c->state[i] >> 24);
        out[i*4+1] = (unsigned char)(c->state[i] >> 16);
        out[i*4+2] = (unsigned char)(c->state[i] >> 8);
        out[i*4+3] = (unsigned char)(c->state[i]);
    }
}

/* ═══════════════════════ 基础 I/O 工具 ═══════════════════════ */
static int g2_read_at(int fd, void *buf, size_t len, off_t off) {
    ssize_t n;
    while (len > 0) {
        n = pread(fd, buf, len, off);
        if (n <= 0) return -1;
        buf = (char *)buf + n; len -= (size_t)n; off += n;
    }
    return 0;
}

static unsigned int g2_rd32le(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static unsigned long long g2_rd64le(const unsigned char *p) {
    return (unsigned long long)g2_rd32le(p) | ((unsigned long long)g2_rd32le(p + 4) << 32);
}

/* ═══════════════════════ APK 定位(精简版) ═══════════════════════
 *
 * 与第一线的 find_apk_path 是【同一目的、不同实现】—— 两条线刻意零代码
 * 共享（AGENTS.md §1：共享 = 单点，改一处两线同废）。所以这里不做"抽公共
 * 模块"，只在本文件内按探测方式拆开，理由与第一线那次重构相同：
 *
 *   2026-11-22：108 行、三层嵌套（maps 扫描 / dladdr 反推 / 逐级回退）
 *   全在一个函数里，且共享 line[]/fp/out 这些可变量。改一路要通读全部。
 *
 * 拆成：
 *   g2_locate_hosttest  宿主测试环境变量
 *   g2_locate_maps      maps 里 base.apk 行
 *   g2_locate_so_dir    由 so 路径反推安装根（含逐级回退）
 *   g2_find_apk         调度：依次试
 *
 * ⚠️ 守恒契约（改前必读）：
 *  ① 每个定位器带 G2_SEC_MARKED_NOVMP —— 它们原本在 .ncx 段里，
 *     漏标 → 掉出加密范围，编译链接全过、防御静默变弱。
 *  ② 顺序不能变：hosttest → maps → so_dir。
 *     看似比第一线少一路（没有 /data/app 遍历）—— 这是刻意的，
 *     见下方注释：那条路在 Android 11+ 必失败，留着只是噪声。
 *  ③ 各自声明缓冲，不共享 line[]/fp。
 *  ④ 返回语义：定位器成功 0 / 失败 -1；调度器任一成功即 0，全失败 -1。
 */

/* 路径字面量：生产走 LSGS 密文，宿主测试用明文本地宏。
 *
 * 为什么要回落：本文件在 SIGGUARD2_HOST_TEST 下【不包含】sig_log_data.h
 * （那是流水线产物），因此 lsg_s / LSGS_G2_* 在该模式下不存在。
 * 宿主测试只验证派生公式，不需要密文 —— 与 g2_block_magic() 同款处理。
 * 生产路径：这 5 条全部走 LSGS 解码，so 里零明文（实测确认）。 */
#ifdef G2_HAVE_LSGS
#  define G2_APK_SUFFIX()  (lsg_s(LSGS_G2_SUFFIX_APK, g2_kbuf1, sizeof(g2_kbuf1)))
#  define G2_DIR_LIB()     (lsg_s(LSGS_G2_DIR_LIB,    g2_kbuf2, sizeof(g2_kbuf2)))
#  define G2_PATH_PROC()   (lsg_s(LSGS_G2_PATH_PROC,  g2_kbuf3, sizeof(g2_kbuf3)))
#  define G2_PATH_ROOT()   (lsg_s(LSGS_G2_PATH_ROOT,  g2_kbuf4, sizeof(g2_kbuf4)))
static char g2_kbuf1[16], g2_kbuf2[16], g2_kbuf3[16], g2_kbuf4[8];
#else
#  define G2_APK_SUFFIX()  ("base.apk")
#  define G2_DIR_LIB()     ("/lib/")
#  define G2_PATH_PROC()   ("/proc/")
#  define G2_PATH_ROOT()   ("root")
#endif

/* 定位器 0：宿主测试环境变量（只在该宏下有效）。 */
G2_SEC_MARKED_NOVMP
static int g2_locate_hosttest(char *out, size_t outlen) {
#ifdef SIGGUARD2_HOST_TEST
    const char *t = getenv("SIGGUARD2_TEST_APK");
    if (t && *t) {
        snprintf(out, outlen, "%s", t);
        return 0;
    }
#else
    (void)out; (void)outlen;
#endif
    return -1;
}

/* 定位器 ①：maps 里出现 "base.apk" 的行 → 截尾部空格后的纯路径。
 *
 * ⚠️ 与第一线的 apk_locate_maps 是两份独立实现（零共享约束）。
 *    第一线那边有一段很长的报错十二/十七历史注释（".so" 子串误命中、
 *    行首元数据没截掉）。本线只取最后一格空格后的路径，天然不受
 *    ".so" 误命中影响 —— 但【不要】因为"看起来更简洁"就把第一线也
 *    改成这个写法：第一线的写法是两轮真机闪退换来的，改动需重新验证。 */
G2_SEC_MARKED_NOVMP
static int g2_locate_maps(char *out, size_t outlen) {
    FILE *fp;
    char line[1024];

#ifdef G2_HAVE_LSGS
    char _mb[24];
    const char *_mp = lsg_s(LSGS_PATH_MAPS2, _mb, sizeof(_mb));
    fp = _mp ? fopen(_mp, "r") : NULL;
#else
    fp = fopen("/proc/self/maps", "r");
#endif
    if (!fp) return -1;

    while (fgets(line, sizeof(line), fp)) {
        /* "base.apk" 走 LSGS（报告 §6.3 点名的明文串之一） */
        const char *_apk = G2_APK_SUFFIX();
        char *p = _apk ? strstr(line, _apk) : NULL;
        if (p) {
            char *sp;
            p += 8;
            *p = '\0';
            sp = strrchr(line, ' ');
            if (sp) {
                snprintf(out, outlen, "%s", sp + 1);
                if (access(out, R_OK) == 0) { fclose(fp); return 0; }
            }
        }
    }
    fclose(fp);
    return -1;
}

/* 定位器 ②：由本 so 路径反推安装根（extractNativeLibs=true 场景）。
 *
 * 三步尝试：/proc/<pid>/root 前缀版 → 原路径 → 逐级回退找根目录。
 * 三级回退是因为 so 可能在 lib/<abi>/ 之外的层级（某些厂商 ROM）。 */
G2_SEC_MARKED_NOVMP
static int g2_locate_so_dir(char *out, size_t outlen) {
    Dl_info info;

    if (dladdr((const void *)&g2_locate_so_dir, &info) == 0 || !info.dli_fname) {
        return -1;
    }
    {
        const char *_libp = G2_DIR_LIB();
        const char *p = _libp ? strstr(info.dli_fname, _libp) : NULL;
        if (p) {
            size_t n = (size_t)(p - info.dli_fname);
            if (n + 64 < outlen) {
                int i;
                const char *_apk2 = G2_APK_SUFFIX();
                memcpy(out, info.dli_fname, n);
                /* /proc/<pid>/root 前缀,获得 SELinux 可读的真实路径。
                 * 格式串本身也是泄露项 → 由两段密文拼装。 */
                snprintf(out + n, outlen - n, "/%s", _apk2 ? _apk2 : "base.apk");
                if (out[0] == '/') {
                    char real[1024];
                    const char *_proc = G2_PATH_PROC();
                    const char *_root = G2_PATH_ROOT();
                    if (_proc && _root) {
                        snprintf(real, sizeof(real), "%s%d/%s%s",
                                 _proc, (int)getpid(), _root, out);
                        if (access(real, R_OK) == 0) {
                            snprintf(out, outlen, "%s", real);
                            return 0;
                        }
                    }
                }
                /* 直接试原路径 */
                if (access(out, R_OK) == 0) return 0;
                /* 逐级回退找根目录 */
                for (i = (int)n - 1; i > 0; i--) {
                    if (out[i] == '/') {
                        char cand[1024];
                        out[i] = '\0';
                        snprintf(cand, sizeof(cand), "%s/%s", out,
                                 _apk2 ? _apk2 : "base.apk");
                        if (access(cand, R_OK) == 0) {
                            snprintf(out, outlen, "%s", cand);
                            return 0;
                        }
                        out[i] = '/';
                    }
                }
            }
        }
    }
    return -1;
}

/* 调度：依次试，第一个成功即返回。
 *
 * ⚠️ 为什么没有第三路「扫 /data/app」：
 *    那条路在 Android 11+ 必失败（SELinux EACCES，第一线的日志实测
 *    errno=13），留着只是噪声。第一线保留它是因为要兼容旧机型；
 *    本线是 2026-10 之后写的"精简版"，有意不复制这个已知无效分支。
 *    如果将来真的要支持 Android 10 以下，在这里加 g2_locate_scan 即可
 *    （需要同时加 G2_SEC_MARKED_NOVMP 与自己的缓冲）。 */
G2_SEC_MARKED_NOVMP
static int g2_find_apk(char *out, size_t outlen) {
    if (g2_locate_hosttest(out, outlen) == 0) return 0;
    if (g2_locate_maps(out, outlen) == 0) return 0;
    if (g2_locate_so_dir(out, outlen) == 0) return 0;
    return -1;
}

/* ═══════════════════════ APK Signing Block 解析 ═══════════════════════
 * 与第一线同布局(AOSP v2/v3),但独立实现。找出证书 DER。 */
/* magic 改运行期解码（2026-10-19）：明文字面量会告诉攻击者
 * 「这是 APK 签名块」，strings 一条命令即中。
 * 返回 16 字节静态缓冲（magic 只有前 14 字节有效，末 2 字节补 0）。 */
#ifdef G2_HAVE_LSGS
static const char *g2_block_magic(void) {
    /* ⚠️ 必须 ≥17：lsg_s 是「C 字符串」语义，缓冲按 len+1 给
     * （16 字节 magic + 1 字节 NUL）。曾写 buf[16] → lsg_decode 判
     * len+1 > buflen 恒失败 → 返回 NULL → magic 比对必败 → 第二线
     * 在真机上 6 路全部 "cert extract fail" 静默跳过（防御自部署起
     * 从未生效，失败语义是"未检出"所以从不崩溃也从不报错）。
     * 2026-11-24 第二线多路化加日志后才暴露。第一线同款函数
     * （sig_check.c:sig_block_magic）2026-10-21 全量误杀事故时已修到
     * buf[17]，教训只修了自己那条线 —— 本文件同构 bug 沉睡至今。
     * 宿主测试测不到它：SIGGUARD2_HOST_TEST 下走明文 #else 分支。 */
    static char buf[17];
    const char *s = lsg_s(LSGS_G2_BLOCK_MAGIC, buf, sizeof(buf));
    if (!s) return NULL;
    return buf;
}
#else
/* 宿主测试：明文字面量（无密文表） */
#  define g2_block_magic()  ("APK Sig Block 42")
#endif
#define G2_V2_ID 0x7109871aULL
#define G2_V3_ID 0xf05368c0ULL

G2_SEC_MARKED_NOVMP
static int g2_extract_cert(int fd, unsigned char **out_der, size_t *out_len) {
    off_t fsize, pos, search_start;
    unsigned char eocd[22], magic[16], sz8[8], header[12];
    unsigned long long cd_off, block_size, pair_len, block_id;
    off_t block_start, pair_pos;
    unsigned char *value = NULL;
    int found = -1;

    fsize = lseek(fd, 0, SEEK_END);
    if (fsize < 22) return -1;

    search_start = (fsize > 65557) ? (fsize - 65557) : 0;
    for (pos = fsize - 22; pos >= search_start; pos--) {
        if (g2_read_at(fd, eocd, 22, pos) != 0) return -1;
        if (eocd[0]==0x50 && eocd[1]==0x4b && eocd[2]==0x05 && eocd[3]==0x06) break;
    }
    if (pos < search_start) return -1;

    cd_off = g2_rd32le(eocd + 16);
    if (cd_off == 0 || cd_off == 0xffffffffULL) return -1;
    if ((off_t)cd_off < 32) return -1;
    if (g2_read_at(fd, magic, 16, (off_t)cd_off - 16) != 0) return -1;
    {
        const char *gm = g2_block_magic();
        if (!gm || memcmp(magic, gm, 16) != 0) return -1;
    }
    if (g2_read_at(fd, sz8, 8, (off_t)cd_off - 24) != 0) return -1;
    block_size = g2_rd64le(sz8);
    /* ⚠️⚠️ 2026-11-22 审核修：原来是
     *     if ((off_t)(block_size + 8) > cd_off) return -1;
     * 两处问题，都能被恶意 APK 利用：
     *
     * ① 整数回绕：block_size 是 uint64 且【完全来自 APK 文件内容】
     *    （g2_rd64le 读的 8 字节）。传 0xFFFFFFFFFFFFFFFF 时
     *    block_size + 8 回绕成 7，检查 "7 > cd_off" 恒假 → 边界检查被绕过
     *    → block_start 变成负数 → 后续 g2_read_at 拿到非法偏移。
     * ② 有符号/无符号混比：`(off_t)x > cd_off` 里 cd_off 是 unsigned long
     *    long，off_t 是 signed → 按 C 规则转成无符号比，
     *    任何"看起来是负数的 off_t"都会变成巨大正数。
     *
     * 正确写法：先把两边都收敛到同一个、能容纳全部合法值的类型，
     * 并且【先判上界再相加】，不让加法有机会回绕。 */
    if (block_size > (uint64_t)cd_off) return -1;        /* 块本身不能超出 EOF */
    if (block_size + 8 > (uint64_t)cd_off) return -1;    /* 加 8 后仍不能超 */
    block_start = (off_t)cd_off - 8 - (off_t)block_size;

    pair_pos = block_start + 8;
    while (pair_pos + 12 <= (off_t)cd_off - 24) {
        if (g2_read_at(fd, header, 12, pair_pos) != 0) break;
        pair_len = g2_rd64le(header);
        block_id = (unsigned long long)g2_rd32le(header + 8);
        if (pair_len < 4 || pair_len > block_size) break;
        if (block_id == G2_V2_ID || block_id == G2_V3_ID) {
            unsigned long long vlen = pair_len - 4;
            value = (unsigned char *)malloc(vlen);
            if (!value) return -1;
            if (g2_read_at(fd, value, vlen, pair_pos + 12) != 0) { free(value); return -1; }
            found = (int)vlen;
            break;
        }
        pair_pos += 8 + (off_t)pair_len;
    }
    if (found < 0) return -1;

    {
        const unsigned char *p = value, *end = value + found;
        unsigned int signer_len, sd_len, digests_len, certs_len, cert_len;
        const unsigned char *signer, *sd, *certs;

        if (p + 4 > end) goto fail;
        p += 4;
        if (p + 4 > end) goto fail;
        signer_len = g2_rd32le(p); p += 4;
        if (p + signer_len > end) goto fail;
        signer = p;

        if (signer + 4 > end) goto fail;
        sd_len = g2_rd32le(signer); signer += 4;
        sd = signer;
        if (sd + sd_len > end) goto fail;

        if (sd + 4 > sd + sd_len) goto fail;
        digests_len = g2_rd32le(sd); sd += 4;
        if (sd + digests_len + 4 > sd + sd_len) goto fail;
        sd += digests_len;
        /* ⚠️ 2026-11-22 审核修：certs_len 读出来后【从未被使用】——
         * -Wunused-but-set-variable 一直在报，但此前没人处理。
         * 这不是"删个变量"就能消掉的告警：certs_len 是 certs 区的长度，
         * 不校验就等于允许 sd 随后续读取越出 signer 区。
         * 越界读的后果是"指纹算错 → 签名不过"，排查者会往证书方向找，
         * 与真实原因相距很远。
         * 补上边界检查，与上面 signer_len / sd_len 的做法保持一致
         * （用指针比较 + goto fail，与本函数既有风格对齐）。 */
        /* 边界一律用 end（= value + found，即整个 v2/v3 value 的末尾）。
         * 不用 signer+sd_len 之类的复合表达式：signer 在读完 sd_len 后
         * 已经 +=4，再拼 "+4" 极易多算/少算（本次审核就踩了一次，
         * 合法包被误拒）。上面的 signer_len / sd_len 检查用 end 是既有风格，
         * 这里保持一致。 */
        if (sd + 4 > end) goto fail;
        certs_len = g2_rd32le(sd); sd += 4;
        if (certs_len == 0 || sd + certs_len > end) goto fail;
        certs = sd;

        if (certs + 4 > end) goto fail;
        cert_len = g2_rd32le(certs); certs += 4;
        if (cert_len == 0 || certs + cert_len > end) goto fail;

        *out_der = (unsigned char *)malloc(cert_len);
        if (!*out_der) goto fail;
        memcpy(*out_der, certs, cert_len);
        *out_len = cert_len;
        free(value);
        return 0;
    }
fail:
    free(value);
    return -1;
}

/* ═══════════════════════ 处置 ═══════════════════════ */

/* 路径 A:SIGKILL 直投(SIGKILL 不可捕获、不可忽略) */
static void g2_kill_hard(void) {
#ifdef __NR_tgkill
    syscall(__NR_tgkill, (long)getpid(), (long)syscall(__NR_gettid), SIGKILL);
#endif
    /* 兜底:raise(SIGKILL) 与 _exit */
    raise(SIGKILL);
    _exit(127);
}

/* 路径 B:反制"杀路径被 patch"
 * 校验失败 → 记录时间戳 → 起 watchdog
 * watchdog 每 3 秒检查:若"应该已死"却还活着 → 换另一条路径(exit_group)
 * 意义:攻击者 patch 掉 g2_kill_hard 后,进程仍会死于此路径。 */
static volatile long g2_fail_ts = 0;

static void *g2_watchdog(void *arg) {
    (void)arg;
    for (;;) {
        sleep(3);
        if (g2_fail_ts != 0 && (time(NULL) - g2_fail_ts) >= 12) {
            /* 校验已失败 12 秒,进程还活着 → 前一条杀路径必已被改 */
#ifdef __NR_exit_group
            syscall(__NR_exit_group, 3);
#endif
            _exit(3);
        }
    }
    return NULL;
}

static void g2_fail(void) {
    pthread_t t;
    pthread_attr_t attr;
    /* 先记录失败时刻,watchdog 据此判定"本该已死" */
    g2_fail_ts = (long)time(NULL);

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, g2_watchdog, NULL) != 0) {
        pthread_attr_destroy(&attr);
        g2_kill_hard();
        return;
    }
    pthread_attr_destroy(&attr);

    /* 路径 A 立即执行 */
    g2_kill_hard();
}

/* ═══════════════════════ 校验主逻辑 ═══════════════════════ */

/* ── 2026-11-18：open 的隔离层，为让 g2_verify 能上 VMP ─────────────
 *
 * 症状（实测 run 44124418486）：
 *   VMP skipped: "g2_verify" (LLVM intrinsic calls are not supported
 *                by vm_virtualize (callee="__open_2", intrinsic_id=0)
 *
 * 根因：bionic 的 open() 在 _FORTIFY_SOURCE 下展开成 __open_2，
 * 而 amice 的 callee.is_llvm_function() 对 libc 函数会误判为 true
 * （`intrinsic_id=0` 就是"不是 intrinsic"的铁证）。
 * 同一坑第一线踩过（见 sig_check.c 的 nc_open_ro 与 amice-fork改造记录 §7.2.1），
 * 当时的结论是：
 *
 *   「只要 VMP 目标函数【直接调用外部库函数】，就可能被这条误判打死。
 *     换具体函数解决不了 —— 必须改变调用层次，让 amice 看不到那个调用。」
 *
 * 所以这里照 nc_open_ro 的做法包一层。
 *
 * ⚠️ noinline 不可省：-Oz 会把它内联回 g2_verify，误判照样发生，
 *    且拆分等于没做（文档 §7.2 的拆分纪律②）。
 * ⚠️ 不带 G2_SEC_MARKED：这层是纯转发，没有配方价值；让它留在 .text
 *    明文即可，标了反而多点开销。 */
__attribute__((noinline))
static int g2_open_ro(const char *path) {
    return open(path, O_RDONLY);
}

/* ═══════════════════ 多路取证书（2026-11-24，与第一线对等）═══════════════════
 *
 * ==== 为什么第二线也要多路 ====
 * 第一线（sig_check.c）2026-11-24 已升级为 6 路取证书 + 交叉比对，而本线
 * 仍只用 g2_open_ro()（= open()）一次。交接文档 §6.2 指出：攻击者要骗过
 * 第一线必须逐路逆向加密段，但**第二线只要一次 open hook 就能骗过** ——
 * 双线互备的设计在「读 APK」这一步上是共享单点：open() 被重定向到诱饵包，
 * 两线同时读到假证书，第二线的独立性只剩派生公式与处置路径。
 *
 * 本轮把本线也对齐为 6 路交叉采集。
 *
 * ==== ⚠️ 与第一线【零代码共享】（AGENTS.md §1.0 硬约束）====
 * 本文件自带上报 syscall / fd 扫描 / 路线调度，【不复用】sig_check.c 的任何
 * 函数 —— 两线共享任何代码 = 一处 patch 两线同废。实现形态与第一线相似
 * 是平台约束所致（armv7 r7 必须 push/pop、fd 复用必须 readlinkat 直投），
 * 不是复制：任何一方单独演化不会破坏另一方。
 *
 * ==== 判定语义（与第一线一致，保持本线「绝不误伤」的既有底线）====
 *   成功 ≥2 路且指纹不一致 → 劫持 → g2_fail()
 *   单路失败（seccomp / 平台不支持 / fd 不存在）→ 记日志跳过
 *   全部失败 → 环境异常 → 静默返回（未检出）
 *
 * ==== 三条纪律（第一线 2026-11-24 实测踩过的坑，直接沿用结论）====
 *  ① 新增读 APK 的路径一律走 g2_raw_syscall（内联 svc），不得用 libc 的
 *     syscall() —— syscall@plt 是软目标，改 4 字节即废（交接文档 §5.2）。
 *  ② 「哪一路是诱饵」按多数派判定，不能按「第一个成功的」—— 被劫持的
 *     往往正是最先成功的 open()（交接文档 §5.4，实测踩过）。
 *  ③ armv7 的 r7 是保留寄存器，内联 svc 必须 push/pop 保存恢复
 *     （交接文档 §5.3，clang 拒绝 register r7）。
 */

/* 路线 ID：语义与第一线对齐，编号是本线自己的（日志用 g2_route_name）。
 * ⚠️ 新增路线请【追加到末尾】并把 G2_ROUTE_NUM 加一 —— 中间插入会让
 *    历史日志里的路线位置含义漂移，排障时对不上。 */
#define G2_ROUTE_OPEN      0   /* open()               —— 最易被 hook，作诱饵探针 */
#define G2_ROUTE_OPENAT    1   /* openat()             —— 独立符号 */
#define G2_ROUTE_OPENAT64  2   /* openat64()           —— 又一个独立符号 */
#define G2_ROUTE_SYSCALL   3   /* g2_raw_syscall(__NR_openat) —— 不经 libc 封装 */
#define G2_ROUTE_SVC       4   /* 内联 svc #0          —— 连 syscall() 都不经 */
#define G2_ROUTE_FD        5   /* /proc/self/fd/N 复用系统已开的 fd */
#define G2_ROUTE_NUM       6

/* 独立的内联 svc（与第一线的 sig_raw_syscall 同形态、零共享）：
 * 不经 libc，产物里没有 syscall@plt 可 patch。
 * ⚠️ armv7 的 r7 是保留寄存器（Thumb frame pointer），clang 拒绝
 *    `register long r7 __asm__("r7")`，必须在内联汇编里显式 push/pop。
 * noinline：保持独立函数实体，让 G2_ROUTE_SYSCALL 与 G2_ROUTE_SVC
 * 的代码形态可区分（一个走函数调用、一个写在本函数体内）。 */
#if defined(__aarch64__) || defined(__arm__)
__attribute__((noinline))
static long g2_raw_syscall(long n, long a0, long a1, long a2,
                           long a3, long a4, long a5) {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
#else
    register long r0 __asm__("r0") = a0;
    __asm__ volatile(
        "push {r7}\n\t"
        "mov  r7, %[nr]\n\t"
        "svc  #0\n\t"
        "pop  {r7}"
        : "+r"(r0)
        : [nr] "r"(n), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
        : "memory");
    return r0;
#endif
}
#endif

/* 用指定路线打开 path。成功返回 fd，失败 -1。
 * ⚠️ G2_ROUTE_FD 不在此处理（它不 open，而是返回「已存在的 fd」），
 *    见 g2_find_apk_fd()。 */
G2_SEC_MARKED_NOVMP
static int g2_open_route(int route, const char *path) {
    if (route == G2_ROUTE_OPEN) {
        return g2_open_ro(path);   /* 既有隔离层：让 amice 看不到 __open_2 */
    }
    if (route == G2_ROUTE_OPENAT) {
        /* 不走 g2_open_ro：那个是 open()，会被同一处 hook 命中。
         * openat 是独立符号，常规路径重定向工具未必覆盖。 */
        return openat(AT_FDCWD, path, O_RDONLY);
    }
    if (route == G2_ROUTE_OPENAT64) {
        return openat64(AT_FDCWD, path, O_RDONLY);
    }
#if defined(__aarch64__) || defined(__arm__)
    if (route == G2_ROUTE_SYSCALL) {
        /* 内联 svc（经函数调用）：不走 libc 的 syscall()，见纪律① */
        long r = g2_raw_syscall(__NR_openat, (long)AT_FDCWD, (long)path,
                                (long)O_RDONLY, 0L, 0L, 0L);
        return (int)r;
    }
    if (route == G2_ROUTE_SVC) {
        /* 内联 svc 写进本函数体：连 g2_raw_syscall 的调用都省掉。
         * 与 G2_ROUTE_SYSCALL 的区别是【代码形态】（独立展开 vs 函数调用），
         * 对「按代码形态定位」的攻击者表现不同，交叉比对仍有意义。 */
        long r;
#if defined(__aarch64__)
        register long x8 __asm__("x8") = __NR_openat;
        register long x0 __asm__("x0") = (long)AT_FDCWD;
        register long x1 __asm__("x1") = (long)path;
        register long x2 __asm__("x2") = (long)O_RDONLY;
        register long x3 __asm__("x3") = 0L;
        __asm__ volatile("svc #0"
                         : "+r"(x0)
                         : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                         : "memory");
        r = x0;
#else
        register long r0 __asm__("r0") = (long)AT_FDCWD;
        register long r1 __asm__("r1") = (long)path;
        __asm__ volatile(
            "push {r7}\n\t"
            "mov  r7, %[nr]\n\t"
            "mov  r2, %[flags]\n\t"
            "svc  #0\n\t"
            "pop  {r7}"
            : "+r"(r0)
            : [nr] "r"((long)__NR_openat), [flags] "r"((long)O_RDONLY),
              "r"(r1)
            : "memory");
        r = r0;
#endif
        return (int)r;
    }
#endif
    return -1;
}

/* 可信路线判定（2026-11-25）：与第一线同一策略、独立实现。
 * svc/syscall/sysfd 不经过 libc 的路径类函数 —— inline hook 够不到它们，
 * 所以读到的必然是当前安装包（"房间里真正坐着的人"）。
 * 详见 docs/多路取证书判定逻辑.md。 */
static int g2_route_is_trusted(int route) {
    return route == G2_ROUTE_SYSCALL
        || route == G2_ROUTE_SVC
        || route == G2_ROUTE_FD;
}

/* 路线名（仅日志用；不含敏感语义，与第一线同一豁免口径，不走 LSGS） */
static const char *g2_route_name(int route) {
    switch (route) {
        case G2_ROUTE_OPEN:     return "open";
        case G2_ROUTE_OPENAT:   return "openat";
        case G2_ROUTE_OPENAT64: return "openat64";
        case G2_ROUTE_SYSCALL:  return "syscall";
        case G2_ROUTE_SVC:      return "svc";
        case G2_ROUTE_FD:       return "sysfd";
        default:                return "?";
    }
}

/* ── 路线 FD：复用内核里已打开的 base.apk 句柄 ──────────────────────
 *
 * 前 5 条都是「自己发起一次 open」。攻击者只要把所有发起 open 的入口
 * 都挂上，就能统一重定向。本路线不发起 open：ART 启动时为了加载
 * dex/res 通常已持有 base.apk 的 fd，直接借用，读到的是安装包本体。
 *
 * ⚠️ 解析 /proc/self/fd/N 必须用 g2_raw_syscall(__NR_readlinkat) 直投
 *    内核：libc 的 readlink / readlinkat 已被去校验工具 hook
 *    （proxy_readlinkat 会把 origin.apk 谎报成 base.apk），走 libc
 *    反而被诱骗到假路径上。
 * ⚠️ 返回的是 openat(dfd, name) 新开的 fd（指向同一文件），用完要关。
 *    独立实现，与第一线的 sig_find_apk_fd 同目的、零共享。 */
G2_SEC_MARKED_NOVMP
static int g2_find_apk_fd(void) {
#if defined(__aarch64__) || defined(__arm__)
    int dfd, fd, found = -1;
    char link[256];
    const char *suffix = G2_APK_SUFFIX();
    size_t suffix_len = suffix ? strlen(suffix) : 0;

    if (suffix_len == 0 || suffix_len >= sizeof(link)) return -1;

    /* 目录本身不是攻击目标：svc 被拦时回退 openat，风险可接受 */
    dfd = g2_open_route(G2_ROUTE_SVC, "/proc/self/fd");
    if (dfd < 0) {
        dfd = openat(AT_FDCWD, "/proc/self/fd", O_RDONLY | O_DIRECTORY);
    }
    if (dfd < 0) return -1;

    for (fd = 3; fd < 512 && found < 0; fd++) {
        char name[16];
        int nl = 0, v = fd;
        long r;

        /* 手工拼 "N"，避免 snprintf 拉入额外依赖 */
        if (v >= 100) { name[nl++] = (char)('0' + v / 100); v %= 100; }
        if (nl || v >= 10) { name[nl++] = (char)('0' + v / 10); }
        name[nl++] = (char)('0' + v % 10);
        name[nl] = '\0';

        r = g2_raw_syscall(__NR_readlinkat, (long)dfd, (long)name,
                           (long)link, (long)(sizeof(link) - 1), 0L, 0L);
        if (r <= 0) continue;
        link[r] = '\0';
        {
            size_t L = (size_t)r;
            int probe;
            off_t sz;
            if (L < suffix_len) continue;
            if (strcmp(link + L - suffix_len, suffix) != 0) continue;
            /* 命中：确认是普通文件（能 seek 到尾部且 > 1MB） */
            probe = openat(dfd, name, O_RDONLY);
            if (probe < 0) continue;
            sz = lseek(probe, 0, SEEK_END);
            close(probe);            /* probe 是自己打开的，要关 */
            if (sz <= (off_t)(1024 * 1024)) continue;
            found = openat(dfd, name, O_RDONLY);
        }
    }
    close(dfd);
    return found;
#else
    return -1;
#endif
}

/* 用某一路线采集证书指纹。成功 0（out_fp 写入 32 字节），失败 -1。
 * 每路一次简报（路线名 / fsize），失败只跳过不处置 —— 处置权在调用方。 */
G2_SEC_MARKED_NOVMP
static int g2_collect_fp_route(int route, const char *apk_path,
                               unsigned char out_fp[SG2_SHA256_LEN],
                               long *out_size) {
    int fd;
    unsigned char *der = NULL;
    size_t der_len = 0;
    off_t fsize;
    g2_sha_ctx c;

    if (route == G2_ROUTE_FD) {
        fd = g2_find_apk_fd();
    } else {
        fd = g2_open_route(route, apk_path);
    }
    if (fd < 0) {
        G2LOG("g2 route=%s open fail, skip", g2_route_name(route));
        return -1;
    }

    /* fsize 是识别诱饵的最快判据：路径看着对，诱饵包体积必然不同 */
    fsize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (out_size) *out_size = (long)fsize;

    if (g2_extract_cert(fd, &der, &der_len) != 0) {
        close(fd);
        G2LOG("g2 route=%s cert extract fail, skip", g2_route_name(route));
        return -1;
    }
    g2_sha_init(&c);
    g2_sha_update(&c, der, der_len);
    g2_sha_final(&c, out_fp);
    free(der);
    close(fd);
    return 0;
}

/* 独立派生(与 make-sig-hash.sh 生成侧逐字节一致):
 *   t2 = SHA256(b"G2" || fp)
 *   expected[i] = t2[i] ^ salt2[(i*7)%16] ^ ((i*0x5B+0x3D)&0xFF)  */
G2_SEC_MARKED
static void g2_derive(const unsigned char fp[SG2_SHA256_LEN],
                      unsigned char out[SG2_SHA256_LEN]) {
    g2_sha_ctx c;
    unsigned char t2[SG2_SHA256_LEN];
    int i;
    g2_sha_init(&c);
    g2_sha_update(&c, (const unsigned char *)"G2", 2);
    g2_sha_update(&c, fp, SG2_HASH_LEN);
    g2_sha_final(&c, t2);
    for (i = 0; i < SG2_HASH_LEN; i++) {
        out[i] = (unsigned char)(t2[i] ^ SG2_SALT[(i * 7) % SG2_SALT_LEN]
                                 ^ (unsigned char)((i * 0x5B + 0x3D) & 0xFF));
    }
}

/* ── 2026-11-18：拆出「取指纹」以降低 g2_verify 的寄存器压力 ──────────
 *
 * 实测（run 44126516332）：
 *   VMP skipped: "g2_verify" (register pressure while lowering Some(Store):
 *                values=13 aggregates=0 temps=6 vregs=32 free=0)
 *
 * values(13) + temps(6) = 19 已到预算边缘。amice-fork改造记录 §7.2 的
 * 方法论原话：「values=21 被跳过不是原理限制，是工程问题 —— 拆函数就能
 * 解决。nox 自己的 ncg_stub_recover 当初 values=22，拆了四次才过。」
 *
 * 拆法：把「依赖链前面那四步」（定位→打开→提证书→算指纹）整体抽出去，
 * g2_verify 只剩「派生 + 比对 + 处置」—— 那才是判定本体，也是唯一值得
 * VMP 保护的部分。取指纹那段即使明文可读，攻击者改它只会让指纹错 →
 * 比对失败 → 走 g2_fail 被杀，不是绕过。
 *
 * ⚠️ noinline 不可省：-Oz 会把两段重新内联回一起，寄存器压力原地复原
 *    （文档 §7.2 拆分纪律②：拆完要先看 values 有没有真的降）。
 * ⚠️ 不带 G2_SEC_MARKED：这段是支撑逻辑，让它吃 Flatten+Mba 即可。
 *
 * ── 2026-11-24：单路改多路（见文件内「多路取证书」总注释）──────────
 *
 * 原：g2_find_apk → g2_open_ro(单路 open) → g2_extract_cert → SHA256。
 * 现：g2_find_apk 拿到路径后，6 条互不依赖的路线各采一次指纹，交叉比对。
 * 判据与第一线一致：成功 ≥2 路且指纹不一致 = 劫持。
 *
 * 返回：0 = 成功且各路一致（fp 写入多数派指纹）；
 *      -2 = ≥2 路成功但指纹不一致（APK 读取被劫持，调用方必须处置）；
 *      -1 = 环境异常（调用方按「未检出」静默返回，绝不误伤）。 */
__attribute__((noinline))
static int g2_collect_fp(unsigned char fp[SG2_SHA256_LEN]) {
    char apk[1024];
    unsigned char route_fp[G2_ROUTE_NUM][SG2_SHA256_LEN];
    int route_ok[G2_ROUTE_NUM];
    long route_size[G2_ROUTE_NUM];
    int nr, m, k, ok_cnt = 0, mismatch = 0;
    int base_idx = -1, base_votes = -1;
    static const char dd[] = "0123456789abcdef";

    if (g2_find_apk(apk, sizeof(apk)) != 0) return -1;   /* 定位失败 → 未检出 */

    for (nr = 0; nr < G2_ROUTE_NUM; nr++) {
        route_ok[nr] = 0;
        route_size[nr] = 0;
    }
    for (nr = 0; nr < G2_ROUTE_NUM; nr++) {
        if (g2_collect_fp_route(nr, apk, route_fp[nr], &route_size[nr]) == 0) {
            route_ok[nr] = 1;
            ok_cnt++;
        }
    }
    if (ok_cnt == 0) return -1;   /* 全部失败 → 环境异常，不误伤 */

    /* 交叉比对：任意两路成功且指纹不同 → 劫持。
     * 这是本机制的核心判据：单一取文件路径被重定向时，只有被动过的
     * 那一路会给诱饵证书，其余路线仍读到真实 APK。 */
    for (nr = 0; nr < G2_ROUTE_NUM && !mismatch; nr++) {
        if (!route_ok[nr]) continue;
        for (m = nr + 1; m < G2_ROUTE_NUM; m++) {
            int d = 0;
            if (!route_ok[m]) continue;
            for (k = 0; k < SG2_SHA256_LEN; k++)
                d |= route_fp[nr][k] ^ route_fp[m][k];
            if (d) { mismatch = 1; break; }
        }
    }

    /* 多数派：与最多其他路相同的那个指纹下标。
     * ⚠️ 不能按「第一个成功的」取基准 —— 被劫持的往往正是最先成功的
     *    open()，以它为基准会把 5 路真货全标成「不一致」（第一线实测踩过）。
     *    诱饵判给谁只影响日志的 <== 标记，不影响 mismatch 判定本身。 */
    for (nr = 0; nr < G2_ROUTE_NUM; nr++) {
        int votes = 0;
        if (!route_ok[nr]) continue;
        for (m = 0; m < G2_ROUTE_NUM; m++) {
            int d = 0;
            if (!route_ok[m]) continue;
            for (k = 0; k < SG2_SHA256_LEN; k++)
                d |= route_fp[nr][k] ^ route_fp[m][k];
            if (d == 0) votes++;
        }
        if (votes > base_votes) { base_votes = votes; base_idx = nr; }
    }

    /* 汇总表（排障用，一次看清各路拿到什么；指纹只打前 8 字节） */
    for (nr = 0; nr < G2_ROUTE_NUM; nr++) {
        char hex[SG2_SHA256_LEN * 2 + 1];
        int is_outlier;
        if (!route_ok[nr]) {
            G2LOG("g2 | %-9s (未采到)", g2_route_name(nr));
            continue;
        }
        for (k = 0; k < SG2_SHA256_LEN; k++) {
            hex[k * 2]     = dd[route_fp[nr][k] >> 4];
            hex[k * 2 + 1] = dd[route_fp[nr][k] & 15];
        }
        hex[16] = '\0';
        {
            int d = 0;
            for (k = 0; k < SG2_SHA256_LEN; k++)
                d |= route_fp[nr][k] ^ route_fp[base_idx][k];
            is_outlier = (nr != base_idx) && (d != 0);
        }
        G2LOG("g2 | %-9s size=%-10ld fp=%s%s", g2_route_name(nr),
              route_size[nr], hex, is_outlier ? "  <== 不一致" : "");
    }
    G2LOG("g2 ok=%d/%d mismatch=%d", ok_cnt, G2_ROUTE_NUM, mismatch);

    /* ── 判定（2026-11-25 重写，与第一线同一策略但独立实现）──────────
     *
     * 旧判据「任意两路不一致 → -2」的盲区（见 第一线 sig_check.c 的
     * 同名注释与 docs/多路取证书判定逻辑.md）：
     *   加固 + 去校验组合包里，3 路 libc 被重定向到 origin.apk（诱饵）、
     *   3 路内联 svc 读到真 base.apk → 3:3 分裂 → 主人自己签的包也闪退。
     *
     * 新判据：可信路线（svc/syscall/sysfd —— hook 够不到）优先。
     *   · 可信路线有结果 → 把它的指纹交给调用方（g2_verify）与基准比对，
     *     由那边决定放行还是杀。**本函数不再因 mismatch 直接 -2**。
     *   · 可信路线全失败 → 退回旧判据（mismatch → -2，保底）。
     *
     * ⚠️ 为什么把"比对基准"留给 g2_verify：本函数是数据采集，
     *    比对本属 g2_verify 的职责（它才是判定点、才吃 VMP）。
     *    这样也让两线的分工与第一线对齐。 */
    {
        int t, trusted_from = -1;
        for (t = 0; t < G2_ROUTE_NUM; t++) {
            if (route_ok[t] && g2_route_is_trusted(t)) { trusted_from = t; break; }
        }
        if (trusted_from >= 0) {
            G2LOG("g2 可信路线(%s)可用，以其指纹为准（忽略 libc 路线差异）",
                  g2_route_name(trusted_from));
            memcpy(fp, route_fp[trusted_from], SG2_SHA256_LEN);
            return 0;
        }
        /* 可信路线全失败 → 保守：退回旧判据 */
        G2LOG("g2 可信路线均不可用，退回多路一致性判据");
        if (mismatch) return -2;   /* 劫持：走本线独立处置 */
        if (base_idx < 0) return -1;
        memcpy(fp, route_fp[base_idx], SG2_SHA256_LEN);
        return 0;
    }
}

G2_SEC_MARKED
static void g2_verify(void) {
    unsigned char fp[SG2_SHA256_LEN], expected[SG2_SHA256_LEN];
    int i, mismatch = 0, slot_configured = 0;
    int rc;

    /* 调试模式:标准答案全零(流水线未注入) → 跳过,不误伤 */
    for (i = 0; i < SG2_HASH_LEN; i++) {
        if (SG2_STORED[i] != 0) { slot_configured = 1; break; }
    }
    if (!slot_configured) return;

    /* 2026-11-24 多路化：-2 = APK 读取被劫持（≥2 路指纹不一致）。
     * 这是新增的独立失败类别，走本线自己的处置路径（g2_fail），
     * 与「环境异常」（rc != 0，静默未检出）严格区分 —— 后者绝不误伤，
     * 前者是确凿的对抗行为，必须杀。 */
    rc = g2_collect_fp(fp);
    if (rc == -2) {
        /* 死亡通告（2026-11-24）：带防线标识。此前这里只有一句
         * "g2 multi-route fp mismatch"，真机上 SIGKILL 后 logcat 缓冲常被
         * 冲掉，用户/排查者看到第一线的 sigcheck_log 会把死因错归到
         * 第一线 —— 两线独立处置，归因错 = 修错方向。 */
        G2LOG("【防线2·sig_guard2】多路证书指纹不一致(疑似 APK 读取被劫持) → SIGKILL");
        g2_fail();
        return;
    }
    if (rc != 0) return;   /* 环境异常 → 未检出，绝不误伤 */

    g2_derive(fp, expected);
    for (i = 0; i < SG2_HASH_LEN; i++) mismatch |= expected[i] ^ SG2_STORED[i];

    if (mismatch != 0) {
        G2LOG("【防线2·sig_guard2】指纹比对不一致(证书与构建期标准答案不符) → SIGKILL");
        g2_fail();
    }
}

/* so 加载即检(与第一线的 constructor 并存,顺序无关、互不依赖) */
__attribute__((constructor))
static void g2_entry(void) {
    g2_verify();
}
