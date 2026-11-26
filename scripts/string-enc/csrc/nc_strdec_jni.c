/* nc_strdec_jni.c — 纯 C 解密桩的 JNI 边界（2026-11-09）
 *
 * 分层：nc_strdec.c 是纯算法（零 JNI，宿主可单测）；本文件只做
 * JNI 类型转换 + 缓存 + 异常处置。
 *
 * 三条硬约束（每条对应一类真实事故）：
 * ① 失败必须【原样返回 payload 对象】不抛不崩不缓存 —— Java 桩原本靠
 *    try/catch 兜底，native 侧没有，兜底责任全在这里。
 * ② 绝不能带 pending exception 继续调 JNI —— 退出统一走 nc_jni_fail()
 *    （先 ExceptionCheck/Clear 再返回兜底值）。
 * ③ 无密钥 / so 未加载也是"原样返回" —— 见 nc_ensure_key()。
 */


#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* access/R_OK：证书绑定要确认 APK 路径可读 */
#include <dlfcn.h>   /* dlsym/dlopen：从壳 so 取字符串密钥种子（2026-11-10 联动） */
#include <link.h>    /* dl_iterate_phdr：遍历已加载 so 找壳 so 的 handle */
#include <android/log.h>  /* __android_log_print：解密失败可见化（2026-11-22） */
#ifdef NC_STRDEC_PROFILE
#include <time.h>    /* clock_gettime：解密耗时统计（仅调试包） */
#endif

/* 构建期生成的配置头（protect.sh 写进 NDK 工程目录，不进 git）。
 * 没有它 = 本次不是 native 桩组合，bootstrap 退化为只记录 JavaVM。
 *
 * ⚠️⚠️ 必须在 "nc_strdec.h" **之前** include（2026-11-09 真机闪退根因）：
 *   nc_strdec.h 里有 `#ifndef NC_STRDEC_ALGO / NC_STRDEC_NKEYS` 的兜底默认值
 *   （0 / 1）。若先包含 nc_strdec.h，这两个宏就被定义成默认值，于是 cfg.h
 *   里同名宏的 `#ifndef` 守卫**整段失效** —— 构建期按用户选的算法加密、
 *   运行期却用默认算法解密，每条都解错，且构建期零报错。
 *   实测症状：`getDeclaredField(<密文>)` → NoSuchFieldException → 闪退，
 *   因为 nc_jni_fail() 把解密失败静默降级成"原样返回密文"。
 *   同理 NKEYS 也一直没生效过（默认值恰好等于生产值，所以历史上没暴露）。 */
#if defined(__has_include)
#  if __has_include("nc_strdec_cfg.h")
#    include "nc_strdec_cfg.h"
#    define NC_STRDEC_HAVE_CFG 1
#  endif
#endif

#include "nc_strdec.h"

/* 从壳取种子的路径只实现 NKEYS=1（8 字节种子 = 一把 key）。NKEYS=4 需要
 * 把种子扩成 32 字节，而 Python 侧没有对应逻辑（那边 seed 就是单个 uint64）。
 * 宁可编译期拒绝，也不要两侧静默不一致（症状是全包乱码、构建期零报错）。
 * ⚠️ 断言必须放在 cfg.h 与 nc_strdec.h **都 include 之后** —— 放前面会读到
 *    头文件的兜底默认值 1，断言永真。 */
#if NC_STRDEC_NKEYS != 1
#  error "纯 C 桩从壳取种子只支持 NKEYS=1（见本文件的联动断言说明）"
#endif

/* ── L1 缓存（对应 Java 桩的 ConcurrentHashMap）─────────────────────
 * 不缓存则每次重算 Base64 + 密钥流 + 分配 String；实测某些位点单次启动
 * 被执行 ~20 次（Compose 重组），累计开销比"换算法"那一档大一个数量级。
 * 上限 30000，racy 检查（并发略超无害），进程生命周期内不释放 ——
 * 与 Java 侧 CHM 语义等同。
 *
 * ⚠️ 2026-11-26 性能定案：key 从 jstring 改成【字节副本】。
 *
 * 实测（真机，全开+stringenc，profile 埋点）：
 *   cache_get 累计 11069ms = 总耗时 99%，其中 GetStringUTFChars
 *   被调用 14826 次，平均 747μs/次（正常应 1~2μs，慢 500 倍），
 *   单次最坏 81ms。根因：原实现把 key 存成 jstring global ref，
 *   每次比较都要跨界取内容 —— 而命中路径上 78% 的探测都命中，
 *   即每次解密都要付一次 JNI 转换（分配临时 buffer + UTF-16↔
 *   Modified UTF-8 转换 + 释放）。
 *
 * 改成存字节副本后，命中路径是纯 memcmp，零 JNI。
 * 代价：每个 key 一份 malloc 副本（30000 × 平均 60B ≈ 1.8MB，
 *       由 NC_CACHE_BYTES_MAX 硬上限兜住）。
 * val 仍保持 global ref —— 返回给 Java 时直接用，不需要转换。 */
#define NC_CACHE_CAP     32768u       /* 2 的幂：h & (CAP-1) 代替除法取模 */
#define NC_CACHE_MASK    (NC_CACHE_CAP - 1u)
#define NC_CACHE_BYTES_MAX (4u * 1024 * 1024)  /* key 副本总量上限 4MB */

/* 极简开放寻址哈希表。不用链表：插入后不删除，探测序列恒有效。 */
typedef struct {
    uint64_t hash;          /* 0 = 空槽（密文 hash 恰为 0 概率 ~2^-64，可接受） */
    char    *key;           /* 密文 payload 的字节副本（malloc） */
    uint32_t klen;          /* 密文长度（memcmp 前先比长度，快路径） */
    jstring  val;           /* 明文的 global ref */
} nc_cache_slot;

static nc_cache_slot nc_cache[NC_CACHE_CAP];
static volatile int nc_cache_n = 0;
static size_t nc_cache_bytes = 0;       /* key 副本累计字节（racy，仅上限判断） */

/* FNV-1a 64：查表用，非密码学用途 */
static uint64_t nc_fnv1a(const char *s, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= 0x100000001b3ULL;
    }
    return h ? h : 1;       /* 保证非 0（0 是空槽标记） */
}

/* 统一的失败出口：清异常 + 返回兜底值。
 * ② 硬约束的唯一实现点 —— 不要在别处直接 return。 */
/* fail-closed 计数（诊断用）。为什么需要：
 * 解密失败时语义是"原样返回密文"（不崩、不抛），这在 App 侧表现为
 * 莫名其妙的业务错误（例如 Room 报 "no table with name <密文>"），
 * 而日志里【一点痕迹都没有】—— 2026-11-09 真机排查花了很久才定位到
 * "是解密静默失败"而不是"加密错了"。
 *
 * ⚠️ 2026-11-22 起【同时打 logcat】。原先只计数不打日志，理由是
 * "避免日志本身成为特征串"。评估后改掉：
 *   ① 只计数不输出 = 静默劣化。计数器没有消费方（没有 JNI 出口、
 *      没有落盘），等于不存在。用户实测反馈"完全看不到"。
 *   ② 特征串风险可控：tag 用不含业务语义的短名，且【只在前几次
 *      和每 100 次】打一条（见 nc_jni_fail），不会把 logcat 刷满，
 *      逆向者靠它反推的信息量远小于"解密全错却无声"带来的排查成本。
 *   ③ 反例更危险：App 起得来但业务全废（SQL 变密文），
 *      没有任何线索指向"字符串解密"，容易误判成加密写错了。
 * 计数器保留（nc_strdec_fail_count 仍可读），两者互补：
 * 日志给"何时出事"，计数给"出了多少"。 */
static volatile unsigned nc_fail_count = 0;

unsigned nc_strdec_fail_count(void)
{
    return nc_fail_count;
}

/* logcat tag。刻意短且无业务语义（不含 strdec/stringenc/decrypt 等
 * 可搜词）—— 与模块内其它标识的纪律一致。 */
#define NC_SD_TAG "sd"

/* ── 耗时统计（仅 NC_STRDEC_PROFILE 编译期开启）────────────────────
 *
 * 为什么需要它：真机实测同一 App 的两个包，开字符串加密的那个启动后
 * 10 秒吃 16.77s CPU，没开的只吃 0.69s（差 24 倍）。而按文档记录
 * ChaCha20 档整包解密增量只有 0.15~0.77ms —— 相差四个数量级，说明
 * "解密被反复触发"或"单次解密远比预期慢"，二者必须靠实测区分。
 *
 * 三个指标分开计，因为对应的病因完全不同：
 *   calls  解密调用次数      → 次数爆炸 = 缓存没命中/被绕过
 *   ns     decrypt 本体耗时  → 大 = 算法或 VMP 开销
 *   keyns  nc_ensure_key 耗时 → 大 = dl_iterate_phdr 每次都在跑
 *
 * ⚠️ 默认不编入。生产包里的字符串明文/统计计数都会成为特征，且
 *    AGENTS §2.6 明令调试开关一律编译期（不用运行期 getenv）。 */
#ifdef NC_STRDEC_PROFILE
static volatile unsigned long nc_prof_calls = 0;
static volatile unsigned long nc_prof_ns = 0;
static volatile unsigned long nc_prof_keyns = 0;
/* 2026-11-26：把 JNI 边界各步骤分开计时 —— 8.78s 的归属必须逐段量出来，
 * 不能只测 decrypt（那是 0.2ms，占 0.002%）。六段 + 总计 = 无处可藏。 */
static volatile unsigned long nc_prof_entry = 0;   /* 入口到取串前 */
static volatile unsigned long nc_prof_getchars = 0;
static volatile unsigned long nc_prof_cacheget = 0;
static volatile unsigned long nc_prof_mallocns = 0;
static volatile unsigned long nc_prof_newstr = 0;
static volatile unsigned long nc_prof_cacheput = 0;
/* 2026-11-26：区分「每次调用都慢」与「某次卡住」——
 * 只记累计耗时会把两者混在一起，修法完全不同：
 *   均匀慢 → 探测器/哈希结构问题
 *   单次卡 → 阻塞等待（JNI/GC/锁）
 * worst_us 记单次最坏耗时，full_scan 记「扫满整表仍未命中」的次数，
 * probes 记累计探测槽数（÷calls 得平均探测深度）。 */
static volatile unsigned long nc_prof_worst_us = 0;
static volatile unsigned long nc_prof_full_scan = 0;
static volatile unsigned long nc_prof_probes = 0;
static volatile unsigned long nc_prof_getchars_n = 0;  /* cache_get 内 GetStringUTFChars 次数 */
static volatile unsigned long nc_prof_total = 0;      /* 整个 JNI 函数 CPU 时间（对账用） */
static unsigned long nc_prof_now_ns(void);
/* cleanup 回调：任何 return 路径离开作用域时自动累加（结构上不可漏） */
static void nc_prof_scope_exit(unsigned long *t)
{
    nc_prof_total += nc_prof_now_ns() - *t;
}

static unsigned long nc_prof_now_ns(void)
{
    /* ⚠️ 2026-11-26：必须用 CLOCK_THREAD_CPUTIME_ID，不能用 CLOCK_MONOTONIC。
     *
     * 用 MONOTONIC（墙钟）测出的数字会被【线程被抢占的时间】污染：
     * 首版测出 cacheget=11069ms，而整个线程 utime 只有 6878ms ——
     * 墙钟累计超过了线程总 CPU 时间，这在物理上就证明它含等待。
     * 于是把「纯内存比较」误判成 80μs/次（实际 ~10ns），
     * 一路归因到 JNI 转换，方向全错。
     *
     * THREAD_CPUTIME 只计本线程真正在 CPU 上执行的时间 ——
     * 它给出的才是「这段代码花了多少 CPU」，不受调度抖动影响。 */
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (unsigned long) ts.tv_sec * 1000000000UL + (unsigned long) ts.tv_nsec;
}

void nc_strdec_profile_dump(void);

void nc_strdec_profile_dump(void)
{
    __android_log_print(ANDROID_LOG_INFO, NC_SD_TAG,
                        "prof: calls=%lu | getchars=%.1fms cacheget=%.1fms "
                        "decrypt=%.1fms malloc=%.1fms newstr=%.1fms "
                        "cacheput=%.1fms key=%.1fms",
                        nc_prof_calls, nc_prof_getchars / 1e6,
                        nc_prof_cacheget / 1e6, nc_prof_ns / 1e6,
                        nc_prof_mallocns / 1e6, nc_prof_newstr / 1e6,
                        nc_prof_cacheput / 1e6, nc_prof_keyns / 1e6);
    __android_log_print(ANDROID_LOG_INFO, NC_SD_TAG,
                        "prof2: worst=%.1fms fullscan=%lu probes=%lu avg=%.1f gcalls=%lu total=%.1fms",
                        nc_prof_worst_us / 1000.0,
                        nc_prof_full_scan,
                        nc_prof_probes,
                        nc_prof_calls
                            ? (double) nc_prof_probes / (double) nc_prof_calls
                            : 0.0,
                        nc_prof_getchars_n, nc_prof_total / 1e6);
}
#endif

static jobject nc_jni_fail(JNIEnv *env, jobject fallback)
{
    unsigned n = ++nc_fail_count;
    /* 限流：前 3 次每次都打（启动期看得到），之后每 100 次打一条。
     * 理由：解密失败常在启动时集中发生（几千条字符串），全打会刷满
     * logcat 缓冲区、挤掉真正有用的崩溃栈。 */
    if (n <= 3 || (n % 100) == 0) {
        __android_log_print(ANDROID_LOG_ERROR, NC_SD_TAG,
                            "decrypt failed (total=%u)", n);
    }
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
    return fallback;
}

/* 把 jstring 内容读成 UTF-8（payload 恒为 ASCII，用 Modified UTF-8 读法
 * 也无差异；但这里显式用 GetStringUTFChars 并检查 NULL）。 */
static const char *nc_jstr_chars(JNIEnv *env, jstring s, jsize *out_len)
{
    const char *p = (*env)->GetStringUTFChars(env, s, NULL);
    if (p == NULL) {
        return NULL;                    /* OOM：异常已挂起，交由 fail 出口清 */
    }
    *out_len = (*env)->GetStringUTFLength(env, s);
    return p;
}

/* ── 缓存查找 ──────────────────────────────────────────────────────── */
static jstring nc_cache_get(JNIEnv *env, const char *payload, size_t n)
{
    (void) env;                         /* 命中路径零 JNI：env 只给 put 用 */
    if (nc_cache_n == 0) {
        return NULL;
    }
    const uint64_t h = nc_fnv1a(payload, n);
    size_t idx = (size_t) h & NC_CACHE_MASK;
#ifdef NC_STRDEC_PROFILE
    size_t _probe_done = 0;
#endif
    for (size_t probe = 0; probe < NC_CACHE_CAP; probe++) {
        const nc_cache_slot *s = &nc_cache[idx];
#ifdef NC_STRDEC_PROFILE
        _probe_done++;
#endif
        if (s->hash == 0) {
            /* 空槽 = 未命中，开放寻址可提前终止。
             * ⚠️ 不走 fullscan 计数 —— 那是「扫满整表仍未命中」的计数器，
             * 提前终止时计入会谎报（2026-11-26 首版就写错了）。 */
#ifdef NC_STRDEC_PROFILE
            nc_prof_probes += _probe_done;
#endif
            return NULL;
        }
        /* ⚠️ 纯内存比较，不调 GetStringUTFChars —— 见文件头 2026-11-26 说明。
         * 先比长度（一次整型比较就能排除绝大多数碰撞），再 memcmp。 */
        if (s->hash == h && s->klen == (uint32_t) n
                && memcmp(s->key, payload, n) == 0) {
#ifdef NC_STRDEC_PROFILE
            nc_prof_probes += _probe_done;
#endif
            return s->val;
        }
        idx = (idx + 1) & NC_CACHE_MASK;
    }
#ifdef NC_STRDEC_PROFILE
    nc_prof_probes += _probe_done;
    nc_prof_full_scan++;
#endif
    return NULL;
}

/* 写入缓存。失败一律静默放弃 —— 缓存是优化不是正确性依赖，
 * 宁可少缓存也不能让解密失败。
 *
 * 写序纪律（并发安全的关键）：先填 key/klen/val，最后写 hash。
 * hash 非 0 是"槽有效"的唯一标志，读侧看到非 0 时其余字段必已就绪。 */
static void nc_cache_put(JNIEnv *env, jstring payload, jstring val)
{
    if (nc_cache_n >= (int) NC_CACHE_CAP || nc_cache_bytes >= NC_CACHE_BYTES_MAX) {
        return;                         /* 上限守卫：racy 检查，略超无害 */
    }
    const char *p = (*env)->GetStringUTFChars(env, payload, NULL);
    if (p == NULL) {
        return;
    }
    const jsize pl = (*env)->GetStringUTFLength(env, payload);
    const uint64_t h = nc_fnv1a(p, pl);

    /* key 字节副本：这里有且只有这一次 GetStringUTFChars */
    char *kcopy = (char *) malloc((size_t) pl);
    if (kcopy == NULL) {
        (*env)->ReleaseStringUTFChars(env, payload, p);
        return;
    }
    memcpy(kcopy, p, (size_t) pl);
    (*env)->ReleaseStringUTFChars(env, payload, p);

    size_t idx = (size_t) h & NC_CACHE_MASK;
    for (size_t probe = 0; probe < NC_CACHE_CAP; probe++) {
        nc_cache_slot *s = &nc_cache[idx];
        if (s->hash == 0) {
            jstring gv = (*env)->NewGlobalRef(env, val);
            if (gv == NULL) {
                free(kcopy);
                return;
            }
            s->key  = kcopy;
            s->klen = (uint32_t) pl;
            s->val  = gv;
            s->hash = h;                /* 最后写：见上方写序纪律 */
            nc_cache_n++;               /* racy，仅用于上限判断 */
            nc_cache_bytes += (size_t) pl;
            return;
        }
        if (s->hash == h && s->klen == (uint32_t) pl
                && memcmp(s->key, kcopy, (size_t) pl) == 0) {
            /* 同一条已存在（并发重复插入）：先写入者胜出，
             * 与 Java 侧 CHM"各算一遍、一个胜出"一致。 */
            free(kcopy);
            return;
        }
        idx = (idx + 1) & NC_CACHE_MASK;
    }
    free(kcopy);                        /* 表满（理论上不会）：放弃缓存 */
}

/* 前置声明：定义在本文件后部（bootstrap 附近），decrypt 里要调。 */
/* ══ 证书绑定：把种子和证书指纹混成最终密钥（2026-11-22）═════════════
 *
 * 【要解决的问题】
 *   此前解密密钥只由构建期随机种子决定，跟证书没关系。
 *   攻击者换个签名重打包 → 签名校验被破 → 字符串照样解得开
 *   → 字符串加密白做。
 *
 * 【做法】最终密钥 = 种子 XOR SHA256(证书DER) 的前 8 字节
 *
 *   证书没变 → 两侧算出同一个值 → 正常解密
 *   证书变了 → 两侧不同     → 全部字符串解成脏数据
 *
 *   种子（每包随机）保证"不同包密钥不同"；
 *   证书指纹保证"换签名即失效"。两个都要。
 *
 *   加密端在 scripts/string-enc/encrypt-strings.py 里做同样的事，
 *   两侧必须逐字节一致（测试 test-cstrdec.sh 对拍）。
 *
 * 【失败处置】拿不到 APK 或证书 → 清掉密钥 → 所有解密 fail-closed
 *   （返回原样密文）。宁可整包乱码（可见、可排查），也不要
 *   "以为有保护、其实没有"。
 */

/* 找本进程的 APK 路径。
 *
 * ⚠️ 不复用 sig_check.c 的 find_apk_path：那个是 static，且只在勾
 *    --sigcheck 时编译。字符串加密不该依赖"另一个可选模块被勾选"。
 *    这里走 /proc/self/maps —— 三条定位路径里最可靠的一条
 *    （extractNativeLibs 两种取值下 maps 都有 base.apk 行）。 */
static int nc_find_apk_path(char *out, size_t outcap)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[1024];

    if (fp == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *hit = strstr(line, "base.apk");
        char *sp;
        if (hit == NULL) {
            continue;
        }
        hit += 8;                  /* strlen("base.apk") */
        *hit = '\0';
        sp = strrchr(line, ' ');   /* 行首元数据与路径之间的分隔空格 */
        if (sp == NULL) {
            continue;
        }
        snprintf(out, outcap, "%s", sp + 1);
        if (access(out, R_OK) == 0) {
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

/* 上游 nox 的符号（经 --whole-archive 链进 libnov.so）。
 * ⚠️ 用强引用而非弱引用：证书绑定是安全功能，静默退化等于没有。
 *    换 nox 版本时若符号改名，链接期就报 undefined symbol ——
 *    构建直接失败，比"运行期悄悄失去防护"好得多。 */
extern int ncg_apk_first_cert_der(const char *apk_path, uint8_t *der,
                                  size_t der_cap, size_t *der_len);
extern void ksha256(const uint8_t *data, size_t len, uint8_t out[32]);

static int nc_key_is_set = 0;

static void nc_set_key_with_cert(void)
{
    static volatile int done = 0;
    int expected = 0;
    char apk[1024];
    uint8_t der[4096];
    size_t der_len = 0;
    uint8_t fp[32];
    uint8_t seed_be[8];
    uint8_t key[NC_STRDEC_KEYLEN];
    int i;

    if (nc_key_is_set) {
        return;
    }
    if (!__atomic_compare_exchange_n(&done, &expected, 1, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return;                         /* 别的线程在做/已做 */
    }

    if (nc_find_apk_path(apk, sizeof(apk)) != 0) {
        nc_strdec_set_key(NULL);        /* 清密钥 → 全部 fail-closed */
        return;
    }
    if (ncg_apk_first_cert_der(apk, der, sizeof(der), &der_len) != 0) {
        nc_strdec_set_key(NULL);
        return;
    }
    ksha256(der, der_len, fp);

    /* 取回刚设好的种子。来源（壳 or 编译期常量）不重要，只关心值。 */
    {
        uint64_t seed = nc_strdec_get_seed();
        /* 大端拆字节，与 Python 的 int.from_bytes(..., 'big') 一致。
         * 写成小端 = 两侧不同源 = 全包静默乱码且构建期零报错。 */
        for (i = 0; i < 8; i++) {
            seed_be[i] = (uint8_t)((seed >> ((7 - i) * 8)) & 0xFF);
        }
    }

    for (i = 0; i < 8; i++) {
        key[i] = (uint8_t)(seed_be[i] ^ fp[i]);
    }
    for (i = 8; i < NC_STRDEC_KEYLEN; i++) {
        key[i] = (uint8_t)(key[i % 8] ^ (uint8_t)(i / 8));
    }

    nc_strdec_set_key(key);

    memset(seed_be, 0, sizeof(seed_be));
    memset(key, 0, sizeof(key));
    memset(fp, 0, sizeof(fp));
    memset(der, 0, sizeof(der));
    nc_key_is_set = 1;
}

static void nc_ensure_key(void);


/* 在壳 so 里查导出符号。为什么不是一行 dlsym(RTLD_DEFAULT)：
 * Android 的 System.load 走 android_dlopen_ext(RTLD_NOW)【不带 RTLD_GLOBAL】，
 * 宿主实测 RTLD_LOCAL 时 dlsym(RTLD_DEFAULT) 返回 NULL。故须先拿 handle：
 * dl_iterate_phdr 按名字找到 → dlopen(RTLD_NOLOAD) 取已有映射（不重复加载）
 * → dlsym → dlclose 归还引用计数。
 * libnc.so 不知道壳 so 的绝对路径（dataDir/abi 只在 Java 层可知），只能遍历。
 * 开销：只在 nc_ensure_key() 首次调用跑一次，几十个 so 各做一次 strstr。 */
typedef struct {
    const char *want;
    void *handle;
} nc_phdr_ctx;

static int nc_phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void) size;
    nc_phdr_ctx *ctx = (nc_phdr_ctx *) data;
    if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0') {
        return 0;                       /* 主程序本身，无路径名，跳过 */
    }
    if (strstr(info->dlpi_name, ctx->want) == NULL) {
        return 0;
    }
    /* RTLD_NOLOAD：只取已有映射的 handle，不重复加载。
     * 加 RTLD_NOW 让符号解析立即完成（失败会返回 NULL，好过延迟爆炸）。 */
    ctx->handle = dlopen(info->dlpi_name, RTLD_NOW | RTLD_NOLOAD);
    return 1;                           /* 非 0 = 停止遍历 */
}

/* 纯 C 桩 ↔ 壳 so 联动（2026-11-10）。完整契约见
 * docs/模块联动关系.md 联动⑧ + §1.0。三个易错点：
 * ① 壳侧必须 extern "C"，否则 mangling 成 _Z10ncg_strkeyv，dlsym 静默失败
 * ② 包壳时 cfg.h 不定义 NC_STRDEC_KEY_BYTES（回退分支编不进去 = 设计）
 * ③ 种子按大端拆字节，与 protect.sh 生成常量、set_key 读法三方一致 */
#define NC_SHELL_SO_HINT "libxixin.so"

/* 在壳 so 里查符号。找到返回地址（handle 已归还），找不到返回 NULL。 */
static void *nc_find_shell_symbol(const char *name)
{
    nc_phdr_ctx ctx;
    ctx.want = NC_SHELL_SO_HINT;
    ctx.handle = NULL;

    dl_iterate_phdr(nc_phdr_cb, &ctx);
    if (ctx.handle == NULL) {
        /* 没包壳（只勾 stringenc-native、不勾 packer），或壳还没加载。
         * 调用方会回退到编译期常量 —— 这是允许的降级，不是错误。 */
        return NULL;
    }

    void *sym = dlsym(ctx.handle, name);
    dlclose(ctx.handle);                /* 归还 NOLOAD 增加的引用计数 */
    return sym;
}


/* ── JNI 入口 ────────────────────────────────────────────────────────
 *
 * 方法名 nc_strdec_jni_decrypt，【不带 Java_ 前缀、不带 JNIEXPORT】：
 *   · 走 RegisterNatives 动态注册 → 名字不进 .dynsym
 *   · 受 -fvisibility=hidden 支配 → 不导出
 *   · 与 nc_link.c 的 nc_link_jni_* 同一套纪律（见 nc_link_jni.c 头部）
 *
 * ⚠️ 谁负责注册：见下面的 nc_strdec_register_natives()，
 *    它必须被 JNI_OnLoad 调用（不能放 constructor —— 那时 classloader
 *    上下文未建立，FindClass 必失败，2026-10-19 真机实证）。
 */
jstring nc_strdec_jni_decrypt(JNIEnv *env, jclass clazz, jstring payload)
{
    (void)clazz;

    /* 函数级 CPU 时间对账：六段之和 vs 总耗时。
     * 差额 = 未被任何分段覆盖的代码（真正的"别处"）。
     * 用 CLOCK_THREAD_CPUTIME_ID，不含抢占（见 nc_prof_now_ns 注释）。
     *
     * ⚠️ 2026-11-26 修正：首版把累加写在最后的 `return out;` 前面 ——
     *    而函数有 10 条 return，其中「缓存命中」那条（占 97% 的调用）
     *    完全没计入，于是得到 total=67ms 的假象。
     *    改用 cleanup 属性：任何 return 路径离开作用域时都自动累加，
     *    结构上不可能漏。 */
#ifdef NC_STRDEC_PROFILE
    unsigned long _t_all __attribute__((cleanup(nc_prof_scope_exit)))
        = nc_prof_now_ns();
#endif

    if (payload == NULL) {
        return nc_jni_fail(env, NULL);  /* 传 null 进来：返回 null，不崩 */
    }

    /* 惰性确保密钥就绪（幂等、无锁快路径）。
     * 为什么放在这里而不是只靠 JNI_OnLoad：纯 stringenc-native 组合没有
     * OnLoad（短名绑定不需要它），bootstrap 永远不会被调 —— 密钥就永远
     * 是空，所有解密都会静默 fail-closed（真机实测：App 起来但功能全废，
     * 日志里只有 fail 计数）。 */
#ifdef NC_STRDEC_PROFILE
    {
        unsigned long _t0 = nc_prof_now_ns();
        nc_ensure_key();
        nc_prof_keyns += nc_prof_now_ns() - _t0;
    }
#else
    nc_ensure_key();
#endif

    if (!nc_strdec_has_key()) {
        /* 没有 cfg 头 = 构建期没注入密钥（非 native 桩组合误编进了本单元）。
         * fail-closed 保持原样。 */
        return nc_jni_fail(env, payload);
    }

    jsize plen = 0;
#ifdef NC_STRDEC_PROFILE
    unsigned long _t_g = nc_prof_now_ns();
#endif
    const char *pchars = nc_jstr_chars(env, payload, &plen);
#ifdef NC_STRDEC_PROFILE
    nc_prof_getchars += nc_prof_now_ns() - _t_g;
#endif
    if (pchars == NULL) {
        return nc_jni_fail(env, payload);
    }

    /* ── 缓存命中：直接返回（intern 语义由 Java 回填链负责，不在这里做）── */
#ifdef NC_STRDEC_PROFILE
    unsigned long _t_cg = nc_prof_now_ns();
#endif
    jstring hit = nc_cache_get(env, pchars, (size_t)plen);
#ifdef NC_STRDEC_PROFILE
    {
        unsigned long _d = nc_prof_now_ns() - _t_cg;
        nc_prof_cacheget += _d;
        if (_d / 1000 > nc_prof_worst_us) {
            nc_prof_worst_us = _d / 1000;   /* 单次最坏（微秒） */
        }
    }
#endif
    if (hit != NULL) {
        (*env)->ReleaseStringUTFChars(env, payload, pchars);
        return hit;
    }

    /* ── 未命中：解码 ────────────────────────────────────────────────
     * 输出缓冲直接在栈上：最大可能明文是 payload 的 3/4 倍。
     * 栈上限保护：超长 payload（>32KB）走堆分配。
     *   · ART 的 Java 线程栈默认 1MB，但 native 侧被 JNI 调用时
     *     可用余量不保证；32000*3/4 = 24KB 是保守值。
     *   · 实测最长真实字符串 5188B，远低于阈值。 */
    /* ⚠️ 栈上限（2026-11-09 真机实测教训）：
     * 第一版用 uint8_t stackbuf[32768] + uint16_t u16stack[16384]
     * = 32KB + 32KB = 64KB 栈缓冲，单次调用就要这么多。
     * 真实包里存在 2047 字节的密文（Room 的 SQL 语句），解出来 1535 字节
     * UTF-8 → 大部分是 3 字节中文 → 约 500 个 UTF-16 码元，栈上限够用；
     * 但 JNI 调用点的可用栈不保证 —— ART 主线程 1MB，而 Binder/后台
     * 线程可能只有 8KB~64KB。栈溢出在 ART 里表现为 SIGSEGV 或
     * 静默失败（本模块选择"失败返回原密文"，于是 SQL 变密文 → Room 报
     * "no table with name AAtkRGFash8="）。
     *
     * 现在：一律走堆分配。解密是低频路径（首次 + 缓存未命中），
     * 一次 malloc 的开销远小于栈溢出的风险。 */
    const size_t cap = ((size_t)plen / 4) * 3 + 8;
#ifdef NC_STRDEC_PROFILE
    unsigned long _t_m = nc_prof_now_ns();
#endif
    uint8_t *decoded = (uint8_t *)malloc(cap);
#ifdef NC_STRDEC_PROFILE
    nc_prof_mallocns += nc_prof_now_ns() - _t_m;
#endif
    if (decoded == NULL) {
        (*env)->ReleaseStringUTFChars(env, payload, pchars);
        return nc_jni_fail(env, payload);
    }

#ifdef NC_STRDEC_PROFILE
    unsigned long _t_dec = nc_prof_now_ns();
#endif
    int dlen = nc_strdec_decrypt(pchars, (size_t)plen, decoded, cap);
#ifdef NC_STRDEC_PROFILE
    if (dlen >= 0) {
        unsigned long n = ++nc_prof_calls;
        nc_prof_ns += nc_prof_now_ns() - _t_dec;
        if ((n % 500) == 0) {
            nc_strdec_profile_dump();
        }
    }
#endif
    (*env)->ReleaseStringUTFChars(env, payload, pchars);

    if (dlen <= 0) {
        free(decoded);
        return nc_jni_fail(env, payload);   /* 硬约束 ①：原样返回 */
    }

    /* ── UTF-8 → UTF-16 → NewString ──────────────────────────────────
     * ⚠️ 不能用 NewStringUTF：它收 modified UTF-8，emoji 会乱码。
     *    详见 nc_strdec.h 的说明与 test-cstrdec-vs-java.sh 的断言。 */
    /* 同上：UTF-16 缓冲也走堆。最坏情况 dlen 个码元（纯 ASCII）。 */
    const size_t u16cap = (size_t)dlen + 1;
    uint16_t *u16 = (uint16_t *)malloc(u16cap * sizeof(uint16_t));
    if (u16 == NULL) {
        free(decoded);
        return nc_jni_fail(env, payload);
    }

    int ulen = nc_strdec_utf8_to_utf16(decoded, (size_t)dlen, u16, u16cap);
    if (ulen <= 0) {
        /* ── 解出的字节不是合法 UTF-8（2026-11-22 改）────────────────
         *
         * 【原来】原样返回密文。问题：密文是 Base64，攻击者一眼就能
         *   看出"这里坏了"，等于直接告诉他密钥错了、问题在哪。
         *
         * 【现在】把字节逐个映射成可见字符，返回一个【等长、看起来正常】
         *   的字符串。攻击者看到的是"解密成功了，但内容不对"，
         *   定位不到是密钥的问题。
         *
         * 为什么不用 U+FFFD / 跳过非法字节：
         *   那会让输出变短或出现明显的替换符，同样能被识别成"解码出错"。
         *   逐个字节映射保证【长度不变】，与正常解密结果无从区分。
         *
         * ⚠️ 这里【不计入】nc_fail_count —— 那是"诊断"通道，
         *    计入会让攻击者通过 logcat 反推出"正在解错"。
         *    真正的失败计数只在"密钥根本没设"时用（那种情况本来就该看见）。 */
        size_t i;
        for (i = 0; i < (size_t)dlen && i < u16cap; i++) {
            /* 映射到可见 ASCII：0x20..0x7E（95 个字符）。
             * 用模运算而非查表：少一个 .rodata 表 = 少一处可被定位的特征。 */
            u16[i] = (uint16_t)(0x20 + (decoded[i] % 95));
        }
        ulen = (int)i;
        if (ulen <= 0) {
            free(decoded);
            free(u16);
            return nc_jni_fail(env, payload);
        }
    }
    free(decoded);

    jstring out = (*env)->NewString(env, (const jchar *)u16, (jsize)ulen);
    free(u16);
    if (out == NULL) {
        return nc_jni_fail(env, payload);   /* OOM */
    }

    /* 只缓存成功结果（防毒缓存，与 Java 侧语义一致） */
#ifdef NC_STRDEC_PROFILE
    unsigned long _t_cp = nc_prof_now_ns();
#endif
    nc_cache_put(env, payload, out);
#ifdef NC_STRDEC_PROFILE
    nc_prof_cacheput += nc_prof_now_ns() - _t_cp;
#endif
    return out;
}

/* ── 密钥注入入口 ────────────────────────────────────────────────────
 *
 * 由桩类的 <clinit> 调用（详见 encrypt-strings.py 的 stub 生成逻辑）。
 * 参数是 byte[]，长度必须是 NC_STRDEC_KEYLEN。
 *
 * 返回 void：失败不抛异常 —— 密钥错了后续解密会走 fail-closed
 * （原样返回密文），不需要在这里制造第二个失败路径。
 *
 * ⚠️ 与 decrypt 不同，本函数【可以】用短名绑定或动态注册；
 *    当前统一走动态注册（见 register_natives）。
 */
void nc_strdec_jni_set_key(JNIEnv *env, jclass clazz, jbyteArray key)
{
    (void)clazz;

    if (key == NULL) {
        return;
    }
    jsize n = (*env)->GetArrayLength(env, key);
    if (n != NC_STRDEC_KEYLEN) {
        return;                         /* 长度不符：静默忽略，解密侧会 fail-closed */
    }

    static uint8_t kbuf[NC_STRDEC_KEYLEN];
    (*env)->GetByteArrayRegion(env, key, 0, n, (jbyte *)kbuf);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return;
    }
    nc_strdec_set_key(kbuf);

    /* 密钥是敏感材料，用完即擦掉临时副本。
     * 不用 memset：-Oz 下可能被判为死存储删掉（sig_check.c 的 ncg_wipe
     * 注释记过这条实测教训），改用 volatile 指针逐字节写。 */
    {
        volatile uint8_t *p = kbuf;
        for (int i = 0; i < NC_STRDEC_KEYLEN; i++) {
            p[i] = 0;
        }
    }
}

/* ── 关于 JNI 绑定方式（2026-11-09 最终形态）───────────────────────
 *
 * 本文件【不注册】任何 native 方法，也不提供 JNI_OnLoad。绑定由构建期
 * 生成的 nc_strdec_bind.c 用 JNI 短名完成（Java_<mangled>_<method>）。
 *
 * 为什么不用 RegisterNatives（真机实测两轮，都是硬崩溃）：
 *   ① 桩类在自己的 <clinit> 里 loadLibrary，此刻该类正在初始化中，
 *      ART 不允许 FindClass 到未完成初始化的类 → 注册失败。
 *   ② 更根本的：ART 对 native 方法的短名解析发生在【类链接阶段】，
 *      早于 <clinit> 执行 —— 那时 so 还没加载，ART 记下"方法不存在"，
 *      之后调用必抛 NoSuchMethodError。
 *   短名绑定由 ART 在【首次调用时】dlsym，天然满足"so 已加载"。
 *
 * 代价（如实）：短名符号会出现在 .dynsym，`nm -D` 可见。名字是随机
 * 包名 + 随机方法名，不含业务语义；且这是 JNI 短名绑定的固有代价
 * （dex2c 产物同样如此）。
 *
 * 密钥也不经过 Java（任何"Java 调 native setKey"都躲不过上面的时序问题），
 * 来源见 nc_ensure_key()：包壳时从壳 so 取，未包壳时用编译期常量。
 */

/* ── 统一引导入口（由持有 JNI_OnLoad 的一方调用）────────────────────
 *
 * 本文件【从不】提供 JNI_OnLoad：一个 so 只能有一个，而 libnc.so 里已有
 * 三方竞争者（Dex2C.cpp / nc_link_jni.c / 本模块）。各自提供会导致
 * `ld.lld: duplicate symbol: JNI_OnLoad`（2026-11-05 CI 实证）。
 * 故只导出 nc_strdec_register_natives()，由已有的那个 OnLoad 调用。
 *
 * 职责：记录 JavaVM + 注册 JNI 方法到构建期随机生成的桩类（名字来自 cfg.h，
 * 写死会让每包随机化失效）。失败建议 fail-fast —— 症状是"所有字符串都是
 * 密文"，比闪退难查。
 */

/* ── 确保密钥已设置（幂等，CAS 保证只设一次）────────────────────────
 * 必须惰性设而不能只靠 bootstrap：纯 --stringenc-native 组合没有
 * JNI_OnLoad，bootstrap 永不执行 → 密钥永远为空 → 全部静默 fail-closed
 * （真机症状：SQL 变密文、Room 报 no table with name <密文>）。
 */
static void nc_ensure_key(void)
{
#if defined(NC_STRDEC_HAVE_CFG) && defined(NC_STRDEC_KEY_BYTES)
    /* 密钥常量的存储位置（2026-11-11）：必须在文件作用域 + .ncx 段。
     *
     * 为什么不能在函数内 static const：
     *   会编译进 .rodata【明文】。攻击者不必逆任何算法，直接读这 8 字节
     *   种子，配公开的 splitmix64/ChaCha20 就能解开全部字符串。
     *
     * 为什么加 volatile：
     *   -Oz 会把 const 数组的内容当编译期常量传播到使用点，
     *   在 .text 里生成明文立即数 —— 那样等于绕过整个段加密。
     *   与 nox 的 ncg_stub_slot 同一手法（见 nox AGENTS.md §2.3 的教训）。
     *
     * ⚠️⚠️ 必须用 .ncxr 而不是 .ncx（2026-11-11 实测踩坑）：
     *   .ncx 是 AXR（可执行）段。把【可写】数据塞进去，链接器会把整个
     *   LOAD 段标成 RWE —— Android 14+ 直接拒绝加载：
     *     UnsatisfiedLinkError: dlopen failed: "libnc.so" has load segments
     *     that are both writable and executable
     *   实测：改成 .ncx 后应用启动即崩，连 constructor 都没跑到。
     *   .ncxr 是 AWR（可写不可执行），本来就是给常量/数据用的，
     *   而且锁箱器同样会加密它（protect.sh 的 --section .ncx,.ncxr）。
     *
     *   这正是 nox AGENTS.md §2.2 的硬约束：「数据段不能用 .ncx」。
     *
     * 为什么这里安全（时序）：
     *   本函数由【首次解密调用】惰性触发，晚于 constructor(50) 解锁 .ncx。
     *   不在 JNI_OnLoad 期读。 */
    static uint8_t nc_strdec_key_cipher[NC_STRDEC_KEYLEN]
        __attribute__((section(".ncxr"), used, retain)) = NC_STRDEC_KEY_BYTES;
#endif

    static volatile int done = 0;
    int expected = 0;
    if (nc_strdec_has_key()) {
        return;
    }
    if (!__atomic_compare_exchange_n(&done, &expected, 1, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return;                         /* 别的线程已经在设/已设好 */
    }

    /* 密钥来源（2026-11-10 联动）：① 壳 so 的 ncg_strkey() → ② 编译期常量。
     *
     * ① 优先：常量躺在 libnc.so 里能被反编译读出来，那样「脱壳后丢掉壳 so
     *    仍能解」，「必须带着壳」就不成立。
     * ② 回退：只在【没包壳】时编得进来（protect.sh 按 WANT_PACKER 决定是否
     *    定义 NC_STRDEC_KEY_BYTES）。包壳时无此宏 → 取不到种子就等于
     *    「壳被去掉了」→ has_key()=0 → 全部 fail-closed，正是期望行为。
     *
     * 两分支必须产出同一把密钥：密文由「本轮种子」加密，而该种子同时写进
     * cfg.h 常量与 dpt 的 stub_seed，同源于 protect.sh 的 stub_seed.txt。 */
    int got = 0;

    /* ① 壳 so */
    {
        typedef uint64_t (*ncg_strkey_fn)(void);
        uint64_t seed = 0;
        void *sym = nc_find_shell_symbol("ncg_strkey");
        if (sym != NULL) {
            seed = ((ncg_strkey_fn) sym)();
        }
        /* seed==0 = 壳在但未开联动（dpt 默认值）。不能拿它当密钥：
         * 0 会算出一把可预测的密钥，比没有更糟。 */
        if (seed != 0) {
            /* 按【大端】拆字节，与 protect.sh 生成常量、set_key 的读法三方一致。
             * 写成小端 = 两侧不同源 = 全包静默乱码且构建期零报错。
             * NKEYS>1 的占位分支实际不会执行（顶部有 NKEYS==1 编译期断言）。 */
            uint8_t k[NC_STRDEC_KEYLEN];
            for (int i = 0; i < NC_STRDEC_KEYLEN; i++) {
                int b = i % 8;
                k[i] = (uint8_t) ((seed >> ((7 - b) * 8)) & 0xFF);
                if (i >= 8) {
                    k[i] ^= (uint8_t) (i / 8);
                }
            }
            nc_strdec_set_key(k);
            memset(k, 0, sizeof(k));
            got = 1;
        }
    }

#if defined(NC_STRDEC_HAVE_CFG) && defined(NC_STRDEC_KEY_BYTES)
    /* ② 回退：编译期常量（仅未包壳时存在此宏） */
    if (!got) {
        /* ⚠️ 2026-11-11：密钥常量必须进 .ncx 加密段。
         *
         * 原来写成函数内 `static const uint8_t k[] = NC_STRDEC_KEY_BYTES;`
         * —— 编译进 .rodata【明文】。攻击者不需要逆任何算法，
         * 直接从 .rodata 捞出这 8 字节种子，用 RFC 上的 splitmix64/ChaCha20
         * 就能解开全部字符串（算法是公开的，密钥才是秘密）。
         *
         * 现在提到文件作用域 + section(".ncx")：
         *   · 段被锁箱器整段加密 → 磁盘上是密文
         *   · 运行期 constructor(50) 解锁后明文可用
         *
         * 时序安全性：读取发生在 nc_ensure_key()，而它由【首次解密调用】
         * 惰性触发（见 nc_strdec_jni.c 里 nc_strdec_jni_decrypt 的注释），
         * 一定晚于 constructor(50) 的解锁。不在 JNI_OnLoad 期读。
         *
         * ⚠️ 用 const volatile：防 -Oz 把数组内容当编译期常量传播到
         *    各使用点（那会在 .text 里生成明文立即数，绕过整个加密）。
         *    与 nox 的 ncg_stub_slot 同一手法。 */
        *(volatile uint8_t *)nc_strdec_key_cipher;   /* 阻止 -Oz 常量传播 */
        nc_strdec_set_key(nc_strdec_key_cipher);
    }
#else
    /* 走到这里 = 包壳且 ① 没拿到种子（或非 native 组合）。
     * 行为相同：无密钥 → fail-closed。不 panic，让上层原样返回密文。 */
    (void) got;
#endif

    /* 种子已设好 → 再叠一层证书。证书变了，最终密钥就变（2026-11-22）。 */
    if (nc_strdec_has_key()) {
        nc_set_key_with_cert();
    }
}
