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
#include <dlfcn.h>   /* dlsym/dlopen：从壳 so 取字符串密钥种子（2026-11-10 联动） */
#include <link.h>    /* dl_iterate_phdr：遍历已加载 so 找壳 so 的 handle */

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
 * 用 global ref（局部引用跨不了调用栈）。上限 30000，racy 检查
 * （并发略超无害），进程生命周期内不释放 —— 与 Java 侧 CHM 语义等同。
 * 命中也要 GetStringUTFChars 查表，不是零成本，但比重算便宜 5~10 倍。 */
#define NC_CACHE_CAP 30000

/* 极简开放寻址哈希表。不用链表：插入后不删除，探测序列恒有效。 */
typedef struct {
    uint64_t hash;          /* 0 = 空槽（密文 hash 恰为 0 概率 ~2^-64，可接受） */
    jstring  key;           /* 密文 payload 的 global ref */
    jstring  val;           /* 明文的 global ref */
} nc_cache_slot;

static nc_cache_slot nc_cache[NC_CACHE_CAP];
static volatile int nc_cache_n = 0;

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
 * 这里只计数，不打日志（避免日志本身成为特征串）；需排障时由
 * 调用方通过 nc_strdec_fail_count() 读取。 */
static volatile unsigned nc_fail_count = 0;

unsigned nc_strdec_fail_count(void)
{
    return nc_fail_count;
}

static jobject nc_jni_fail(JNIEnv *env, jobject fallback)
{
    nc_fail_count++;
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
    if (nc_cache_n == 0) {
        return NULL;
    }
    const uint64_t h = nc_fnv1a(payload, n);
    size_t idx = (size_t)(h % NC_CACHE_CAP);
    for (size_t probe = 0; probe < NC_CACHE_CAP; probe++) {
        const nc_cache_slot *s = &nc_cache[idx];
        if (s->hash == 0) {
            return NULL;                /* 空槽 = 未命中（开放寻址可提前终止）*/
        }
        if (s->hash == h) {
            /* hash 相同还要比内容：hash 碰撞是可能的，不能只比 hash */
            const char *k = (*env)->GetStringUTFChars(env, s->key, NULL);
            if (k == NULL) {
                return NULL;
            }
            jsize kl = (*env)->GetStringUTFLength(env, s->key);
            int same = (kl == (jsize)n) && (memcmp(k, payload, n) == 0);
            (*env)->ReleaseStringUTFChars(env, s->key, k);
            if (same) {
                return s->val;
            }
        }
        idx = (idx + 1) % NC_CACHE_CAP;
    }
    return NULL;
}

/* 写入缓存。失败（NewGlobalRef 返回 NULL）静默放弃 ——
 * 缓存是优化不是正确性依赖，宁可少缓存也不能让解密失败。 */
static void nc_cache_put(JNIEnv *env, jstring payload, jstring val)
{
    if (nc_cache_n >= NC_CACHE_CAP) {
        return;                         /* 上限守卫：racy 检查，略超无害 */
    }
    const char *p = (*env)->GetStringUTFChars(env, payload, NULL);
    if (p == NULL) {
        return;
    }
    const jsize pl = (*env)->GetStringUTFLength(env, payload);
    const uint64_t h = nc_fnv1a(p, pl);
    (*env)->ReleaseStringUTFChars(env, payload, p);

    size_t idx = (size_t)(h % NC_CACHE_CAP);
    for (size_t probe = 0; probe < NC_CACHE_CAP; probe++) {
        nc_cache_slot *s = &nc_cache[idx];
        if (s->hash == 0) {
            jstring gk = (*env)->NewGlobalRef(env, payload);
            if (gk == NULL) {
                return;
            }
            jstring gv = (*env)->NewGlobalRef(env, val);
            if (gv == NULL) {
                (*env)->DeleteGlobalRef(env, gk);
                return;
            }
            s->key = gk;
            s->val = gv;
            s->hash = h;                /* 最后写 hash：保证并发下"槽有效"才可见 */
            nc_cache_n++;               /* racy，仅用于上限判断 */
            return;
        }
        if (s->hash == h) {
            /* 同 hash 已存在：可能是同一条（并发重复插入）或碰撞。
             * 不覆盖 —— 先写入者胜出，行为与 Java 侧 CHM 的
             * "两线程同时未命中各算一遍、一个写入胜出"一致。 */
            return;
        }
        idx = (idx + 1) % NC_CACHE_CAP;
    }
}

/* 前置声明：定义在本文件后部（bootstrap 附近），decrypt 里要调。 */
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

    if (payload == NULL) {
        return nc_jni_fail(env, NULL);  /* 传 null 进来：返回 null，不崩 */
    }

    /* 惰性确保密钥就绪（幂等、无锁快路径）。
     * 为什么放在这里而不是只靠 JNI_OnLoad：纯 stringenc-native 组合没有
     * OnLoad（短名绑定不需要它），bootstrap 永远不会被调 —— 密钥就永远
     * 是空，所有解密都会静默 fail-closed（真机实测：App 起来但功能全废，
     * 日志里只有 fail 计数）。 */
    nc_ensure_key();

    if (!nc_strdec_has_key()) {
        /* 没有 cfg 头 = 构建期没注入密钥（非 native 桩组合误编进了本单元）。
         * fail-closed 保持原样。 */
        return nc_jni_fail(env, payload);
    }

    jsize plen = 0;
    const char *pchars = nc_jstr_chars(env, payload, &plen);
    if (pchars == NULL) {
        return nc_jni_fail(env, payload);
    }

    /* ── 缓存命中：直接返回（intern 语义由 Java 回填链负责，不在这里做）── */
    jstring hit = nc_cache_get(env, pchars, (size_t)plen);
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
    uint8_t *decoded = (uint8_t *)malloc(cap);
    if (decoded == NULL) {
        (*env)->ReleaseStringUTFChars(env, payload, pchars);
        return nc_jni_fail(env, payload);
    }

    int dlen = nc_strdec_decrypt(pchars, (size_t)plen, decoded, cap);
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
    free(decoded);
    if (ulen <= 0) {
        free(u16);
        /* 密文解出来的字节不是合法 UTF-8 = 密文损坏或密钥错。
         * fail-closed：原样返回密文（一眼看出坏了），
         * 而不是返回含 U+FFFD 的"看起来正常"的垃圾。 */
        return nc_jni_fail(env, payload);
    }

    jstring out = (*env)->NewString(env, (const jchar *)u16, (jsize)ulen);
    free(u16);
    if (out == NULL) {
        return nc_jni_fail(env, payload);   /* OOM */
    }

    /* 只缓存成功结果（防毒缓存，与 Java 侧语义一致） */
    nc_cache_put(env, payload, out);
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
        static const uint8_t k[NC_STRDEC_KEYLEN] = NC_STRDEC_KEY_BYTES;
        nc_strdec_set_key(k);
    }
#else
    /* 走到这里 = 包壳且 ① 没拿到种子（或非 native 组合）。
     * 行为相同：无密钥 → fail-closed。不 panic，让上层原样返回密文。 */
    (void) got;
#endif
}
