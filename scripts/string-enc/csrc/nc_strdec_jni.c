/* nc_strdec_jni.c — 纯 C 解密桩的 JNI 边界（2026-11-09）
 *
 * 职责边界（刻意切分）：
 *   nc_strdec.c       纯算法（Base64 / 密钥流 / UTF-8→UTF-16），零 JNI 依赖
 *   本文件            只做 JNI 类型转换 + 缓存 + 异常处置
 *
 * 为什么切开：宿主测试要能编 nc_strdec.c 而不需要 JVM；
 *   将来若把桩搬进 dpt 壳 so，也只需重写这一层。
 *
 * ── 三条硬约束（每条都对应一个真实事故类型）───────────────────────
 *
 * ① 失败必须【原样返回传入的 payload 对象】，不抛异常、不崩、不缓存
 *    现有 Java 桩的语义是 try{return dn()}catch{return payload}。
 *    改成 native 后 dex 侧没有 try/catch，兜底责任全在本文件。
 *    返回原对象（而不是 NewString 一个新串）也保证了"失败时
 *    业务拿到的就是密文本身"这个可观察行为不变。
 *
 * ② 绝不能带着 pending exception 继续调 JNI
 *    中途中止时若有异常挂起，后续所有 JNI 调用都未定义。
 *    故退出路径统一走 nc_jni_fail()：先 ExceptionCheck/Clear，再返回兜底值。
 *
 * ③ so 未加载 / 密钥未设置 → 也是"原样返回"而不是崩
 *    但这两件事在正常产物里不该发生：so 由桩类的 <clinit> 加载
 *    （见 encrypt-strings.py 的 _inject_loadlib_into_stub_clinit），
 *    密钥由 <clinit> 经 setKey 注入。真发生了说明构建期缺步骤，
 *    此时返回密文（App 不崩但字符串是密文）比闪退更容易定位。
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "nc_strdec.h"

/* 构建期生成的配置头（protect.sh 写进 NDK 工程目录，不进 git）。
 * 没有它 = 本次不是 native 桩组合，bootstrap 退化为只记录 JavaVM。 */
#if defined(__has_include)
#  if __has_include("nc_strdec_cfg.h")
#    include "nc_strdec_cfg.h"
#    define NC_STRDEC_HAVE_CFG 1
#  endif
#endif

/* ── L1 缓存 ──────────────────────────────────────────────────────────
 *
 * 为什么必须有：现有 Java 桩有 ConcurrentHashMap 缓存（StrDec.java 的
 * CACHE）。搬到 C 之后若不缓存，每次调用都要重算 Base64 + 密钥流 + 分配
 * String；而实测某些位点单次启动会被执行 ~20 次（Compose 重组），
 * 累计开销比"换算法"那一档大一个数量级。
 *
 * 为什么用 global ref：JNI 局部引用只在当前调用栈有效，缓存必须跨调用，
 * 只能用 NewGlobalRef。
 *
 * 上限：与 Java 桩同值 30000。racy 检查（并发略超无害）。
 * 内存：每条 ~(对象头 + 全局引用表项)，30000 条量级是几 MB，
 * 与 Java 侧 CHM 的占用同数量级，不构成新问题。
 *
 * ⚠️ 已知边界（与 Java 版一致）：
 *   · 进程生命周期内不释放 —— 与 Java 侧 CHM 语义等同（进程死即空）
 *   · key = 密文 jstring 内容，查表要 GetStringUTFChars（有分配），
 *     所以"命中"不是零成本，但比重算便宜约 5~10 倍（实测见 README）
 */
#define NC_CACHE_CAP 30000

/* 极简开放寻址哈希表。不用链表：插入后不删除，探测序列恒有效。 */
typedef struct {
    uint64_t hash;          /* 0 = 空槽（密文 hash 恰为 0 概率 ~2^-64，可接受） */
    jstring  key;           /* 密文 payload 的 global ref */
    jstring  val;           /* 明文的 global ref */
} nc_cache_slot;

static nc_cache_slot nc_cache[NC_CACHE_CAP];
static volatile int nc_cache_n = 0;
static JavaVM *nc_vm = NULL;

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
static jobject nc_jni_fail(JNIEnv *env, jobject fallback)
{
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

    /* 密钥未就绪 → 原样返回（硬约束 ③）。
     * 正常产物不该走到这里（<clinit> 会先 setKey）。 */
    if (!nc_strdec_has_key()) {
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
    const size_t cap = ((size_t)plen / 4) * 3 + 8;
    uint8_t stackbuf[32768];
    uint8_t *decoded = stackbuf;
    if (cap > sizeof stackbuf) {
        decoded = (uint8_t *)malloc(cap);
        if (decoded == NULL) {
            (*env)->ReleaseStringUTFChars(env, payload, pchars);
            return nc_jni_fail(env, payload);
        }
    }

    int dlen = nc_strdec_decrypt(pchars, (size_t)plen, decoded, cap);
    (*env)->ReleaseStringUTFChars(env, payload, pchars);

    if (dlen <= 0) {
        if (decoded != stackbuf) {
            free(decoded);
        }
        return nc_jni_fail(env, payload);   /* 硬约束 ①：原样返回 */
    }

    /* ── UTF-8 → UTF-16 → NewString ──────────────────────────────────
     * ⚠️ 不能用 NewStringUTF：它收 modified UTF-8，emoji 会乱码。
     *    详见 nc_strdec.h 的说明与 test-cstrdec-vs-java.sh 的断言。 */
    const size_t u16cap = (size_t)dlen + 1;
    uint16_t u16stack[16384];
    uint16_t *u16 = u16stack;
    if (u16cap > sizeof u16stack / sizeof u16stack[0]) {
        u16 = (uint16_t *)malloc(u16cap * sizeof(uint16_t));
        if (u16 == NULL) {
            if (decoded != stackbuf) {
                free(decoded);
            }
            return nc_jni_fail(env, payload);
        }
    }

    int ulen = nc_strdec_utf8_to_utf16(decoded, (size_t)dlen, u16, u16cap);
    if (decoded != stackbuf) {
        free(decoded);
    }
    if (ulen <= 0) {
        if (u16 != u16stack) {
            free(u16);
        }
        /* 密文解出来的字节不是合法 UTF-8 = 密文损坏或密钥错。
         * fail-closed：原样返回密文（一眼看出坏了），
         * 而不是返回含 U+FFFD 的"看起来正常"的垃圾。 */
        return nc_jni_fail(env, payload);
    }

    jstring out = (*env)->NewString(env, (const jchar *)u16, (jsize)ulen);
    if (u16 != u16stack) {
        free(u16);
    }
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

/* ── 动态注册表 ──────────────────────────────────────────────────────
 *
 * 方法名与签名的存储纪律（与 nc_link_jni.c 同源）：
 *   把字符串 XOR 0x5A 存，避免 `strings` 直接扫出方法名。
 *   ⚠️ 这是【混淆】不是【加密】，如实标注：读下面十几行就能还原。
 *      真实收益只有一条 —— `strings` 扫不到"这里有个解密入口"。
 *
 * 改方法名必须同步三处：
 *   ① 本表
 *   ② encrypt-strings.py 生成桩时用的 JNI 描述符
 *   ③ 桩的 smali（由 encrypt-strings.py 生成，不该手写）
 * 漏一处的症状是运行期 NoSuchMethodError（RegisterNatives 会让它变明确）。
 */
#define NC_XOR 0x5A

static void nc_dexor(char *out, size_t cap,
                     const unsigned char *enc, size_t enclen)
{
    size_t i;
    for (i = 0; i + 1 < cap && i < enclen; i++) {
        out[i] = (char)(enc[i] ^ NC_XOR);
    }
    out[cap - 1] = '\0';
}

/* ── 混淆表 ──────────────────────────────────────────────────────────
 * ⚠️ 本表由脚本生成，不要手改（手算 XOR 极易错，且错了是运行期
 *    NoSuchMethodError，构建期拦不住）。生成方式：
 *      python3 -c "print(', '.join('0x%02X'%(c^0x5A) for c in b'ncDec\x00'))"
 *    反向校验见 tests/test-cstrdec.sh 的「混淆表反解」断言。
 */
/* "ncDec" ^ 0x5A */
static const unsigned char nc_name_dec[] = {
    0x34, 0x39, 0x1E, 0x3F, 0x39, 0x5A
};
/* "(Ljava/lang/String;)Ljava/lang/String;" ^ 0x5A */
static const unsigned char nc_sig_dec[] = {
    0x72, 0x16, 0x30, 0x3B, 0x2C, 0x3B, 0x75, 0x36, 0x3B, 0x34, 0x3D, 0x75,
    0x09, 0x2E, 0x28, 0x33, 0x34, 0x3D, 0x61, 0x73, 0x16, 0x30, 0x3B, 0x2C,
    0x3B, 0x75, 0x36, 0x3B, 0x34, 0x3D, 0x75, 0x09, 0x2E, 0x28, 0x33, 0x34,
    0x3D, 0x61, 0x5A
};
/* "ncSetKey" ^ 0x5A */
static const unsigned char nc_name_setkey[] = {
    0x34, 0x39, 0x09, 0x3F, 0x2E, 0x11, 0x3F, 0x23, 0x5A
};
/* "([B)V" ^ 0x5A */
static const unsigned char nc_sig_setkey[] = {
    0x72, 0x01, 0x18, 0x73, 0x0C, 0x5A
};

int nc_strdec_register_natives(JNIEnv *env, const char *class_dot)
{
    if (env == NULL || class_dot == NULL) {
        return -1;
    }

    jclass clazz = (*env)->FindClass(env, class_dot);
    if (clazz == NULL) {
        (*env)->ExceptionClear(env);
        return -1;
    }

    char name_dec[8], name_setkey[16];
    char sig_dec[64], sig_setkey[16];    nc_dexor(name_dec, sizeof name_dec, nc_name_dec, sizeof nc_name_dec);
    nc_dexor(sig_dec, sizeof sig_dec, nc_sig_dec, sizeof nc_sig_dec);
    nc_dexor(name_setkey, sizeof name_setkey,
             nc_name_setkey, sizeof nc_name_setkey);
    nc_dexor(sig_setkey, sizeof sig_setkey,
             nc_sig_setkey, sizeof nc_sig_setkey);

    JNINativeMethod methods[2];
    methods[0].name = name_dec;
    methods[0].signature = sig_dec;
    methods[0].fnPtr = (void *)nc_strdec_jni_decrypt;
    methods[1].name = name_setkey;
    methods[1].signature = sig_setkey;
    methods[1].fnPtr = (void *)nc_strdec_jni_set_key;

    int rc = (*env)->RegisterNatives(env, clazz, methods, 2);
    (*env)->DeleteLocalRef(env, clazz);
    if (rc != 0) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        return -1;
    }
    return 0;
}

/* ── JNI_OnLoad 归属：本文件【从不】提供 JNI_OnLoad ─────────────────
 *
 * 一个 so 只能有一个 JNI_OnLoad，而 libnc.so 里已有三方竞争者：
 *   ① Dex2C.cpp        （勾了 --dex2c 时提供）
 *   ② nc_link_jni.c    （勾了 --sigcheck 且无 dex2c 时提供）
 *   ③ 本模块           （--stringenc-native）
 *
 * 若每方各自提供，任意组合都会 `ld.lld: error: duplicate symbol: JNI_OnLoad`
 * （2026-11-05 CI run 42030806689 实证）。
 *
 * 故本模块只导出 nc_strdec_register_natives()，由【已有的那个】JNI_OnLoad
 * 调用 —— 与 nc_link_jni.c 的既有做法完全一致（见其头部注释）。
 * 顺序见 protect.sh 的注入段：无论哪一方持有 OnLoad，都会调到这里。
 */
/* ── 统一引导入口（供各持有 JNI_OnLoad 的一方调用）──────────────────
 *
 * 做两件事：记录 JavaVM + 注册 ncDec/ncSetKey 到本次随机生成的桩类。
 * 桩类名来自构建期生成的 nc_strdec_cfg.h（protect.sh 写，不进 git）。
 *
 * 为什么桩类名必须构建期注入：桩名每包随机（防固定签名），
 * 而 RegisterNatives 需要真实类名 —— 写死会让随机化失效。
 *
 * 返回 0 = 成功。失败时调用方不一定要返回 JNI_ERR：
 * 桩注册不上会导致解密走 fail-closed（返回密文），不会崩，
 * 但会表现为"所有字符串都是密文" —— 比闪退更难查，故建议 fail-fast。
 */
int nc_strdec_bootstrap(JavaVM *vm, JNIEnv *env)
{
    int rc = nc_strdec_jni_attach(vm);
    if (rc != 0) {
        return rc;
    }
#if defined(NC_STRDEC_HAVE_CFG)
    /* cfg 头存在 = 本次确实要用 native 桩 */
    return nc_strdec_register_natives(env, NC_STRDEC_STUB_CLASS);
#else
    (void)env;
    return 0;
#endif
}

int nc_strdec_jni_attach(JavaVM *vm)
{
    if (vm == NULL) {
        return -1;
    }
    nc_vm = vm;                          /* 供将来的线程附着用 */
    return 0;
}
