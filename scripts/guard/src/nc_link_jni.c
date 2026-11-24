/* nc_link_jni.c — NcLink 三个 JNI 入口的【动态注册】（2026-11-04）
 *
 * 改的是"谁来告诉 JVM 这些 native 方法在哪"这件事：
 *
 *   短名绑定（2026-10-19 至今）：
 *     nm -D libnc.so | grep NcLink
 *       Java_com_nc_link_NcLink_ncVerify      ← 等于告诉逆向者「从这里读」
 *       Java_com_nc_link_NcLink_heartbeat
 *       Java_com_nc_link_NcLink_selftest
 *     `-fvisibility=hidden` 收敛不掉它们：JNIEXPORT 自带
 *     visibility("default")，对该编译选项免疫（lib-ndk.sh 的注释已记录）。
 *
 *   动态注册（本文件）：
 *     方法名只作为字符串存在于本单元，RegisterNatives 在运行期按名字绑定，
 *     不进 .dynsym。产物 `nm -D` 只剩 JNI_OnLoad 与 libc 的 UND。
 *
 * ── 为什么 2026-10-19 那次失败，这次不会 ──────────────────────────────
 * 那次崩在【constructor(200) 里调 FindClass】。constructor 由动态链接器
 * 在 dlopen 内部执行，此时 classloader 上下文尚未建立，FindClass 必失败。
 *
 * 本次走 JNI_OnLoad：由 ART 的 nativeloader 主动回调，ART 会临时把
 * classloader 切到发起 load 的那一个 —— FindClass 在该位置是 JNI 规范
 * 明确支持的用法。dex2c 的 DynamicRegister.cpp 已用同一条路径真机验证
 * （EARLY FindClass OK / RegisterNatives -> 0，见 protect.sh:378 的注释）。
 * ⚠️ 不要把 constructor 的失败经验平移到 JNI_OnLoad 上，位置不同。
 *
 * ── 与 Dex2C.cpp 的 JNI_OnLoad 冲突 ──────────────────────────────────
 * Dex2C.cpp:270 也定义 JNI_OnLoad（勾 dex2c 时参与编译）。同一个 so 里
 * 两个 JNI_OnLoad = 重复符号 → 链接失败。故用编译期宏二选一：
 *
 *   NC_LINK_JNI_OWN_ONLOAD 已定义（未勾 dex2c）→ 本单元提供 JNI_OnLoad
 *   NC_LINK_JNI_OWN_ONLOAD 未定义（勾了 dex2c）→ 由 Dex2C.cpp 调用
 *                                                 nc_link_register_natives()
 * 由 protect.sh 在拷贝源码时决定，无运行期分支。
 *
 * ⚠️ 默认值是【开启】：没有 dex2c 的组合是常态（sigcheck 单独 / +envcheck /
 *    +packer），而 dex2c 组合会在 protect.sh 里把本文件尾部那段 JNI_OnLoad
 *    注释掉。反过来做（默认关闭、靠 -D 打开）需要给 Android.mk 加
 *    APP_CFLAGS 注入通道，多一处可失效的环节 —— 不如源码默认开。
 */
#include <jni.h>
#include <stddef.h>

#include "nc_jni_selfcheck.h"   /* nc_jni_selfcheck()：注册前的表项校验 */
#include "nc_link_jni.h"

#if !defined(NC_LINK_JNI_NO_ONLOAD)
#  define NC_LINK_JNI_OWN_ONLOAD 1
#endif
#if defined(NCLINK_HOST_TEST)
/* 宿主测试不编 JNI 部分（与 nc_link.c 同约定：宿主没有 JVM） */
#else

/* ── 方法名/签名表 ──────────────────────────────────────────────────
 * 名字与签名用 XOR 0x5A 存储。理由：RegisterNatives 的 name 参数是 C
 * 字符串，字面量会落进 .rodata，`strings` 一样能搜到 "ncVerify"。
 *
 * ⚠️ 这是【混淆】不是【加密】，如实标注别高估：读下面那十几行还原循环
 *    就能解出来。真实收益只有一条 —— `strings` 直接扫不到方法名，
 *    抬高"一眼看穿"的成本。
 *
 * 每项 = 明文字节 ^ 0x5A（含结尾 NUL 一起 XOR）。
 * 改方法名必须【同步三处】：NcLink.java（语义真相源）/
 * inject-javacheck.py 生成的 smali / 本表。漏一处的症状是运行期
 * NoSuchMethodError，而 RegisterNatives 的返回值会把它变成明确的 JNI_ERR。
 */
static const unsigned char kName_ncVerify[] = {
    0x34, 0x39, 0x0C, 0x3F, 0x28, 0x33, 0x3C, 0x23, 0x5A   /* "ncVerify" */
};
static const unsigned char kSig_ncVerify[] = {
    0x72, 0x01, 0x18, 0x73, 0x00, 0x5A                      /* "([B)Z" */
};
static const unsigned char kName_heartbeat[] = {
    0x32, 0x3F, 0x3B, 0x28, 0x2E, 0x38, 0x3F, 0x3B, 0x2E, 0x5A  /* "heartbeat" */
};
static const unsigned char kSig_void[] = {
    0x72, 0x73, 0x0C, 0x5A                                 /* "()V" */
};
static const unsigned char kName_selftest[] = {
    0x29, 0x3F, 0x36, 0x3C, 0x2E, 0x3F, 0x29, 0x2E, 0x5A   /* "selftest" */
};
static const unsigned char kSig_int[] = {
    0x72, 0x73, 0x13, 0x5A                                 /* "()I" */
};
/* lastJudge() —— 风控上报（2026-11-25）
 *
 * 为什么要它：ncVerify 返回 jboolean，只有过/不过两态。C 层算出的
 * 「PackageManager 被污染但主人在场」这个区分在 JNI 边界被折成 true 丢掉，
 * 排障时看不到。本方法把最近一次裁决的结果码原样交给 Java 侧打日志。
 *
 * ⚠️ 只读最近一次结果，不重新裁决、不影响任何判定 —— 纯观测探针。
 * ⚠️ 与 selftest 一样可选：Java 侧没声明它就不会被调到；
 *    这里注册失败也不影响 ncVerify / heartbeat（表驱动，槽位 = i）。 */
static const unsigned char kName_lastJudge[] = {
    0x36, 0x3B, 0x29, 0x2E, 0x10, 0x2F, 0x3E, 0x3D, 0x3F,
    0x5A                                                   /* "lastJudge" */
};

#define NC_STR_MAX 16           /* 最长 "heartbeat"=9+1，留足 */

/* XOR 还原到调用方栈缓冲。返回 0 = 成功。
 * 不返回堆内存，避免"忘记 free → 方法名常驻堆"这类泄漏。 */
static int nc_restore(char *out, size_t cap,
                      const unsigned char *enc, size_t enclen) {
    if (enclen == 0 || enclen > cap) return -1;
    for (size_t i = 0; i < enclen; i++) {
        out[i] = (char)(enc[i] ^ 0x5A);
    }
    return 0;
}

/* 实现在 nc_link.c（非 static，靠 -fvisibility=hidden 收敛符号面）。
 * 这三个 wrapper 保留 JNI 短名的【函数体】，只是不再由符号表暴露。 */
extern jboolean nc_link_jni_ncVerify(JNIEnv *, jclass, jbyteArray);
extern void nc_link_jni_heartbeat(JNIEnv *, jclass);
extern jint nc_link_jni_lastJudge(JNIEnv *, jclass);
/* selftest 在 nc_guard_jni.c；该文件不参与编译时用弱符号兜底 */
extern jint nc_link_jni_selftest(JNIEnv *, jobject) __attribute__((weak));

/* ── 注册表：条目数与槽位数从同一个宏派生，结构上不可能错位 ────────────
 *
 * 2026-11-22 之前这里是三段手抄代码，配 `names[2][NC_STR_MAX]` 两个槽，
 * 却要注册三个方法（ncVerify / heartbeat / selftest）。selftest 的还原
 * 写的是 names[0] —— 把 ncVerify 的名字【原地覆盖】成 "selftest"：
 *
 *     tab[0] = { name: "selftest", sig: "()I", fnPtr: nc_link_jni_ncVerify }
 *     tab[2] = { name: "selftest", sig: "()I", fnPtr: nc_link_jni_selftest }
 *
 * ART 拿到的表里没有 "ncVerify" → 方法没绑上 → 调用即
 *     No implementation found for ...NcLink.ncVerify(byte[])
 * → Guard 的 catch(UnsatisfiedLinkError) → kill() → 真机闪退。
 * 而 RegisterNatives 的返回值【没有反映这个错误】，整条链静默。
 *
 * 那次的修法是把 2 槽改成 3 槽 —— 修了"这一次"，没修"这一类"：
 * 加第四个方法时同样的错会原样再来。现在改成表驱动：
 *
 *   · 条目数 = NC_BIND_MAX = sizeof kBinds / sizeof kBinds[0]
 *   · names/sigs 的维度、tab 的维度、循环上界全部用它
 *   · 循环变量 i 同时索引 kBinds[i] / names[i] / sigs[i]
 *
 * 于是"槽位与条目错位"这种错误在结构上无法表达。加方法只需在表里加一行。
 * 弱符号（selftest）也无需特殊分支 —— fn == NULL 就在循环里跳过，
 * 且被跳过的方法不会挤占别人的槽位（槽位永远等于 i）。
 */
typedef struct {
    const unsigned char *name;  size_t nlen;   /* XOR 密文（含结尾 NUL） */
    const unsigned char *sig;   size_t slen;
    void *fn;                                  /* NULL = 该实现未编入 */
} nc_bind_t;

static const nc_bind_t kBinds[] = {
    { kName_ncVerify,  sizeof kName_ncVerify,  kSig_ncVerify, sizeof kSig_ncVerify,
      (void *)nc_link_jni_ncVerify  },
    { kName_heartbeat, sizeof kName_heartbeat, kSig_void,     sizeof kSig_void,
      (void *)nc_link_jni_heartbeat },
    { kName_selftest,  sizeof kName_selftest,  kSig_int,      sizeof kSig_int,
      (void *)nc_link_jni_selftest  },          /* weak：未编入时为 NULL */
    /* 风控上报（2026-11-25）：只读最近一次裁决结果。
     * 加这一行即可 —— 表驱动保证槽位 = i，不存在 2026-11-22 那种错位。 */
    { kName_lastJudge, sizeof kName_lastJudge, kSig_int,      sizeof kSig_int,
      (void *)nc_link_jni_lastJudge },
};

#define NC_BIND_MAX ((int)(sizeof kBinds / sizeof kBinds[0]))

int nc_link_register_natives(JNIEnv *env) {
    /* ⚠️⚠️ 必须是 static，不能是栈上的局部数组（2026-11-22 真机实证）：
     *
     * JNINativeMethod 的 name / signature 是 const char*，ART 的
     * RegisterNatives 在 Linux/ART 上【不保证立即复制这两个字符串】——
     * 它把 JNINativeMethod 数组登记进方法结构，之后按需读取。
     *
     * 原来这里写的是栈数组，且在 RegisterNatives 返回后立刻 nc_wipe 清零
     * → ART 读到空串 → 按名字找不到方法。为什么以前"能跑"：未定义行为，
     * 栈在被清空后、被后续调用复用前原字节还残留着。一旦调用链长度变化
     * （本次是 javalink 注入的 Java 代码改动），栈布局变了，问题立刻显现。
     *
     * 改 static 之后：缓冲区常驻 .bss，进程生命周期内有效。
     * 代价：方法名/签名以明文常驻内存 —— 但它们本来就以明文存在于
     * .rodata 的 XOR 密文里、且 RegisterNatives 语义要求 ART 能读到，
     * 加密的目的（strings 扫不到）不受影响。
     */
    static char names[NC_BIND_MAX][NC_STR_MAX];
    static char sigs [NC_BIND_MAX][NC_STR_MAX];

    JNINativeMethod tab[NC_BIND_MAX];
    size_t i;
    int n = 0;
    int rc;
    jclass cls;

    if (env == NULL) return -1;

    /* ① 先备表 —— 不碰 JVM，失败早退不会在类上留下半截状态。
     *    注意槽位用 i 而非 n：某个方法被跳过（弱符号缺失）时，
     *    后面的方法仍用自己固定的槽位，不会挤到别人的位置上。 */
    for (i = 0; i < (size_t)NC_BIND_MAX; i++) {
        if (kBinds[i].fn == NULL) continue;
        if (nc_restore(names[i], NC_STR_MAX, kBinds[i].name, kBinds[i].nlen) != 0) {
            return -2;
        }
        if (nc_restore(sigs[i], NC_STR_MAX, kBinds[i].sig, kBinds[i].slen) != 0) {
            return -2;
        }
        tab[n].name      = names[i];
        tab[n].signature = sigs[i];
        tab[n].fnPtr     = kBinds[i].fn;
        n++;
    }

    /* ② 注册前自检（见 nc_jni_selfcheck.c 的注释：不能只信 RegisterNatives
     *    返回值 —— 2026-11-22 实测 rc=0 但方法从未绑上） */
    if (nc_jni_selfcheck(tab, n) != 0) return -4;

    /* ③ FindClass + 注册 */
    cls = (*env)->FindClass(env, "com/nc/link/NcLink");
    if (cls == NULL) {
        /* 清 pending exception：它会传染给调用方，变成难定位的崩溃 */
        (*env)->ExceptionClear(env);
        return -1;
    }

    rc = (*env)->RegisterNatives(env, cls, tab, n);
    if (rc != 0) {
        /* 注册失败保留异常信息给 logcat，但清掉以免传染 */
        (*env)->ExceptionClear(env);
    }

    /* ⚠️ 这里【不能】清 names/sigs —— 见函数上方 static 的说明：
     * ART 可能在 RegisterNatives 返回之后才读取这两个字符串。 */
    (*env)->DeleteLocalRef(env, cls);
    return rc == 0 ? 0 : -3;
}

#if defined(NC_LINK_JNI_OWN_ONLOAD)
/* ── 未勾 dex2c：本单元提供唯一的 JNI_OnLoad ──────────────────────────
 *
 * 不勾 dex2c 时工程里没有任何 JNI_OnLoad（lib-ndk.sh:189 会扫描源码，
 * 没有定义就不往 version script 里声明），所以必须自己提供一个。
 *
 * 返回 JNI_ERR 的语义是刻意的 fail-closed：注册不上时 Java 侧本来就没有
 * 可用实现，与其带着半残的 native 表继续跑，不如在加载点就炸。
 * Guard.c 的 catch(UnsatisfiedLinkError) → kill()，"so 不可用"与
 * "so 缺失"走同一条处置路径。
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    (void)reserved;
    if (vm == NULL || (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    if (nc_link_register_natives(env) != 0) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
#endif /* NC_LINK_JNI_OWN_ONLOAD */

#endif /* NCLINK_HOST_TEST */
