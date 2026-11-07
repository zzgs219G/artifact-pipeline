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

/* 清零。不用 memset：-Oz 下可能被当死存储删掉（sig_check.c 的 ncg_wipe
 * 注释记过这条实测）。 */
static void nc_wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

/* 实现在 nc_link.c（非 static，靠 -fvisibility=hidden 收敛符号面）。
 * 这三个 wrapper 保留 JNI 短名的【函数体】，只是不再由符号表暴露。 */
extern jboolean nc_link_jni_ncVerify(JNIEnv *, jclass, jbyteArray);
extern void nc_link_jni_heartbeat(JNIEnv *, jclass);
/* selftest 在 nc_guard_jni.c；该文件不参与编译时用弱符号兜底 */
extern jint nc_link_jni_selftest(JNIEnv *, jobject) __attribute__((weak));

int nc_link_register_natives(JNIEnv *env) {
    if (env == NULL) return -1;

    jclass cls = (*env)->FindClass(env, "com/nc/link/NcLink");
    if (cls == NULL) {
        /* 清 pending exception：它会传染给调用方，变成难定位的崩溃 */
        (*env)->ExceptionClear(env);
        return -1;
    }

    char names[2][NC_STR_MAX];
    char sigs[2][NC_STR_MAX];
    JNINativeMethod tab[3];
    int n = 0;
    int rc;

    /* ① ncVerify([B)Z */
    if (nc_restore(names[0], NC_STR_MAX, kName_ncVerify,
                   sizeof(kName_ncVerify)) != 0
        || nc_restore(sigs[0], NC_STR_MAX, kSig_ncVerify,
                      sizeof(kSig_ncVerify)) != 0) {
        (*env)->DeleteLocalRef(env, cls);
        return -2;
    }
    tab[n].name      = names[0];
    tab[n].signature = sigs[0];
    tab[n].fnPtr     = (void *)nc_link_jni_ncVerify;
    n++;

    /* ② heartbeat()V */
    if (nc_restore(names[1], NC_STR_MAX, kName_heartbeat,
                   sizeof(kName_heartbeat)) != 0
        || nc_restore(sigs[1], NC_STR_MAX, kSig_void,
                      sizeof(kSig_void)) != 0) {
        (*env)->DeleteLocalRef(env, cls);
        return -2;
    }
    tab[n].name      = names[1];
    tab[n].signature = sigs[1];
    tab[n].fnPtr     = (void *)nc_link_jni_heartbeat;
    n++;

    /* ③ selftest()I —— 仅当 nc_guard_jni.c 参与编译时注册。
     * 不编译时 Java 侧调用会抛 UnsatisfiedLinkError，但
     * inject-javacheck.py 已把 selftest 包在独立 try/catch 里
     * （报错四十九的教训：自检失败不许影响主流程）。 */
    if (nc_link_jni_selftest != NULL) {
        if (nc_restore(names[0], NC_STR_MAX, kName_selftest,
                       sizeof(kName_selftest)) == 0
            && nc_restore(sigs[0], NC_STR_MAX, kSig_int,
                          sizeof(kSig_int)) == 0) {
            tab[n].name      = names[0];
            tab[n].signature = sigs[0];
            tab[n].fnPtr     = (void *)nc_link_jni_selftest;
            n++;
        }
    }

    rc = (*env)->RegisterNatives(env, cls, tab, n);
    if (rc != 0) {
        /* 注册失败保留异常信息给 logcat，但清掉以免传染 */
        (*env)->ExceptionClear(env);
    }

    /* 栈上的方法名立即清掉 —— 注册完就没价值了 */
    nc_wipe(names, sizeof(names));
    nc_wipe(sigs, sizeof(sigs));
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
