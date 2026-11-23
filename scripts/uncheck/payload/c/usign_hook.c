// usign_hook.c —— 通用 APK 路径重定向（native 层签名校验绕过）
//
// 目标：让 native 代码读 base.apk 时，实际读到 origin.apk（原签名 APK 副本）。
//
// ==== 为什么要这一层 ====
// Java 层 hook（PackageInfo.CREATOR / PMS 代理 / signingInfo）只能覆盖
// "通过 PackageManager 问签名"的路径。目标 App 若自己读 APK 文件：
//   · Java:   new ZipFile(getPackageResourcePath()) → META-INF/*.RSA
//   · native: open/fopen + fstat + mmap 解析 APK Signing Block（v2/v3）
// 就完全不受影响。
//
// ==== hook 哪些函数：由目标 so 的导入表决定 ====
// 实测两个目标 so（`readelf -r` 看 R_AARCH64_JUMP_SLOT）：
//   libSecureFuck.so: fopen@LIBC, __open_2@LIBC, stat, fstat, mmap, access, opendir, popen
//   libliteso.so    : open@LIBC, __open_2@LIBC, fopen@LIBC, access, stat, fstat, mmap, opendir
//
// 关键结论：
//   · 两个都**没有 openat** —— 所以只 hook open/openat 的初版完全无效
//   · fopen / __open_2 都是 PLT 跳转槽（JUMP_SLOT）→ **PLT hook 就能拦住**，
//     不需要 inline hook
//     （我曾以为 fopen 内部直调 open 所以必须 inline hook，实测证伪：
//       对 libc 而言 fopen 是导出函数，目标 so 调用它走自己的 PLT）
//
// ==== 为什么只 hook 路径类函数，不 hook fd 类 ====
// open 返回的 fd 一旦指向 origin.apk，后续 fstat/mmap/read/fstat 全部自然正确。
// 反而**不能** hook fstat/mmap：它们拿 fd 作参数，目标进程里所有文件操作都会
// 经过，hook 进去无法判断 fd 属于哪个文件（要维护 fd→path 映射，成本高且易错）。
//
// 编译：见 payload/c/build-native.sh

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <android/log.h>
#include <pthread.h>

#include "shadowhook.h"

#define TAG "USign"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─────────────────────────── 状态 ───────────────────────────

static char s_apk_path[PATH_MAX];
static char s_rep_path[PATH_MAX];
static size_t s_apk_len = 0;
static volatile int s_installed = 0;

static inline int is_target_apk(const char *path) {
    if (path == NULL || s_apk_len == 0) return 0;
    return strcmp(path, s_apk_path) == 0;
}

// ─────────────────────── 原始函数指针 ───────────────────────

typedef int   (*open_t)(const char *, int, ...);
typedef FILE *(*fopen_t)(const char *, const char *);
typedef int   (*access_t)(const char *, int);
typedef int   (*stat_t)(const char *, struct stat *);
typedef int   (*faccessat_t)(int, const char *, int, int);
typedef ssize_t (*readlink_t)(const char *, char *, size_t);
typedef DIR  *(*opendir_t)(const char *);

static open_t      orig_open      = NULL;
static open_t      orig_open64    = NULL;
static open_t      orig___open_2  = NULL;
static fopen_t     orig_fopen     = NULL;
static fopen_t     orig_fopen64   = NULL;
static access_t    orig_access    = NULL;
static faccessat_t orig_faccessat = NULL;
static stat_t      orig_stat      = NULL;
static stat_t      orig_lstat     = NULL;
static stat_t      orig___stat    = NULL;
static readlink_t  orig_readlink  = NULL;
static opendir_t   orig_opendir   = NULL;

// ─────────────────────────── 代理实现 ───────────────────────────

static int proxy_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t) va_arg(ap, int); va_end(ap);
    }
    if (is_target_apk(path)) return orig_open(s_rep_path, flags, mode);
    return orig_open(path, flags, mode);
}

static int proxy_open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t) va_arg(ap, int); va_end(ap);
    }
    if (is_target_apk(path)) return orig_open64(s_rep_path, flags, mode);
    return orig_open64(path, flags, mode);
}

// __open_2 是 fortify 版（无 mode 参数）—— 两个目标 so 都导入它
static int proxy___open_2(const char *path, int flags) {
    if (is_target_apk(path)) return orig___open_2(s_rep_path, flags);
    return orig___open_2(path, flags);
}

static FILE *proxy_fopen(const char *path, const char *mode) {
    if (is_target_apk(path)) return orig_fopen(s_rep_path, mode);
    return orig_fopen(path, mode);
}

static FILE *proxy_fopen64(const char *path, const char *mode) {
    if (is_target_apk(path)) return orig_fopen64(s_rep_path, mode);
    return orig_fopen64(path, mode);
}

static int proxy_access(const char *path, int mode) {
    if (is_target_apk(path)) return orig_access(s_rep_path, mode);
    return orig_access(path, mode);
}

static int proxy_faccessat(int dirfd, const char *path, int mode, int flags) {
    // 只有绝对路径才可能是目标 APK；相对路径（相对 dirfd）保持原样
    if (path != NULL && path[0] == '/' && is_target_apk(path)) {
        return orig_faccessat(dirfd, s_rep_path, mode, flags);
    }
    return orig_faccessat(dirfd, path, mode, flags);
}

static int proxy_stat(const char *path, struct stat *buf) {
    if (is_target_apk(path)) return orig_stat(s_rep_path, buf);
    return orig_stat(path, buf);
}

static int proxy_lstat(const char *path, struct stat *buf) {
    if (is_target_apk(path)) return orig_lstat(s_rep_path, buf);
    return orig_lstat(path, buf);
}

// ── readlink：fd 路径伪装 ──
// libsupport.so 导入 readlink。目标 so 可以 readlink("/proc/self/fd/N")
// 解析出 fd 的真实文件路径做一致性校验：open(base.apk) 被我们重定向后，
// fd 实际指向 code_cache/sigfix-origin.apk —— readlink 一查就露馅
// （路径对不上 base.apk）。代理：结果路径等于 rep_path 时改报 apk_path。
static ssize_t proxy_readlink(const char *path, char *buf, size_t bufsiz) {
    ssize_t r = orig_readlink(path, buf, bufsiz);
    if (r > 0 && (size_t) r == strlen(s_rep_path)
            && strncmp(buf, s_rep_path, (size_t) r) == 0) {
        // fd 确实指向 origin.apk —— 谎报为安装包路径
        ssize_t n = (ssize_t) strlen(s_apk_path);
        if ((size_t) n <= bufsiz) {
            memcpy(buf, s_apk_path, (size_t) n);
            return n;
        }
    }
    return r;
}

// ── opendir：目录打开重定向 ──
// libzhuque/libsupport/libSecureFuck 都导入 opendir/readdir。主要风险点：
// ① 目标 so opendir(base.apk 所在目录) 后 readdir 枚举——目录本身没有
//    可疑条目（我们没在安装目录写东西），透传安全；
// ② 但 code_cache 下有 sigfix-origin.apk / sigfix-payload.dex —— 若目标
//    扫 code_cache 会发现注入痕迹。当前无证据表明它扫 code_cache，
//    先透传并留好扩展点（若后续实测暴露，在此挂拦截）。
static DIR *proxy_opendir(const char *path) {
    return orig_opendir(path);
}

// ─────────────────────── hook 安装 ───────────────────────

// xhook_register 的 pattern 传 ".*" —— 匹配所有已加载和后续加载的 so。
// 回调里靠 is_target_apk 判断，不匹配的立即透传，开销可忽略。
static void hook_one(const char *name, void *proxy, void **orig) {
    void *stub = shadowhook_hook_sym_name("libc.so", name, proxy, orig);
    if (stub != NULL) {
        LOGI("hooked: %s", name);
    } else {
        int e = shadowhook_get_errno();
        LOGE("hook fail: %s (%d %s)", name, e, shadowhook_to_errmsg(e));
    }
}

static void patch_all(void) {
    // shadowhook 初始化。
    //
    // UNIQUE 模式：独占 hook（同一地址不允许被多方同时 hook）。
    // 对本项目足够，且比 SHARED 少一层代理开销。
    //
    // 注：third_party/shadowhook/shadowhook.c 已打补丁，
    //     linker mod 失败不再导致 init 整体失败。
    int r = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, 0);
    if (r != 0) {
        LOGE("shadowhook_init failed: %d (%s)", r, shadowhook_to_errmsg(r));
        return;
    }
    LOGI("shadowhook init ok (v%s)", shadowhook_get_version());

    hook_one("open",      (void *) proxy_open,      (void **) &orig_open);
    hook_one("open64",    (void *) proxy_open64,    (void **) &orig_open64);
    hook_one("__open_2",  (void *) proxy___open_2,  (void **) &orig___open_2);
    hook_one("fopen",     (void *) proxy_fopen,     (void **) &orig_fopen);
    hook_one("fopen64",   (void *) proxy_fopen64,   (void **) &orig_fopen64);
    hook_one("access",    (void *) proxy_access,    (void **) &orig_access);
    hook_one("faccessat", (void *) proxy_faccessat, (void **) &orig_faccessat);
    hook_one("stat",      (void *) proxy_stat,      (void **) &orig_stat);
    hook_one("lstat",     (void *) proxy_lstat,     (void **) &orig_lstat);
    // 2026-11-23 补全（对照 so 导入表）：
    //   libzhuque.so   : open/stat/lstat/mmap/read/opendir/readdir
    //   libsupport.so  : access/fopen/mmap/read/opendir/readdir/readlink
    //   libSecureFuck.so: __open_2/fopen/stat/mmap
    // readlink 是 fd 路径一致性校验的关键漏点；opendir 先透传占位。
    hook_one("readlink",  (void *) proxy_readlink,  (void **) &orig_readlink);
    hook_one("opendir",   (void *) proxy_opendir,   (void **) &orig_opendir);

    // 统计关键函数是否挂上：open / __open_2 / fopen 是目标 so 的主力，
    // 加上 access / stat 共 5 个。至少 3 个成功才算可用。
    int ok = 0;
    if (orig_open)     ok++;
    if (orig___open_2) ok++;
    if (orig_fopen)    ok++;
    if (orig_access)   ok++;
    if (orig_stat)     ok++;
    LOGI("hook 汇总: %d/5 关键函数挂上", ok);

    s_installed = (ok >= 3) ? 1 : 0;
}

// ─────────────────────── JNI 入口 ───────────────────────

JNIEXPORT jboolean JNICALL
Java_com_nc_uncheck_SigFix_nativeHookApkPath(JNIEnv *env, jclass clazz,
                                             jstring apkPath, jstring repPath) {
    if (s_installed) return JNI_TRUE;

    const char *a = (*env)->GetStringUTFChars(env, apkPath, NULL);
    const char *b = (*env)->GetStringUTFChars(env, repPath, NULL);
    if (!a || !b) {
        if (a) (*env)->ReleaseStringUTFChars(env, apkPath, a);
        if (b) (*env)->ReleaseStringUTFChars(env, repPath, b);
        return JNI_FALSE;
    }
    strncpy(s_apk_path, a, sizeof(s_apk_path) - 1);
    strncpy(s_rep_path, b, sizeof(s_rep_path) - 1);
    s_apk_len = strlen(s_apk_path);
    (*env)->ReleaseStringUTFChars(env, apkPath, a);
    (*env)->ReleaseStringUTFChars(env, repPath, b);

    LOGI("hookApkPath: apk=%s", s_apk_path);
    LOGI("hookApkPath: rep=%s", s_rep_path);

    patch_all();

    LOGI("native hook install %s", s_installed ? "OK" : "FAILED");
    return s_installed ? JNI_TRUE : JNI_FALSE;
}
