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
// 不同目标 so 导入的路径类函数各不相同（`readelf -r` 看 R_AARCH64_JUMP_SLOT）：
//   有的只用 fopen/__open_2，有的用 open，有的还带 access/stat/opendir。
// 所以这里覆盖「路径类 libc 函数」全集，逐个核对导入表时按需取舍。
//
// 关键结论：
//   · 部分目标 so **没有 openat** —— 只 hook open/openat 会漏
//   · fopen / __open_2 都是 PLT 跳转槽（JUMP_SLOT）→ PLT hook 就能拦住
//
// ==== 为什么只 hook 路径类函数，不 hook fd 类 ====
// open 返回的 fd 一旦指向 origin.apk，后续 fstat/mmap/read/fstat 全部自然正确。
// 反而**不能** hook fstat/mmap：它们拿 fd 作参数，目标进程里所有文件操作都会
// 经过，hook 进去无法判断 fd 属于哪个文件（要维护 fd→path 映射，成本高且易错）。
//
// 编译：见 payload/c/build-native.sh

#include <jni.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
/* struct statx（Android 11+ 的 statx 代理用）。定义在 linux/stat.h，
 * 而 sys/stat.h 只声明函数原型。 */
#include <linux/stat.h>
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

/* hook 分层（2026-11-27）。数值越大注册的接口越多，每层是上一层的超集。
 * 定义放在这里而不是枚举，是为了让 JNI 侧直接传 int，不做字符串解析。 */
#define NC_HOOK_LEVEL_CORE  1   /* open/fopen/access/stat —— 商业 App 主路径 */
#define NC_HOOK_LEVEL_FULL  2   /* + at 家族 + readlink/readlinkat */
/* 3 = 下面三个逐个叠加的起点（等价旧"全量"）。4/5/6 是定位用的细分档，
 * 每档只多一个接口 —— 见 patch_all 里第 3~5 层的说明。 */
#define NC_HOOK_LEVEL_STEP  3   /* 档 3：与档 2 相同（兼容旧值） */
#define NC_HOOK_LEVEL_OPENAT2 4 /* + openat2 */
#define NC_HOOK_LEVEL_STATX   5 /* + statx */
#define NC_HOOK_LEVEL_ALL   6   /* + opendir（默认，覆盖最广） */
static int s_hook_level = NC_HOOK_LEVEL_ALL;

static inline int is_target_apk(const char *path) {
    if (path == NULL || s_apk_len == 0) return 0;
    return strcmp(path, s_apk_path) == 0;
}

// ─────────────────────── 原始函数指针 ───────────────────────

typedef int   (*open_t)(const char *, int, ...);
typedef int   (*openat_t)(int, const char *, int, ...);
typedef int   (*openat2_t)(int, const char *, void *, size_t);
typedef FILE *(*fopen_t)(const char *, const char *);
typedef int   (*access_t)(const char *, int);
typedef int   (*stat_t)(const char *, struct stat *);
typedef int   (*faccessat_t)(int, const char *, int, int);
typedef ssize_t (*readlink_t)(const char *, char *, size_t);
typedef ssize_t (*readlinkat_t)(int, const char *, char *, size_t);
typedef DIR  *(*opendir_t)(const char *);
typedef int   (*statx_t)(int, const char *, int, unsigned int, struct statx *);

static open_t      orig_open      = NULL;
static open_t      orig_open64    = NULL;
static open_t      orig___open_2  = NULL;
static openat_t    orig_openat    = NULL;
static openat_t    orig_openat64  = NULL;
static openat_t    orig___openat_2= NULL;
static openat2_t   orig_openat2   = NULL;
static fopen_t     orig_fopen     = NULL;
static fopen_t     orig_fopen64   = NULL;
static access_t    orig_access    = NULL;
static faccessat_t orig_faccessat = NULL;
static stat_t      orig_stat      = NULL;
static stat_t      orig_lstat     = NULL;
static stat_t      orig___stat    = NULL;
static readlink_t  orig_readlink  = NULL;
static readlinkat_t orig_readlinkat = NULL;
static opendir_t   orig_opendir   = NULL;
static statx_t     orig_statx     = NULL;

// ─────────────────────────── 代理实现 ───────────────────────────

static int proxy_open(const char *path, int flags, ...) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_open == NULL) { errno = ENOSYS; return -1; }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t) va_arg(ap, int); va_end(ap);
    }
    if (is_target_apk(path)) return orig_open(s_rep_path, flags, mode);
    return orig_open(path, flags, mode);
}

static int proxy_open64(const char *path, int flags, ...) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_open64 == NULL) { errno = ENOSYS; return -1; }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t) va_arg(ap, int); va_end(ap);
    }
    if (is_target_apk(path)) return orig_open64(s_rep_path, flags, mode);
    return orig_open64(path, flags, mode);
}

// __open_2 是 fortify 版（无 mode 参数）—— 两个目标 so 都导入它
static int proxy___open_2(const char *path, int flags) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig___open_2 == NULL) { errno = ENOSYS; return -1; }

    if (is_target_apk(path)) return orig___open_2(s_rep_path, flags);
    return orig___open_2(path, flags);
}

/* ── openat 家族（2026-11-24 补）──
 *
 * ⚠️ 这是本模块最容易被漏掉的一族，理由很实在：
 *    在 C 里写 `openat(AT_FDCWD, path, O_RDONLY)`，_FORTIFY_SOURCE 会把它
 *    编成 **`__openat_2`**，不是 `openat`。只挂 `openat` 完全拦不住
 *    （实测：加固侧的 sig_check.c 就编成了 __openat_2，见其导入表）。
 *    三个符号都得挂。
 *
 * 只在 dirfd == AT_FDCWD（相对当前目录）时判断路径：
 *    其它 dirfd 下 path 是相对该目录的，与绝对路径 base.apk 不可能相等，
 *    直接透传（也避免误伤）。 */
static int proxy_openat(int dirfd, const char *path, int flags, ...) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_openat == NULL) { errno = ENOSYS; return -1; }

    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t) va_arg(ap, int); va_end(ap); }
    if (dirfd == AT_FDCWD && is_target_apk(path))
        return orig_openat(dirfd, s_rep_path, flags, mode);
    return orig_openat(dirfd, path, flags, mode);
}

static int proxy_openat64(int dirfd, const char *path, int flags, ...) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_openat64 == NULL) { errno = ENOSYS; return -1; }

    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t) va_arg(ap, int); va_end(ap); }
    if (dirfd == AT_FDCWD && is_target_apk(path))
        return orig_openat64(dirfd, s_rep_path, flags, mode);
    return orig_openat64(dirfd, path, flags, mode);
}

/* __openat_2 是 fortify 版：没有 mode 参数（调用方保证不带 O_CREAT） */
static int proxy___openat_2(int dirfd, const char *path, int flags) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig___openat_2 == NULL) { errno = ENOSYS; return -1; }

    if (dirfd == AT_FDCWD && is_target_apk(path))
        return orig___openat_2(dirfd, s_rep_path, flags);
    return orig___openat_2(dirfd, path, flags);
}

/* openat2 是 Linux 5.6+/Android 11+ 的新接口，第三个参数是 struct open_how*。
 * 不解析该结构，只改路径；how 原样透传。 */
static int proxy_openat2(int dirfd, const char *path, void *how, size_t size) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_openat2 == NULL) { errno = ENOSYS; return -1; }

    if (dirfd == AT_FDCWD && is_target_apk(path))
        return orig_openat2(dirfd, s_rep_path, how, size);
    return orig_openat2(dirfd, path, how, size);
}

static FILE *proxy_fopen(const char *path, const char *mode) {
    if (orig_fopen == NULL) { errno = ENOSYS; return NULL; }

    if (is_target_apk(path)) return orig_fopen(s_rep_path, mode);
    return orig_fopen(path, mode);
}

static FILE *proxy_fopen64(const char *path, const char *mode) {
    if (orig_fopen64 == NULL) { errno = ENOSYS; return NULL; }

    if (is_target_apk(path)) return orig_fopen64(s_rep_path, mode);
    return orig_fopen64(path, mode);
}

static int proxy_access(const char *path, int mode) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_access == NULL) { errno = ENOSYS; return -1; }

    if (is_target_apk(path)) return orig_access(s_rep_path, mode);
    return orig_access(path, mode);
}

static int proxy_faccessat(int dirfd, const char *path, int mode, int flags) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_faccessat == NULL) { errno = ENOSYS; return -1; }

    // 只有绝对路径才可能是目标 APK；相对路径（相对 dirfd）保持原样
    if (path != NULL && path[0] == '/' && is_target_apk(path)) {
        return orig_faccessat(dirfd, s_rep_path, mode, flags);
    }
    return orig_faccessat(dirfd, path, mode, flags);
}

static int proxy_stat(const char *path, struct stat *buf) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_stat == NULL) { errno = ENOSYS; return -1; }

    if (is_target_apk(path)) return orig_stat(s_rep_path, buf);
    return orig_stat(path, buf);
}

static int proxy_lstat(const char *path, struct stat *buf) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_lstat == NULL) { errno = ENOSYS; return -1; }

    if (is_target_apk(path)) return orig_lstat(s_rep_path, buf);
    return orig_lstat(path, buf);
}

// ── readlink：fd 路径伪装 ──
// 部分 so 导入 readlink。目标 so 可以 readlink("/proc/self/fd/N")
// 解析出 fd 的真实文件路径做一致性校验：open(base.apk) 被我们重定向后，
// fd 实际指向 code_cache/sigfix-origin.apk —— readlink 一查就露馅
// （路径对不上 base.apk）。代理：结果路径等于 rep_path 时改报 apk_path。
static ssize_t proxy_readlink(const char *path, char *buf, size_t bufsiz) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_readlink == NULL) { errno = ENOSYS; return -1; }

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

// ── readlinkat：fd 路径伪装（at 版本，2026-11-24 补）──
// 目标 so 可能用 readlinkat(AT_FDCWD, "/proc/self/fd/N", ...) 而不是 readlink。
// 加固侧的 sig_find_apk_fd 正是用 readlinkat 反查 fd 真实路径 ——
// 如果只挂 readlink，那一路就能识破重定向。
static ssize_t proxy_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_readlinkat == NULL) { errno = ENOSYS; return -1; }

    ssize_t r = orig_readlinkat(dirfd, path, buf, bufsiz);
    if (r > 0 && (size_t) r == strlen(s_rep_path)
            && strncmp(buf, s_rep_path, (size_t) r) == 0) {
        ssize_t n = (ssize_t) strlen(s_apk_path);
        if ((size_t) n <= bufsiz) {
            memcpy(buf, s_apk_path, (size_t) n);
            return n;
        }
    }
    return r;
}

// ── statx：新式 stat（2026-11-24 补）──
// Android 11+ 的 statx 是 stat 的现代替代；只挂 stat/lstat 会漏。
// 返回结构体很复杂，但路径重定向只需要换路径，结构由内核填。
static int proxy_statx(int dirfd, const char *path, int flags,
                       unsigned int mask, struct statx *buf) {
    /* orig 为 NULL = shadowhook 没给回原函数指针（该符号在目标系统
     * 不存在，或 hook 半成功）。退化为不重定向，而不是空指针崩溃。 */
    if (orig_statx == NULL) { errno = ENOSYS; return -1; }

    if (dirfd == AT_FDCWD && is_target_apk(path))
        return orig_statx(dirfd, s_rep_path, flags, mask, buf);
    return orig_statx(dirfd, path, flags, mask, buf);
}

// ── opendir：目录打开重定向 ──
// 多个目标 so 导入 opendir/readdir。主要风险点：
// ① 目标 so opendir(base.apk 所在目录) 后 readdir 枚举——目录本身没有
//    可疑条目（我们没在安装目录写东西），透传安全；
// ② 但 code_cache 下有 sigfix-origin.apk / sigfix-payload.dex —— 若目标
//    扫 code_cache 会发现注入痕迹。当前无证据表明它扫 code_cache，
//    先透传并留好扩展点（若后续实测暴露，在此挂拦截）。
static DIR *proxy_opendir(const char *path) {
    if (orig_opendir == NULL) { errno = ENOSYS; return NULL; }

    return orig_opendir(path);
}

// ─────────────────────── hook 安装 ───────────────────────

// xhook_register 的 pattern 传 ".*" —— 匹配所有已加载和后续加载的 so。
// 回调里靠 is_target_apk 判断，不匹配的立即透传，开销可忽略。
/* 有些"失败"是预期内的，降到 INFO 并用中性措辞，避免日志里出现红色 E
 * 让人以为出了问题（2026-11-27）：
 *
 *   · errno 16 SHADOWHOOK_ERRNO_DUP = 该符号与本体重名同址。
 *     真机 libc 实测：open@0x8f150 == open64@0x8f150、
 *     openat@0x8f410 == openat64@0x8f410、fopen@0xa3530 == fopen64@0xa3530。
 *     本体先注册已占用该地址，别名再注册必报 16 —— 功能完整。
 *
 *   · errno 18 SHADOWHOOK_ERRNO_ELF = 该符号在 libc 里不存在。
 *     典型是 openat2（内核有、bionic 无封装），见 patch_all 的说明。
 */
/* ⚠️ 这两个编号来自 shadowhook 的 sh_errno.c 消息表，不是 shadowhook.h 的
 * SHADOWHOOK_ERRNO_DUP(=36，那是 init/fini 回调的重复码) —— 两套编号不同，
 * 别混用。这里用 US_ 前缀避免与头文件宏撞名。 */
#define US_SH_ERRNO_DUP  16   /* "Duplicate shared hook" */
#define US_SH_ERRNO_ELF  18   /* "Find symbol in ELF failed" */

static void hook_one_opt(const char *name, void *proxy, void **orig,
                         const char *why) {
    void *stub = shadowhook_hook_sym_name("libc.so", name, proxy, orig);
    if (stub != NULL) {
        LOGI("hooked: %s", name);
        return;
    }
    int e = shadowhook_get_errno();
    if (e == US_SH_ERRNO_DUP || e == US_SH_ERRNO_ELF
            || why != NULL) {
        /* why != NULL 表示调用方已声明"这个挂了也不算失败" */
        LOGI("skip: %s (%d %s%s%s)", name, e, shadowhook_to_errmsg(e),
             why ? " - " : "", why ? why : "");
        return;
    }
    LOGE("hook fail: %s (%d %s)", name, e, shadowhook_to_errmsg(e));
}

static void hook_one(const char *name, void *proxy, void **orig) {
    hook_one_opt(name, proxy, orig, NULL);
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

    // ══ 分层注册（2026-11-27）═══════════════════════════════════════
    //
    // 为什么分层而不是全挂：18 个 hook 全部生效时，会波及**与签名校验无关**
    // 的进程内所有代码。实测（JMComic / Capacitor WebView）：
    //   Java + native 两层 → 图片与网络加载失败
    //   仅 Java 层         → 一切正常
    // 但没定位到具体是哪几个 hook 引起的。所以做成能力分层：
    // 代码全留，只是按 profile 决定注册哪些，便于按 App 类型权衡。
    //
    // profile 由 JNI 入口传入（Java 侧从 sigfix.json 的 "hookProfile" 读），
    // 取值：
    //   U. 全量（默认，覆盖最广，副作用最大）
    //   C  核心（open/fopen/access/stat 家族）—— 商业 App 的主要路径
    //   A  核心 + at 家族 + readlink —— 加防 fd 反查
    //
    // ⚠️ 每一层都是【上一层的超集】，不会出现"开了 C 反而少了某个"的情况。
    // ⚠️ 各函数实现一字未改 —— 只是注册与否。将来要改行为，改 proxy_xxx。
    const int lv = s_hook_level;

    // ── 第 1 层：核心（任何 native 校验都必须先打开 base.apk）──
    hook_one("open",      (void *) proxy_open,      (void **) &orig_open);
    hook_one_opt("open64",    (void *) proxy_open64,    (void **) &orig_open64,
                 "open 的别名，同址已挂");
    hook_one("__open_2",  (void *) proxy___open_2,  (void **) &orig___open_2);
    hook_one("fopen",     (void *) proxy_fopen,     (void **) &orig_fopen);
    hook_one_opt("fopen64",   (void *) proxy_fopen64,   (void **) &orig_fopen64,
                 "fopen 的别名，同址已挂");
    hook_one("access",    (void *) proxy_access,    (void **) &orig_access);
    hook_one("stat",      (void *) proxy_stat,      (void **) &orig_stat);

    if (lv < NC_HOOK_LEVEL_FULL) {
        // 第 2 层以下是"边缘路径"。选 C 档时到此为止 —— WebView /
        // Capacitor / Flutter 这类自带 IO 栈的 App 用这一档。
        LOGI("hook level = core（%d 个），跳过边缘路径", lv);
    } else {
        // ── 第 2 层：at 家族 + fd 反查（防 sig_find_apk_fd 那类取证）──
        hook_one("faccessat",  (void *) proxy_faccessat,  (void **) &orig_faccessat);
        hook_one("lstat",      (void *) proxy_lstat,      (void **) &orig_lstat);
        hook_one("openat",     (void *) proxy_openat,     (void **) &orig_openat);
        hook_one_opt("openat64",   (void *) proxy_openat64,   (void **) &orig_openat64,
                     "openat 的别名，同址已挂");
        hook_one("__openat_2", (void *) proxy___openat_2, (void **) &orig___openat_2);
        // readlink / readlinkat：目标 so 可能 readlink("/proc/self/fd/N")
        // 反查 fd 真实路径。加固侧 sig_check.c 正是用 readlinkat 这么做的。
        // 代价：只要目标 App 自己也有代码 readlink 到 origin.apk 的 fd，
        // 拿到的是伪造路径（实测未见此情况，但保留开关以便排除）。
        hook_one("readlink",   (void *) proxy_readlink,   (void **) &orig_readlink);
        hook_one("readlinkat", (void *) proxy_readlinkat, (void **) &orig_readlinkat);

        // ── 第 3~5 层：Android 11+ 新接口，逐个加（2026-11-27）──
        //
        // 为什么拆成一个接口一档：实测 JMComic(Capacitor WebView) 在
        // 档 1(7 个) / 档 2(14 个) 下图片和网络都正常，档 3(18 个) 坏。
        // 所以问题一定在下面这 3 个里的某一个。一档加一个就能一次定位，
        // 比反复二分省事。
        //
        // ⚠️ 定位完成后应该把这三档收敛回去（保留发现的坏接口单独成档，
        //    其余合并），否则档位会一直膨胀。收敛前别在 UI 里暴露 4/5/6。
        if (lv >= 4) {
            /* ⚠️ 不注册 openat2（2026-11-27）。
             *
             * 真机 libc 实测：open/openat/fopen 及其 64 位别名都在，但
             * **openat2 不存在**（NDK 的 API 23/29/30/35 sysroot 全无此符号）。
             * 它是内核 Linux 5.6+ 的系统调用，bionic 从未给它做 libc 封装 ——
             * 应用要调只能自己写 syscall(__NR_openat2, ...)，不经过 libc 符号，
             * 我们也就 hook 不到。
             *
             * 注册它的唯一效果是每次启动多一次 dlsym 失败 + 一条日志。
             * proxy_openat2 / orig_openat2 的实现全部保留：万一将来 bionic
             * 加了封装，把下面这行取消注释即可（档位语义不变）。
             */
            /* hook_one("openat2", (void *) proxy_openat2, (void **) &orig_openat2); */
        }
        if (lv >= 5) {
            hook_one("statx",   (void *) proxy_statx,   (void **) &orig_statx);
        }
        if (lv >= 6) {
            // opendir 目前是纯透传（proxy_opendir 直接 return orig_opendir），
            // 挂上去只是占位，留位置给将来"拦扫 code_cache 找注入痕迹"。
            hook_one("opendir", (void *) proxy_opendir, (void **) &orig_opendir);
        }
    }

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
                                             jstring apkPath, jstring repPath,
                                             jint level) {
    if (s_installed) return JNI_TRUE;

    /* hook 分层（2026-11-27）：默认 ALL，调用方可降档。
     * 为什么由 Java 传而不是编译期常量：同一个 so 要在不同 App 上复用，
     * 而"该用哪档"取决于目标 App 的 IO 栈（WebView/Flutter 类要降档）。
     * 越界值一律钳到 [CORE, ALL]，不报错 —— 这是尽力而为的降级，不是契约。 */
    if (level < NC_HOOK_LEVEL_CORE) level = NC_HOOK_LEVEL_CORE;
    if (level > NC_HOOK_LEVEL_ALL)  level = NC_HOOK_LEVEL_ALL;
    s_hook_level = (int) level;
    LOGI("hook level = %d（1=core 2=+at 3=all）", s_hook_level);

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
