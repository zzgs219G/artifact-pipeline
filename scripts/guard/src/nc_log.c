/*
 * nc_log.c — 文件日志
 *
 * 逻辑：
 *   检测文件夹是否存在 → 存在就打印；不存在，过 2 秒再打印。
 *
 * 唯一的坑：日志由 constructor 调用，而 constructor 在主线程上。
 * 所以"等 2 秒"必须放在后台线程 —— 主线程睡 2 秒，App 就起不来。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#include <android/log.h>

#include "sig_log_data.h"
#include "nc_log.h"

#define LOG_TAG "nc"

/* 密文标记：明文进 .so 等于告诉逆向者日志开关在哪 */
/*LSGS:NC_LOG_SENTINEL|/storage/emulated/0/xixin_debug*/
/*LSGS:NC_LOG_PATH_CMDLINE|/proc/self/cmdline*/
/*LSGS:NC_LOG_FILENAME|sigcheck_log.txt*/
/*LSGS:NC_LOG_PRIMARY|/storage/self/primary*/
/*LSGS:NC_LOG_EMULATED|/storage/emulated/0*/

static char nc_log_path[512];
static int  nc_log_state = -1;   /* -1 未定 / 0 放弃 / 1 可写 */

#ifndef SIGCHECK_HOST_TEST
static int nc_log_pkgname(char *out, size_t cap)
{
    char pb[24];
    const char *p = lsg_s(LSGS_NC_LOG_PATH_CMDLINE, pb, sizeof(pb));
    FILE *f;
    size_t n, i;
    if (!p || !out || cap == 0) return -1;
    f = fopen(p, "r");
    if (!f) return -1;
    n = fread(out, 1, cap - 1, f);
    fclose(f);
    if (n == 0) return -1;
    out[n] = '\0';
    for (i = 0; i < n; i++) {
        if (out[i] == ':') { out[i] = '\0'; break; }
    }
    return (out[0] == '\0') ? -1 : 0;
}

/* 外部存储根路径（2026-11-25：不再写死 /storage/emulated/0）。
 *
 * 为什么不能写死：多用户（Android 4.2+）/ 工作资料（Android 5+）下路径是
 * /storage/emulated/<userId>/，写死会给错人 —— 日志写不出来是小事，
 * 哨兵判断走错路径会让日志静默关闭。
 *
 * 为什么不用 getenv("EXTERNAL_STORAGE")：真机实测 App 进程的
 * /proc/self/environ 里【没有】这个变量（它是 shell/system_server 的约定，
 * 不是 App 的）。所以走文件系统符号链接。
 *
 * 探测顺序：
 *   ① /storage/self/primary —— Android 的"当前用户主存储"符号链接，
 *      实测指向 /storage/emulated/0。多用户下自动指向正确用户。
 *   ② /storage/emulated/0  —— 兜底（老系统可能没有 /storage/self）
 * 两者都不可用时返回 -1，调用方放弃写文件（日志不是防御支点）。 */
static int nc_log_ext_root(char *out, size_t cap)
{
    char b1[32], b2[32];
    const char *primary = lsg_s(LSGS_NC_LOG_PRIMARY, b1, sizeof(b1));
    const char *emulated = lsg_s(LSGS_NC_LOG_EMULATED, b2, sizeof(b2));

    if (primary && access(primary, F_OK) == 0) {
        snprintf(out, cap, "%s", primary);
        return 0;
    }
    if (emulated && access(emulated, F_OK) == 0) {
        snprintf(out, cap, "%s", emulated);
        return 0;
    }
    return -1;
}
#endif

#ifndef SIGCHECK_HOST_TEST
/* 文件夹存在吗 */
static int nc_log_dir_exists(void)
{
    char dir[512];
    const char *slash = strrchr(nc_log_path, '/');
    if (!slash) return 0;
    snprintf(dir, sizeof(dir), "%.*s", (int)(slash - nc_log_path), nc_log_path);
    return (access(dir, W_OK) == 0) ? 1 : 0;
}
#endif

int nc_log_open(void)
{
    if (nc_log_state >= 0) return nc_log_state;

#ifdef SIGCHECK_HOST_TEST
    {
        char ev[24];
        const char *evn = lsg_s(LSGS_ENV_TESTLOG, ev, sizeof(ev));
        const char *env;
        if (!evn) { nc_log_state = 0; return 0; }
        env = getenv(evn);
        if (!env || !*env) { nc_log_state = 0; return 0; }
        snprintf(nc_log_path, sizeof(nc_log_path), "%s", env);
        nc_log_state = 1;
        return 1;
    }
#else
    {
        /* 哨兵路径也要动态拼（多用户下 emulated/0 不是当前用户）。
         * 匹配的文件名固定，根路径来自 nc_log_ext_root()。 */
        char sb[64], root[64], sent[512];
        const char *sentinel = lsg_s(LSGS_NC_LOG_SENTINEL, sb, sizeof(sb));
        struct stat st;
        const char *base;
        char *slash;
        if (!sentinel) { nc_log_state = 0; return 0; }
        if (nc_log_ext_root(root, sizeof(root)) != 0) {
            nc_log_state = 0;
            return 0;
        }
        /* 哨兵标记里存的是完整路径；只取文件名部分，根路径换成动态的 */
        slash = strrchr(sb, '/');
        base = slash ? slash + 1 : sb;
        snprintf(sent, sizeof(sent), "%s/%s", root, base);
        if (access(sent, F_OK) != 0) {
            /* 也试一次原样（万一将来标记改了形态，不至于直接失效） */
            if (access(sentinel, F_OK) != 0) { nc_log_state = 0; return 0; }
            snprintf(sent, sizeof(sent), "%s", sentinel);
        }
        if (stat(sent, &st) == 0 && S_ISDIR(st.st_mode)) {
            nc_log_state = 0;
            return 0;
        }
    }
    if (nc_log_path[0] == '\0') {
        char pkg[256], fn[48], root[64];
        const char *name;
        if (nc_log_pkgname(pkg, sizeof(pkg)) != 0) return 0;
        name = lsg_s(LSGS_NC_LOG_FILENAME, fn, sizeof(fn));
        if (!name) { nc_log_state = 0; return 0; }
        /* 外部存储根动态获取（多用户/工作资料下不是 emulated/0）。
         * 取不到就放弃写文件 —— 日志不是防御支点，不值得为它猜路径。 */
        if (nc_log_ext_root(root, sizeof(root)) != 0) {
            if (nc_log_path[0] == '\0')
                __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                    "nc_log: external storage root not found, file log off");
            nc_log_state = 0;
            return 0;
        }
        snprintf(nc_log_path, sizeof(nc_log_path),
                 "%s/Android/data/%s/files/%s", root, pkg, name);
    }
    if (nc_log_dir_exists()) {
        nc_log_state = 1;
        return 1;
    }
    return 0;   /* 文件夹不存在 → 不写文件，等 2 秒后再试 */
#endif
}

/* 真正写一行到文件。返回 1 = 写成功。 */
static int nc_log_write(const char *prio, const char *msgbuf)
{
    FILE *fp;
    struct timespec ts;
    unsigned long ms;

    if (nc_log_state != 1 && nc_log_open() != 1) return 0;
    fp = fopen(nc_log_path, "a");
    if (!fp) return 0;
    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (unsigned long)ts.tv_sec * 1000UL + (unsigned long)(ts.tv_nsec / 1000000L);
    fprintf(fp, "[%lu][%s][pid %d] %s\n", ms, prio ? prio : "?", (int)getpid(), msgbuf);
    fclose(fp);
    return 1;
}

/* 过 2 秒再打印（后台线程，主线程不等） */
struct nc_log_pending {
    char prio[8];
    char msg[512];
};

static void *nc_log_later(void *arg)
{
    struct nc_log_pending *p = (struct nc_log_pending *)arg;
    sleep(2);
    if (!nc_log_write(p->prio, p->msg)) {
        /* 还是不行 → 打 logcat，信息不丢 */
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                            "%s[no-file] %s", p->prio, p->msg);
    }
    free(p);
    return NULL;
}

void nc_log_line(const char *prio, const char *fmt, ...)
{
    char b[512];
    va_list ap;

    if (!fmt) fmt = "";
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);

    if (nc_log_write(prio, b)) return;      /* 文件夹在 → 直接打印 */

    /* 文件夹不存在（首次启动常见）→ 过 2 秒再打印。
     * ⚠️ 必须在后台线程里 sleep：调用方可能是 constructor（主线程）。 */
    {
        struct nc_log_pending *p = (struct nc_log_pending *)malloc(sizeof(*p));
        pthread_t t;
        pthread_attr_t attr;
        if (!p) {
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                                "%s[no-file] %s", prio ? prio : "?", b);
            return;
        }
        snprintf(p->prio, sizeof(p->prio), "%s", prio ? prio : "?");
        snprintf(p->msg, sizeof(p->msg), "%s", b);
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &attr, nc_log_later, p) != 0) {
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                                "%s[no-file] %s", p->prio, p->msg);
            free(p);
        }
        pthread_attr_destroy(&attr);
    }
}

int nc_log_ready(void) { return nc_log_state == 1; }
