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
        char sb[64];
        const char *sentinel = lsg_s(LSGS_NC_LOG_SENTINEL, sb, sizeof(sb));
        struct stat st;
        if (!sentinel) { nc_log_state = 0; return 0; }
        if (access(sentinel, F_OK) != 0) { nc_log_state = 0; return 0; }
        if (stat(sentinel, &st) == 0 && S_ISDIR(st.st_mode)) {
            nc_log_state = 0;
            return 0;
        }
    }
    if (nc_log_path[0] == '\0') {
        char pkg[256], fn[48];
        const char *name;
        if (nc_log_pkgname(pkg, sizeof(pkg)) != 0) return 0;
        name = lsg_s(LSGS_NC_LOG_FILENAME, fn, sizeof(fn));
        if (!name) { nc_log_state = 0; return 0; }
        snprintf(nc_log_path, sizeof(nc_log_path),
                 "/storage/emulated/0/Android/data/%s/files/%s", pkg, name);
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
