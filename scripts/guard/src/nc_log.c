/*
 * nc_log.c — 文件日志
 *
 * 逻辑：目录能写就写文件，不能写就打 logcat（带 [no-file] 标记）。
 * 本模块任何函数都不 sleep —— constructor 在主线程上跑，睡了 App 就起不来。
 * 重试由 env_check 的看门狗线程（每 5 秒）调 nc_log_retry()。
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
/* 读包名：/proc/self/cmdline，遇 ':' 截断 */
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

/* 目录能写吗（只查询，不建、不睡） */
static int nc_log_dir_ok(void)
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
    int first = (nc_log_path[0] == '\0');
    (void)first;

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
        if (access(sentinel, F_OK) != 0) {
            /* 哨兵不存在 = 用户没开日志，常态，直接放弃 */
            nc_log_state = 0;
            return 0;
        }
        if (stat(sentinel, &st) == 0 && S_ISDIR(st.st_mode)) {
            nc_log_state = 0;
            return 0;
        }
    }

    if (nc_log_path[0] == '\0') {
        char pkg[256], fn[48];
        const char *name;
        if (nc_log_pkgname(pkg, sizeof(pkg)) != 0) {
            if (first) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: cannot read package name");
            return 0;
        }
        name = lsg_s(LSGS_NC_LOG_FILENAME, fn, sizeof(fn));
        if (!name) { nc_log_state = 0; return 0; }
        snprintf(nc_log_path, sizeof(nc_log_path),
                 "/storage/emulated/0/Android/data/%s/files/%s", pkg, name);
    }

    if (nc_log_dir_ok()) {
        nc_log_state = 1;
        return 1;
    }
    if (first) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "nc_log: dir not ready (%s), retry from watchdog", nc_log_path);
    return 0;
#endif
}

void nc_log_retry(void)
{
    if (nc_log_state != -1) return;
    nc_log_open();
}

int nc_log_ready(void) { return nc_log_state == 1; }

void nc_log_line(const char *prio, const char *fmt, ...)
{
    FILE *fp;
    struct timespec ts;
    unsigned long ms;
    va_list ap;
    char b[512];

    if (nc_log_state != 1 && nc_log_open() != 1) {
        if (fmt) {
            va_start(ap, fmt);
            vsnprintf(b, sizeof(b), fmt, ap);
            va_end(ap);
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                                "%s[no-file] %s", prio ? prio : "?", b);
        }
        return;
    }

    fp = fopen(nc_log_path, "a");
    if (!fp) return;
    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (unsigned long)ts.tv_sec * 1000UL + (unsigned long)(ts.tv_nsec / 1000000L);
    fprintf(fp, "[%lu][%s][pid %d] ", ms, prio ? prio : "?", (int)getpid());
    if (fmt) {
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        va_end(ap);
    }
    fputc('\n', fp);
    fclose(fp);
}
