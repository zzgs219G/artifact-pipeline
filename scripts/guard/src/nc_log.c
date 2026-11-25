/*
 * nc_log.c — 文件日志通道（2026-11-25）
 *
 * ═══ 一句话逻辑 ═══
 * 要写日志时，如果日志目录还没建好，就等 2 秒再查一次；建好了就直接写。
 * 就这么简单。
 *
 * ═══ 为什么需要"等 2 秒" ═══
 * 日志目录 /storage/emulated/0/Android/data/<pkg>/files 不是系统在启动时
 * 创建，而是【第一次有文件写入时才被隐式创建】。而本 so 的 constructor
 * 跑在那之前，第一次写日志时目录必然不存在。
 *
 * 真机实测（2026-11-25，干净安装 + 只启动一次）：
 *   09:19:19.611  进程启动
 *   09:19:19.719  constructor 探测 → 目录不存在（mkdir 得 EACCES 13）
 *   09:19:21.740  等 2 秒后重试 → 目录已可写 → 写入成功
 *
 * 另外两条实测结论（决定了本文件为什么这么写）：
 *   · <pkg>/ 这一层 App 无权自建 —— 父目录 Android/data 的权限是
 *     drwxrws--x（其他用户 --x，能进不能写），mkdir 必然 EACCES。
 *     所以只能等，不能强建。
 *   · 目录出现的时间【不可预测】（实测从 2 秒到 104 秒都有），
 *     所以"等多久"不能写死一次，必须允许重复等。
 *
 * ═══ 与曾经的复杂版本的差异（刻意回滚）═══
 * 中途试过：探测配额、失败节流、延时节流、asnyc 轮询线程、结论摘要。
 * 全部砍掉 —— 因为它们的总收益只是"首次启动能多一条摘要"，而代价是
 * 400 行代码 + 一堆互相影响的开关。现在只保留一个"等 2 秒再试"。
 *
 * ⚠️ 唯一保留的复杂度：等待是【有界】的（NC_LOG_WAIT_TRIES 次）。
 *    哨兵文件不存在是常态（用户没开日志），不能每次都白等 2 秒。
 *    一旦确认"哨兵不存在"，立刻落 0 放弃，不再等待。
 *
 * ═══ 安全边界 ═══
 * 日志内容只有路径 / 指纹哈希 / 分支结论，无密钥、无用户数据。
 * 所有 I/O 失败一律静默忽略，绝不影响判定主流程。
 * 不缓冲日志文本（不引入明文常驻内存）。
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

#include "sig_log_data.h"   /* lsg_s / lsg_decode + 本文件的密文表 */
#include "nc_log.h"

#define LOG_TAG "nc"

/* ── 密文标记（本文件自带；protect.sh 把 nc_log.c 加进 make-sig-log.py 入参）
 * 明文进 .so 等于把「日志开关在哪」直接写给逆向者（strings 一条命令即中）。 */
/*LSGS:NC_LOG_SENTINEL|/storage/emulated/0/xixin_debug*/
/*LSGS:NC_LOG_PATH_CMDLINE|/proc/self/cmdline*/
/*LSGS:NC_LOG_FILENAME|sigcheck_log.txt*/

static char nc_log_path[512];
static int  nc_log_state = -1;   /* -1 未探测/待重试, 0 已放弃, 1 可写 */

#ifndef SIGCHECK_HOST_TEST
/* 读自身包名：/proc/self/cmdline，遇到 ':' 截断（子进程带 ":remote"）。 */
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

/* 日志目录现在可写吗？不建目录、不改状态，纯查询。
 * 供"等 2 秒"的循环判断用。 */
static int nc_log_dir_ok(void)
{
    char dir[512];
    const char *slash = strrchr(nc_log_path, '/');
    if (!slash) return 0;
    snprintf(dir, sizeof(dir), "%.*s", (int)(slash - nc_log_path), nc_log_path);
    return (access(dir, W_OK) == 0) ? 1 : 0;
}
#endif /* !SIGCHECK_HOST_TEST (这两个辅助仅真机分支用) */

int nc_log_open(void)
{
    int first_try;
#ifndef SIGCHECK_HOST_TEST
    int waited;   /* 只在真机分支的等待循环里用 */
#endif

    if (nc_log_state >= 0) return nc_log_state;
    first_try = (nc_log_path[0] == '\0');

#ifdef SIGCHECK_HOST_TEST
    /* 宿主测试：不碰 sdcard，开关走环境变量（与抽取前同语义） */
    {
        char ev[24];
        const char *evn = lsg_s(LSGS_ENV_TESTLOG, ev, sizeof(ev));
        const char *env;
        if (!evn) {
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: host env name decode failed");
            nc_log_state = 0;
            return 0;
        }
        env = getenv(evn);
        if (!env || !*env) {
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: host env %s unset (log off)", evn);
            nc_log_state = 0;
            return 0;
        }
        snprintf(nc_log_path, sizeof(nc_log_path), "%s", env);
        nc_log_state = 1;
        return 1;
    }
#else
    /* ── ① 哨兵开关（不存在 = 用户没开日志，立刻放弃，不等待）──────── */
    {
        char sb[64];
        const char *sentinel = lsg_s(LSGS_NC_LOG_SENTINEL, sb, sizeof(sb));
        struct stat st;
        if (!sentinel) {
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: sentinel name decode failed");
            nc_log_state = 0;
            return 0;
        }
        if (access(sentinel, F_OK) != 0) {
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: sentinel absent (%s), file log off", sentinel);
            nc_log_state = 0;      /* 常态：用户没开日志 → 不等待 */
            return 0;
        }
        /* access 过了但可能是目录（用户误建成目录）→ fopen 必然失败 */
        if (stat(sentinel, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: sentinel is a DIRECTORY (%s) — rmdir it and touch "
                "a file", sentinel);
            nc_log_state = 0;
            return 0;
        }
    }

    /* ── ② 包名 + 文件名（只在首次拼一次）──────────────────────────── */
    if (nc_log_path[0] == '\0') {
        char pkg[256];
        char fn[48];
        const char *name;
        if (nc_log_pkgname(pkg, sizeof(pkg)) != 0) {
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: cannot read own package name");
            return 0;
        }
        name = lsg_s(LSGS_NC_LOG_FILENAME, fn, sizeof(fn));
        if (!name) {
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: file name decode failed");
            nc_log_state = 0;
            return 0;
        }
        snprintf(nc_log_path, sizeof(nc_log_path),
                 "/storage/emulated/0/Android/data/%s/files/%s", pkg, name);
    }

    /* ── ③ 目录没建就等 2 秒再查（本文件的核心）────────────────────
     *
     * 为什么只能等、不能建：<pkg>/ 那层的父目录是 Android/data
     * （drwxrws--x，其他用户只有 --x），mkdir 必然 EACCES(13)。
     * 真机实测就是这个错误码，不是权限配置失误，是 Android 的存储模型。
     *
     * 为什么有界：目录何时出现不可预测（实测 2 秒 ~ 104 秒），但
     * 哨兵没开是常态，不能为此让每条日志都白等。所以最多等
     * NC_LOG_WAIT_TRIES 次（2 秒 × 5 = 10 秒），过了就放弃。
     *
     * ⚠️ 只有【首条日志】会走到这个等待循环；一旦 nc_log_state 变 1，
     *    后续所有日志零等待。所以最坏情况是"启动慢 10 秒"，不是每条都慢。 */
    for (waited = 0; waited < NC_LOG_WAIT_TRIES; waited++) {
        if (nc_log_dir_ok()) {
            nc_log_state = 1;
            if (first_try && waited > 0)
                __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                    "nc_log: dir ready after %d ms", waited * NC_LOG_WAIT_MS);
            return 1;
        }
        if (first_try && waited == 0)
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: dir not ready yet (%s) — waiting up to %d ms "
                "(the system creates <pkg>/files on first write)",
                nc_log_path, NC_LOG_WAIT_MS * NC_LOG_WAIT_TRIES);
        usleep(NC_LOG_WAIT_MS * 1000);
    }
#endif

    if (first_try)
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "nc_log: gave up waiting for %s", nc_log_path);
    nc_log_state = 0;
    return 0;
}

int nc_log_ready(void) { return nc_log_state == 1; }

void nc_log_line(const char *prio, const char *fmt, ...)
{
    FILE *fp;
    struct timespec ts;
    unsigned long ms;
    va_list ap;
    char b[512];

    if (nc_log_state != 1) {
        /* 未就绪：先尝试打开（含"等 2 秒"），成功才写文件 */
        if (nc_log_open() != 1) {
            /* 仍然不可写 → 打到 logcat，至少排障时不丢信息。
             * ⚠️ 只打 logcat，不递归（避免无限递归）。 */
            if (fmt) {
                va_start(ap, fmt);
                vsnprintf(b, sizeof(b), fmt, ap);
                va_end(ap);
                __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                                    "%s[no-file] %s", prio ? prio : "?", b);
            }
            return;
        }
    }

    fp = fopen(nc_log_path, "a");
    if (!fp) return;
    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (unsigned long)ts.tv_sec * 1000UL + (unsigned long)(ts.tv_nsec / 1000000UL);
    fprintf(fp, "[%lu][%s][pid %d] ", ms, prio ? prio : "?", (int)getpid());
    if (fmt) {
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        va_end(ap);
    }
    fputc('\n', fp);
    fclose(fp);
}
