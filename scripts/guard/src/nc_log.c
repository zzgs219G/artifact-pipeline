/*
 * nc_log.c — 文件日志通道（2026-11-25 从 sig_check.c / env_check.c 合并）
 *
 * 抽取动机、为什么不违反"零代码共享"、首次启动为什么要重试 ——
 * 全部见 nc_log.h 头注。本文只写实现要点。
 *
 * ═══ 一个关键事实 ═══
 * 抽取前两份实现写的是【同一个文件】sigcheck_log.txt，各自探测、各自维护
 * ready 状态。合并后只有一个状态机，不存在"一边开了另一边没开"的错位。
 *
 * ═══ 探测失败为什么不能落死 ═══
 * 日志目录 /storage/emulated/0/Android/data/<pkg>/files 由 system_server
 * 在「应用数据目录初始化」时创建，而本 so 的 constructor 跑在它之前。
 * 且 <pkg>/ 那一层 App 无权自建（父目录 drwxrws--x，其他用户 --x）——
 * 真机实测 mkdir 得 pkg_rc=13(EACCES)。
 *
 * 所以：失败保持 -1（可重试），落到 0 只发生在「试够 NC_LOG_MAX_TRIES 次」。
 * 任何后续 nc_log_line() 都会推进一步，系统建好目录后自动恢复。
 *
 * ═══ 首次启动的补写 ═══
 * nc_log_late_flush()：constructor 末尾起一个短延时线程，1.5 秒后
 * 主动触发一次探测 + 写摘要行。为什么不是全文缓冲：
 * 缓冲会让【解密后的明文日志】常驻 .bss，而 Frida 一旦挂上，Memory.scan
 * 就能整块读走 —— 那等于把排障资料直接送给逆向者。本项目既有纪律是
 * 字符串必须密文化（strings 扫不到语义），引入 8KB 明文常驻与之冲突。
 * 摘要只存几个整数（rc / 路数 / 裁决），泄露面约 16 字节。
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

#include "sig_log_data.h"   /* lsg_s / lsg_decode + 本文件的密文表 */
#include "nc_log.h"

#define LOG_TAG "nc"

/* ── 密文标记（本文件自带；protect.sh 把 nc_log.c 加进 make-sig-log.py 入参）
 *
 * ⚠️ 为什么这三个路径必须密文化：明文进 .so 等于把「日志开关在哪」
 *    直接写给逆向者（strings 一条命令即中）。与 sig_check.c 的做法同源。
 *
 * ⚠️ 语义标记（LSG:）留给真正的中文文案；本文件的诊断/摘要行是英文代号，
 *    不含"检测/加固"类路标词，不需要密文化（也不该进密文表白占条目）。 */
/*LSGS:NC_LOG_SENTINEL|/storage/emulated/0/xixin_debug*/
/*LSGS:NC_LOG_PATH_CMDLINE|/proc/self/cmdline*/
/*LSGS:NC_LOG_FILENAME|sigcheck_log.txt*/

static char nc_log_path[512];
static int  nc_log_state = -1;   /* -1 未探测/待重试, 0 已放弃, 1 可写 */
static int  nc_log_tries = 0;

/* 首次启动的结论摘要（constructor 期写入，延时线程读取后落盘）
 * ⚠️ 只放整数，不放任何字符串 —— 这是"不引入明文常驻"的具体落实。 */
static volatile signed char nc_sum_rc      = -1;  /* 防线0 rc，-1=未知 */
static volatile signed char nc_sum_routes  = -1;  /* 六路成功数 */
static volatile signed char nc_sum_verdict = -1;  /* 0=拒 1=放行 2=PM污染 3=旧语义 */
static volatile signed char nc_sum_done    = 0;

/* 读自身包名：/proc/self/cmdline，遇到 ':' 截断（子进程带 ":remote"）。 */
#ifndef SIGCHECK_HOST_TEST   /* 两个辅助仅真机分支用，见下有说明 */
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

/* 建 /…/<pkg>/ 与 /…/<pkg>/files 两层。
 * ⚠️ 不逐级 mkdir：中间层（/storage、/storage/emulated…）本来就存在或不可写，
 *    逐级建会撞 EACCES 干扰判断。与 nox 报告模块的做法对齐（只建最后两层）。
 * 返回 0 = 目录可写（可能刚建好）。 */
static int nc_log_mkdir_target(const char *file_path)
{
    char dir[512];
    const char *slash = strrchr(file_path, '/');
    char base[512];
    size_t dl;
    int rc, e1 = 0, e2 = 0;

    if (!slash) return -1;
    snprintf(dir, sizeof(dir), "%.*s", (int)(slash - file_path), file_path);
    if (access(dir, W_OK) == 0) return 0;        /* 已就绪，最常见路径 */

    /* ① 先建 <pkg>/（去掉末尾的 "/files"）。
     * ⚠️ 2026-11-25 实测修 bug：原来写 `strcmp(base + dl - 6, "/files")`，
     *    而 "files" 是 5 字符 + NUL —— base+dl-6 指向的是 "files"，
     *    拿去和 "/files"（6 字符）比永不相等 → 这个分支从来没执行过。
     *    正确偏移是 dl - 5。 */
    snprintf(base, sizeof(base), "%s", dir);
    dl = strlen(base);
    if (dl > 5 && strcmp(base + dl - 5, "files") == 0 && base[dl - 6] == '/') {
        base[dl - 6] = '\0';                     /* → .../com.nivii.app */
        rc = mkdir(base, 0770);
        if (rc != 0 && errno != EEXIST) e1 = errno;
    }
    /* ② 再建 .../files */
    rc = mkdir(dir, 0770);
    if (rc != 0 && errno != EEXIST) e2 = errno;
    if (access(dir, W_OK) != 0) {
        /* 打真实 errno —— 上一次就是靠"加诊断"才定位到 pkg_rc=13。 */
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "nc_log: mkdir failed pkg_errno=%d files_errno=%d (%s)",
            e1, e2, dir);
        return -1;
    }
    return 0;
}
#endif /* !SIGCHECK_HOST_TEST (真机专用的路径/mkdir 辅助) */

int nc_log_open(void)
{
    int first_try;

    if (nc_log_state >= 0) return nc_log_state;
    if (nc_log_tries >= NC_LOG_MAX_TRIES) { nc_log_state = 0; return 0; }

    first_try = (nc_log_tries == 0);
    nc_log_tries++;

#ifdef SIGCHECK_HOST_TEST
    /* ── 宿主测试：不碰 sdcard，开关走环境变量（与抽取前同语义）────────
     * 变量名本身也密文化（LSGS_ENV_TESTLOG），解码失败 → 放弃不重试：
     * 宿主端拿不到变量名属于构建问题，重试无意义。 */
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
            /* 未设 = 用户明确不要日志 → 放弃，不重试（宿主常态） */
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: host env %s unset (log off)", evn);
            nc_log_state = 0;
            return 0;
        }
        snprintf(nc_log_path, sizeof(nc_log_path), "%s", env);
        if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "nc_log: host log -> %s", env);
        nc_log_state = 1;
        return 1;
    }
#else
    /* 真机分支专用变量（宿主分支不用 → 放这里避免 -Wunused） */
    char pkg[256];
    char fn[48];
    const char *name;
    const char *sentinel;
    struct stat st;
    /* ── ① 哨兵开关 ──────────────────────────────────────────────── */
    {
        char sb[64];
        sentinel = lsg_s(LSGS_NC_LOG_SENTINEL, sb, sizeof(sb));
        if (!sentinel) {
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: sentinel name decode failed");
            return 0;
        }
        if (access(sentinel, F_OK) != 0) {
            /* 哨兵不存在是【用户没开日志】的常态 —— 直接放弃，不重试。
             * 与"目录还没建好"区分开：后者要重试。 */
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: sentinel absent (%s), file log off", sentinel);
            nc_log_state = 0;
            return 0;
        }
        /* access 过了但可能是目录（用户误建成目录）→ fopen 会失败且无线索 */
        if (stat(sentinel, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                "nc_log: sentinel is a DIRECTORY (%s) — rmdir it and touch "
                "a file; retrying", sentinel);
            return 0;                       /* 保持 -1，给人修的时间 */
        }
    }

    /* ── ② 包名 + 文件名 ─────────────────────────────────────────── */
    if (nc_log_pkgname(pkg, sizeof(pkg)) != 0) {
        if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "nc_log: cannot read own package name");
        return 0;                           /* 可重试（cmdline 早期可能读不到） */
    }
    name = lsg_s(LSGS_NC_LOG_FILENAME, fn, sizeof(fn));
    if (!name) {
        if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "nc_log: file name decode failed");
        return 0;
    }
    snprintf(nc_log_path, sizeof(nc_log_path),
             "/storage/emulated/0/Android/data/%s/files/%s", pkg, name);

    /* ── ③ 目录（首次启动这里是失败点，见头注）──────────────────── */
    if (nc_log_mkdir_target(nc_log_path) != 0) {
        if (first_try) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "nc_log: dir not ready yet (%s) — system creates <pkg>/ on first "
            "launch; will retry", nc_log_path);
        return 0;                           /* 保持 -1 → 后续调用再试 */
    }

    nc_log_state = 1;
    return 1;
#endif /* SIGCHECK_HOST_TEST */
}

int nc_log_ready(void) { return nc_log_state == 1; }

void nc_log_line(const char *prio, const char *fmt, ...)
{
    FILE *fp;
    struct timespec ts;
    unsigned long ms;
    va_list ap;

    /* 未就绪时先试一次 —— 这是"首次启动最终能写出来"的触发点。
     * 没有这一行，constructor 那次失败后就再也没人推进状态。 */
    if (nc_log_state < 0) nc_log_open();
    if (nc_log_state != 1) {
        /* 仍然不可写：把该行打到 logcat，至少排障时不丢信息。
         * ⚠️ 只打 logcat，不递归调用本函数（避免无限递归）。 */
        if (fmt) {
            char b[512];
            va_start(ap, fmt);
            vsnprintf(b, sizeof(b), fmt, ap);
            va_end(ap);
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                                "%s[no-file] %s", prio ? prio : "?", b);
        }
        return;
    }

    fp = fopen(nc_log_path, "a");
    if (!fp) {
        /* 打开失败：可能目录刚被删/FUSE 短暂不可用 → 退回 -1 再试 */
        nc_log_state = -1;
        return;
    }
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

/* ── 首次启动的结论摘要 + 延时补写 ────────────────────────────────────
 *
 * 为什么只记摘要而不是全文：见 nc_log.h「安全边界」与 nc_log.c 头注。
 *
 * 三路调用：
 *   nc_log_summary(rc, routes, verdict)  constructor 里算完就填（纯整数）
 *   nc_log_late_flush()                  constructor 末尾调，起延时线程
 *   （线程）                             sleep 1.5s → nc_log_line(摘要)
 *
 * 1.5 秒的依据：真机实测 constructor 在 ~30ms 内跑完，system_server 建
 * <pkg>/ 目录通常在 200ms 内（首次启动最坏几百 ms）。1.5s 留了 5 倍余量，
 * 又不至于让用户等太久（用户明确要求"一两秒就出结果"）。
 *
 * ⚠️ 线程只在"摘要已填且文件日志还没就绪"时启动 —— 已经能写的场景
 *    （第二次启动及之后）不付这个成本。 */
void nc_log_summary(int rc, int routes, int verdict)
{
    nc_sum_rc      = (signed char)rc;
    nc_sum_routes  = (signed char)routes;
    nc_sum_verdict = (signed char)verdict;
    nc_sum_done    = 1;
}

static void *nc_log_late_thread(void *arg)
{
    int i;
    (void)arg;
    /* ⚠️ 2026-11-25 真机实测：files/ 目录比 <pkg>/ 晚得多 ——
     *   08:01:43.410 constructor
     *   08:01:44.032 系统建 <pkg>/ 与 cache/
     *   08:02:00.928 files/ 才出现（17 秒后，由第一次实际写入触发）
     * 原来只试 1s + 1s = 2 秒，必然错过。
     *
     * 现在改成【最多 8 次、每次间隔 2 秒】（约 16 秒），覆盖实测的 17 秒
     * 最坏情况；一旦成功就立刻停。为什么不用更密的重试：每次都要 access()
     * 两个路径，2 秒粒度对"首次启动补日志"这个场景完全够，且不占 CPU。
     *
     * ⚠️ 线程是 detached，进程退出自然回收，不需要 join。 */
    for (i = 0; i < 8; i++) {
        sleep(2);
        nc_log_open();
        if (nc_log_ready()) break;
    }
    if (nc_sum_done) {
        nc_log_line("I",
            "===== summary(constructor): rc=%d routes=%d verdict=%d "
            "(detail lines were emitted before the log dir existed; "
            "see logcat) =====",
            (int)nc_sum_rc, (int)nc_sum_routes, (int)nc_sum_verdict);
    }
    return NULL;
}

void nc_log_late_flush(void)
{
    pthread_t t;
    pthread_attr_t attr;
    /* 已就绪就不折腾（常见于第二次启动及之后） */
    if (nc_log_ready()) return;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, nc_log_late_thread, NULL) == 0)
        pthread_attr_destroy(&attr);
    else
        pthread_attr_destroy(&attr);
}
