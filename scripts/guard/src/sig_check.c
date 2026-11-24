/*
 * sig_check.c — 纯 Native 签名校验（第四版方案核心）
 *
 * 设计要点：
 *   1. 入口使用 __attribute__((constructor))，在 so 被 dlopen 时、
 *      甚至早于 JNI_OnLoad 执行，早于一切 Java 业务代码与入口重定向。
 *      （dcc 工具链的 libnc.so 已占用 JNI_OnLoad，故不与其冲突）
 *   2. 完全不经过 Java 层 API（不调 PackageManager / FileInputStream），
 *      直接 open/read /data/app/.../base.apk，手工解析 APK Signing Block
 *      (v2: 0x7109871a / v3: 0xf05368c0)，提取证书 DER 后计算 SHA-256，
 *      经双轮派生(derive_expected,2026-10 追加)后与 sig_hash.h 中的
 *      SIG_HASH_STORED 比对——明文指纹不再落盘(防搜索替换攻击)。
 *   3. 校验失败不直接 exit(0)：起分离线程延时随机 abort，
 *      让"hook exit/abort 即绕过"的通用脚本失效（二期继续增强为隐蔽破坏）。
 *      当前延时 1~3 秒(调试)，改法见 delayed_kill 函数上方注释。
 *   4. SIG_HASH_STORED 全零 = 调试模式（流水线未注入派生槽位时跳过校验，便于本地测试）。
 *
 * 编译：由流水线把本文件与 dcc 生成的 C 代码一起放进 ndk 工程编译，
 *      最终产物与业务逻辑同在 libnc.so，防剥离。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>     /* 2026-10-19 方案2：SIGABRT（sig_raw_die 用） */
#include <sys/syscall.h> /* __NR_tgkill / gettid */
#include <android/log.h>

#include "sig_hash.h"

#define LOG_TAG "nc"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* ─────────────────────────── 文件日志(追加能力,用户 2026-09-08 需求) ───────────────────────────
 * 背景:logcat 在无 adb 的真机排障场景拿不到,"签名一致仍闪退"无法定位。
 * 方案:LOGD/LOGI/LOGE 在原 logcat 输出之外,同步追加写入应用外部目录文件。
 *
 * 开关(哨兵文件,运行时生效,无需重编译/重装):
 *   /storage/emulated/0/xixin_debug   存在 → 写文件日志
 *   (2026-xx 用户要求统一改名:原 sigcheck_debug → xixin_debug,与 jian_box
 *    普通 App 的崩溃日志开关共用同一文件名,用户只记一个开关)
 *   (放 sdcard 根而非 Android/data:MT 管理器等工具在 Android 11+ 也能直接建)
 * 日志输出:
 *   /storage/emulated/0/Android/data/<包名>/files/sigcheck_log.txt
 *
 * 安全性:所有文件 I/O 失败一律静默忽略(constructor 早期 FUSE 可能未就绪),
 * 不影响校验主流程;日志内容只有路径/指纹哈希/分支结论,无密钥无用户数据。 */

#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <dlfcn.h>     /* 报错十四: dladdr/dlsym 定位本 so 真实路径 */

/* 调试哨兵路径(2026-10-16 LSGS 密文化):原明文 #define 是攻击者可读的
 * 「调试开关位置」泄露。明文唯一载体:本文件「外围串 LSGS 标记区」的标记
 * (在 sig_log_data.h include 之后,那里才有 lsg_s/LSGS_*)。
 * 此处只放前向声明,siglog_detect 里调用的辅助函数在标记区后实现。 */
static const char *siglog_sentinel(char *buf, size_t buflen);
#ifdef SIGCHECK_HOST_TEST
static const char *siglog_testlog_env(char *buf, size_t buflen);
static const char *siglog_testapk_env(char *buf, size_t buflen);
#endif
static const char *siglog_logname(char *buf, size_t buflen);

static char siglog_path[512];   /* 日志文件完整路径,'' = 未探测 */
static int  siglog_ready = -1;  /* -1 未探测/待重试, 0 已放弃, 1 可写 */
/* 探测次数上限（2026-11-25）。为什么需要上限：
 * 哨兵不存在是【常态】（用户没开日志），此时每次 siglog 调用都重试
 * access() 会白花系统调用。上限 6 次覆盖 constructor + 前几次运行时
 * 调用，足够等到 /storage 的 FUSE 挂载就绪，之后放弃、零开销。 */
static int  siglog_tries = 0;
#define SIGLOG_MAX_TRIES 6

/* 前向声明:get_pkg_name 定义在本文件后部(§定位 base.apk),此处先用 */
static int get_pkg_name(char *out, size_t outlen);

/* ── 日志开关探测（2026-11-25 重写：从「一次性」改成「可重试」）─────────
 *
 * ═══ 修的 bug（用户真机实测）═══
 * 症状：装完 App【第一次】打开，sigcheck_log.txt 永远不出现；
 *       关掉再打开【第二次】就有了。同包同哨兵同 uid，只差在"第二次"。
 *
 * 根因：本函数原来第二行就 `siglog_ready = 0`（先假定失败），
 *       而 constructor 阶段 /storage/emulated/0 的 FUSE 可能还没为这个
 *       uid 挂载好 → access(sentinel) 因 EACCES 失败 → 直接 return
 *       → siglog_ready 永久留在 0 → 本次进程再也不会写文件日志。
 *       第二次启动时 FUSE 已就绪（首次启动间接促成了挂载）→ 正常。
 *
 *       这不是猜测：本文件 53 行早就写着「constructor 早期 FUSE 可能未就绪」，
 *       变更历史 2026-11-24 条也记了「早期写 sdcard 靠不住（同一次启动
 *       早期失败、晚期成功）」。当时的选择是"静默忽略"，代价是用户在
 *       最想看的第一次启动里拿不到任何日志。
 *
 * ═══ 现在怎么做 ═══
 *   ① 失败【不落 0】：保持 -1，下一次 siglog() 调用会再试（见 siglog 首行）。
 *   ② 探测上限 6 次：哨兵确实不存在时不能无限重试（常态，白花 syscall）。
 *   ③ 失败原因进 logcat（只在第 1 次打，避免 20s 复查把 logcat 刷满）：
 *      文件日志写不了，但 logcat 一定能写 —— 与 ncg_death_notice 同款理由。
 *   ④ 区分「不存在」与「存在但进不去」：前者是用户没开哨兵，后者是环境
 *      问题（权限/类型），修法完全不同。用户实测踩过一次：哨兵路径被建成
 *      【目录】且属主是别的 uid、权限 drwxrws--- → access 失败 →
 *      判成"不存在" → 无线索。现在会明说是目录。
 *
 * ⚠️ 用早期可用的 LOGI（logcat）而不是 LOGI_S（LSG 密文，定义在文件后部，
 *    此处不可见）；文案用英文短代号 —— 功能语义字符串必须走 LSG 才能过
 *    test-lsgs-strings.sh 的零泄漏断言，而这几句是【诊断元信息】，
 *    进 LSG 只会平添密文条目。 */
static void siglog_detect(void) {
    char pkg[256];
    char sbuf[64];
    int first_try;

    if (siglog_ready >= 0) return;              /* 已成功或已放弃 */
    if (siglog_tries >= SIGLOG_MAX_TRIES) {     /* 试够了，放弃（零开销） */
        siglog_ready = 0;
        return;
    }
    first_try = (siglog_tries == 0);
    siglog_tries++;

    /* 只在首次失败时说明原因；后续重试静默（否则 20s 复查会刷屏） */
#define SIGLOG_FAIL(why) do {                                        \
        if (first_try) LOGI("siglog: " why);                         \
        return;                     /* 保持 -1 → 下次再试 */          \
    } while (0)

#ifdef SIGCHECK_HOST_TEST
    /* 宿主测试:不碰 sdcard,开关用环境变量控制 */
    {
        /* ⚠️ env 声明在 ifdef 内部：真机构建下这段不编译，
         * 放外面会变成 unused variable（-Werror 会拦）。
         * 2026-11-22：本条与 env_check.c 的同名变量一起导致
         * 这两个文件长期编不过 -Werror —— 而 CI 的所有 guard 测试
         * 都没开 -Werror，所以告警存在但从未拦过任何东西。 */
        const char *env;
        char ev[24];
        const char *evn = siglog_testlog_env(ev, sizeof(ev));
        if (!evn) SIGLOG_FAIL("host: log-name env decode failed");
        env = getenv(evn);
        if (!env || !*env) {
            /* 宿主端变量未设 = 用户明确不要日志 → 直接放弃，不重试 */
            if (first_try) LOGI("siglog: host env %s unset (log off)", evn);
            siglog_ready = 0;
            return;
        }
        snprintf(siglog_path, sizeof(siglog_path), "%s", env);
        siglog_ready = 1;
        return;
    }
#endif
    {
        const char *sentinel = siglog_sentinel(sbuf, sizeof(sbuf));
        if (!sentinel) SIGLOG_FAIL("sentinel name decode failed");
        if (access(sentinel, F_OK) != 0) {
            int e = errno;
            if (first_try) {
                LOGI("siglog: sentinel not accessible: %s errno=%d(%s) "
                     "(retry up to %d; if this path is a directory, "
                     "rmdir it and touch a file)",
                     sentinel, e, strerror(e), SIGLOG_MAX_TRIES);
            }
            return;
        }
        /* access 过了但可能是目录：fopen("a") 会失败，那时更没线索。 */
        {
            struct stat st;
            if (stat(sentinel, &st) == 0 && S_ISDIR(st.st_mode)) {
                if (first_try) {
                    LOGI("siglog: sentinel is a DIRECTORY (%s) — rmdir it "
                         "and touch a file; retrying", sentinel);
                }
                return;
            }
        }
    }
    if (get_pkg_name(pkg, sizeof(pkg)) != 0)
        SIGLOG_FAIL("cannot read own package name (/proc/self/cmdline)");
    {
        char logname[48];
        const char *ln = siglog_logname(logname, sizeof(logname));
        if (!ln) SIGLOG_FAIL("log file name decode failed");
        snprintf(siglog_path, sizeof(siglog_path),
                 "/storage/emulated/0/Android/data/%s/files/%s", pkg, ln);
    }
    {
        /* 目标目录可写性：原来靠 fopen 失败再静默置 0，用户只看到
         * "文件没出现"。这里提前探一次，失败就说明原因。
         *
         * ⚠️⚠️ 2026-11-25 实测补漏：首次启动时
         * /storage/emulated/0/Android/data/<pkg>/files 【目录还不存在】
         * （系统在 App 首次运行时才建），access(W_OK) 得 ENOENT →
         * 判"不可写" → 日志关闭。而 nox 的报告模块能写出 ncguard_log.md，
         * 是因为它自己 mkdir 了。这里同样补上逐级 mkdir。
         *
         * 三种情形分开处置：
         *   目录不存在     → 逐级 mkdir 后复查（成功即继续）
         *   目录在但不可写 → 真问题，报 errno 并留给下次重试
         *   mkdir 也失败   → 不致命（可能别的进程刚建好），继续试 fopen
         */
        char dir[512];
        const char *slash = strrchr(siglog_path, '/');
        int dir_bad = 0;
        if (slash != NULL) {
            snprintf(dir, sizeof(dir), "%.*s",
                     (int)(slash - siglog_path), siglog_path);
            if (access(dir, W_OK) != 0) {
                int e = errno;
                if (e == ENOENT) {
                    /* ⚠️ 2026-11-25 实测：与 nox 报告模块对齐 —— 它只 mkdir
                     * 最后一层 files/，因为 /…/<pkg>/ 由系统在 App 启动早期
                     * 就建好了（cache/ files/ 是它的子目录）。
                     *
                     * 第一版这里做了「逐级 mkdir」，但循环里没判 EEXIST，
                     * 且路径中间层（/storage、/storage/emulated …）本来就
                     * 存在或不可写 —— 逐级建会撞 EACCES 而干扰判断。
                     * 现在只建 <pkg>/ 与 <pkg>/files 两层，并记录真实 errno
                     * 到诊断日志（不再用 (void) 把错误吞掉）。 */
                    char base[512];
                    int rc1 = 0, rc2 = 0;
                    size_t dl;
                    snprintf(base, sizeof(base), "%s", dir);
                    dl = strlen(base);
                    /* 去掉末尾的 "/files" 得到 <pkg>/ */
                    if (dl > 6 && strcmp(base + dl - 6, "/files") == 0) {
                        base[dl - 6] = '\0';
                        rc1 = mkdir(base, 0770);
                        if (rc1 != 0 && errno != EEXIST) rc1 = errno; else rc1 = 0;
                    }
                    rc2 = mkdir(dir, 0770);
                    if (rc2 != 0 && errno != EEXIST) rc2 = errno; else rc2 = 0;
                    if (access(dir, W_OK) == 0) {
                        if (first_try)
                            LOGI("siglog: created log dir %s", dir);
                        dir_bad = 0;
                    } else {
                        dir_bad = 1;
                        if (first_try) {
                            LOGI("siglog: mkdir %s failed (pkg_rc=%d files_rc=%d) "
                                 "— parent is system-managed (drwxrws--x), "
                                 "only the system can create it; will retry",
                                 dir, rc1, rc2);
                        }
                    }
                } else {
                    dir_bad = 1;
                }
                if (dir_bad && first_try) {
                    LOGI("siglog: log dir not writable: %s errno=%d(%s) "
                         "(retrying)", dir, e, strerror(e));
                }
            }
        }
        if (dir_bad) return;      /* 保持 -1，下次再试 */
    }
#undef SIGLOG_FAIL
    siglog_ready = 1;
}

static void siglog(const char *prio, const char *fmt, ...) {
    FILE *fp;
    struct timespec ts;
    unsigned long ms;
    va_list ap;
    /* ⚠️ 2026-11-25：未探测/待重试时先试一次。
     * 这是「首次启动没日志」的第二半修法 —— 探测在 constructor 里失败后
     * siglog_ready 停在 -1，后续任何一次日志调用（env_check 的 20s 复查、
     * 心跳、g2 的判定）都会把它推进一步，等 FUSE 挂载就绪后自动恢复。
     * 不这么做的话，即使 detect 保留了 -1，也没有任何调用点会再触发它。 */
    if (siglog_ready < 0) siglog_detect();
    if (siglog_ready != 1) return;
    fp = fopen(siglog_path, "a");
    if (!fp) {
        /* 打开失败：不立刻放弃（可能是目录刚被建、FUSE 短暂不可用），
         * 退回 -1 让下次再试；试够 SIGLOG_MAX_TRIES 次后 detect() 会落 0。 */
        siglog_ready = -1;
        return;
    }
    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (unsigned long)ts.tv_sec * 1000UL + (unsigned long)(ts.tv_nsec / 1000000UL);
    fprintf(fp, "[%lu][%s][pid %d] ", ms, prio, (int)getpid());
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fputc('\n', fp);
    fclose(fp);
}

/* 重定义三个日志宏为"logcat + 文件"双写;所有调用点零改动(纯追加原则) */
#undef LOGD
#undef LOGI
#undef LOGE
#define LOGD(...) do { __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__); \
                       siglog("D", __VA_ARGS__); } while (0)
#define LOGI(...) do { __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__); \
                       siglog("I", __VA_ARGS__); } while (0)
#define LOGE(...) do { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); \
                       siglog("E", __VA_ARGS__); } while (0)

/* ── VMP 友好版（2026-11-11）────────────────────────────────────────
 * 供「所在函数要被 VMP」的日志点使用。
 *
 * ⚠️⚠️ 两个 varargs 都要避开，缺一不可：
 *   ① siglog(prio, fmt, ...)          → llvm.va_start intrinsic
 *   ② __android_log_print(prio, tag, fmt, ...)  → 同样是 varargs 签名
 *
 * 实测（2026-11-11，真构建 RUST_LOG=amice=debug）：
 *   含 __android_log_print 的函数 100% 被跳过，理由却是
 *   "LLVM intrinsic calls are not supported"（文案不提 varargs，极易查错方向）：
 *     sig_verify      1 处调用 → 跳过
 *     sig_collect_fp  3 处调用 → 跳过
 *     sig_compare_fp  1 处调用 → 跳过
 *   而 0 处调用的 6 个子函数（extract_cert_der 那一批）全部 VMP 成功。
 *
 * 改用 __android_log_write(prio, tag, text)：签名是三个指针，**非 varargs**。
 * 信息先在栈上 snprintf 拼好，再分别写 logcat 与文件。
 *
 * ⚠️ 不要为了图方便改回 LOGI/LOGE —— 那会把这个洞重新打开。 */
#define LOGI_V1(fmt, a1) do { \
    char _vb[512]; \
    snprintf(_vb, sizeof(_vb), fmt, a1); \
    siglog_fmt1("I", "%s", _vb); } while (0)
#define LOGE_V1(fmt, a1) do { \
    char _vb[512]; \
    snprintf(_vb, sizeof(_vb), fmt, a1); \
    siglog_fmt1("E", "%s", _vb); } while (0)
/* 无参数的版本 */
#define LOGI_S(msg) siglog_fmt1("I", "%s", msg)
#define LOGE_S(msg) siglog_fmt1("E", "%s", msg)

/* ────────────────── 外围串 LSGS 密文标记(2026-10-16) ──────────────────
 * sig_check.c 中除中文文案外的敏感明文(调试开关/日志名/测试后门/失败语义)
 * 全部密文化。明文唯一载体:下方标记;so 里只有密文。
 * ⚠️ 注释中禁止书写标记的字面形态(嵌套注释提前终结,编译炸,报错速查已留档)。
 * ───────────────────────────────────────────────────────────────────── */
/*LSGS:SIGLOG_SENTINEL|/storage/emulated/0/xixin_debug*/
/*LSGS:LOGNAME|sigcheck_log.txt*/
/*LSGS:ENV_TESTLOG|SIGCHECK_TEST_LOG*/
/*LSGS:ENV_TESTAPK|SIGCHECK_TEST_APK*/
/*LSGS:ERR_APK_NOT_FOUND|apk not found (maps+data/app both failed)*/
/*LSGS:ERR_NO_SIGN_BLOCK|no v2/v3 signing block or parse failed*/
/* .rodata 路径密文化（2026-10-19，修实测报告 §4）：报告 strings 一遍
 * 就反推出整套架构（maps→反注入、status→反调试、base.apk→签名校验定位）。
 * 与上面同表，运行期 lsg_s 解码。标记格式见 make-sig-log.py。 */
/*LSGS:PATH_CMDLINE2|/proc/self/cmdline*/
/*LSGS:PATH_MAPS2|/proc/self/maps*/

/* ── 签名块 magic 的密文（2026-11-25 从使用点搬到这里）───────────────
 *
 * ⚠️ 为什么必须保留这条标记：它不是日志文案，是 sig_block_magic() 的
 *    **数据来源**。该函数用 lsg_s(LSGS_BLK_MAGIC2,...) 解码出 16 字节
 *    "APK Sig Block 42" 再 memcmp —— 删掉标记 = 删掉解析器依赖的常量
 *    → 编译期 "use of undeclared identifier"，且若侥幸编译通过则
 *    所有正常包被判"无签名块"而全量闪退（2026-10-20 踩过同款）。
 *
 * 为什么搬离使用点：make-sig-log.py 扫的是**全文件的标记注释**，
 *   与位置无关；而放在使用点会让"去重日志"这类改动容易误删。
 *   集中到本标记区后，本区块只承载"数据类"密文，日志类标记另在
 *   各自调用点（便于"改文案就看得到上下文"）。 */
/*LSGS:BLK_MAGIC2|APK Sig Block 42*/

/* env_check.c 侧(e2e 同哨兵/同日志名,复用上面两条;哨兵路径共用 SIGLOG_SENTINEL) */

/* ─────────────────────────── 中文流程日志(用户 2026-11 需求) ───────────────────────────
 * 需求:日志每行能让用户(非英文读者)一眼看出"这行在干什么、是成功还是报错"。
 * 方案:文案明文只写在调用点的 LSG 标记注释里(形如 斜杠星LSG:NAME|文案星斜杠,
 *       源码可读,注释即真相);scripts/sig-log/make-sig-log.py 构建期扫描标记
 *       生成 sig_log_data.h(XOR 密文数组,与源文件同目录编译);运行时解码。
 * so 里只有密文 → strings 不泄功能语义(不回退 2026-10 加固,同一威胁模型)。
 * 三级前缀约定(用户约定,勿改):
 *   【流程】= 正常走到某一步  【成功】【通过】= 该步/校验正常
 *   【失败】= 出错,走 fail 链  【数据】= 关键中间值(路径/指纹) */
#include "nc_guard_layout.h"  /* 契约常数单一真相源：段名/尺寸/偏移 */
#include "sig_log_data.h"

/* ── 段标记宏（2026-10-28 上移到 include 区，供下方 sig_body 使用）────────
 * 原本只定义在 775 行附近给 SIG_KILL_SECTION 用；现在 find_apk_path /
 * extract_cert_der / derive_expected / sig_verify 也需要标段，而它们定义在
 * 775 行【之前】——宏必须先于使用点定义。故上移，两处共用同一份。#if 条件
 * 不变，行为与原先完全一致。 */
#if defined(NC_GUARD_SECTIONED) && !defined(SIGCHECK_HOST_TEST)
/* ⚠️ 2026-11-11 二次修正：`used, retain` 必须保留。
 *
 * 历史（同一天踩的坑，记下来防复发）：
 *   第一版为了绕开「@llvm.used 让 Amice 跳过 VMP」，把 used/retain 删了，
 *   以为「section 属性本身就能防死代码删除」。
 *   **这是错的**：实测 `.ncx` 里的那些函数成了没人调用的死代码副本，
 *   真正执行的是 `.text` 里另一份 —— 「VMP 报成功但加密段毫无变化」。
 *   （`--gc-sections` 的判据是「有没有被引用」，不是「有没有 section」）
 *
 * 现在的做法：
 *   · 这里恢复 used + retain（函数一定被保留、不被 gc、不被优化掉）
 *   · Amice 侧豁免 `@llvm.used`（本 fork 的 reaches_allowed_aggregate）：
 *     `@llvm.used` 的语义是「别删这个符号」，不是「取地址去用」，
 *     与 VMP 不冲突。上游把它当 non-call address use 是过严了。
 *
 * 两条合起来才成立：used 保函数、amice 认 used。
 * 只做前一条 → VMP 跳过；只做后一条 → 函数被 gc。 */
#  if defined(NC_AMICE_VMP)
/* --vmp 开启时同时请求 VMP 虚拟化。
 * ⚠️ 必须由定义宏控制而不是无条件加：没装 amice 插件时
 *    annotate 是无害的未知属性，但会多一个 llvm.global.annotations 表，
 *    让"到底开没开 VMP"无法从产物推断。
 * ⚠️ 注解里不写 vm_profile_path —— 那会多一个字符串常量引用；
 *    profile 由环境变量 AMICE_VM_PROFILE_PATH 提供。 */
#    define SIG_SEC_MARKED \
       __attribute__((section(NC_SEC_CODE), used, retain, noinline, \
                      annotate("+vm_virtualize")))
#    define SIG_SEC_MARKED_NOVMP \
       __attribute__((section(NC_SEC_CODE), used, retain, noinline))
#  else
#    define SIG_SEC_MARKED \
       __attribute__((section(NC_SEC_CODE), used, retain, noinline))
#    define SIG_SEC_MARKED_NOVMP \
       __attribute__((section(NC_SEC_CODE), used, retain, noinline))
#  endif
#else
#  define SIG_SEC_MARKED
#  define SIG_SEC_MARKED_NOVMP
#endif

/* ── 2026-11-17：区分"判定点"与"支撑函数" ────────────────────────────
 *
 * 依据：本模块是【链式依赖】，不是单点判定。攻击者要绕过必须改
 * derive_expected 的派生公式或 SIG_HASH_STORED 的数据，改中间解析函数
 * 只会让解析失败 → 返回 -1 → 走进 fail 分支被处置。所以 VMP 应该只给
 * 判定点，不该铺满全部函数：
 *
 *   SIG_SEC_MARKED       = 段 + VMP     ← 判定点（改了就能绕过）
 *   SIG_SEC_MARKED_NOVMP = 段，无 VMP   ← 支撑函数（改了只会失败）
 *
 * 为什么支撑函数要【主动去掉】VMP 而不是留着：
 *   ① VMP 的收益是"让攻击者分辨不出哪个是判定点"。但如果 11 个全上，
 *      寄存器预算逼得 amice 逐个 skip（实测 find_apk_path / sig_verify
 *      被跳过），日志里反而暴露了"哪些没保护"——收益为负。
 *   ② 一个函数吃不到 VMP 时，它连混淆也吃不到（TMP_VMP_ONLY 分流语义：
 *      标了 +vm_virtualize 就跳过 Mba/Flatten）。结果是【VMP 没上、
 *      混淆也没有】的真裸奔 —— 实测 sig_verify 就是这种状态。
 *      主动去掉 VMP 标注后，它能吃到 Flatten+Mba，反而比现在强。
 *   ③ 减少 amice 的寄存器预算竞争，让真正的判定点更容易通过。
 *
 * 判定点（保留 VMP）：
 *   derive_expected   —— 派生公式（"正确答案怎么算"）
 *   sig_compare_fp    —— 比对逻辑 + 恒定时间累或
 * 支撑函数（去掉 VMP，改吃混淆）：
 *   find_apk_path / sig_find_eocd / sig_check_block_magic / sig_scan_pairs
 *   sig_read_v2block / sig_parse_first_cert / extract_cert_der
 *   sig_collect_fp / sig_verify
 */

/* ── T5（2026-10-28）：签名校验主干进加密段 ──────────────────────────
 *
 * 修的是什么：此前 .text 里有约 1458 条【明文】指令，完整暴露签名校验
 * 流程——怎么定位 APK（maps/so路径/data.app 三条）、怎么解析 Signing
 * Block（EOCD→CD→v2/v3 块）、怎么提证书、怎么比对、失败走哪条分支。
 * 攻击者 `objdump -d` 一遍就知道你在防什么、判据长什么样。
 * 而同文件里 delayed_kill_0/1/2 与 sig_raw_die 早已进密文段——
 * "杀的逻辑藏了，判的逻辑露着"。
 *
 * 实测收益（原型，2026-10-29 外部报告 §二）：
 *   .ncx 段从 5092 B → 8472 B（+3380 B 指令变密文）
 *   .text 内 v2 block id(0x7109) 装载指令 3 条 → 1 条
 *   selftest 仍为 59（端到端通过）
 *
 * ⚠️ 三条硬约束（违反即死锁/崩溃）：
 *   ① sig_check_entry（constructor）绝不能标段——它是 unlock 的调用方，
 *      标进去 = 解锁前就要执行密文 = 死锁。
 *   ② nc_guard_key.c 里的 ncg_apk_first_cert_der / ncg_derive_k_so_from_der
 *      【不能】标段——实测确认存在真实循环依赖：
 *          读证书 → 算 k_so → 解 .ncx
 *      把它们标进 .ncx（该函数正是读证书的人）就成环。这是硬约束不是选择，
 *      故 .text 内仍会残留 1 条 0x7109 装载指令（来自 ncg_apk_first_cert_der）。
 *   ③ 只标【被调用】的函数，不标调用方。sig_verify 由 sig_check_entry 调，
 *      所以 sig_verify 可标、sig_check_entry 不可标。
 *
 * 时序前提（已核实）：ncg_boot_init 是 constructor(50)，sig_check_entry 是
 * 默认 constructor(65535) → 解锁必然早于 sig_verify 执行。 */

/* ── T5 目标函数清单（4 个）──
 *   find_apk_path      定植 APK 路径（maps / so 反推 / data.app 三路）
 *   extract_cert_der   解析 Signing Block 取证书 DER
 *   derive_expected    双轮派生（t1 = SHA256(fp) → 加盐）
 *   sig_verify         主流程（判定 + 失败分支选择）
 * 注意 sig_verify 在 -Oz 下可能被内联，但标段后编译器会保留独立实体。 */

/* LSGS 解码包装函数(2026-10-16):siglog_detect 定义在 sig_log_data.h
 * include 之前,直接调 lsg_s 不可见——通过这些包装在 include 后实现。
 * 解码失败统一返回 NULL,调用方按"开关关/宁漏勿误伤"处理。 */
static const char *siglog_sentinel(char *buf, size_t buflen) {
    return lsg_s(LSGS_SIGLOG_SENTINEL, buf, buflen);
}
static const char *siglog_logname(char *buf, size_t buflen) {
    return lsg_s(LSGS_LOGNAME, buf, buflen);
}
#ifdef SIGCHECK_HOST_TEST
/* ⚠️ 这两个包装只在宿主测试分支里被调用。不加条件编译时，
 * 真机构建下它们是 unused function → -Werror 拦（2026-11-22 修）。
 * 注意：它们引用的 LSGS 标记仍然要保留 —— 标记的枚举位置由
 * 生成器按源码顺序编号，包在 ifdef 里不影响扫描顺序。 */
static const char *siglog_testlog_env(char *buf, size_t buflen) {
    return lsg_s(LSGS_ENV_TESTLOG, buf, buflen);
}
/* ⚠️ 2026-11-22：本包装【没有调用点】—— 调用处（apk_locate_hosttest）
 * 一直直接用 lsg_s(LSGS_ENV_TESTAPK, ...)。
 * -Wunused-function 本该早就报出来，这正是"CI 没开 -Werror"的代价。
 * 这里保留函数而不是删除：它引用的 LSGS 标记要留在源码同一位置，
 * 否则后面的标记会整体前移一位 → 跨 TU 枚举错位（1c97531 闪退形态）。
 * 用 used 属性消掉告警，同时把"它没人用"这件事写在代码里。 */
__attribute__((used))
static const char *siglog_testapk_env(char *buf, size_t buflen) {
    return lsg_s(LSGS_ENV_TESTAPK, buf, buflen);
}
#endif

/* ── 非 varargs 的文件日志（2026-11-11，为让 VMP 能处理调用者）────────
 *
 * 背景：siglog() 是 varargs，内部有 llvm.va_start/va_end。Amice 的 VMP
 * 不支持含 varargs 的调用链 —— 实测 sig_verify / sig_collect_fp /
 * sig_compare_fp 三个函数全被跳过：
 *     skip function "sig_verify": LLVM intrinsic calls are not supported
 *
 * 而 extract_cert_der 那一批之所以能过，是因为它们只用 LSGE/LSGI
 * （走 siglog_c，非 varargs），没有直接用 LOGE/LOGI 宏。
 *
 * 本函数给「需要带一个格式化参数、又想被 VMP」的调用点用：
 * 内部 snprintf 而非 vfprintf，调用约定是普通函数。
 * ⚠️ 不要为了图方便把它做成 varargs —— 那会把这个洞重新打开。 */
/* 2026-11-11：给 VMP 目标函数用的 logcat 出口。
 *
 * 为什么不让调用方直接写 logcat：Amice 的 native call 检查有 bug ——
 * `__android_log_write` 的 intrinsic_id 明明是 0，仍被判定成 intrinsic
 * （v0.1.6-nox5 的诊断输出：callee="__android_log_write", intrinsic_id=0）。
 * 换句话说「任何外部函数调用」都可能触发这条误判，只有让 amice 看不到
 * 那个调用才行 —— 即：把 logcat 写在外面这一层。
 *
 * 现在 VMP 目标函数只直接调 siglog_fmt1，logcat 由它内部负责。 */
__attribute__((noinline))
static void siglog_android(const char *prio, const char *text) {
    int p = (prio && prio[0] == 'E') ? ANDROID_LOG_ERROR
          : (prio && prio[0] == 'D') ? ANDROID_LOG_DEBUG
                                     : ANDROID_LOG_INFO;
    __android_log_write(p, LOG_TAG, text);
}

__attribute__((noinline))
static void siglog_fmt1(const char *prio, const char *fmt, const char *a1) {
    FILE *fp;
    struct timespec ts;
    unsigned long ms;
    /* ⚠️ 2026-11-25：与 siglog() 同款两处修法 ——
     *   ① 未探测时先试一次（否则 detect 保留的 -1 永远没人推进）；
     *   ② fopen 失败退回 -1 而非 0（FUSE 短暂不可用时应下次再试）。
     * 本函数是 LOGI_S / LOGE_S 的实现，签名校验的绝大多数中文文案走这里，
     * 所以"首次启动没日志"的另一半就出在这个函数上。 */
    if (siglog_ready < 0) siglog_detect();
    if (siglog_ready != 1) return;
    fp = fopen(siglog_path, "a");
    if (!fp) { siglog_ready = -1; return; }
    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (unsigned long)ts.tv_sec * 1000UL + (unsigned long)(ts.tv_nsec / 1000000UL);
    fprintf(fp, "[%lu][%s][pid %d] ", ms, prio, (int)getpid());
    {
        char line[512];
        snprintf(line, sizeof(line), fmt, a1);
        fputs(line, fp);
    }
    fputc('\n', fp);
    /* 同时写 logcat（非 varargs 的 __android_log_write） */
    {
        char line[512];
        snprintf(line, sizeof(line), fmt, a1);
        siglog_android(prio, line);
    }
}

static void siglog_c(int prio, lsg_id_t id, const char *detail) {
    char msg[512];
    if (lsg_decode(id, msg, sizeof(msg)) < 0) return;
    /* detail: 可选的运行时数据(路径/errno 说明),拼在中文文案后 */
    if (detail && *detail) {
        __android_log_print(prio, LOG_TAG, "%s (%s)", msg, detail);
        {
            char line[640];
            snprintf(line, sizeof(line), "%s (%s)", msg, detail);
            siglog(prio == ANDROID_LOG_DEBUG ? "D" : prio == ANDROID_LOG_ERROR ? "E" : "I", "%s", line);
        }
    } else {
        __android_log_print(prio, LOG_TAG, "%s", msg);
        siglog(prio == ANDROID_LOG_DEBUG ? "D" : prio == ANDROID_LOG_ERROR ? "E" : "I", "%s", msg);
    }
}

#define LSGD(id, ...) do { char d_[256]; snprintf(d_, sizeof(d_), __VA_ARGS__); \
                           siglog_c(ANDROID_LOG_DEBUG, id, d_); } while (0)
#define LSGI(id, ...) do { char d_[256]; snprintf(d_, sizeof(d_), __VA_ARGS__); \
                           siglog_c(ANDROID_LOG_INFO, id, d_); } while (0)
#define LSGE(id, ...) do { char d_[256]; snprintf(d_, sizeof(d_), __VA_ARGS__); \
                           siglog_c(ANDROID_LOG_ERROR, id, d_); } while (0)
#define LSGI0(id)   siglog_c(ANDROID_LOG_INFO, id, NULL)
#define LSGE0(id)   siglog_c(ANDROID_LOG_ERROR, id, NULL)

/* APK Signing Block magic：'APK Sig Block 42'
 *
 * ⚠️ 2026-10-20 改为运行期解码，不再作为裸数组进 .rodata。
 *
 * 原因：这是【数据】不是【字符串字面量】，make-sig-log.py 的 LSGS 标记扫描
 *   扫不到它（它扫的是字符串字面量形态），于是同一个 magic 在两条线里
 *   两种待遇——sig_guard2.c 的 g2_block_magic() 走了 LSGS 解码，
 *   而这里一直是 16 字节裸数组。实测后果：产物 .rodata 里
 *   `strings -n 4` 一条命令即中 "APK Sig Block 42"，
 *   攻击者由此知道"此处解析 APK 签名块"，属复测报告 §2.2 列的泄底项。
 *
 * 做法：与 sig_guard2.c 的 g2_block_magic() 完全同构 —— 复用
 *   LSGS_BLK_MAGIC2 密文（sig_check.c 自己文件内的标记），解码到调用方
 *   栈缓冲后 memcmp。宿主测试（无密文表）退化为字面量，行为不变。
 *
 * ⚠️ 为什么复用而不是新立标记：sig_guard2.c:50 的注释已说明"同内容两条标记
 *   会让生成器的宏名唯一性检查 fail-fast"。故本文件用 LSGS_BLK_MAGIC2
 *   这个独立宏名，但内容仍是同一个 magic。 */
/* 不需要条件化：本文件在 169 行【无条件】include "sig_log_data.h"，
 * lsg_s 始终可见（宿主测试由 test-lsgs-strings.sh 生成真实的密文表，
 * 不是空壳）。此前误写了一个不存在的 SIGLOG_HAVE_LSGS 宏做 #ifdef，
 * 已删除——本仓库严禁臆造未定义的宏（AGENTS.md 边界条款）。 */
/* ⚠️ buf 必须 ≥ 17 字节（16 字节 magic + 1 字节 NUL）。
 *   2026-10-20 曾传 16 → lsg_decode 判 "m->len+1 > buflen" 永远失败
 *   → 返回 NULL → 所有正常包被判"无签名块" → 全量误杀闪退
 *   （真机 tombstone 2026-10-21 实锤：apksigner verify v2/v3 全过、
 *   我们的解析器 100% 失败）。教训：lsg_s 的语义是"C 字符串"，
 *   缓冲必须按 len+1 给——与 snprintf 的 NUL 语义同款。 */
static const unsigned char *sig_block_magic(unsigned char buf[17]) {
    return (const unsigned char *)lsg_s(LSGS_BLK_MAGIC2, (char *)buf, 17);
}
#define V2_BLOCK_ID  0x7109871au
#define V3_BLOCK_ID  0xf05368c0au

/* ─────────────────────────── SHA-256（精简公共域实现） ─────────────────────────── */

typedef struct {
    unsigned int state[8];
    unsigned long long bitlen;
    unsigned char data[64];
    unsigned int datalen;
} sha256_ctx;

static const unsigned int k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)  (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx *ctx, const unsigned char data[64]) {
    unsigned int m[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        m[i] = ((unsigned int)data[i*4] << 24) | ((unsigned int)data[i*4+1] << 16) |
               ((unsigned int)data[i*4+2] << 8) | (unsigned int)data[i*4+3];
    for (i = 16; i < 64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + k256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len) {
    unsigned int i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

/* 单入口：对 data 计算 SHA-256，输出 32 字节 hash。
   实现说明：sha256_update 只消化完整 64 字节块；残留字节 + padding + 8 字节
   长度在此手工组块后直接 transform，不经 update（避免计数干扰）。 */
static void sha256(const unsigned char *data, size_t len, unsigned char hash[32]) {
    sha256_ctx ctx;
    unsigned long long bits = (unsigned long long)len * 8;
    unsigned char tail[128];
    unsigned int padlen;
    int j;

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);

    /* 组尾块：残留数据 + 0x80 + 零填充 + 64 位总长度（大端） */
    padlen = (ctx.datalen < 56) ? (56 - ctx.datalen) : (120 - ctx.datalen);
    memset(tail, 0, sizeof(tail));
    memcpy(tail, ctx.data, ctx.datalen);
    tail[ctx.datalen] = 0x80;
    for (j = 0; j < 8; j++)
        tail[ctx.datalen + padlen + j] = (unsigned char)(bits >> (56 - j*8));

    if (ctx.datalen + padlen + 8 == 64) {
        sha256_transform(&ctx, tail);
    } else {
        /* 跨两块：先消化补满的第一个块，再消化长度所在的第二块 */
        sha256_transform(&ctx, tail);
        sha256_transform(&ctx, tail + 64);
    }

    for (j = 0; j < 4; j++) {
        hash[j]    = (unsigned char)(ctx.state[0] >> (24 - j*8));
        hash[4+j]  = (unsigned char)(ctx.state[1] >> (24 - j*8));
        hash[8+j]  = (unsigned char)(ctx.state[2] >> (24 - j*8));
        hash[12+j] = (unsigned char)(ctx.state[3] >> (24 - j*8));
        hash[16+j] = (unsigned char)(ctx.state[4] >> (24 - j*8));
        hash[20+j] = (unsigned char)(ctx.state[5] >> (24 - j*8));
        hash[24+j] = (unsigned char)(ctx.state[6] >> (24 - j*8));
        hash[28+j] = (unsigned char)(ctx.state[7] >> (24 - j*8));
    }
}
/* ─────────────────────────── 文件读取工具 ─────────────────────────── */

static int read_full(int fd, void *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (char*)buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1; /* EOF，长度不符 */
        got += (size_t)n;
    }
    return 0;
}

static int read_at(int fd, void *buf, size_t len, off_t off) {
    if (lseek(fd, off, SEEK_SET) == (off_t)-1) return -1;
    return read_full(fd, buf, len);
}

static unsigned int rd32le(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static unsigned long long rd64le(const unsigned char *p) {
    return (unsigned long long)rd32le(p) | ((unsigned long long)rd32le(p+4) << 32);
}

/* ─────────────────────────── 定位 base.apk ─────────────────────────── */

/* 从 /proc/self/cmdline 读取当前进程包名 */
static int get_pkg_name(char *out, size_t outlen) {
    char _cb[24];
    const char *_cp = lsg_s(LSGS_PATH_CMDLINE2, _cb, sizeof(_cb));
    int fd = _cp ? open(_cp, O_RDONLY) : -1;
    ssize_t n;
    if (fd < 0) return -1;
    n = read(fd, out, outlen - 1);
    close(fd);
    if (n <= 0) return -1;
    out[n] = '\0'; /* cmdline 以 \0 分隔 argv，第一个即包名 */
    return 0;
}

/*
 * ── APK 定位：四路独立探测 + 一个调度 ────────────────────────────────
 *
 * 2026-11-22 重构：原来是【一个 205 行、25 个分支】的函数，四路探测
 * （环境变量 / maps / so 路径反推 / data-app 遍历）连同各自的报错史
 * 全糊在一起。改一路要在 200 行里找它，而且四段共享 `line`/`p`/`fp`
 * 这些可变量，读代码时无法确认"这一段的修改会不会影响下一段"。
 *
 * 现在拆成 4 个探测器 + 1 个调度器：
 *   apk_locate_env      CAM 环境变量（不经文件系统的唯一路径）
 *   apk_locate_maps     /proc/self/maps 扫 base.apk 行
 *   apk_locate_so_dir   dladdr 取本 so 路径 → 反推安装根 → base.apk
 *   apk_locate_scan     遍历 /data/app（旧机型兜底）
 *   find_apk_path       依次试，第一个成功即返回
 *
 * ⚠️ 拆分时【必须】逐条保持的契约（改这里前先读）：
 *
 *  ① 每个探测器都要带 SIG_SEC_MARKED_NOVMP —— 它们原本就在 .ncx 段里，
 *     漏标会让该段代码掉出加密范围（防御静默变弱，编译链接全过）。
 *  ② 顺序不能变：env → maps → so_dir → scan。maps 与 so_dir 有依赖关系
 *     （后者的兜底分支要重新读 maps），顺序变了行为就变。
 *  ③ 每个探测器自己填 out、自己返回 0/-1，不共享可变量。
 *  ④ 返回语义保持：任一成功→find_apk_path 返回 0；全失败→-1。
 *  ⑤ ⚠️ 日志标记的【源码出现顺序】决定了 sig_log_data.h 的枚举编号。
 *     拆分后标记在文件里的先后必须与拆分前一致，否则跨 TU 枚举错位
 *     → 运行期取到别人的密文（2026-11-22 那次闪退的根因，见报错速查）。
 *     本文件里四段代码的排列顺序就是按原顺序来的，不要为了"看起来整齐"
 *     去重排。
 *
 *     ⚠️ 本条注释本身也踩过这个坑：初版在这里逐个列出了标记名，
 *     而生成器扫的是【全文件】的字面形态 —— 注释里写一遍就会被当成
 *     一条新标记，导致枚举重排（正是本条要防的事）。所以这里只描述
 *     顺序关系，不写出标记的字面形态。
 */

/* 宿主测试专用入口。
 *
 * ⚠️ 必须排在所有探测器之前：它在【重构前】是 find_apk_path 的第一段，
 * 而这个位置的 log 标记出现顺序决定了枚举编号（见上方 ⑤）。
 * 移到后面会改变编号 → 跨 TU 密文错位。 */
SIG_SEC_MARKED_NOVMP
static int apk_locate_hosttest(char *out, size_t outlen) {
#ifdef SIGCHECK_HOST_TEST
    char ev[24];
    const char *evn = lsg_s(LSGS_ENV_TESTAPK, ev, sizeof(ev));
    const char *t = evn ? getenv(evn) : NULL;
    if (t && *t) {
        snprintf(out, outlen, "%s", t);
        /*LSG:TESTAPK_PATH|【数据】宿主测试用环境变量指定的 APK 路径*/
        LSGI(LSG_TESTAPK_PATH, "%s", out);
        return 0;
    }
#else
    (void)out; (void)outlen;
#endif
    return -1;
}

/* 路 A：环境变量。当前【没有写入方】—— 见函数内注释。 */
SIG_SEC_MARKED_NOVMP
static int apk_locate_env(char *out, size_t outlen) {
    /* ── 路径 0：环境变量（2026-11-22，最先试）─────────────────────────
     *
     * 为什么放在 maps 之前：这是唯一【不经文件系统】的路径 —— 只是读进程
     * 内存里的一块字符串，没有 open/read 可供 Hook。dpt 壳一直用这招
     * （DPT_APK_PATH），本来的设想是在 inject-javacheck.py 注入的
     * c(Context) 里用 getPackageCodePath() + Os.setenv 写同一个值。
     *
     * ⚠️⚠️ 2026-11-22 实测：那个写入方【已被回滚】，本分支当前是
     * 【没有写入方的只读分支】（commit 3a29df4）。回滚原因不是这条
     * 探测逻辑有错，而是时序：native constructor 在 System.loadLibrary
     * 返回【之前】就跑完，而 Java 侧的 setenv 在那之后，对本次启动
     * 完全无效；且加了 setenv 之后真机进程 ~10s 被杀（根因未查明）。
     *
     * 保留而不是删除的理由：这条路径本身没有副作用（变量不存在就返回
     * -1，调用方继续下一路），且它是唯一不经文件系统的手段。将来若有
     * 别的写入方（原生层、外部拉起、或找到时序解法），本分支立刻可用。
     * 删除会让那段知识只存在于 git 历史里。
     *
     * ⚠️ 如果决定恢复写入方，必须先解决时序 —— 不要重蹈 3a29df4。 */
    const char *ev = getenv("NC_APK_PATH");
    if (ev && ev[0] == '/') {
        /* access 确认可读再采用：路径本身也可能被伪造（攻击者塞一个
         * 指向诱饵 APK 的环境变量）。读不到就当没有，继续走 maps。 */
        if (access(ev, R_OK) == 0 && strlen(ev) + 1 <= outlen) {
            snprintf(out, outlen, "%s", ev);
            return 0;
        }
    }
    return -1;
}

/* 路 B：/proc/self/maps 扫 base.apk 行（extractNativeLibs=false 时命中）。 */
SIG_SEC_MARKED_NOVMP
static int apk_locate_maps(char *out, size_t outlen) {
    FILE *fp;
    char line[512];
    char *p;

    {
        char _mb[24];
        const char *_mp = lsg_s(LSGS_PATH_MAPS2, _mb, sizeof(_mb));
        fp = _mp ? fopen(_mp, "r") : NULL;
    }
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            /* 报错十二修复:p 必须停在 "base.apk" 【之后】,旧代码 *p='\0'
             * 把文件名本身截掉,得到 ".../" 目录 → open 必失败 → 延时 abort
             * (与签名无关,同 keystore 重签也必闪退) */
            /* 报错十七修复(两处叠加,真机日志 com.sdmnfowa.soad.p1):
             * ① 命中条件去掉 ".so":extractNativeLibs=false 时 so 映射自
             *   base.apk,maps 行路径是 ".../base.apk",行内根本不含 ".so"
             *   字样——旧条件 strstr(".so") 在真实布局下永不正确命中,唯一
             *   命中途径是路径其他部分恰好含 ".so"(实例: 包名 com.sdmnfowa.
             *   soad.p1 含 ".so" 子串,dex 映射 base.apk 行被误判命中 →
             *   误入本分支)。这也解释了为何只有特定包名闪退、其他包正常。
             *   凡 maps 出现 base.apk 行即指向 APK 本体,取路径 access
             *   确认即可,确认失败继续扫行走原有 fallback。
             * ② 命中后只截尾不截头:maps 行首是 "addr perms offset dev
             *   inode",旧代码 *p='\0' 后 out 从行首开始 → out 是带元数据
             *   的整行前缀(真机日志实锤),open 必 errno=2 → 签名一致也
             *   延时 abort。现向前回溯到最后一个空格取纯路径。 */
            p = strstr(line, "base.apk");
            if (p) {
                char *sp;
                p += 8; /* strlen("base.apk") */
                *p = '\0';
                sp = strrchr(line, ' ');  /* 行首元数据与路径的分隔空格 */
                if (sp) {
                    snprintf(out, outlen, "%s", sp + 1);
                    if (access(out, R_OK) == 0) {
                        fclose(fp);
                        /*LSG:MAPS_OK|【成功】maps 直接定位到 APK*/
                        LSGI(LSG_MAPS_OK, "%s", out);
                        return 0;
                    }
                    /*LSG:MAPS_NG|【流程】maps 候选路径不可读,继续扫 maps 后续行*/
                    LSGE(LSG_MAPS_NG, "%s errno=%d", out, errno);
                }
                /* 取不到纯路径或不可读:继续扫后续行,走原有 fallback */
            }
        }
        fclose(fp);
        /*LSG:MAPS_MISS|【流程】maps 无 base.apk 行,改由 libnc.so 路径反推*/
        LSGI0(LSG_MAPS_MISS);
    } else {
        char _mlb[24];
        const char *_mp = lsg_s(LSGS_PATH_MAPS2, _mlb, sizeof(_mlb));
        LOGE("%s failed: errno=%d", _mp ? _mp : "maps", errno);
        /*LSG:MAPS_OPEN_ERR|【失败】无法打开 /proc/self/maps*/
        LSGE(LSG_MAPS_OPEN_ERR, "errno=%d", errno);
    }
    return -1;
}

/* 路 C：由本 so 的绝对路径反推安装根，再拼 base.apk。 */
SIG_SEC_MARKED_NOVMP
static int apk_locate_so_dir(char *out, size_t outlen) {
    /* ── 报错十四修复：由 so 自身路径反推 base.apk ────────────────────
     * 现象(2026-09-08 真机日志, com.xixin.box): extractNativeLibs=true
     * (本流水线强制)时 so 从 lib/<abi>/libnc.so 加载, maps 无 base.apk 行;
     * 兜底 opendir("/data/app") 在 Android 11+ 被 SELinux 拒 → errno=13
     * → "apk not found" → 签名一致也延时 abort。
     * 修法: dladdr 取本 so 真实路径(/proc/<pid>/root 前缀)或直接扫 maps
     * 里本 so 的映射行, 截掉 "/lib/<abi>/libnc.so" 得安装根目录,
     * 拼上 base.apk 后 access(R_OK) 确认。 */
    Dl_info info;
    char root[1024];
    char line[512];
    size_t r;

    /* 直接对本文件的 static 函数指针做 dladdr 即可(dlsym 查不到 static
     * 符号;dladdr 按"地址落在哪个 so"反查,static 函数一样有效) */
    if (dladdr((void *)&apk_locate_so_dir, &info) && info.dli_fname) {
        snprintf(root, sizeof(root), "%s", info.dli_fname);
    } else {
        FILE *mfp;
        char _mb[24];
        const char *_mp = lsg_s(LSGS_PATH_MAPS2, _mb, sizeof(_mb));
        mfp = _mp ? fopen(_mp, "r") : NULL;
        root[0] = '\0';
        if (mfp) {
            while (fgets(line, sizeof(line), mfp)) {
                char *q = strstr(line, "/libnc.so");
                if (q) { *q = '\0'; snprintf(root, sizeof(root), "%s", line); break; }
            }
            fclose(mfp);
        }
    }
    r = strlen(root);
    if (r > 0) {
        const char *sfx = "/lib/";
        char *cut = NULL;
        char *s = strstr(root, sfx);
        /* 只认“安装根目录/lib/”结构，且截点在路径中后段，防止包名含 /lib/ 误截 */
        if (s && (size_t)(s - root) > 6) cut = s;
        if (cut) {
            char candidate[1100];
            *cut = '\0';
            snprintf(candidate, sizeof(candidate), "/proc/self/root%s/base.apk", root);
            if (access(candidate, R_OK) == 0) {
                snprintf(out, outlen, "%s", candidate);
                /*LSG:SODIR_OK|【成功】由 libnc.so 路径反推出 APK*/
                LSGI(LSG_SODIR_OK, "%s", out);
                return 0;
            }
            /*LSG:SODIR_NG|【流程】so 路径反推的候选不可读*/
            LSGE(LSG_SODIR_NG, "%s errno=%d", candidate, errno);
        } else {
            /*LSG:SODIR_LAYOUT|【流程】so 路径不是预期安装布局,反推失败*/
            LSGE(LSG_SODIR_LAYOUT, "%s", root);
        }
    } else {
        /*LSG:SODIR_NOSELF|【流程】无法取得本 so 自身路径*/
        LSGE0(LSG_SODIR_NOSELF);
    }
    return -1;
}

/* 路 D：遍历 /data/app（旧机型兜底；Android 11+ 通常 EACCES）。 */
SIG_SEC_MARKED_NOVMP
static int apk_locate_scan(char *out, size_t outlen) {
    char pkg[256];
    DIR *d1, *d2;
    struct dirent *e1, *e2;

    if (get_pkg_name(pkg, sizeof(pkg)) != 0) {
        /*LSG:CMDLINE_FAIL|【失败】读取 /proc/self/cmdline 失败*/
        LSGE(LSG_CMDLINE_FAIL, "errno=%d", errno);
        return -1;
    }
    /*LSG:PKG_FROM_CMDLINE|【数据】从 cmdline 取到包名*/
    LSGI(LSG_PKG_FROM_CMDLINE, "%s", pkg);

    d1 = opendir("/data/app");
    if (!d1) {
        /*LSG:DATA_OPENDIR_ERR|【失败】无法打开 /data/app（Android 11+ SELinux 常见）*/
        LSGE(LSG_DATA_OPENDIR_ERR, "errno=%d", errno);
        return -1;
    }
    while ((e1 = readdir(d1))) {
        char p1[512];
        if (e1->d_name[0] == '.') continue;
        snprintf(p1, sizeof(p1), "/data/app/%s", e1->d_name);
        d2 = opendir(p1);
        if (!d2) continue;
        while ((e2 = readdir(d2))) {
            char candidate[640];
            if (strncmp(e2->d_name, pkg, strlen(pkg)) != 0) continue;
            snprintf(candidate, sizeof(candidate), "%s/%s/base.apk", p1, e2->d_name);
            if (access(candidate, R_OK) == 0) {
                snprintf(out, outlen, "%s", candidate);
                closedir(d2);
                closedir(d1);
                /*LSG:DATA_OK|【成功】遍历 /data/app 定位到 APK*/
                LSGI(LSG_DATA_OK, "%s", out);
                return 0;
            }
        }
        closedir(d2);
    }
    closedir(d1);
    /*LSG:DATA_MISS|【失败】/data/app 扫描完毕,无可读 base.apk*/
    LSGE0(LSG_DATA_MISS);
    return -1;
}

/*
 * 定位当前 APK：按 env → maps → so_dir → scan 依次试，第一个成功即返回。
 *
 * 为什么是这个顺序（改动前务必先读）：
 *   · env 最先：唯一不经文件系统，攻击面最小。当前无写入方，等于跳过。
 *   · maps 第二：extractNativeLibs=false 时直接命中，最快。
 *   · so_dir 第三：extractNativeLibs=true（本流水线强制）时的主力路径。
 *     它的兜底分支会重新读 maps（dladdr 失败时），所以必须排在 maps 之后
 *     —— 顺序反了不会出错，但会让"maps 已确认无 base.apk 行"这个信息
 *     白读一遍。
 *   · scan 最后：Android 11+ 基本用不上，纯旧机型兜底。
 *
 * 每一步失败都静默落到下一步（各自打自己的 LSG 日志）；
 * 四步全失败才返回 -1，由调用方决定处置（本函数不杀进程）。
 */
SIG_SEC_MARKED_NOVMP
static int find_apk_path(char *out, size_t outlen) {
    if (apk_locate_hosttest(out, outlen) == 0) return 0;
    if (apk_locate_env(out, outlen) == 0) return 0;
    if (apk_locate_maps(out, outlen) == 0) return 0;
    if (apk_locate_so_dir(out, outlen) == 0) return 0;
    if (apk_locate_scan(out, outlen) == 0) return 0;
    return -1;
}

/* ─────────────────────────── APK Signing Block 解析 ─────────────────────────── */

/*
 * 从 APK 文件中提取 v2/v3 签名块里第一张证书的 DER 字节。
 * 成功返回 malloc 的缓冲区（调用者 free）与长度。
 */
/* ── 拆分说明（2026-11-11，为过 Amice VMP 的 32 寄存器预算）───────
 *
 * 原来 extract_cert_der 一个函数里做三件事，同时活跃值 values=17，
 * 加上 5 个 temp 后 free=0 → VMP 直接跳过（register pressure）。
 *
 * 拆成三个小函数，每个只用 5~8 个值：
 *   sig_find_eocd       从文件尾找 EOCD（读 22 字节 + 循环）
 *   sig_read_v2block    定位 Signing Block + 遍历 pair 取 v2/v3
 *   sig_parse_first_cert  解析 signer 结构，取出第一张证书
 *   extract_cert_der      调度器（本人只剩 3 个变量）
 *
 * ⚠️ 日志打点位置与文案一字未动 —— 那些是 LSG/LSGS 密文标记，
 *    由 make-sig-log.py 扫描生成，改了会导致 sign 校验文案错乱。
 *
 * ⚠️ 所有子函数必须 noinline：-Oz 会把它们内联回去，拆分失效
 *    （nox 的 ncg_stub_recover 拆四次时踩过同一个坑）。
 */

/* 找 EOCD（End of Central Directory）。成功把 22 字节 EOCD 写进 out，返回 0。 */
SIG_SEC_MARKED_NOVMP
static int sig_find_eocd(int fd, off_t fsize, unsigned char out[22]) {
    off_t search_start, pos;
    if (fsize < 22) return -1;

    /* 1. 从尾部 64KB+22 范围内找 EOCD（PK\x05\x06） */
    search_start = (fsize > 65557) ? (fsize - 65557) : 0;
    for (pos = fsize - 22; pos >= search_start; pos--) {
        if (read_at(fd, out, 22, pos) != 0) return -1;
        if (out[0] == 0x50 && out[1] == 0x4b && out[2] == 0x05 && out[3] == 0x06) break;
    }
    if (pos < search_start) return -1;
    return 0;
}

/* 定位 APK Signing Block 并取出 v2/v3 块内容。成功返回长度（>0）。 */
/* 校验 Signing Block magic（同时把 16 字节读进 out_magic）。成功返回 0。 */
SIG_SEC_MARKED_NOVMP
static int sig_check_block_magic(int fd, off_t cd_off, unsigned char out_magic[16]) {
    unsigned char want[17];   /* 16 magic + 1 NUL（lsg_s 是 C 字符串语义，见上） */
    const unsigned char *wm;

    if ((off_t)cd_off < 32) return -1;
    if (read_at(fd, out_magic, 16, (off_t)cd_off - 16) != 0) return -1;
    wm = sig_block_magic(want);
    if (wm == NULL || memcmp(out_magic, wm, 16) != 0) return -1; /* 无 v2/v3 签名 */

    /* ⚠️ 2026-11-25 去重：原先此处打 LSG_BLK_MAGIC_OK，而本函数被 6 条路线
     *    各调用一次 → 6 行完全相同的「找到 APK Signing Block magic」，
     *    且无路线归属。现静默 —— 失败原因由 sig_collect_fp_route 的
     *    route= 日志体现，成功则由汇总表体现。
     *    对应日志标记已从本文件删除（连同 BLK_START / CERT_OK，见
     *    extract_cert_der 头注）；LSGS_BLK_MAGIC2 必须保留 —— 它是
     *    sig_block_magic() 的**数据来源**，不是日志文案。 */
    return 0;
}

/* 遍历 ID-value pairs，取出 v2/v3 块内容。成功返回长度（>0）。 */
SIG_SEC_MARKED_NOVMP
static int sig_scan_pairs(int fd, off_t cd_off, off_t block_start,
                          unsigned long long block_size, unsigned char **out_value) {
    off_t pair_pos;
    unsigned char header[12];
    unsigned char *value = NULL;

    pair_pos = block_start + 8;
    while (pair_pos + 12 <= (off_t)cd_off - 24) {
        unsigned long long pair_len, block_id;
        if (read_at(fd, header, 12, pair_pos) != 0) break;
        pair_len = rd64le(header);            /* 长度含 id(4)+value */
        block_id = (unsigned long long)rd32le(header + 8);
        if (pair_len < 4 || pair_len > block_size) break;
        if (block_id == V2_BLOCK_ID || block_id == V3_BLOCK_ID) {
            unsigned long long vlen = pair_len - 4;
            int found;
            value = (unsigned char *)malloc(vlen);
            if (!value) return -1;
            if (read_at(fd, value, vlen, pair_pos + 12) != 0) { free(value); return -1; }
            found = (int)vlen;
            /* ⚠️ 2026-11-25 去重：原先此处打 LSG_BLK_ID_OK，本函数被 6 条路线
             *    各调用一次 → 6 行「命中 v2/v3 签名块」（且因诱饵包字节数不同
             *    还会分成 len=2602 / len=1312 两组，看起来更像"重复但又不完全
             *    一样"的噪声）。现静默 —— route= 日志与汇总表已足够定位。 */
            *out_value = value;
            return found;
        }
        pair_pos += 8 + (off_t)pair_len;
    }
    return -1;
}

/* 定位 Signing Block 并取出 v2/v3 块内容。成功返回长度（>0）。 */
SIG_SEC_MARKED_NOVMP
static int sig_read_v2block(int fd, off_t cd_off,
                            unsigned char magic[16], unsigned char **out_value) {
    off_t block_start;
    unsigned long long block_size;
    unsigned char sz8[8];

    if (sig_check_block_magic(fd, cd_off, magic) != 0) return -1;

    if (read_at(fd, sz8, 8, (off_t)cd_off - 24) != 0) return -1;
    block_size = rd64le(sz8);
    if ((off_t)(block_size + 8) > cd_off) return -1;
    block_start = (off_t)cd_off - 8 - (off_t)block_size;

    return sig_scan_pairs(fd, cd_off, block_start, block_size, out_value);
}

/* 从 v2/v3 块内容解析出第一张证书的 DER（malloc，调用者 free）。成功返回 0。 */
SIG_SEC_MARKED_NOVMP
static int sig_parse_first_cert(const unsigned char *value, int found,
                                unsigned char **out_der, size_t *out_len) {
    const unsigned char *p = value;
    const unsigned char *end = value + found;
    unsigned int signer_len, sd_len, digests_len, certs_len, cert_len;
    const unsigned char *signer, *sd, *certs;

    /*
     * 解析 signer 结构（所有长度均为 uint32 LE 前缀）：
     *   value = [len signers][signer...]
     *   signer = [len][signed_data][len signatures][len public_key]
     *   signed_data = [len digests][len certificates][len additional]
     *   certificates = [len cert1][...]
     */
    p += 4;                                     /* signers 区总长（无需使用） */
    if (p + 4 > end) return -1;
    signer_len = rd32le(p); p += 4;             /* 第一个 signer 的长度 */
    if (p + signer_len > end) return -1;
    signer = p;

    /* signer 内部：signed_data */
    if (signer + 4 > signer + signer_len) return -1;
    sd_len = rd32le(signer); signer += 4;
    sd = signer;
    if (sd + sd_len > end) return -1;

    /* signed_data 内部：跳过 digests，取 certificates */
    if (sd + 4 > sd + sd_len) return -1;
    digests_len = rd32le(sd); sd += 4;
    if (sd + digests_len + 4 > sd + sd_len) return -1;
    sd += digests_len;
    certs_len = rd32le(sd); sd += 4;            /* certificates 区总长 */
    certs = sd;

    if (certs + 4 > certs + certs_len) return -1;
    cert_len = rd32le(certs); certs += 4;       /* 第一张证书 DER */
    if (cert_len == 0 || certs + cert_len > end) return -1;

    *out_der = (unsigned char *)malloc(cert_len);
    if (!*out_der) return -1;
    memcpy(*out_der, certs, cert_len);
    *out_len = cert_len;
    return 0;
}

/* extract_cert_der 的失败原因码（2026-11-25）
 *
 * ⚠️ 为什么需要它：清掉本函数内部的 3 条日志后，5 个失败返回点全部静默，
 *    调用方只能打一条笼统的「证书提取失败」，分不清是"无 EOCD"还是
 *    "无签名块 magic"还是"v2 块结构异常" —— 那是删日志带来的**信息损失**，
 *    与"信息量不减"的初衷矛盾。
 * 解法：函数返回原因码，调用方把它和 route 名一起打（一条日志同时有
 *    「哪条路」+「什么原因」），既去重又不丢信息。
 *
 * 值沿用返回码约定：0 = 成功，负 = 失败（与 sig_collect_fp 的 -1/-2 同域
 * 但不同变量，调用方只看 != 0）。 */
#define EXTRACT_OK          0
#define EXTRACT_E_TOO_SMALL  (-1)   /* 文件小于 22 字节（连 EOCD 都放不下） */
#define EXTRACT_E_NO_EOCD    (-2)   /* 尾部找不到 PK\x05\x06 */
#define EXTRACT_E_BAD_CDOFF  (-3)   /* EOCD 里的 CD offset 非法（0 或 zip64） */
#define EXTRACT_E_NO_BLOCK   (-4)   /* 找不到 v2/v3 签名块（无 magic / 无 pair） */
#define EXTRACT_E_BAD_CERT   (-5)   /* 签名块结构异常，取不出第一张证书 DER */

SIG_SEC_MARKED_NOVMP
static int extract_cert_der(int fd, unsigned char **out_der, size_t *out_len) {
    off_t fsize;
    unsigned char eocd[22];
    unsigned char magic[16];
    unsigned char *value = NULL;
    int found;

    fsize = lseek(fd, 0, SEEK_END);
    if (fsize < 22) return EXTRACT_E_TOO_SMALL;

    /* ⚠️ 2026-11-25 去重（用户反馈"日志一直在重复文本"）：
     *    本函数被 6 条路线各调用一次，原先内部打 3 条日志
     *    （BLK_START / BLK_MAGIC_OK / CERT_OK），叠加起来就是
     *    3 × 6 = 18 行，外加 sig_check_block_magic 的 6 行 = 24 行，
     *    占单次启动日志的 27%，而且**不带路线归属**，6 条路混在一起
     *    完全无法定位"是哪个 route 出的问题"。
     *
     *    现在本函数静默：每路的结果统一由 sig_collect_fp_route() 打
     *    一条带 route= 前缀的日志（那才是排障需要的粒度），
     *    6 路汇总由 sig_collect_fp() 的表格呈现。
     *    净效果：24 行 → 0 行（信息量不减，归属反而更清楚）。
     *
     *    BLK_START / CERT_OK 两个标记已随之删除（无代码引用）。
     *    LSGS_BLK_MAGIC2 必须保留 —— 见下方标记区的说明，它是数据不是文案。 */

    if (sig_find_eocd(fd, fsize, eocd) != 0) return EXTRACT_E_NO_EOCD;

    {
        unsigned long long cd_off = rd32le(eocd + 16);
        if (cd_off == 0 || cd_off == 0xffffffffULL)
            return EXTRACT_E_BAD_CDOFF; /* 空/zip64 不支持 */
        found = sig_read_v2block(fd, (off_t)cd_off, magic, &value);
    }
    if (found < 0) return EXTRACT_E_NO_BLOCK;

    if (sig_parse_first_cert(value, found, out_der, out_len) != 0) {
        free(value);
        return EXTRACT_E_BAD_CERT;
    }

    free(value);
    /* 证书 DER 长度改由调用方（sig_collect_fp_route）随 route 一起打 —— 见本函数头的去重说明 */
    return EXTRACT_OK;
}

/* ─────────────────────────── 校验主逻辑 ─────────────────────────── */

/* [2026-10 追加] 双轮派生:期望值存储形态还原(与 make-sig-hash.sh 生成侧逐字节一致)。
 * 背景:明文指纹 SIG_HASH 在 so 里可被十六进制搜索替换(攻击者拿公开证书指纹
 * 原地覆盖期望值即绕过)。改为存 SIG_SALT/SIG_HASH_STORED:
 *   生成侧: salt=os.urandom(16); t1=SHA256(fp); stored[i]=t1[i]^salt[i%16]^(i*0x9E&0xFF)
 *   校验侧(本函数): 对运行时提取的实际指纹 actual 做同样变换,再与 stored 比对。
 * 明文指纹从二进制中消失;攻击者无法脱离本函数的派生逻辑构造替换目标。
 * ⚠️ 两侧实现必须逐字节一致,否则正确签名也闪退(显性失败,联调即暴露)。 */
SIG_SEC_MARKED
static void derive_expected(const unsigned char actual[32], unsigned char out[32]) {
    unsigned char t1[32];
    int i;
    sha256(actual, 32, t1);   /* 复用文件内已有 sha256,零新增依赖 */
    for (i = 0; i < 32; i++)
        out[i] = (unsigned char)(t1[i] ^ SIG_SALT[i % SIG_SALT_LEN]
                                 ^ (unsigned char)((i * 0x9E) & 0xFF));
}

/* ── Java 层判决的可信输入槽（2026-11-25）─────────────────────────────
 *
 * 为什么要这个槽：Java 侧 Guard.c() 用 PackageManager 测证书 —— 而那正是
 * 去校验模块在 IPackageManager 代理层撒谎的地方。于是「加固 + 去校验」组合
 * 包里，Java 测到的永远是原开发者的诱饵证书（3c81b429…），与本文件的标准
 * 答案 SIG_HASH_STORED（逆向者自己的证书 d82e48da…）必然不符 →
 * ncVerify 返回 false → Guard.kill() → 主人自己签的包也闪退。
 *
 * 判据不变，只换「谁来测」：本文件的可信路线（内联 svc / 裸 syscall / 复用
 * 系统 fd）读的是真实 base.apk，inline hook 够不到，测出来的就是主人自己的
 * 证书。把那一路的 t1 = SHA256(可信指纹) 存进本槽，由 nc_link.c 的 ncVerify
 * 优先取用，Java 入参降级为回退。
 *
 * ⚠️ 存的是【实测事实】而不是【比对结论】：这里记 t1 = SHA256(可信指纹)，
 *    与 SIG_HASH_STORED 的比对仍然发生在 nc_link.c 的 nc_verify_t1 里。
 *    若改成"本文件判过了就记个通过标志"，第二道防线就退化成恒真 —— 那是
 *    把这道门变成装饰。记事实、让对方自己判，才是两道独立比对。
 *
 * ⚠️ 本槽不改变本文件的判定：下方 sig_verify 该杀还是杀（延时暗杀那条路
 *    独立存在）。槽位只是把同一份可信实测结果多交一份给 Java 判决线。
 * ⚠️ 作用域仅限同一个 so —— protect.sh 把 sig_check.c 与 nc_link.c 拷进
 *    同一 NDK 工程（protect.sh:719），这是本设计的前提。
 * ⚠️ 与 nc_link.c 必然成对编入同一个 so（protect.sh:717-719 无条件成对拷），
 *    不存在"本文件在、nc_link.c 不在"的组合。nc_link.c 侧那个 weak 声明
 *    是为宿主测试注入假可信值用的，不是为这种缺席场景。
 */
static volatile int nc_trusted_t1_ready = 0;
static unsigned char nc_trusted_t1[SIG_HASH_LEN];

/* 发布可信实测证书指纹（入参是指纹本身，不是 t1）。
 * 无条件调用：调用点不做任何判断，把"测到什么"如实记下。
 * 非 static → 由 -fvisibility=hidden 收敛符号面，不进 .dynsym。 */
void nc_trusted_fp_publish(const unsigned char fp[32]) {
    unsigned char t1[SIG_HASH_LEN];
    int i;
    sha256(fp, 32, t1);                       /* 与 nc_link.c 的入参语义同源 */
    for (i = 0; i < SIG_HASH_LEN; i++) nc_trusted_t1[i] = t1[i];
    __atomic_store_n(&nc_trusted_t1_ready, 1, __ATOMIC_RELEASE);
}

/* 供 nc_link.c 取用。返回 1 = 可信值就绪（已写入 out）；0 = 尚未测得。 */
int nc_trusted_t1_get(unsigned char out[SIG_HASH_LEN]) {
    if (!__atomic_load_n(&nc_trusted_t1_ready, __ATOMIC_ACQUIRE)) return 0;
    memcpy(out, nc_trusted_t1, SIG_HASH_LEN);
    return 1;
}

/* 失败后延时随机 abort，攻击者难以关联崩溃原因。
 * 二期升级为污染数据等更隐蔽的破坏策略。
 *
 * 【改延时看这里】直接改下面 delay 一行:
 *   delay = 1 + rand_r(&seed) % 3   →  随机 1~3 秒(当前,方便调试肉眼确认)
 *   想改回正式发布的 90~270 秒,把那行换成:
 *   delay = 90 + rand_r(&seed) % 180
 *   (通用格式: 下限 + rand_r(&seed) % 跨度, 跨度=上限-下限+1)
 * ⚠️ 发布前记得改回大延时,否则 hook 绕过成本大幅下降。 */
/* ── kill 链进加密段（2026-10-19 方案4）────────────────────────────
 *
 * 与 env_check.c 的 env_delayed_kill 同一策略：把真正的处置逻辑标进
 * .ncx 密文段，让攻击者【找不到】它，而不是改成静默污染
 * （那需要业务语义知识，无法对任意 APK 通用）。
 *
 * 实测报告 §12.1 的绕过路径是"改 3 个 PLT 桩废掉 380 个调用点"。
 * 本方案把 kill 函数藏进密文段后，静态搜 abort@plt 的引用只能看到
 * "某处 bl 进了一段解不开的东西"。
 *
 * ⚠️ 时序前提：delayed_kill 只在 sig_verify 判定失败后被 pthread_create
 *    拉起，而 sig_verify 由 sig_check_entry(constructor) 调用；解锁入口
 *    ncg_auto_unlock 是 constructor(50)，优先级早于默认 constructor ——
 *    所以线程真正执行到本函数时，段必定已是明文。已实测 selftest=59 通过。
 * ⚠️ 条件化：SIGCHECK_HOST_TEST 下不标段（宿主没有解锁设施）。
 * ⚠️ 本函数是【被调用方】，调用方 sig_verify/sig_check_entry 不标段
 *    （它们是 unlock 的使用者，标进去会导致"解锁前就要调用密文"）。 */
#if defined(NC_GUARD_SECTIONED) && !defined(SIGCHECK_HOST_TEST)
#  define SIG_KILL_SECTION __attribute__((section(NC_SEC_CODE), retain, used, noinline))
#else
#  define SIG_KILL_SECTION
#endif

/* ── 不依赖 PLT 的强制终止（2026-10-19 方案2，本文件自带一份）────────
 *
 * 为什么不复用 env_check.c 的 env_raw_die：**sigcheck-only 组合下
 * env_check.c 不参与编译**（protect.sh 的拷贝清单里只有 env_check 勾选时
 * 才拷它）。跨文件依赖会让"只勾签名校验"直接链接失败。
 * 为什么用 static：两个文件同时参与编译时（sigcheck+envcheck）会各自
 * 有一份 static 副本，互不冲突，也不导出符号扩大攻击面。多 100 字节
 * 代码换"任何组合都能编过"，值得。
 *
 * 语义：svc 直投 tgkill(SIGABRT) → 立即终止；信号被拦时 __builtin_trap()
 * 生成 brk #1 兜底。两条路径都不经 libc，二进制里没有 abort@plt/
 * raise@plt 可改——这正是实测报告 §12.1 的软目标。 */
#if defined(__aarch64__)
static inline long sig_raw_syscall(long n, long a0, long a1, long a2,
                                   long a3, long a4, long a5) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
}
#elif defined(__arm__)
/* ⚠️ r7 在 ARMv7 是保留寄存器（Thumb frame pointer / 平台寄存器），
 * clang 拒绝 `register long r7 __asm__("r7")`：
 *   CI 报 error: write to reserved register 'R7' → armeabi-v7a 编译失败。
 * （本地交叉编译漏 `-mthumb` 才没复现。）改为内联汇编显式 push/pop r7。 */
static inline long sig_raw_syscall(long n, long a0, long a1, long a2,
                                   long a3, long a4, long a5) {
    register long r0 __asm__("r0") = a0;
    __asm__ volatile(
        "push {r7}\n\t"
        "mov  r7, %[nr]\n\t"
        "svc  #0\n\t"
        "pop  {r7}"
        : "+r"(r0)
        : [nr] "r"(n), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
        : "memory");
    return r0;
}
#endif

__attribute__((noreturn, noinline))
static void sig_raw_die(void) {
#if defined(__aarch64__) || defined(__arm__)
#  ifdef __NR_tgkill
    /* tid 也用 syscall 拿：gettid() 在部分老 bionic 上是 API 21+ 符号，
     * 直调 __NR_gettid 免依赖（本函数存在的意义就是"不经 libc"）。 */
    long tid = sig_raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    (void) sig_raw_syscall(__NR_tgkill, (long)getpid(), tid, SIGABRT, 0, 0, 0);
#  endif
#endif
    __builtin_trap();      /* 不可达兜底；SIGILL 也会留 tombstone */
}

SIG_KILL_SECTION
/* ── 多出口 kill 链（2026-10-19，修报告 §10「13 分支 → 1 汇聚点」）────
 *
 * 报告实测：`0x23ae4` 是 13 个校验分支的【唯一】汇聚点，处理这一处，
 * 13 个校验全部失效。典型 patch 就是在汇聚点写一条 `b`。
 *
 * 修法：不同失败原因走【不同的】处置函数，各自独立的：
 *   · 延迟范围（不同种子与跨度，崩溃时机分布不同）
 *   · 堆破坏轮数（不同的内存扰动模式）
 *   · 函数实体（不共用代码，patch 一个不影响其他）
 *
 * 三个变体按失败类别分配（见 sig_verify 的调用点）：
 *   variant 0：APK 定位/打开失败（环境异常类）
 *   variant 1：签名块解析失败（畸形输入类）
 *   variant 2：指纹比对不一致（真正的重签攻击类）
 *
 * ⚠️ 为什么不共用一个函数加参数：共用函数 = 一处 patch 全废，
 *    参数化只改变量不改控制流，攻击者改一条比较就能让三个变体都走
 *    最轻的路径。必须是【三个独立函数体】才有意义。
 * ⚠️ 三个都标进 .ncx（ENV_KILL_SECTION 同款），未解锁时都是密文。 */

/* variant 0：环境异常类 —— 短延迟（这类失败多半是环境问题，快杀快排障） */
SIG_KILL_SECTION
static void *delayed_kill_0(void *arg) {
    /* pthread 入口的标准签名，本变体不需要参数。
     * 2026-11-22：此前这里编不过 -Werror（unused parameter），
     * 而 CI 的 guard 测试都没开 -Werror，所以一直没被发现。 */
    (void)arg;
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid() ^ 0x51u);
    int delay = 1 + (int)(rand_r(&seed) % 2);
    LOGD("v");
    /*LSG:KILL|【流程】【防线1·sig_check】延时退出线程启动:随机延时后 abort(校验失败后的反应)*/
    LSGD(LSG_KILL, "%s", "delay=1~3s");
    /* [so加固 2026-10 追加] 延时堆破坏:校验失败除延时 abort 外,先在后台
     * 以随机间隔持续 malloc/free 不同尺寸的块(不写入,不崩溃),使攻击者
     * 即便 hook 掉 abort()/sleep() 让本线程失效,进程堆布局也已碎片化,
     * 后续任意时点的崩溃/异常都难以归因到本校验。纯 malloc/free,不触碰
     * 任何业务内存,宿主测试(SIGCHECK_HOST_TEST)同样安全。 */
    {
        int rounds = 8 + (int)(rand_r(&seed) % 16);   /* 8~23 轮,量级随机 */
        int i;
        for (i = 0; i < rounds; i++) {
            size_t sz = (size_t)(64 + (rand_r(&seed) % 4096));
            void *p = malloc(sz);
            int j;
            for (j = 0; j < 50 + (int)(rand_r(&seed) % 200); j++) {
                usleep(1000 + (rand_r(&seed) % 3000));   /* 1~4ms 抖动 */
            }
            free(p);
        }
    }
    sleep(delay);
    /* 2026-10-19 方案2：不用 abort@plt（改 4 字节即废所有调用点） */
    sig_raw_die();
    return NULL;   /* 不可达 */
}

/* variant 1：畸形输入类 —— 中等延迟 + 更多堆破坏轮次 */
SIG_KILL_SECTION
static void *delayed_kill_1(void *arg) {
    (void)arg;
    unsigned int seed = (unsigned int)(time(NULL) * 7u ^ getpid() ^ 0xA3u);
    int delay = 1 + (int)(rand_r(&seed) % 3);
    {
        int rounds = 16 + (int)(rand_r(&seed) % 20);   /* 16~35 轮（比 v0 多） */
        int i;
        for (i = 0; i < rounds; i++) {
            size_t sz = (size_t)(128 + (rand_r(&seed) % 8192));
            void *p = malloc(sz);
            int j;
            for (j = 0; j < 30 + (int)(rand_r(&seed) % 150); j++) {
                usleep(1000 + (rand_r(&seed) % 2000));
            }
            free(p);
        }
    }
    sleep(delay);
    sig_raw_die();
    return NULL;
}

/* variant 2：真正的重签攻击 —— 最长延迟 + 最重的堆扰动（拖住攻击者） */
SIG_KILL_SECTION
static void *delayed_kill_2(void *arg) {
    (void)arg;
    unsigned int seed = (unsigned int)(time(NULL) * 13u ^ getpid() ^ 0x7Cu);
    int delay = 2 + (int)(rand_r(&seed) % 3);
    {
        int rounds = 24 + (int)(rand_r(&seed) % 24);   /* 24~47 轮 */
        int i;
        for (i = 0; i < rounds; i++) {
            size_t sz = (size_t)(256 + (rand_r(&seed) % 16384));
            void *p = malloc(sz);
            int j;
            for (j = 0; j < 20 + (int)(rand_r(&seed) % 120); j++) {
                usleep(1000 + (rand_r(&seed) % 1500));
            }
            free(p);
        }
    }
    sleep(delay);
    sig_raw_die();
    return NULL;
}

/* 统一的"起线程"包装：三个变体共用拉起方式，但函数体各自独立。
 * 起线程失败同样不走 PLT。 */
static void sig_kill_via(int variant) {
    pthread_t t;
    pthread_attr_t attr;
    void *(*fn)(void *) = (variant == 0) ? delayed_kill_0
                        : (variant == 1) ? delayed_kill_1
                                         : delayed_kill_2;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, fn, NULL) != 0) sig_raw_die();
    pthread_attr_destroy(&attr);
}

/* ── 拆分说明（2026-11-11，为过 Amice VMP 的 32 寄存器预算）───────
 *
 * 原来 sig_verify 一个函数 values=21 + temps=1 → free=0 → VMP 跳过。
 * 拆成「采集指纹」+「比对」+「调度」三段，每段变量数降到一个数量级以内。
 *
 * 三条纪律（与 extract_cert_der 的拆分相同）：
 *   ① 日志文案一字未动（LSG/LSGS 是加密标记，改了会错乱）
 *   ② 每个子函数都 SIG_SEC_MARKED（进 .ncx，且带 noinline 防内联）
 *   ③ killvar 语义不变：失败分支自己决定走哪个处置变体
 */

/* ── 给 VMP 目标函数用的 close/free 出口（2026-11-14）────────────────
 *
 * 同理：`close()` 与 `free()` 都是外部调用，Amice 的 native call 检查
 * 一律当 intrinsic（callee + intrinsic_id=0）。挪一层即可。 */
__attribute__((noinline))
static void nc_close_fd(int fd) {
    if (fd >= 0) close(fd);
}

__attribute__((noinline))
static void nc_free_ptr(void *p) {
    free(p);
}

/* ── 给 VMP 目标函数用的 errno 读取（2026-11-14）─────────────────────
 *
 * `errno` 不是变量，是宏 —— 展开成 `__errno()` 函数调用。
 * Amice 的 native call 检查把它也当 intrinsic，于是 sig_collect_fp 在
 * 修掉 __open_2 之后又卡在 __errno 上：
 *
 *     [amice] VMP skipped: "sig_collect_fp"
 *       (callee="__errno", intrinsic_id=0)
 *
 * 同样挪到一层 noinline 外面。⚠️ 必须 noinline，内联回去等于没做。 */
__attribute__((noinline))
static int nc_errno(void) {
    return errno;
}

/* ── 给 VMP 目标函数用的 open 出口（2026-11-14）────────────────────────
 *
 * 为什么需要：`sig_collect_fp` 是签名校验的数据入口（读 APK → 提证书 →
 * 算指纹），价值最高的几个函数之一，但一直上不了 VMP：
 *
 *     [amice] VMP skipped: "sig_collect_fp"
 *       (LLVM intrinsic calls are not supported by vm_virtualize
 *        (callee="__open_2", intrinsic_id=0))
 *
 * `__open_2` 不是我们写的 —— 是 NDK r27d 的 _FORTIFY_SOURCE 把
 * `open(path, O_RDONLY)` 换成了带边界检查的 `__open_2`。而 Amice 的
 * native call 检查把任何「不认识的被调方」都当成 intrinsic（同一个 bug
 * 让 __android_log_write 也被误判，见 siglog_android 的注释）。
 *
 * 修法与 siglog_fmt1 / siglog_android 完全一致：把那个调用挪到一层
 * noinline 外面，VMP 只看到对本函数的普通调用。
 *
 * ⚠️ 不用 syscall(SYS_openat,...) 直投：部分 ROM 的 seccomp 会拦，
 *    而这行代码跑在 constructor 早期（进程刚起来），失败即 fail-closed
 *    杀进程，代价太高。挪一层只多一条 bl，语义完全不变。
 * ⚠️ 必须 noinline：内联回去等于没做，VMP 又看得见 __open_2 了。 */
__attribute__((noinline))
static int nc_open_ro(const char *path) {
    return open(path, O_RDONLY);
}

/* ── 多路取证书（2026-11-24）────────────────────────────────────────
 *
 * ==== 为什么要有"多路" ====
 * 原实现只走 `open()` 一条路。而「去签名校验」这类工具用 inline hook
 * 把 `open(base.apk)` 重定向到一份诱饵 APK（证书是官方原版），
 * 于是一次 hook 就让整条签名校验读到错误的证书并通过。
 * 真机日志实证：打印的 path 是 base.apk，但 fsize=5066408 对应的是
 * 诱饵包（真实 base.apk 是 10MB）——路径没变、打开的却是别的文件。
 *
 * 对策：用**多条互不依赖的取文件路径**各拿一次证书，交叉比对。
 *   路 A: open()                 —— 最容易被 hook（保留，作诱饵探针）
 *   路 B: openat(AT_FDCWD, ...)  —— 语义等价，但函数不同，常规 hook 常漏
 *   路 C: syscall(__NR_openat)   —— 直投内核，不经 libc
 *   路 D: 内联 svc #0（arm64/armv7）—— 连 syscall() 函数都不经
 * 任何一路被拦截 → 该路的指纹与他人不同 → 判定被劫持 → fail-closed。
 *
 * ==== 降级策略（重要）====
 * B/C/D 失败（seccomp 拦截、非 ARM 平台等）**不杀进程**，只记日志并跳过；
 * 只有当「至少两路成功且指纹不一致」才判定被劫持。
 * 理由是这几路属于"加强"而非"必需"：加进来是为了发现劫持，
 * 不是为了在个别 ROM 上把正常包判死。
 */

/* 路径 ID：写在日志里，便于对照"哪一路拿到了什么"。
 *
 * ⚠️ 新增路线请【追加到末尾】并把 SIG_ROUTE_NUM 加一 —— 中间插入会让
 *    历史日志里的 route= 编号含义漂移，排障时对不上。 */
#define SIG_ROUTE_OPEN      0   /* open()               —— 最易被 hook，作诱饵探针 */
#define SIG_ROUTE_OPENAT    1   /* openat()             —— 独立符号 */
#define SIG_ROUTE_OPENAT64  2   /* openat64()           —— 又一个独立符号 */
#define SIG_ROUTE_SYSCALL   3   /* syscall(__NR_openat) —— 不经 libc 封装 */
#define SIG_ROUTE_SVC       4   /* 内联 svc #0          —— 连 syscall() 都不经 */
#define SIG_ROUTE_FD        5   /* /proc/self/fd/N 复用系统已开的 fd */
#define SIG_ROUTE_NUM       6

/* ── 可信路线（2026-11-25，见 docs/多路取证书判定逻辑.md）─────────────
 *
 * 判据变化的核心：从「检查有没有陌生人」改成「检查主人在不在场」。
 *
 * 为什么 3/4/5 是可信的：
 *   它们都不经过 libc 的路径类函数 —— syscall 是内联 svc、svc 更是直接
 *   写在本函数体里、sysfd 复用内核已开的 fd（压根不 open）。inline hook
 *   只能改 libc 里的函数体，够不到这三条。所以它们读到的必然是
 *   **当前安装的 base.apk**，即"房间里真正坐着的人"。
 *
 * 为什么 0/1/2 不可信：
 *   去签名校验工具（本仓库 scripts/uncheck 的 libusign.so）正是 hook
 *   这三个函数，把 open(base.apk) 重定向到 origin.apk（内含原开发者
 *   证书）。对**逆向者自己**的包来说，这是设计功能不是入侵 ——
 *   但加固若不区分，就会把主人的替身当成敌人。
 *
 * 判定优先级（sig_collect_fp 里实现）：
 *   ① 可信路线有结果 → 用它与基准比对（一致=放行，不一致=杀）
 *   ② 可信路线全失败（seccomp 拦/平台不支持）→ 退回旧逻辑
 *      「任意两路不一致就杀」（保底，宁可误杀不可漏防）
 */
static int sig_route_is_trusted(int route) {
    return route == SIG_ROUTE_SYSCALL
        || route == SIG_ROUTE_SVC
        || route == SIG_ROUTE_FD;
}

/* 用指定路线打开 path。成功返回 fd，失败 -1（errno 不强求准确）。
 *
 * ⚠️ SIG_ROUTE_FD 不在此处理（它不 open，而是返回"已存在的 fd"），
 *    见 sig_find_apk_fd()。 */
SIG_SEC_MARKED_NOVMP
static int sig_open_route(int route, const char *path) {
    if (route == SIG_ROUTE_OPEN) {
        return nc_open_ro(path);
    }
    if (route == SIG_ROUTE_OPENAT) {
        /* ⚠️ 不走 nc_open_ro：那个是 open()，会被同一处 hook 命中。
         * openat 是独立符号，常规路径重定向工具通常只挂 open/open64。 */
        return openat(AT_FDCWD, path, O_RDONLY);
    }
    if (route == SIG_ROUTE_OPENAT64) {
        return openat64(AT_FDCWD, path, O_RDONLY);
    }
#if defined(__aarch64__) || defined(__arm__)
    if (route == SIG_ROUTE_SYSCALL) {
        /* ⚠️ 用 sig_raw_syscall（内联 svc），不用 libc 的 syscall()：
         *    仓库有一条 T9 断言 —— 产物里不得存在 abort/_exit/raise/syscall
         *    四个 PLT 表项（攻击者改 4 字节即可废掉整条 kill 链）。
         *    这里若写 syscall(...) 会把 syscall@plt 拉回来，T9 立刻变红
         *    （2026-11-24 实测踩过）。
         *
         *    与下面 SIG_ROUTE_SVC 的区别：本路走**函数调用**到
         *    sig_raw_syscall（编译器可能复用一个展开），下面那条是
         *    **独立内联汇编**写入本函数体。两者对"按代码形态定位"的
         *    攻击者表现不同，交叉比对仍有意义。 */
        long r = sig_raw_syscall(__NR_openat, (long)AT_FDCWD, (long)path,
                                 (long)O_RDONLY, 0L, 0L, 0L);
        return (int)r;
    }
    if (route == SIG_ROUTE_SVC) {
        /* 内联 svc：连 libc 的 syscall() 都不经过。
         * arm64: 号进 x8，参数 x0..x5。
         * armv7: 号必须进 r7，但 r7 是【保留寄存器】（Thumb frame pointer），
         *        clang 拒绝 `register long r7 __asm__("r7")`
         *        （CI 实证 `error: write to reserved register 'R7'`）。
         *        必须在内联汇编里显式 push/pop 保存恢复 —— 与
         *        env_check.c:env_raw_syscall 的写法保持一致。 */
        long r;
#if defined(__aarch64__)
        register long x8 __asm__("x8") = __NR_openat;
        register long x0 __asm__("x0") = (long)AT_FDCWD;
        register long x1 __asm__("x1") = (long)path;
        register long x2 __asm__("x2") = (long)O_RDONLY;
        register long x3 __asm__("x3") = 0L;
        __asm__ volatile("svc #0"
                         : "+r"(x0)
                         : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                         : "memory");
        r = x0;
#else
        register long r0 __asm__("r0") = (long)AT_FDCWD;
        register long r1 __asm__("r1") = (long)path;
        __asm__ volatile(
            "push {r7}\n\t"
            "mov  r7, %[nr]\n\t"
            "mov  r2, %[flags]\n\t"
            "svc  #0\n\t"
            "pop  {r7}"
            : "+r"(r0)
            : [nr] "r"((long)__NR_openat), [flags] "r"((long)O_RDONLY),
              "r"(r1)
            : "memory");
        r = r0;
#endif
        return (int)r;
    }
#endif
    return -1;
}

/* 路线名（只用于日志；不含敏感语义，不触发 LSG 密文化要求） */
static const char *sig_route_name(int route) {
    switch (route) {
        case SIG_ROUTE_OPEN:     return "open";
        case SIG_ROUTE_OPENAT:   return "openat";
        case SIG_ROUTE_OPENAT64: return "openat64";
        case SIG_ROUTE_SYSCALL:  return "syscall";
        case SIG_ROUTE_SVC:      return "svc";
        case SIG_ROUTE_FD:       return "sysfd";
        default:                 return "?";
    }
}

/* ── 路线 FD：复用内核里已打开的 base.apk 句柄 ──────────────────────
 *
 * ==== 为什么这条最抗 hook ====
 * 前 5 条都是"自己发起一次 open"。无论用 open / openat / syscall / svc，
 * 攻击者只要把**所有发起 open 的入口**都挂上，就能统一重定向。
 *
 * 本路线不发起 open：ART 在启动时为了加载 dex/res，通常已经持有
 * base.apk 的 fd（`/proc/self/fd/N` → .../base.apk）。直接借用那个句柄，
 * 读到的必然是**安装包本体**，与任何 hook 无关。
 *
 * 判据：遍历 /proc/self/fd/N，用 readlinkat 解析目标路径，挑出以
 * "base.apk" 结尾且能 lseek 到文件尾（即普通文件）的那个。
 *
 * ⚠️ readlink 已被去校验 hook（proxy_readlink 会谎报成 base.apk），
 *    所以这里 **必须** 用 syscall(SYS_readlinkat) 直投内核。
 *    否则本路线反而会被诱骗到假路径上。
 *
 * ⚠️⚠️ 2026-11-25 补漏（本路线此前只有"一半"抗 hook）：
 *    上面找路用内联 svc 是对的，但"确认大小"和"真正拿 fd"两步原本写的是
 *    `openat(dfd, name, O_RDONLY)` —— 反汇编里就是 `bl openat@plt`，可被 hook。
 *    当时没被利用仅因去校验的 proxy_openat 判据是「dirfd==AT_FDCWD 且 path
 *    完全等于 base.apk 路径」，而这里传的是 dirfd=/proc/self/fd、path="1234"，
 *    两个条件都不满足 → 巧合性安全，不是结构性安全。
 *    攻击者只要把判断改成"解析真实路径再比"，这条号称最抗 hook 的路线就废。
 *
 *    现改为全程内联 svc（sig_raw_syscall），与 sig_open_route 的 SVC 路线同源。
 *    验收：反汇编本函数体内不得出现 openat@plt / open@plt 调用。
 *
 * ⚠️ 不关闭返回的 fd：它属于系统，不是我们打开的。
 *    调用方只能 pread/lseek，不能 close。 */
SIG_SEC_MARKED_NOVMP
static int sig_find_apk_fd(void) {
#if defined(__aarch64__) || defined(__arm__)
    int dfd, fd, found = -1;
    char link[256];

    dfd = sig_open_route(SIG_ROUTE_SVC, "/proc/self/fd");
    if (dfd < 0) {
        /* ⚠️ 2026-11-25：原退回 openat —— 本函数的存在意义就是"抗 hook"，
         *    退回可被 hook 的入口等于自废。现直接用内联 svc 再试一次
         *    （sig_open_route 的 SVC 分支与本行同源，此处是显式兜底，
         *    刻意不复用那个函数以免它将来改动影响本路线）。 */
        dfd = (int)sig_raw_syscall(__NR_openat, (long)AT_FDCWD,
                                   (long)"/proc/self/fd",
                                   (long)(O_RDONLY | O_DIRECTORY), 0L, 0L, 0L);
    }
    if (dfd < 0) return -1;

    for (fd = 3; fd < 512 && found < 0; fd++) {
        char name[16];
        int nl = 0, v = fd;

        /* 手工拼 "N" —— 避免 snprintf 拉入额外依赖 */
        if (v >= 100) { name[nl++] = (char)('0' + v / 100); v %= 100; }
        if (nl || v >= 10) { name[nl++] = (char)('0' + v / 10); }
        name[nl++] = (char)('0' + v % 10);
        name[nl] = '\0';

        long r = sig_raw_syscall(__NR_readlinkat, (long)dfd, (long)name,
                                 (long)link, (long)(sizeof(link) - 1), 0L, 0L);
        if (r <= 0) continue;
        link[r] = '\0';
        {
            size_t L = (size_t)r;
            if (L < 8) continue;
            if (strcmp(link + L - 8, "base.apk") != 0) continue;
            /* 命中：确认是普通文件（能 seek 到尾部且长度 > 1MB）
             *
             * ⚠️ 2026-11-25：原为 openat(dfd, name, O_RDONLY) —— 可被 hook。
             *    改走内联 svc。注意 fd 语义完全一致（openat 返回新 fd，
             *    close 由我们自己负责），后续 pread/lseek 用法不变。 */
            {
                long probe = sig_raw_syscall(__NR_openat, (long)dfd,
                                             (long)name, (long)O_RDONLY,
                                             0L, 0L, 0L);
                long sz;
                if (probe < 0) continue;
                sz = sig_raw_syscall(__NR_lseek, probe, 0L, 2L /* SEEK_END */,
                                     0L, 0L, 0L);
                sig_raw_syscall(__NR_close, probe, 0L, 0L, 0L, 0L, 0L);
                if (sz <= (long)(1024 * 1024)) continue;
            }
            /* 真正使用时要 dup 一份，避免调用方误关。
             * ⚠️ 仍用内联 svc：这里若退回 openat，等于前面全部白做。 */
            found = (int)sig_raw_syscall(__NR_openat, (long)dfd, (long)name,
                                         (long)O_RDONLY, 0L, 0L, 0L);
        }
    }
    sig_raw_syscall(__NR_close, (long)dfd, 0L, 0L, 0L, 0L, 0L);
    return found;
#else
    return -1;
#endif
}

/* 用某一路线采集证书指纹。成功 0（fp 写入 out_fp），失败 -1。
 * 每路都打印：路线名 / open 结果 / fsize / 证书指纹。 */
SIG_SEC_MARKED_NOVMP
static int sig_collect_fp_route(int route, const char *apk_path,
                                unsigned char out_fp[32], long *out_size) {
    int fd;
    unsigned char *der = NULL;
    size_t der_len = 0;
    off_t fsize;
    int fd_from_sys = 0;      /* 1 = fd 属于系统，不能 close */

    if (route == SIG_ROUTE_FD) {
        fd = sig_find_apk_fd();
        fd_from_sys = 1;
    } else {
        fd = sig_open_route(route, apk_path);
    }
    if (fd < 0) {
        /*LSG:ROUTE_OPEN_FAIL|【流程】该路取证书打开失败(记日志后跳过)*/
        LSGE(LSG_ROUTE_OPEN_FAIL, "route=%s", sig_route_name(route));
        return -1;
    }

    /* fsize 是被劫持的关键破绽：路径看着对，文件大小却对不上。
     * 真实 base.apk 与诱饵 origin.apk 体积必然不同。 */
    fsize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    /*LSG:ROUTE_OPEN_OK|【数据】该路取证书成功打开(fd/size)*/
    LSGI(LSG_ROUTE_OPEN_OK, "route=%s fd=%d size=%ld",
         sig_route_name(route), fd, (long)fsize);
    if (out_size) *out_size = (long)fsize;

    {
        int ex = extract_cert_der(fd, &der, &der_len);
        if (ex != EXTRACT_OK) {
            if (fd_from_sys) close(fd); else nc_close_fd(fd);
            /*LSG:ROUTE_NO_CERT|【流程】该路证书提取失败(记日志后跳过)*/
            /* ⚠️ 2026-11-25：带上失败原因码。上一版删掉 extract_cert_der 内部
             *    的 3 条日志后，6 条路失败时都只打这一句笼统的话，分不清是
             *    "无 EOCD"还是"无签名块 magic"还是"结构异常" —— 那是删日志
             *    带来的信息损失。现在一条日志同时给出「哪条路」+「什么原因」。
             *    码值见 EXTRACT_E_* 定义（负数，语义稳定）。 */
            LSGE(LSG_ROUTE_NO_CERT, "route=%s reason=%d",
                 sig_route_name(route), ex);
            return -1;
        }
    }
    sha256(der, der_len, out_fp);
    nc_free_ptr(der);
    if (fd_from_sys) close(fd); else nc_close_fd(fd);
    /* 不在每路里打印指纹 —— 统一由调用方的汇总表输出，
     * 避免同一份数据打两遍（原来那样日志里每路出现两次，很难读）。 */
    return 0;
}

/* 采集 APK 证书指纹：定位 → 打开 → 提取证书 → SHA256。
 * 成功返回 0 并把 32 字节指纹写进 actual；失败返回该走的 killvar 变体（≥0）
 * 或 -1 表示"环境异常类，走 variant 0"。 */
SIG_SEC_MARKED_NOVMP
static int sig_collect_fp(unsigned char actual[32]) {
    char apk_path[1024];
    int fd;
    unsigned char *der = NULL;
    size_t der_len = 0;

    /*LSG:FIND_START|【流程】开始定位 APK 文件 find_apk_path*/
    LSGI0(LSG_FIND_START);

    if (find_apk_path(apk_path, sizeof(apk_path)) != 0) {
        /* LSGS 密文化(2026-10-16):原文案直接暴露"这是签名校验"。 */
        char m[64];
        const char *mm = lsg_s(LSGS_ERR_APK_NOT_FOUND, m, sizeof(m));
        if (mm) LOGE_V1("%s", mm);
        /*LSG:NOT_FOUND|【失败】四条定位路径(env/maps/so反推/data/app)全部失败*/
        LSGE0(LSG_NOT_FOUND);
        return -1;            /* 环境异常类 → variant 0 */
    }

    fd = nc_open_ro(apk_path);
    if (fd < 0) {
        /* 三参数 → 先拼一次，再走单参数版本（siglog 是 varargs，VMP 不支持）
         * ⚠️ errno 走 nc_errno()：它是宏，展开成 __errno() 调用，
         *    VMP 会当成 intrinsic 而跳过本函数（实测过）。 */
        { int _e = nc_errno(); char _b[256]; snprintf(_b, sizeof(_b), "open apk failed: %s errno=%d(%s)", apk_path, _e, strerror(_e)); LOGE_S(_b); }
        /*LSG:OPEN_ERR|【失败】打开 APK 失败 open()*/
        LSGE(LSG_OPEN_ERR, "%s errno=%d", apk_path, nc_errno());
        return -1;            /* 环境异常类 → variant 0 */
    }
    /*LSG:OPEN_OK|【成功】APK 已打开*/
    LSGI(LSG_OPEN_OK, "%s", apk_path);

    /* ── 多路交叉采集（2026-11-24）──────────────────────────────────
     * 路 A 用 fd（上面已打开的 open 句柄）拿指纹；再依次用 B/C/D 各拿一次。
     * 只有「成功 ≥2 路 且 指纹不一致」才判定被劫持 —— 单路失败（seccomp /
     * 平台不支持）只记日志跳过，不冤杀正常包。 */
    {
        unsigned char route_fp[SIG_ROUTE_NUM][32];
        int route_ok[SIG_ROUTE_NUM];
        long route_size[SIG_ROUTE_NUM];
        long size_a = 0;
        int nr, first_ok = -1, mismatch = 0;

        for (nr = 0; nr < SIG_ROUTE_NUM; nr++) { route_ok[nr] = 0; route_size[nr] = 0; }

        for (nr = 0; nr < SIG_ROUTE_NUM; nr++) route_ok[nr] = 0;

        /* 路 A：复用已打开的 fd（避免重复 open，也保持原有行为不变）。
         * 先记下文件大小 —— 这是识别诱饵的最快判据（诱饵包体积必然不同）。 */
        size_a = (long)lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        {
            int ex = extract_cert_der(fd, &der, &der_len);
            if (ex != EXTRACT_OK) {
                nc_close_fd(fd);
                /* LSGS 密文化(2026-10-16):原文案暴露"这是签名校验"+教会攻击者怎么重签。 */
                {
                    char m[128];
                    const char *mm = lsg_s(LSGS_ERR_NO_SIGN_BLOCK, m, sizeof(m));
                    /* 两参数 → 同上 */
                    { char _b[256]; snprintf(_b, sizeof(_b), "%s: %s reason=%d", mm, apk_path, ex); LOGE_S(_b); }
                }
                /*LSG:BLK_FAIL|【失败】签名块解析失败(无 v2/v3 或结构异常)*/
                LSGE(LSG_BLK_FAIL, "%s reason=%d", apk_path, ex);
                return -1;
            }
        }
        sha256(der, der_len, route_fp[SIG_ROUTE_OPEN]);
        nc_free_ptr(der);
        nc_close_fd(fd);
        route_ok[SIG_ROUTE_OPEN] = 1;
        first_ok = SIG_ROUTE_OPEN;
        route_size[SIG_ROUTE_OPEN] = (long)size_a;

        /* 路 B/C/D/E/F（openat / openat64 / syscall / svc / sysfd） */
        for (nr = SIG_ROUTE_OPENAT; nr < SIG_ROUTE_NUM; nr++) {
            if (sig_collect_fp_route(nr, apk_path, route_fp[nr], &route_size[nr]) == 0) {
                route_ok[nr] = 1;
                if (first_ok < 0) first_ok = nr;
                else {
                    int k, diff = 0;
                    for (k = 0; k < 32; k++)
                        diff |= route_fp[nr][k] ^ route_fp[first_ok][k];
                    if (diff) mismatch = 1;
                }
            }
        }

        /* ── 汇总表（排障用，一次看清 6 路各自拿到什么）──────────────
         *
         * 输出形如：
         *   ┌─ 多路证书采集 ─────────────────────────────
         *   │ open       size=5071296    fp=d82e48da…  <== 不一致（疑似诱饵）
         *   │ openat     size=10169286   fp=93622a73…
         *   │ …
         *   └─ ok=6/6 mismatch=1  ← 被劫持
         *
         * ⚠️ "哪一路是诱饵"按【多数派】判定，不能按"第一个成功的"：
         *    被劫持的那一路往往正是最先成功的 open()，若以它为基准，
         *    会把 5 路真货全标成"不一致"（2026-11-24 实测踩过）。 */
        {
            /* 选多数派：与最多其他路相同的那个指纹下标 */
            int base_idx = -1, base_votes = -1;
            for (nr = 0; nr < SIG_ROUTE_NUM; nr++) {
                int m, votes = 0;
                if (!route_ok[nr]) continue;
                for (m = 0; m < SIG_ROUTE_NUM; m++) {
                    int k, d2 = 0;
                    if (!route_ok[m]) continue;
                    for (k = 0; k < 32; k++)
                        d2 |= route_fp[nr][k] ^ route_fp[m][k];
                    if (d2 == 0) votes++;
                }
                if (votes > base_votes) { base_votes = votes; base_idx = nr; }
            }
            if (base_idx >= 0) first_ok = base_idx;
        }

        /*LSG:ROUTE_TBL_HEAD|【数据】多路证书采集表头*/
        LSGI0(LSG_ROUTE_TBL_HEAD);
        for (nr = 0; nr < SIG_ROUTE_NUM; nr++) {
            char hex[65];
            int k;
            static const char dd[] = "0123456789abcdef";
            int is_outlier = 0;

            if (!route_ok[nr]) {
                /*LSG:ROUTE_TBL_SKIP|【数据】该路未采到(失败/不支持)*/
                LSGI(LSG_ROUTE_TBL_SKIP, "| %-9s (未采到)",
                     sig_route_name(nr));
                continue;
            }
            for (k = 0; k < 32; k++) {
                hex[k*2]   = dd[route_fp[nr][k] >> 4];
                hex[k*2+1] = dd[route_fp[nr][k] & 15];
            }
            hex[64] = '\0';
            hex[16] = '\0';
            /* 与 first_ok 比对，标出不同的那一路 */
            {
                int d2 = 0;
                for (k = 0; k < 32; k++)
                    d2 |= route_fp[nr][k] ^ route_fp[first_ok][k];
                is_outlier = (nr != first_ok) && (d2 != 0);
            }
            if (is_outlier) {
                /*LSG:ROUTE_TBL_ODD|【数据】表中偏离的一路(疑似诱饵)*/
                LSGI(LSG_ROUTE_TBL_ODD, "| %-9s size=%-10ld fp=%s  <== 不一致",
                     sig_route_name(nr), route_size[nr], hex);
            } else {
                /*LSG:ROUTE_TBL_ROW|【数据】表中正常的一路*/
                LSGI(LSG_ROUTE_TBL_ROW, "| %-9s size=%-10ld fp=%s",
                     sig_route_name(nr), route_size[nr], hex);
            }
        }
        {
            int ok = 0;
            for (nr = 0; nr < SIG_ROUTE_NUM; nr++) ok += route_ok[nr];
            /*LSG:ROUTE_SUM|【数据】多路采集汇总(成功路数/是否不一致)*/
            LSGI(LSG_ROUTE_SUM, "ok=%d/%d mismatch=%d",
                 ok, SIG_ROUTE_NUM, mismatch);
        }

        /* ── 判定（2026-11-25 重写）──────────────────────────────────
         *
         * ⚠️⚠️ 旧的判据是「任意两路不一致 → 杀」，它有个致命盲区：
         *   加固 + 去校验组合包里，3 路 libc 被重定向到 origin.apk（诱饵）、
         *   3 路内联 svc 读到真 base.apk → 3:3 分裂 → 一律判"被劫持" →
         *   主人自己签的包也闪退。
         *
         *   类比：门卫只清点"陌生面孔"，不看"主人是否在场"。
         *   主人（逆向者自己的证书）明明坐在这里，却被当成入侵者。
         *   更糟的是这反过来成了攻击面：攻击者只要让任意一路读错文件，
         *   就能触发 fail-closed 让正常包崩溃，不必伪造任何证书。
         *
         * 新判据（详见 scripts/guard/docs/多路取证书判定逻辑.md）：
         *   ① 可信路线（svc/syscall/sysfd）有结果 → 拿它和基准比对
         *        与 SIG_HASH_STORED 一致 → 主人自己在场 → 放行（ignore 诱饵）
         *        不一致               → 主人真被换了 → 杀
         *   ② 可信路线全失败 → 退回旧逻辑「任意不一致就杀」（保底）
         *
         * ⚠️ 为什么①仍然安全：svc 路线读的是真实安装包，重签/改包必然
         *    让它与基准不符；而 inline hook 改不了内联 svc 指令。
         *    唯一的"放行"场景是"真身 == 基准"，那正是主人的定义。 */
        {
            int trusted_fp[32];
            int trusted_from = -1;
            int t;

            /* 找第一条成功的可信路线（3/4/5 中任一） */
            for (t = 0; t < SIG_ROUTE_NUM; t++) {
                if (route_ok[t] && sig_route_is_trusted(t)) {
                    memcpy(trusted_fp, route_fp[t], 32);
                    trusted_from = t;
                    break;
                }
            }

            if (trusted_from >= 0) {
                unsigned char expect[32];
                int i2, diff = 0;
                derive_expected((const unsigned char *)trusted_fp, expect);
                for (i2 = 0; i2 < 32; i2++)
                    diff |= expect[i2] ^ SIG_HASH_STORED[i2];

                /* 把可信实测指纹交给 Java 判决线（nc_link.c 的 ncVerify）。
                 *
                 * ⚠️⚠️ 发布点必须在【比对之前、无条件执行】：
                 *    它记的是"可信路线测到了什么"这个事实，不是"比对通过"
                 *    这个结论。若挪进下面的 diff==0 分支，则"可信路线读到了
                 *    陌生证书"（真被重签）时槽位为空 → ncVerify 回退到 Java
                 *    那条被代理污染的值 → 攻击者只要让 PM 报基准值就能过。
                 *    实测事实与判决结论必须分开，这是本改动的核心纪律。
                 *
                 * 一致性由 nc_verify_t1 自己再判一遍（两道独立比对，不是
                 * 复制结论）—— 见 nc_trusted_fp_publish 的头注。 */
                nc_trusted_fp_publish((const unsigned char *)trusted_fp);

                if (diff == 0) {
                    /* 主人在场 → 放行。故意继续走 sig_compare_fp：
                     * 它会把指纹打出来（排障需要），且会再比一次（冗余但
                     * 无副作用 —— 这里已经确认一致了）。 */
                    /*LSG:ROUTE_TRUSTED_OK|【通过】可信路线(内联svc)与基准一致,主人自己在场,放行*/
                    LSGI(LSG_ROUTE_TRUSTED_OK, "route=%s",
                         sig_route_name(trusted_from));
                    memcpy(actual, trusted_fp, 32);
                    return 0;
                }
                /* 可信路线也不符基准 → 真被重签了 → 走最重处置 */
                /*LSG:ROUTE_TRUSTED_NG|【失败】可信路线(内联svc)也与基准不符,确认被重签*/
                LSGE0(LSG_ROUTE_TRUSTED_NG);
                return -2;
            }

            /* ② 可信路线全失败：退回旧判据（保底） */
            /*LSG:ROUTE_NO_TRUSTED|【流程】可信路线均不可用,退回多路一致性判据*/
            LSGI0(LSG_ROUTE_NO_TRUSTED);
            if (mismatch) {
                /*LSG:ROUTE_SPLIT|【失败】【防线1·sig_check】多路证书指纹不一致(疑似 APK 读取被劫持)*/
                LSGE0(LSG_ROUTE_SPLIT);
                return -2;        /* 独立语义：劫持，走最重处置 */
            }

            if (first_ok >= 0) {
                memcpy(actual, route_fp[first_ok], 32);
                return 0;
            }
        }
        /* 所有路都失败：退回"环境异常"语义 */
        return -1;
    }
}

/* 打印实际指纹（排障用）并做双轮派生比对。
 * 返回 0 = 一致；非 0 = 不一致。 */
SIG_SEC_MARKED
static int sig_compare_fp(const unsigned char actual[32]) {
    unsigned char expected[32];
    int i, mismatch = 0;

    {
        char hex[65];
        static const char d[] = "0123456789abcdef";
        for (i = 0; i < 32; i++) {
            hex[i*2]   = d[actual[i] >> 4];
            hex[i*2+1] = d[actual[i] & 15];
        }
        hex[64] = '\0';
        LOGI_V1("nc: fp=%s", hex);   /* so加固2026-10: 原文 "cert fp actual=%s",改缩写,fp=指纹(排障用) */
        /*LSG:FP|【数据】实际证书指纹 actual_fp*/
        LSGI(LSG_FP, "%s", hex);
    }

    /* [2026-10 改] 恒定时间比较:对实际指纹做双轮派生后与 SIG_HASH_STORED 比对
     * (原来直接比明文 SIG_HASH;expected 含派生结果,still 恒定时间) */
    derive_expected(actual, expected);
    for (i = 0; i < 32; i++) mismatch |= expected[i] ^ SIG_HASH_STORED[i];
    return mismatch;
}

SIG_SEC_MARKED_NOVMP
static void sig_verify(void) {
    unsigned char actual[32];
    int i;
    int slot_configured = 0;
    /* 失败变体选择（2026-10-19 多出口）：缺省 2 = 最重处置，
     * 保证任何未显式设置的失败路径都不会被"轻处理"。 */
    int killvar = 2;

    siglog_detect();   /* 文件日志开关探测(只做一次,失败静默) */

    /* ⚠️ 2026-11-25 启动分隔线（用户反馈：多个包的日志追加在同一文件里，
     *    只能靠 pid/size 自己分辨，同签名不同包完全分不清）。
     *    这里打一条纯 ASCII 分隔行 + 一条带 size 的标识。
     *
     *    ⚠️ 为什么不能只打"======"：文件是 append 模式，跨进程共享。
     *    同一进程内 sig_verify 只跑一次（constructor），所以一条分隔线
     *    就等价于一次启动。但【不同包】的 size 不同，必须带上 ——
     *    那是唯一能区分"装的是哪个包"的字段（pid 会复用、时间会看错）。
     *
     *    ⚠️ 不新增 LSG 标记：分隔线是纯符号（无中文语义），
     *    不属于"功能语义字符串"，不触发 LSGS 密文化要求。 */
    siglog("I", "---------------------------------------- "
                "new launch (sig_verify) "
                "----------------------------------------");
    /*LSG:ENTER|【流程】so 已加载,进入签名校验 sig_verify*/
    LSGI0(LSG_ENTER);

    /* [2026-10 改] 调试模式判定改用派生后的存储槽位(全零=流水线未注入则跳过) */
    for (i = 0; i < 32; i++) {
        if (SIG_HASH_STORED[i] != 0) { slot_configured = 1; break; }
    }
    if (!slot_configured) {
        LOGI_S("nc: slot empty");   /* so加固2026-10: 原文 "sig hash slot empty, skip verify" 含路标词,改中性 */
        /*LSG:SLOT_EMPTY|【通过】指纹槽全零:流水线未注入,跳过校验(调试模式)*/
        LSGI0(LSG_SLOT_EMPTY);
        return;
    }

    if (sig_collect_fp(actual) != 0) {
        killvar = 0;          /* 环境异常类 → variant 0 */
        goto fail;
    }

    if (sig_compare_fp(actual) == 0) {
        LOGI_S("nc: ok");   /* so加固2026-10: 原文 "signature verify ok",改中性 */
        /*LSG:VERIFY_OK|【通过】指纹比对一致,签名校验通过,放行*/
        LSGI0(LSG_VERIFY_OK);
        return;
    }
    LOGE_S("nc: mm");   /* so加固2026-10: 原文 "signature mismatch (actual vs expected...)",排障走上方 fp 行 */
    /*LSG:VERIFY_MM|【失败】【防线1·sig_check】指纹比对不一致 → 校验失败,延时退出已安排*/
    LSGE0(LSG_VERIFY_MM);

fail:
    /* 2026-10-19：不再只有一个汇聚点——按失败原因走不同变体。
     * killvar 由各失败分支在 goto fail 前设置（见上方各分支）。
     * 缺省 2（最重的那条），确保"忘了设"也走最严格处置。 */
    sig_kill_via(killvar);
}

/* dlopen 后最先执行的入口（早于 JNI_OnLoad 与一切 Java 代码） */
__attribute__((constructor)) static void sig_check_entry(void) {
    sig_verify();
}

/* ── 宿主端测试钩子（仅 SIGCHECK_HOST_TEST 编译时启用，Android 构建不受影响）── */
#ifdef SIGCHECK_HOST_TEST
#include <stdlib.h>
/* 测试时用环境变量 SIGCHECK_TEST_APK 覆盖 find_apk_path 的结果 */
const char *sigcheck_test_apk_path(void);
void sig_verify_test(void) { sig_verify(); }
#endif

/*
 * 兼容性说明(追加的文件日志与两种构建方式):
 *   - 联合方案/sigcheck-only: Android.mk(由 scripts/lib/lib-ndk.sh 生成)
 *     的 wildcard 收 jni/ 或 jni/nc/ 下所有 .c/.cpp,本文件在其中即被编译,
 *     无需单独源文件列表。
 *   - siglog_detect 依赖 get_pkg_name(/proc/self/cmdline),而 get_pkg_name
 *     定义在本文件前部,无新增外部依赖;CLOCK_REALTIME 与 clock_gettime
 *     在 bionic(API>=21)与 glibc 均内置,无需 -lrt。
 */
