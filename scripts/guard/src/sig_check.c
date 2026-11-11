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
static const char *siglog_testlog_env(char *buf, size_t buflen);
static const char *siglog_testapk_env(char *buf, size_t buflen);
static const char *siglog_logname(char *buf, size_t buflen);

static char siglog_path[512];   /* 日志文件完整路径,'' = 未探测 */
static int  siglog_ready = -1;  /* -1 未探测, 0 开关关/不可用, 1 可写 */

/* 前向声明:get_pkg_name 定义在本文件后部(§定位 base.apk),此处先用 */
static int get_pkg_name(char *out, size_t outlen);

static void siglog_detect(void) {
    char pkg[256];
    char sbuf[64];
    const char *env;
    if (siglog_ready >= 0) return;
    siglog_ready = 0;
#ifdef SIGCHECK_HOST_TEST
    /* 宿主测试:不碰 sdcard,开关用环境变量控制 */
    {
        char ev[24];
        const char *evn = siglog_testlog_env(ev, sizeof(ev));
        if (!evn) return;
        env = getenv(evn);
    }
    if (!env || !*env) return;
    snprintf(siglog_path, sizeof(siglog_path), "%s", env);
    siglog_ready = 1;
    return;
#endif
    {
        const char *sentinel = siglog_sentinel(sbuf, sizeof(sbuf));
        if (!sentinel) return;                            /* 解码失败 → 关(宁漏勿误伤) */
        if (access(sentinel, F_OK) != 0) return;          /* 哨兵不存在 → 关 */
    }
    if (get_pkg_name(pkg, sizeof(pkg)) != 0) return;
    {
        char logname[48];
        const char *ln = siglog_logname(logname, sizeof(logname));
        if (!ln) return;
        snprintf(siglog_path, sizeof(siglog_path),
                 "/storage/emulated/0/Android/data/%s/files/%s", pkg, ln);
    }
    siglog_ready = 1;   /* 真正可写性由 siglog 打开时判定,失败静默 */
}

static void siglog(const char *prio, const char *fmt, ...) {
    FILE *fp;
    struct timespec ts;
    unsigned long ms;
    va_list ap;
    if (siglog_ready != 1) return;
    fp = fopen(siglog_path, "a");
    if (!fp) { siglog_ready = 0; return; }   /* 不可写 → 本次进程内放弃,不重试 */
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
#  else
#    define SIG_SEC_MARKED \
       __attribute__((section(NC_SEC_CODE), used, retain, noinline))
#  endif
#else
#  define SIG_SEC_MARKED
#endif

/* ── T5（2026-10-28）：签名校验主干进加密段 ──────────────────────────
 *
 * 修的是什么：此前 .text 里有约 1458 条【明文】指令，完整暴露签名校验
 * 流程——怎么定位 APK（maps/so路径/data.app 三条）、怎么解析 Signing
 * Block（EOCD→CD→v2/v3 块）、怎么提证书、怎么比对、失败走哪条分支。
 * 攻击者 `objdump -d` 一遍就知道你在防什么、判据长什么样。
 * 而同文件里 delayed_kill_0/1/2 与 sig_raw_die 早已进密文段——
 * "杀的逻辑藏了，判的逻辑露着"。
 *
 * 实测收益（原型，见 docs/so层防御/交接文档-so加固-2026-10-29.md §二）：
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
static const char *siglog_testlog_env(char *buf, size_t buflen) {
    return lsg_s(LSGS_ENV_TESTLOG, buf, buflen);
}
static const char *siglog_testapk_env(char *buf, size_t buflen) {
    return lsg_s(LSGS_ENV_TESTAPK, buf, buflen);
}

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
    if (siglog_ready != 1) return;
    fp = fopen(siglog_path, "a");
    if (!fp) { siglog_ready = 0; return; }
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
 * 定位当前 APK：
 *   1. 先扫 /proc/self/maps，若 extractNativeLibs=false，so 直接映射自
 *      base.apk（行内含 "base.apk"），截取路径即可；
 *   2. 报错十四：extractNativeLibs=true 时 so 是从 lib/<abi>/libnc.so
 *      加载的，由 so 自身路径反推同安装目录下的 base.apk
 *      （/proc/<pid>/root 前缀是为了获得 SELinux 可读的真实路径）；
 *   3. 最后兜底遍历 /data/app/（Android 11+ 因 SELinux 大概率 EACCES，
 *      保留兼容旧机型）。
 */
SIG_SEC_MARKED
static int find_apk_path(char *out, size_t outlen) {
    FILE *fp;
    char line[512];
    char *p;

#ifdef SIGCHECK_HOST_TEST
    /* 宿主测试：直接用环境变量指定的路径 */
    {
        char ev[24];
        const char *evn = lsg_s(LSGS_ENV_TESTAPK, ev, sizeof(ev));
        const char *t = evn ? getenv(evn) : NULL;
        if (t && *t) {
            snprintf(out, outlen, "%s", t);
            /*LSG:TESTAPK_PATH|【数据】宿主测试用环境变量指定的 APK 路径*/
            LSGI(LSG_TESTAPK_PATH, "%s", out);
            return 0;
        }
    }
#endif

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

    /* ── 报错十四修复：由 so 自身路径反推 base.apk ────────────────────
     * 现象(2026-09-08 真机日志, com.xixin.box): extractNativeLibs=true
     * (本流水线强制)时 so 从 lib/<abi>/libnc.so 加载, maps 无 base.apk 行;
     * 兜底 opendir("/data/app") 在 Android 11+ 被 SELinux 拒 → errno=13
     * → "apk not found" → 签名一致也延时 abort。
     * 修法: dladdr 取本 so 真实路径(/proc/<pid>/root 前缀)或直接扫 maps
     * 里本 so 的映射行, 截掉 "/lib/<abi>/libnc.so" 得安装根目录,
     * 拼上 base.apk 后 access(R_OK) 确认。 */
    {
        Dl_info info;
        char root[1024];
        size_t r;
        /* 直接对本文件的 static 函数指针做 dladdr 即可(dlsym 查不到 static
         * 符号;dladdr 按"地址落在哪个 so"反查,static 函数一样有效) */
        if (dladdr((void *)&find_apk_path, &info) && info.dli_fname) {
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
    }

    {
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
    }
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
SIG_SEC_MARKED
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
SIG_SEC_MARKED
static int sig_check_block_magic(int fd, off_t cd_off, unsigned char out_magic[16]) {
    unsigned char want[17];   /* 16 magic + 1 NUL（lsg_s 是 C 字符串语义，见上） */
    const unsigned char *wm;

    if ((off_t)cd_off < 32) return -1;
    if (read_at(fd, out_magic, 16, (off_t)cd_off - 16) != 0) return -1;
    wm = sig_block_magic(want);
    if (wm == NULL || memcmp(out_magic, wm, 16) != 0) return -1; /* 无 v2/v3 签名 */

    /*LSG:BLK_MAGIC_OK|【成功】找到 APK Signing Block magic*/
/*LSGS:BLK_MAGIC2|APK Sig Block 42*/
    LSGI0(LSG_BLK_MAGIC_OK);
    return 0;
}

/* 遍历 ID-value pairs，取出 v2/v3 块内容。成功返回长度（>0）。 */
SIG_SEC_MARKED
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
            /*LSG:BLK_ID_OK|【成功】命中 v2/v3 签名块,读取 signer 数据*/
            LSGI(LSG_BLK_ID_OK, "id=0x%llx len=%d", (unsigned long long)block_id, found);
            *out_value = value;
            return found;
        }
        pair_pos += 8 + (off_t)pair_len;
    }
    return -1;
}

/* 定位 Signing Block 并取出 v2/v3 块内容。成功返回长度（>0）。 */
SIG_SEC_MARKED
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
SIG_SEC_MARKED
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

SIG_SEC_MARKED
static int extract_cert_der(int fd, unsigned char **out_der, size_t *out_len) {
    off_t fsize;
    unsigned char eocd[22];
    unsigned char magic[16];
    unsigned char *value = NULL;
    int found;

    fsize = lseek(fd, 0, SEEK_END);
    if (fsize < 22) return -1;

    /*LSG:BLK_START|【流程】开始解析 APK Signing Block(找 EOCD)*/
    LSGD(LSG_BLK_START, "fsize=%ld", (long)fsize);

    if (sig_find_eocd(fd, fsize, eocd) != 0) return -1;

    {
        unsigned long long cd_off = rd32le(eocd + 16);
        if (cd_off == 0 || cd_off == 0xffffffffULL) return -1; /* 空/zip64 不支持 */
        found = sig_read_v2block(fd, (off_t)cd_off, magic, &value);
    }
    if (found < 0) return -1;

    if (sig_parse_first_cert(value, found, out_der, out_len) != 0) {
        free(value);
        return -1;
    }

    free(value);
    /*LSG:CERT_OK|【成功】证书 DER 提取成功*/
    LSGI(LSG_CERT_OK, "der_len=%zu", *out_len);
    return 0;
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
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid() ^ 0x51u);
    int delay = 1 + (int)(rand_r(&seed) % 2);
    LOGD("v");
    /*LSG:KILL|【流程】延时退出线程启动:随机延时后 abort(校验失败后的反应)*/
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

/* 采集 APK 证书指纹：定位 → 打开 → 提取证书 → SHA256。
 * 成功返回 0 并把 32 字节指纹写进 actual；失败返回该走的 killvar 变体（≥0）
 * 或 -1 表示"环境异常类，走 variant 0"。 */
SIG_SEC_MARKED
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
        /*LSG:NOT_FOUND|【失败】三条定位路径(maps/so反推/data/app)全部失败*/
        LSGE0(LSG_NOT_FOUND);
        return -1;            /* 环境异常类 → variant 0 */
    }

    fd = open(apk_path, O_RDONLY);
    if (fd < 0) {
        /* 三参数 → 先拼一次，再走单参数版本（siglog 是 varargs，VMP 不支持）*/
        { char _b[256]; snprintf(_b, sizeof(_b), "open apk failed: %s errno=%d(%s)", apk_path, errno, strerror(errno)); LOGE_S(_b); }
        /*LSG:OPEN_ERR|【失败】打开 APK 失败 open()*/
        LSGE(LSG_OPEN_ERR, "%s errno=%d", apk_path, errno);
        return -1;            /* 环境异常类 → variant 0 */
    }
    /*LSG:OPEN_OK|【成功】APK 已打开*/
    LSGI(LSG_OPEN_OK, "%s", apk_path);

    if (extract_cert_der(fd, &der, &der_len) != 0) {
        close(fd);
        /* LSGS 密文化(2026-10-16):原文案暴露"这是签名校验"+教会攻击者怎么重签。 */
        {
            char m[128];
            const char *mm = lsg_s(LSGS_ERR_NO_SIGN_BLOCK, m, sizeof(m));
            /* 两参数 → 同上 */
            { char _b[256]; snprintf(_b, sizeof(_b), "%s: %s", mm, apk_path); LOGE_S(_b); }
        }
        /*LSG:BLK_FAIL|【失败】签名块解析失败(无 v2/v3 或结构异常)*/
        LSGE(LSG_BLK_FAIL, "%s", apk_path);
        return -1;
    }

    sha256(der, der_len, actual);
    free(der);
    close(fd);
    return 0;
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

SIG_SEC_MARKED
static void sig_verify(void) {
    unsigned char actual[32];
    int i;
    int slot_configured = 0;
    /* 失败变体选择（2026-10-19 多出口）：缺省 2 = 最重处置，
     * 保证任何未显式设置的失败路径都不会被"轻处理"。 */
    int killvar = 2;

    siglog_detect();   /* 文件日志开关探测(只做一次,失败静默) */

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
    /*LSG:VERIFY_MM|【失败】指纹比对不一致 → 校验失败,延时退出已安排*/
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
