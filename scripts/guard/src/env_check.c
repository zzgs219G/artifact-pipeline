/*
 * env_check.c — 纯 Native 环境检测(Frida / Xposed / 调试器),2026-10 新增模块
 *
 * 设计要点:
 *   1. 与 sig_check.c 同型:__attribute__((constructor)) 入口,so 加载即检,
 *      早于一切 Java 代码。由流水线(--envcheck)并入 libnc.so,不勾选则完全不参与编译。
 *   2. 只检测、不检测 Root/Magisk(用户拍板:避免误伤正常 root 用户)。
 *      检测项:
 *        a. Frida: 默认端口 27042 可连接 / 进程内存映射含 frida 特征 / frida-server 进程名
 *        b. Xposed/LSPosed: 已加载库特征(lspd/xposed_art 等)与常见模块文件
 *        c. 调试器: /proc/self/status 的 TracerPid != 0
 *   3. 检测到 → 与 sig_check.delayed_kill 同款反应:分离线程随机延时 abort,
 *      攻击者无法关联是哪个检测触发(两个模块的延时线程天然难以区分)。
 *   4. 全部探测失败均静默:任何一步 I/O 异常都视为"未检出",绝不误伤正常用户。
 *   5. 不依赖 sig_check.c 的任何符号(模块化契约:独立脚本/源文件,零交叉引用);
 *      自带精简日志(logcat 单路,不写文件——避免与 sigcheck 日志文件相互踩)。
 *
 * 编译:流水线 --envcheck 勾选时,把本文件并入 ndk 工程(wildcard 收编),
 *      产物与业务逻辑同在 libnc.so,防剥离。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>

/* .ncx 段解锁(2026-12)：本文件 12 个探针已标进加密段，constructor 里
 * 必须先解锁再跑探针，否则调用的是密文 → SIGILL。实现见 nc_guard_unlock.c
 * （与 so-section-lock.py 配套的"开箱"半边）。 */
extern int ncguard_unlock(void);
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <android/log.h>
/* 2026-12 追加:内存完整性校验(CRC32/ELF 解析)与常驻复查线程所需头 */
#include <stdint.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/uio.h>   /* process_vm_readv 的 iovec(d4 指令检测) */
#include <elf.h>
#include <sys/auxv.h>   /* 2026-12 追加:运行时探测 CPU CRC32 扩展(getauxval/AT_HWCAP) */
#include <sys/ptrace.h> /* 2026-10 追加:PTRACE_TRACEME 反调试抢占 */
#include <sys/prctl.h>  /* 2026-10 追加:PR_SET_DUMPABLE 禁内存 dump */
#include <sys/syscall.h> /* 2026-10 追加:探针可信化 —— syscall 直调绕开 libc hook */
#include <signal.h>      /* 2026-10 追加:方案 F —— SIGABRT 直投内核 */
#include <setjmp.h>      /* 2026-11-08 追加:SIGTRAP 陷阱用 sigsetjmp/siglongjmp */
#include <stdarg.h>
#if defined(__aarch64__)
#include <arm_acle.h>   /* 2026-12 追加:__crc32* 内建即硬件 CRC32(需 target("crc")) */
#endif

/* 中文流程日志(与 sig_check.c 同一套生成数据,static 定义互不冲突):
 * 文案在源码 LSG 标记注释里(可读),so 内密文(strings 不泄语义),
 * 运行时解码后写与 sig_check 同一个日志文件(哨兵开关控制)。
 * 注:env_check 自身无文件日志能力(设计要点5:零交叉引用),解码后
 * 走 sig_check.c 提供的同名 siglog 文件通道? —— 不,遵守契约:
 * 这里自带一份最小文件写入(envlog_c),路径探测复用 sig_check 已探测
 * 的结果不可行(跨模块),故独立探测哨兵/包名,逻辑与 sig_check 对称。 */
#include "nc_guard_layout.h"  /* 契约常数单一真相源：段名/尺寸/偏移 */
#include "sig_log_data.h"
#include "env_internal.h"   /* 2026-11-08: 探针声明（env_probes.c）*/

#define LOG_TAG "nc"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static char envlog_path[512];
static int  envlog_ready = -1;

static void envlog_detect(void) {
    char pkg[256];
    const char *env;
    FILE *fp;
    int fd;
    if (envlog_ready >= 0) return;
    envlog_ready = 0;
#ifdef SIGCHECK_HOST_TEST
    {
        char ev[24];
        const char *evn = lsg_s(LSGS_ENV_TESTLOG, ev, sizeof(ev));
        if (!evn) return;
        env = getenv(evn);
    }
    if (!env || !*env) return;
    snprintf(envlog_path, sizeof(envlog_path), "%s", env);
    envlog_ready = 1;
    return;
#endif
    /* 哨兵与 sig_check 同一个(2026-10-16 LSGS 密文化):解码后比对,失败=关 */
    {
        char sb[48];
        const char *sn = lsg_s(LSGS_SIGLOG_SENTINEL, sb, sizeof(sb));
        if (!sn || access(sn, F_OK) != 0) return;
    }
    {
        char _pb[24];
        const char *_p = lsg_s(LSGS_PATH_CMDLINE, _pb, sizeof(_pb));
        FILE *c = _p ? fopen(_p, "r") : NULL;
        if (!c) return;
        {
            size_t n = fread(pkg, 1, sizeof(pkg) - 1, c);
            fclose(c);
            if (n == 0) return;
            pkg[n] = '\0';
        }
    }
    {
        char ln2[48];
        const char *ln = lsg_s(LSGS_LOGNAME, ln2, sizeof(ln2));
        if (!ln) return;
        snprintf(envlog_path, sizeof(envlog_path),
                 "/storage/emulated/0/Android/data/%s/files/%s", pkg, ln);
    }
    /* 预检可写性(以追加方式打开一次即验证),失败则本次进程内放弃 */
    fd = open(envlog_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) return;
    close(fd);
    (void)fp;
    envlog_ready = 1;
}

static void envlog(const char *prio, const char *msg) {
    FILE *fp;
    struct timespec ts;
    unsigned long ms;
    if (envlog_ready != 1) return;
    fp = fopen(envlog_path, "a");
    if (!fp) { envlog_ready = 0; return; }
    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (unsigned long)ts.tv_sec * 1000UL + (unsigned long)(ts.tv_nsec / 1000000UL);
    fprintf(fp, "[%lu][%s][pid %d] %s\n", ms, prio, (int)getpid(), msg);
    fclose(fp);
}

/* 解码 + 写文件 + logcat(prio: 0=I 1=E) */
void envlog_c(int is_err, lsg_id_t id, const char *detail) {
    char msg[512];
    char line[640];
    const char *prio = is_err ? "E" : "I";
    if (lsg_decode(id, msg, sizeof(msg)) < 0) return;
    if (detail && *detail) {
        snprintf(line, sizeof(line), "%s (%s)", msg, detail);
        __android_log_print(is_err ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, LOG_TAG, "%s", line);
        envlog(prio, line);
    } else {
        __android_log_print(is_err ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, LOG_TAG, "%s", msg);
        envlog(prio, msg);
    }
}

/* ─────────────────────────── 检测到危险环境后的反应 ───────────────────────────
 * 与 sig_check.c 的 delayed_kill 同款:分离线程随机延时后处置。
 * 注:两个模块各有一条延时线程,攻击者 hook 掉其一,另一条仍在——天然互为备份。
 *
 * 前向声明:safe_syscall 定义在下方 a0b 节(探针可信化),本节的处置需要提前用它。 */
long safe_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5);

/* 2026-10-19 方案2：不依赖任何 PLT 表项的强制终止（实现见 a0b 节）。
 * 前向声明放这里，因为 env_delayed_kill / env_fail 要在它之前调用。
 * 与 abort() 的语义差异：本函数 noreturn 且不经 libc，二进制里没有
 * abort@plt 那种"改 4 字节废全部"的软目标。 */
__attribute__((noreturn)) static void env_raw_die(long n, long a0, long a1,
                                                  long a2, long a3, long a4,
                                                  long a5);
long env_raw_syscall(long n, long a0, long a1, long a2,
                                   long a3, long a4, long a5);

/* * 2026-10 增强(方案 F):让处置"不直白、难 hook、难归因"
 *   ① 延时堆破坏:先以随机间隔 malloc/free 不同尺寸的块(不写入业务内存),
 *      使进程堆布局碎片化。攻击者即便 hook 掉后续的发信号/abort,进程状态
 *      也已被扰动,后续任意时点的崩溃都难以归因到本校验。
 *      纯 malloc/free,不触碰任何业务数据(通用工具不做业务耦合)。
 *   ② syscall 直调发信号:SIGABRT 用 __NR_tgkill 直投内核,不经 libc 的
 *      abort()——攻击者 LD_PRELOAD/Frida hook abort 不再有效(与方案 C
 *      探针可信化同一思路)。
 *   ③ 保留随机延时:崩溃时机不可预测,攻击者难以把崩溃与"刚触发了什么"关联。
 *
 * 失败兜底:syscall 不可用(被 seccomp 拦等)时回落 abort(),绝不静默放行。 */
/* ── .rodata 路径字符串密文化（2026-10-19，修实测报告 §4）─────
 *
 * 报告实测：`.rodata` 明文躺着 20+ 条路径，一条未加密，
 * 且不是零散泄漏，而是【完整的防御决策树】：
 *   /proc/self/status → 反调试    /proc/self/maps → 反注入
 *   /proc/net/tcp     → 反双开    /proc/self/task → 线程级反调试
 *   APK Sig Block 42  → 直读签名块
 * 攻击者 strings 一遍就能反推出整套架构。
 *
 * 用既有 LSGS 机制（构建期 XOR 密文 / 运行期解码），与特征串同表。
 * ⚠️ 标记格式见 make-sig-log.py（此处不写其字面形态——嵌套注释会提前
 *    终结注释块，编译炸 top level declarator，报错速查已留档两次）。
 */
/*LSGS:PATH_CMDLINE|/proc/self/cmdline*/
/*LSGS:PATH_MAPS|/proc/self/maps*/
/*LSGS:PATH_NET_TCP|/proc/net/tcp*/
/*LSGS:PATH_NET_TCP6|/proc/net/tcp6*/
/*LSGS:PATH_STATUS|/proc/self/status*/
/*LSGS:PATH_TASK|/proc/self/task*/
/*LSGS:PATH_TASK_COMM|/proc/self/task/%s/comm*/
/*LSGS:PATH_TASK_STATUS|/proc/self/task/%s/status*/
/*LSGS:PATH_STAT|/proc/self/stat*/
/*LSGS:PATH_NET_UNIX|/proc/net/unix*/
/*LSGS:PATH_LIBC|libc.so*/

/* ── kill 链进加密段（2026-10-19，方案4：去掉 PLT 单点的可发现性）────
 *
 * 修的是外部实测报告（docs/so层防御/外部实测报告结论汇总.md §五 记录的第一版攻破链）
 * 指出的最廉价绕过路径：
 *   `abort@plt` / `_exit@plt` / `raise@plt` 三个 PLT 桩，各改 4 字节，
 *   380 个调用点全部失效 —— 攻击者 30 秒拿到可在真机常驻运行的绕过包。
 *
 * 本方案不是"改成静默污染"（那需要业务语义知识，无法对任意 APK 通用），
 * 而是让攻击者【找不到】kill 逻辑：把真正的处置函数标进 .ncx 密文段。
 * 未解锁时它是密文，`strings`/`objdump` 都看不到；静态搜 `abort@plt`
 * 的引用也只能看到"某处 bl 进了一段解不开的东西"。
 *
 * ⚠️ 三条纪律（违反任一即死锁或崩溃）：
 *   ① env_fail()【绝不能】进 .ncx —— 它是本函数的调用方，且被
 *      env_check_run() 在构造期调用。锁进去 = 开锁器锁进箱子 = 死锁。
 *      本处只标【被调用】的 env_delayed_kill。
 *   ② 必须条件化 NC_GUARD_SECTIONED（同 nc_link.c 的理由：宿主编译没有
 *      解锁设施，标了段就读到密文 → 假红）。
 *   ③ 调用时序必须安全 —— 已确认：env_check_entry 首行就是
 *      ncguard_unlock()，所以 env_fail → 线程 → env_delayed_kill
 *      这条链上，段必定已是明文。
 *
 * 为什么放在 .ncx 而不是 .ncxr：这是【代码】不是常量表，
 * 需要执行权限，.ncxr 是 AWR 不可执行段。
 *
 * 效果边界（如实）：它提高的是【发现成本】，不是【patch 成本】。
 * 攻击者若能离线解开 .ncx（当前 master 仍是占位符，报告实测 8 分钟），
 * 就又能看到这段代码。真正断绝这条路要靠 master 随机化（P1-1，未做）
 * 与内联 svc 打散出口（方案2，未做）。本方案是纵深的一层，不是终点。 */
#if defined(NC_GUARD_SECTIONED) && !defined(ENVCHECK_HOST_TEST)
#  define ENV_KILL_SECTION __attribute__((section(NC_SEC_CODE), retain, used, noinline))
#else
#  define ENV_KILL_SECTION
#endif

ENV_KILL_SECTION
static void *env_delayed_kill(void *arg) {
    (void)arg;
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid());
    int delay = 1 + (int)(rand_r(&seed) % 3);   /* 与 sig_check 调试延时保持一致 */

    /* ① 延时堆破坏(与 sig_check.c 的 delayed_kill 同款手法) */
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

    /* ② syscall 直调发 SIGABRT(绕开 libc 的 abort,防 hook) */
#ifdef __NR_tgkill
    if (safe_syscall(__NR_tgkill, (long)getpid(), (long)gettid(), SIGABRT, 0, 0, 0) == 0) {
        /* 信号已投递;若因屏蔽未致死,下面兜底 */
    }
#endif
    /* ③ 兜底:syscall 失败或被拦时仍要死,绝不静默放行。
     * 2026-10-19 方案2：不再走 abort@plt（改 4 字节即废），改 svc 直投
     * SIGABRT / brk 兜底，二进制里没有对应的 PLT 表项可改。 */
    {
        long tid = env_raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
        env_raw_die(__NR_tgkill, (long)getpid(), tid, SIGABRT, 0, 0, 0);
    }
    return NULL;   /* 不可达，仅为满足 noreturn 语义 */
}

void env_fail(void) {
    LOGI("nc: t");   /* so加固2026-10: 原文 "env check triggered" 含路标词,改中性 */
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, env_delayed_kill, NULL) != 0) {
        /* 起线程失败则直接崩，不能放行。
         * 2026-10-19 方案2：同上，不用 abort@plt。 */
        {
            long tid = env_raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
            env_raw_die(__NR_tgkill, (long)getpid(), tid, SIGABRT, 0, 0, 0);
        }
    }
    pthread_attr_destroy(&attr);
}

/* ────────────────── a0. 反调试抢占(2026-10 追加) ──────────────────
 * tracer_probe(下方 c 项)是【被动】读 /proc/self/status 查 TracerPid——
 * 攻击者 attach 后立即 detach 即可避开(探针只在构造时 + 每 20s 跑)。
 * 本函数改为【主动】向内核声明"本进程不许被调试":
 *   ptrace(PTRACE_TRACEME) —— 声明自身为被跟踪者后,内核拒绝任何外部
 *     ptrace attach(EBUSY),调试器/事后挂载在系统层面被堵死,不依赖轮询时机。
 *   prctl(PR_SET_DUMPABLE, 0) —— 同时禁掉 /proc/pid/mem 与 core dump 的可达性,
 *     抬高内存 dump 与 Frida 注入的门槛。
 *
 * 性能:仅构造期执行一次,零运行期开销。
 * 失败处理:PTRACE_TRACEME 返回 -1 且 errno==EPERM 表示"本进程已被跟踪"
 *   (真机可能被系统的其他调试设施占用,如 Android Studio 的 profileable),
 *   此时【不判失败】——交由 tracer_probe 的 TracerPid 判定,避免误伤;
 *   其他错误同样静默(宁漏勿误伤,与全文件误报兜底纪律一致)。
 * 注:已有 tracer 挂着时 PTRACE_TRACEME 会失败,这是预期行为,不算异常。 */
static void anti_debug_preempt(void) {
    (void)ptrace(PTRACE_TRACEME, 0, 0, 0);
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

/* ────────────────── a0b. 探针可信化:syscall 直调(2026-10 追加) ──────────────────
 * 背景:全文件的 /proc 探针(以及 ELF 解析)一律走 libc 的 fopen/fgets/fread。
 * 攻击者只需 LD_PRELOAD 或 Frida 挂一个假的 fopen,即可让【全部探针】读到
 * 伪造内容(maps 里藏掉 frida、status 里 TracerPid 归零、net/unix 清空),
 * 一行 hook 废掉整个环境检测模块。
 *
 * 对策:所有敏感读取改走 syscall() 直调内核,不经 libc 的 FILE* 层。
 * 攻击者要绕过就必须 hook syscall 本身(或内核级 rootkit),门槛显著抬高。
 *
 * 性能:syscall 直调比 fopen/fgets 更轻(少一层缓冲与锁),零额外开销。
 * 兼容:__NR_openat 在 arm64 与 armv7 上均为 257,无需分架构处理;
 *       read/close 的号也不分架构。不可用(seccomp 等)时返回"读失败",
 *      由调用方的"宁漏勿误伤"兜底接住,绝不误判。
 *
 * 本函数只负责【读一段文件到内存】,不做任何判定 —— 探针的判定逻辑一行不改。 */
/* ── 2026-10-19 方案2：内联 svc，去掉 syscall@plt 这个软目标 ──────────
 *
 * 背景（实测报告 §12.1）：攻击者发现 `abort@plt` / `_exit@plt` / `raise@plt`
 * 三个 PLT 桩各 4 字节，改掉即废 380 个调用点。本文件此前虽然已经
 * "syscall 直调绕过 libc"，但那是调用 libc 的 syscall() —— 它【本身也是一个
 * PLT 表项】（syscall@plt）。所以真正的绕过成本只是"改 4 个桩而不是 3 个"。
 *
 * 现在改为内联 svc #0：编译器直接发指令，二进制里没有 syscall@plt 可改。
 * 攻击者要拦，只能在指令层逐处 patch（每个调用点 4 字节，且分散在密文段内
 * 看不见），或上内核级 hook。
 *
 * 双 ABI 差异（这是必须分架构的原因，不是冗余）：
 *   arm64 : 系统调用号在 x8，参数 x0-x5，返回 x0；指令 svc #0
 *   armv7 : 系统调用号在 r7，参数 r0-r5，返回 r0；指令 svc #0（EABI）
 * 用 GNU 内联汇编的具名寄存器变量绑定，让编译器自己安排其余寄存器，
 * 不写死 x0-x5 的物理分配（写死会与编译器分配的实参寄存器冲突）。
 *
 * 失败语义完全不变：返回 -errno 由内核给出，与 syscall() 一致；
 * 调用方的"宁漏勿误伤"兜底逻辑一行未动。
 * ⚠️ 本函数【不】执行任何判定，只做系统调用转发。 */
#if defined(__aarch64__)
/* 强制终止，且不经过任何 PLT 表项（2026-10-19 方案2）。
 * 用 tgkill 直投 SIGABRT：内核立刻发信号，不返回。
 * 为什么不用 abort()：abort@plt 是单个 4 字节表项，改掉即废所有调用点
 * （实测报告 §12.1 的核心绕过路径）。这里没有表项可改。
 * 为什么不用 _exit()：_exit@plt 同理；且 _exit 不发崩溃信号，
 * tombstone 里没有记录，反而对攻击者更"友好"。
 * 为什么带 __attribute__((noreturn))：让编译器知道后续代码不可达，
 * 避免它把兜底逻辑优化成"可达"而插入多余的分支。 */
__attribute__((noreturn, noinline))
static void env_raw_die(long n, long a0, long a1, long a2,
                        long a3, long a4, long a5);
long env_raw_syscall(long n, long a0, long a1, long a2,
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
long safe_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    return env_raw_syscall(n, a0, a1, a2, a3, a4, a5);
}
#elif defined(__arm__)
/* ⚠️ 2026-10-19 CI 实证：ARMv7 的 r7 是【保留寄存器】（Thumb 下作 frame pointer，
 * 也是平台寄存器），clang 拒绝 `register long r7 __asm__("r7")` ——
 * CI 报 `error: write to reserved register 'R7'`，armeabi-v7a 整个编译失败。
 * 本地交叉编译没复现，是因为漏了 `-mthumb`（NDK 对 armv7 默认 Thumb）。
 *
 * 修法：不把 r7 声明成寄存器变量，改为在内联汇编里显式 push/pop 保存恢复。
 * 这样既满足内核 ABI（调用号必须在 r7），又不让编译器认为我们在"占用"它。
 * 已用 --target=armv7-linux-androideabi -mthumb 在 -O2/-Oz/±frame-pointer
 * 四种组合下验证：零 error 零 warning，生成 push {r7} / mov r7 / svc / pop {r7}。
 *
 * 参数只用 r0-r3（AAPCS 的前四个整型参数寄存器），超过 4 个时由编译器
 * 自行压栈/取用；这里刻意把 n 放在最后用 "r" 约束交给编译器分配，
 * 由 mov r7 搬进系统调用寄存器。 */
long env_raw_syscall(long n, long a0, long a1, long a2,
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
long safe_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    return env_raw_syscall(n, a0, a1, a2, a3, a4, a5);
}
#else
/* 非 ARM 平台（宿主编译）走 libc：没有 svc 指令，且宿主测试不关心这条 */
long safe_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    return syscall(n, a0, a1, a2, a3, a4, a5);
}
#endif

__attribute__((noreturn, noinline))
static void env_raw_die(long n, long a0, long a1, long a2,
                        long a3, long a4, long a5) {
#if defined(__aarch64__) || defined(__arm__)
    (void) env_raw_syscall(n, a0, a1, a2, a3, a4, a5);
    /* 理论不可达：tgkill(SIGABRT) 会立刻终止本线程。
     * 若信号被屏蔽/被 seccomp 拦，走到这里说明本进程已不可信 —— 用
     * 非法指令兜底。SIGILL 同样产生 tombstone，且没有 PLT 依赖。 */
    __builtin_trap();
#else
    (void) n; (void) a0; (void) a1; (void) a2; (void) a3; (void) a4; (void) a5;
    __builtin_trap();
#endif
}

/* 读整个文件到 calloc 的缓冲(调用方 free)。成功返回长度(不含结尾 \0),失败返回 -1。
 * 注:缓冲末尾补 \0,便于按字符串处理(与 fgets 语义衔接)。 */
long safe_read_alloc(const char *path, char **out) {
    int fd;
    char *buf = NULL;
    size_t cap = 0, len = 0;
    *out = NULL;
    fd = (int)safe_syscall(__NR_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0) return -1;
    cap = 65536;
    buf = (char *)malloc(cap);
    if (!buf) { safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0); return -1; }
    for (;;) {
        long r;
        if (len + 4096 + 1 > cap) {
            char *nb;
            size_t ncap = cap * 2;
            nb = (char *)realloc(buf, ncap);
            if (!nb) { free(buf); safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0); return -1; }
            buf = nb; cap = ncap;
        }
        r = safe_syscall(__NR_read, fd, (long)(buf + len), (long)(cap - len - 1), 0, 0, 0);
        if (r < 0) { free(buf); safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0); return -1; }
        if (r == 0) break;
        len += (size_t)r;
        if (len > (32u << 20)) break;   /* 上限守卫:防超大文件耗尽内存 */
    }
    safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    buf[len] = '\0';
    *out = buf;
    return (long)len;
}

/* ────────────────────── 行迭代器(替代 fopen+fgets 组合) ──────────────────────
 * 用法与 fgets 循环同构,便于逐处替换而不动判定逻辑:
 *   safe_lines_t it; const char *line;
 *   if (safe_lines_open(&it, path) == 0) {
 *       while ((line = safe_lines_next(&it)) != NULL) { ...原 fgets 循环体... }
 *       safe_lines_close(&it);
 *   } */
int safe_lines_open(safe_lines_t *it, const char *path) {
    it->buf = NULL; it->pos = 0; it->len = -1;
    it->len = safe_read_alloc(path, &it->buf);
    if (it->len < 0 || it->buf == NULL) { it->len = -1; return -1; }
    return 0;
}

/* 返回下一行(已去尾换行),到末尾返回 NULL。行内容指向 it->buf 内部,无需释放。 */
char *safe_lines_next(safe_lines_t *it) {
    size_t start;
    if (it->len < 0 || it->buf == NULL) return NULL;
    if (it->pos >= (size_t)it->len) return NULL;
    start = it->pos;
    while (it->pos < (size_t)it->len && it->buf[it->pos] != '\n') it->pos++;
    it->buf[it->pos] = '\0';
    if (it->pos < (size_t)it->len) it->pos++;   /* 跳过换行 */
    return it->buf + start;
}

void safe_lines_close(safe_lines_t *it) {
    if (it->buf) { free(it->buf); it->buf = NULL; }
    it->len = -1; it->pos = 0;
}

/* g. 常驻复查线程:周期性重跑全部探测,补"启动后才挂载"的窗口。
 *    与构造时一次性检测并存(env_check_run 先跑一次,再启动本线程)。
 *
 * Java 心跳检查(2026-10 借鉴 XopProtector 双向绑定):
 *    nc_heartbeat_expired 由 nc_link.c 提供(sigcheck 勾选时在工程里);
 *    envcheck 单勾时 nc_link 不在工程 → weak 弱引用自动落空返回 0,
 *    检查静默跳过,组合自洽(见 weak 符号注释)。 */
#if defined(__GNUC__)
__attribute__((weak))
#endif
int nc_heartbeat_expired(void);

/* 武装端(2026-10-16 修复):so constructor 调用,同 weak 规则 */
#if defined(__GNUC__)
__attribute__((weak))
#endif
void nc_heartbeat_arm_constructor(void);

/* 代码页完整性校验(2026-10-30 提交二):由 nc_guard_boot.c 提供。
 * weak 规则同上 —— 该函数在 nc_guard_boot.c(必编),但用 weak 是为了
 * 与本文件既有风格一致,且容许"精简组合裁掉 boot.c"的极端情况。
 * 返回 1=完好, 0=被改过(判定与处置由本文件决定,它不自己杀)。 */
#if defined(__GNUC__)
__attribute__((weak))
#endif
int ncguard_code_check(void);

static void *env_watchdog(void *arg) {
    (void)arg;
    unsigned round = 0;   /* CRC 降频计数:指令检测每轮跑,CRC 每 5 轮跑一次 */
    for (;;) {
        int hit = 0;
        /* 轮询间隔:20s(2026-10-21 修复——此前一直停在 2026-10-16 的调试值
         * sleep(2),注释写着"发布前必须改回"但从未改回,属漏改参数)。
         *
         * 为什么 20s 不损失防御效果:Frida/Xposed 是"装完长期驻留"型攻击,
         * 不是"出现 2 秒就消失"——20s 内必然再次命中,检出延迟的差别只
         * 影响攻击者的"第几分钟被看见",不影响"能不能被看见"。
         * 而 2s 的代价是每天 43200 次唤醒 × 11 个探针,CPU 常驻与耗电
         * 肉眼可见(低端机尤其明显)。
         *
         * 为什么这个参数不再需要"调试期改短":调试场景是"手动挂 Frida
         * 验证能不能检测到"——挂上后 20s 内必报,等 20s 与等 2s 验证的
         * 是同一件事,验证效率无损失。真正的"快出结果"调试(删调用点
         * 快速死)由心跳宽限窗(Guard.java 的 5s 喂食周期)承担,不在这里。
         *
         * 若未来确需临时改短:用 -DNC_HB_DEBUG_FAST（见 nc_link.c），
         * 严禁把发布值改掉再提交——本次漏改已证明"注释提醒"拦不住。
         *
         * ⚠️ 本间隔与 nc_link.c 的心跳参数是【联动】的（2026-10-21）：
         *   "删喂食后到进程死" = 轮询周期 + 保活窗（两者在 nc_link.c
         *   的注释里有完整的选型推导）。
         *   现行发布值 5s 轮询 + 8s 保活 → 调试最坏 ~13s 出结果，
         *   无需再分调试/发布两套（用户的调试方式就是拿发布包做
         *   逆向实验，宏开关对真实工作流无效——ca3fce1 的盲点）。
         *   5s 轮询的代价核算：每天 17280 次唤醒，其中 11 个探针里
         *   重的两个（CRC 全量比对）仍是每 5 轮一次（~25s），轻探针
         *   都是 maps/端口级别的 open+read，单轮毫秒级——CPU 常驻
         *   占用仍远低于当年 sleep(2) 全速轮询的 1/10。 */
#ifdef NC_HB_DEBUG_FAST
        sleep(2);
#else
        sleep(5);
#endif
        round++;
        /* d4 指令打分(纳秒级)每轮先跑;命中才轮到重的 CRC(命中通常也意味着
         * 下一轮 CRC 会确认;这里独立判定,两个探针抓的攻击面不同,见各自注释) */
        if (!hit && libc_hook_probe())       hit = 1;
        if (frida_port_probe())              hit = 1;
        if (!hit && frida_maps_probe())      hit = 1;
        if (!hit && frida_tcp_table_probe()) hit = 1;
        if (!hit && frida_thread_probe())    hit = 1;
        if (!hit && frida_unix_probe())      hit = 1;
        if (!hit && xposed_maps_probe())     hit = 1;
        if (!hit && xposed_file_probe())     hit = 1;
        if (!hit && tracer_probe())          hit = 1;
        /* 2026-11-08 追加:全线程 TracerPid + stat state。两项都放在
         * tracer_probe 之后 —— 它们是同一目标(/proc 里的调试痕迹)的
         * 不同通道,主通道没命中才走补充通道,省 I/O。 */
        if (!hit && tracer_all_threads_probe()) hit = 1;
        if (!hit && stat_state_probe())         hit = 1;
        /* 2026-11-08 追加：SIGTRAP 陷阱。返回三态 —— 只有 ==1 才判命中，
         * -1（skip）必须当"未检出"，绝不因"建不起线程"误报。 */
        if (!hit && trap_probe() == 1)          hit = 1;
        /* CRC 全量比对降频(2026-10):Inline hook 是"装完长期驻留"型攻击,
         * 100s 检出延迟对效果无损,换来 80% 轮次的毫秒级开销归零 */
        if (!hit && (round % 5 == 0) && libc_text_crc_probe()) hit = 1;
        if (!hit && (round % 5 == 0) && self_text_crc_probe()) hit = 1;
        /* 代码页完整性(2026-10-30 提交二):解密后 .ncx/.ncxr 明文是否被改。
         * 这是当前唯一能抓 inline hook 的探针 —— 上面两个 CRC 探针比的是
         * 【磁盘 vs 内存】(抓"文件被改后加载"),而 .ncx 在磁盘上是密文,
         * 那套方法对它天然不适用。本项比的是"解锁时的基线 vs 当前内存",
         * 补的正是这个空洞。
         * 同样降频到每 5 轮(~25s):全段 CRC 是重探针;inline hook 长期
         * 驻留,25s 内必然被看见,检出的早与晚不影响"能不能看见"。
         * ⚠️ weak 落空(NULL)时跳过,不误判 —— 组合自洽(同心跳的规则)。 */
        if (!hit && (round % 5 == 0) && ncguard_code_check && !ncguard_code_check()) hit = 1;
        /* 心跳超时(Java 层被删/被绕过)——独立于上面的环境探针,
         * 不占 hit 位:env_fail 路径相同,但语义上分两条日志便于排障
         * ⚠️ 2026-11-08: 加 NULL 检查。weak 符号缺失时直接调用会跳 0 崩溃
         *    （真机 SIGSEGV 实证见 env_check_entry 里 nc_heartbeat_arm_constructor
         *    的同类修复）。envcheck 单勾时 nc_link 不在工程，本符号必缺失。 */
        if (!hit && nc_heartbeat_expired && nc_heartbeat_expired())  hit = 2;
        if (hit == 1) {
            /*LSG:ENV_WATCHDOG_HIT|【失败】常驻复查线程检出危险环境*/
            envlog_c(1, LSG_ENV_WATCHDOG_HIT, NULL);
            env_fail();
        } else if (hit == 2) {
            /*LSG:ENV_HB_LOST|【失败】Java 心跳丢失(壳被删或被绕过)*/
            envlog_c(1, LSG_ENV_HB_LOST, NULL);
            env_fail();
        }
    }
    return NULL;
}

static void env_watchdog_start(void) {
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, env_watchdog, NULL) == 0) {
        /*LSG:ENV_WATCHDOG_START|【流程】常驻复查线程已启动(每 20s 重检)*/
        envlog_c(0, LSG_ENV_WATCHDOG_START, NULL);
    }
    pthread_attr_destroy(&attr);
}

/* ─────────────────────────── 检测主逻辑 ─────────────────────────── */

static void env_check_run(void) {
    int hit = 0;
    int r;

    envlog_detect();

    /*LSG:ENV_START|【流程】so 已加载,进入环境检测 env_check_run*/
    envlog_c(0, LSG_ENV_START, NULL);

    r = frida_port_probe();
    /*LSG:ENV_FRIDA_PORT|【数据】frida 端口探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_PORT, r ? "hit" : "clean");
    if (r) hit = 1;

    r = frida_maps_probe();
    /*LSG:ENV_FRIDA_MAPS|【数据】frida maps 特征探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_MAPS, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = frida_tcp_table_probe();
    /*LSG:ENV_FRIDA_TCP|【数据】frida tcp LISTEN 探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_TCP, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = xposed_maps_probe();
    /*LSG:ENV_XP_MAPS|【数据】Xposed/LSPosed maps 特征探测结果*/
    envlog_c(0, LSG_ENV_XP_MAPS, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = xposed_file_probe();
    /*LSG:ENV_XP_FILE|【数据】Xposed/LSPosed 文件痕迹探测结果*/
    envlog_c(0, LSG_ENV_XP_FILE, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = tracer_probe();
    /*LSG:ENV_TRACER|【数据】调试器 TracerPid 探测结果*/
    envlog_c(0, LSG_ENV_TRACER, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    /* ── 2026-11-08 追加探测(只追加,不改上方逻辑) ── */
    r = tracer_all_threads_probe();
    /*LSG:ENV_TRACER_ALL|【数据】全线程 TracerPid 探测结果*/
    envlog_c(0, LSG_ENV_TRACER_ALL, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = stat_state_probe();
    /*LSG:ENV_STAT_STATE|【数据】/proc/self/stat 的 state 字段探测结果*/
    envlog_c(0, LSG_ENV_STAT_STATE, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    /* SIGTRAP 陷阱（2026-11-08）：三态，-1 = skip 不算命中 */
    r = trap_probe();
    /*LSG:ENV_TRAP|【数据】SIGTRAP 信号链探测结果*/
    envlog_c(0, LSG_ENV_TRAP, r < 0 ? "skip" : (r ? "hit" : "clean"));
    if (!hit && r == 1) hit = 1;

    /* ── 2026-12 追加探测(只追加,不改上方逻辑) ── */
    r = frida_thread_probe();
    /*LSG:ENV_FRIDA_THREAD|【数据】frida 线程名探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_THREAD, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = frida_unix_probe();
    /*LSG:ENV_FRIDA_UNIX|【数据】frida unix socket 探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_UNIX, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = libc_text_crc_probe();
    /*LSG:ENV_CRC|【数据】libc .text 内存完整性校验结果*/
    envlog_c(0, LSG_ENV_CRC, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = self_text_crc_probe();
    /*LSG:ENV_SELF_CRC|【数据】本 so .text 内存完整性校验结果*/
    envlog_c(0, LSG_ENV_SELF_CRC, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    if (hit) {
        /*LSG:ENV_FAIL|【失败】检出危险环境 → 延时退出已安排*/
        envlog_c(1, LSG_ENV_FAIL, NULL);
        env_fail();
    } else {
        /*LSG:ENV_CLEAN|【通过】全部探测干净,环境检测通过*/
        envlog_c(0, LSG_ENV_CLEAN, NULL);
    }
}

/* dlopen 后最先执行的入口(与 sig_check_entry 并存,顺序不定,互不依赖) */
__attribute__((constructor)) static void env_check_entry(void) {
    /* .ncx 解锁(2026-12)：必须排在【所有探针之前】——本文件的 12 个探针
     * 已用 __attribute__((section(NC_SEC_CODE))) 标进加密段，未解锁时它们是密文，
     * 提前调用会执行密文 → SIGILL。
     * 幂等：ncguard_unlock() 内部以 .nck 槽的 magic 判重，未锁/已解锁都返回 0；
     * 失败(负数)不阻断——解密失败时下面调探针会崩，但那正是要暴露的问题，
     * 且 selftest 入口已能从 Java 侧读到失败码。
     * 注：本段是新追加的逻辑行，不改动下面任何既有行（AGENTS.md §2.4）。 */
    ncguard_unlock();
    anti_debug_preempt();   /* 2026-10 追加:先抢占(声明不许被调试),再跑探针 */
    /* 心跳武装(2026-10-16 修复):so 加载即倒计时——N 秒内 Java 必须开始喂。
     * nc_link 仅在勾 sigcheck 时入工程,envcheck 单勾时符号缺失 → weak 落空跳过。
     *
     * ⚠️⚠️ 2026-11-08 修真机 SIGSEGV：原代码直接调用，没有 NULL 检查。
     *    `__attribute__((weak))` 只保证【编译期】不报未定义，不保证【运行期】安全：
     *    符号真的缺失时，链接器生成的 PLT 桩指向地址 0，
     *    `bl <nc_heartbeat_arm_constructor@plt>` 一执行就跳 0 → SIGSEGV。
     *
     *    真机实证（只勾 --envcheck 的包，Redmi 2602BRT18C / Android 17）：
     *        backtrace:
     *          #00 pc 0000000000000000  <unknown>
     *          #01 pc 000000000002d484  libnc.so
     *        反汇编该地址：bl 0x57a90 <nc_heartbeat_arm_constructor@plt>
     *    nm 显示 `w nc_heartbeat_arm_constructor`（弱未定义）。
     *
     *    这与 weak 的标准用法有出入：weak 未定义时【取地址】得 NULL、
     *    【直接调用】并非安全空操作（不同链接器/架构行为不一致，
     *    实测 bionic + lld 下就是跳 0）。所以调用 weak 符号必须显式判空。 */
    if (nc_heartbeat_arm_constructor) nc_heartbeat_arm_constructor();
    env_check_run();
    env_watchdog_start();   /* 2026-12 追加:常驻复查线程(不影响上面的"加载即检") */
}
