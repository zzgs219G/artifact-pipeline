/* env_probes.c — 13 个环境检测探针（2026-11-08 从 env_check.c 拆出）
 *
 * ── 为什么拆 ──────────────────────────────────────────────────────
 *   env_check.c 原本 1600+ 行，其中探针占 942 行。拆开后：
 *     env_check.c   约 754 行（日志 / syscall / IO / kill / watchdog / 调度）
 *     env_probes.c  约 942 行（13 个探针 + 它们专用的 CRC/ELF/内存工具）
 *
 * ── 为什么不按功能拆 4 个文件 ─────────────────────────────────────
 *   LSGS 标记前缀由 make-sig-log.py 按【文件基名】生成。拆多个文件会让
 *   前缀规则变复杂，牵动 sig_log_data.h 里全部枚举名、所有 envlog_c
 *   调用点、以及测试断言 —— 那是爆炸级改动。拆两个文件则前缀不变。
 *
 * ── 段标记纪律（与拆分前一致）────────────────────────────────────
 *   所有探针标 __attribute__((section(NC_SEC_CODE), retain))：
 *     · NC_SEC_CODE = .ncx，未解锁时是密文，静态视角读不到逻辑
 *     · retain 防 lib-ndk.sh 的 --gc-sections 回收（无引用即被删）
 *   ⚠️ 属性与函数之间【不能夹 #define】—— 属性会落到那个 #define 上，
 *      函数本体反而没有段标记。拆出时已逐条核对。
 *
 * ── 依赖纪律 ──────────────────────────────────────────────────────
 *   本文件依赖 env_check.c 提供的基础设施（syscall 包装 / 文件读取 /
 *   行迭代器 / 日志 / 处置），声明见 env_internal.h。反向不依赖。
 *   即：env_check.c 不知道探针内部怎么实现，只知道它们返回 0/1。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <arm_acle.h>

#include "nc_guard_layout.h"   /* NC_SEC_CODE */
#include "sig_log_data.h"      /* lsg_s / LSGS_* */
#include "env_internal.h"

/* ─────────────────────────── a. Frida 检测 ─────────────────────────── */

/* a1. frida 默认端口 27042 / 27043 是否有监听者(127.0.0.1 回环快扫,50ms 超时) */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int frida_port_probe(void) {
    static const int ports[] = { 27042, 27043 };
    size_t i;
    for (i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)ports[i]);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        /* 非阻塞连接探测:正常机器连接立即被拒(ECONNREFUSED)= 未检出 */
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
        int hit = 0;
        if (r == 0) {
            hit = 1;                          /* 立即连上 = 有监听 */
        } else if (errno == EINPROGRESS) {
            fd_set wset;
            struct timeval tv = { 0, 50 };    /* 50ms,足够本机回环 */
            FD_ZERO(&wset);
            FD_SET(fd, &wset);
            if (select(fd + 1, NULL, &wset, NULL, &tv) > 0) {
                int err = 0;
                socklen_t elen = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                hit = (err == 0);             /* 真连上才算,其他错误=未检出 */
            }
            /* 超时:视作未检出(宁漏勿误伤) */
        }
        close(fd);
        if (hit) return 1;
    }
    return 0;
}

/* ────────────────── a2. 特征串密文标记(LSGS) ──────────────────
 * 明文只活在下面的标记注释里(与 LSG 中文文案同一套机制);
 * 构建期 make-sig-log.py 扫描加密 → so 里只有密文;
 * 运行时 lsg_s() 解码到栈缓冲。改特征串 = 改这里的标记明文。
 * ⚠️ 注释里严禁出现 LSGS 标记的字面示例(嵌套注释会提前终结本注释块,
 *    编译炸"top level declarator")——写法示例只存在于 make-sig-log.py。
 * ─────────────────────────────────────────────────────────────── */
/*LSGS:FRIDA_AGENT|frida-agent*/
/*LSGS:FRIDA_GADGET|frida-gadget*/
/*LSGS:FRIDA_INJECT|frida-inject*/
/*LSGS:GADGET_FRIDA|gadget_frida*/

/* a2. /proc/self/maps 里有没有 frida 特征库(frida-gadget/frida-agent 注入痕迹)
 * 特征串不明文进 so(2026-10,借鉴 XopProtector 的 OBSC 思路,走自家 LSG 机制):
 * 探针比对用的 4 个特征串来自上方 LSGS 标记(构建期加密,运行时 lsg_s 解码)。
 * strings 扫 so 得不到任何检测特征。
 * 解码失败(NULL)按"未检出"处理,与全文件宁漏勿误伤纪律一致。
 * ⚠️ 本注释及全文件任何注释中禁止书写 LSGS 标记的字面形态(嵌套注释会
 *    提前终结注释块,编译炸 top level declarator;报错速查已留档)。 */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int frida_maps_probe(void) {
    safe_lines_t it;
    char *line;
    char s1[24], s2[24], s3[24], s4[24];
    int hit = 0;
    const char *k1 = lsg_s(LSGS_FRIDA_AGENT, s1, sizeof(s1));
    const char *k2 = lsg_s(LSGS_FRIDA_GADGET, s2, sizeof(s2));
    const char *k3 = lsg_s(LSGS_FRIDA_INJECT, s3, sizeof(s3));
    const char *k4 = lsg_s(LSGS_GADGET_FRIDA, s4, sizeof(s4));
    if (!k1 || !k2 || !k3 || !k4) return 0;   /* 解码失败 → 未检出 */
    char _pb[24];
    const char *_p = lsg_s(LSGS_PATH_MAPS, _pb, sizeof(_pb));
    if (!_p || safe_lines_open(&it, _p) != 0) return 0;
    /* 只认明显的 frida 命名特征,宁漏勿误伤 */
    while ((line = safe_lines_next(&it)) != NULL) {
        if (strstr(line, k1) || strstr(line, k2) ||
            strstr(line, k3) || strstr(line, k4)) {
            hit = 1;
            break;
        }
    }
    safe_lines_close(&it);
    return hit;
}

/* ────────────────── a3. TCP 端口特征标记 ────────────────── */
/*LSGS:TCP_69A2|:69A2*/
/*LSGS:TCP_69A3|:69A3*/

/* a3. /proc/net/tcp(及 tcp6) 里 27042/27043 的十六进制端口是否处于 LISTEN(0A)
 * 端口特征串( ":69A2"/":69A3" )同样走 LSGS 密文,不明文进 so。 */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int frida_tcp_table_probe(void) {
    char _tb[16], _t6[16];
    const char *_pt = lsg_s(LSGS_PATH_NET_TCP, _tb, sizeof(_tb));
    const char *_p6 = lsg_s(LSGS_PATH_NET_TCP6, _t6, sizeof(_t6));
    const char *tables[] = { _pt, _p6 };
    char p1[12], p2[12];
    const char *hexports[2];
    size_t t, p;
    hexports[0] = lsg_s(LSGS_TCP_69A2, p1, sizeof(p1));
    hexports[1] = lsg_s(LSGS_TCP_69A3, p2, sizeof(p2));
    if (!hexports[0] || !hexports[1]) return 0;
    for (t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
        safe_lines_t it;
        char *line;
        if (safe_lines_open(&it, tables[t]) != 0) continue;
        while ((line = safe_lines_next(&it)) != NULL) {
            for (p = 0; p < 2; p++) {
                /* 形如 "...:69A2 00...:0000 0A ..." — 本地端口匹配 + state=0A(LISTEN) */
                if (strstr(line, hexports[p]) && strstr(line + 10, " 0A ")) {
                    safe_lines_close(&it);
                    return 1;
                }
            }
        }
        safe_lines_close(&it);
    }
    return 0;
}

/* ─────────────────────────── b. Xposed / LSPosed 检测 ─────────────────────────── */

/* ────────────────── b1/b2. Xposed 特征标记 ────────────────── */
/*LSGS:XP_LIBXPOSED|libxposed*/
/*LSGS:XP_LSPD|lspd*/
/*LSGS:XP_LSPOSED|lsposed*/
/*LSGS:XP_EDXPOSED|edxposed*/
/*LSGS:XP_LIBRIRU|libriru*/
/*LSGS:XP_LIBZYGISK|libzygisk*/
/*LSGS:XP_PATH_LSPD|/data/adb/lspd*/
/*LSGS:XP_PATH_ZYGISK_LSP|/data/adb/modules/zygisk_lsposed*/
/*LSGS:XP_PATH_RIRU_LSP|/data/adb/modules/riru_lsposed*/
/*LSGS:XP_PATH_ZYGISK_EDX|/data/adb/modules/zygisk_edxposed*/
/*LSGS:XP_PATH_XBRIDGE|/system/framework/XposedBridge.jar*/

/* b1. 已加载库特征(读 maps,比文件存在性可靠——hook 框架必然注入自身库)
 * 6 个特征串全走 LSGS 密文(不明文进 so),解码失败按"未检出"。 */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int xposed_maps_probe(void) {
    safe_lines_t it;
    char *line;
    char s1[16], s2[8], s3[16], s4[16], s5[16], s6[16];
    int hit = 0;
    const char *k1 = lsg_s(LSGS_XP_LIBXPOSED, s1, sizeof(s1));
    const char *k2 = lsg_s(LSGS_XP_LSPD,      s2, sizeof(s2));
    const char *k3 = lsg_s(LSGS_XP_LSPOSED,   s3, sizeof(s3));
    const char *k4 = lsg_s(LSGS_XP_EDXPOSED,  s4, sizeof(s4));
    const char *k5 = lsg_s(LSGS_XP_LIBRIRU,   s5, sizeof(s5));
    const char *k6 = lsg_s(LSGS_XP_LIBZYGISK, s6, sizeof(s6));
    if (!k1 || !k2 || !k3 || !k4 || !k5 || !k6) return 0;
    char _pb[24];
    const char *_p = lsg_s(LSGS_PATH_MAPS, _pb, sizeof(_pb));
    if (!_p || safe_lines_open(&it, _p) != 0) return 0;
    while ((line = safe_lines_next(&it)) != NULL) {
        if (strstr(line, k1) || strstr(line, k2) ||
            strstr(line, k3) || strstr(line, k4) ||
            strstr(line, k5) || strstr(line, k6)) {
            hit = 1;
            break;
        }
    }
    safe_lines_close(&it);
    return hit;
}

/* b2. 已加载类特征:Xposed 环境 Java 栈里常有 XposedBridge(读自身进程 oatatmp 不可靠,
 * 改为探测 Xposed 安装痕迹文件——仅命中高置信路径)
 * 5 个路径全走 LSGS 密文(路径本身也是检测特征,不明文进 so)。 */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int xposed_file_probe(void) {
    char p1[48], p2[48], p3[48], p4[48], p5[48];
    const char *paths[5];
    size_t i;
    paths[0] = lsg_s(LSGS_XP_PATH_LSPD,        p1, sizeof(p1));   /* LSPosed daemon */
    paths[1] = lsg_s(LSGS_XP_PATH_ZYGISK_LSP,  p2, sizeof(p2));   /* LSPosed zygisk 模块 */
    paths[2] = lsg_s(LSGS_XP_PATH_RIRU_LSP,    p3, sizeof(p3));   /* LSPosed riru 旧版 */
    paths[3] = lsg_s(LSGS_XP_PATH_ZYGISK_EDX,  p4, sizeof(p4));   /* EdXposed */
    paths[4] = lsg_s(LSGS_XP_PATH_XBRIDGE,     p5, sizeof(p5));   /* 原版 Xposed */
    for (i = 0; i < 5; i++) {
        if (!paths[i]) continue;          /* 单条解码失败跳过该条,不影响其余 */
        if (access(paths[i], F_OK) == 0) return 1;
    }
    return 0;
}

/* ────────────────── c/e/f. 调试器与 Frida 特征标记 ────────────────── */
/*LSGS:TRACERPID|TracerPid:*/
/*LSGS:THR_GUMJS|gum-js-loop*/
/*LSGS:THR_POOL|pool-frida*/
/*LSGS:THR_FRIDA|frida*/
/*LSGS:UNX_FRIDA|frida*/
/*LSGS:UNX_LINJECTOR|linjector*/
/*LSGS:UNX_GUMJS|gum-js*/
/*LSGS:SYM_FOPEN|fopen*/
/*LSGS:SYM_OPEN|open*/
/*LSGS:SYM_CONNECT|connect*/
/*LSGS:SYM_READ|read*/
/* 2026-10-19 新增 4 个（复测报告 §13.3 第一条动态路径）：
 * hook mprotect 是拿到解密后明文 .ncx 的主力手法，原 4 个符号不含它。 */
/*LSGS:SYM_MPROTECT|mprotect*/
/*LSGS:SYM_MMAP|mmap*/
/*LSGS:SYM_DLOPEN|dlopen*/
/*LSGS:SYM_PVMREAD|process_vm_readv*/

/* ─────────────────────────── c. 调试器检测 ─────────────────────────── */

/* /proc/self/status 的 TracerPid:被 ptrace 附着(调试器/memfault 工具)时非 0
 * "TracerPid:" 前缀走 LSGS 密文(它是调试检测的最直接路标词)。 */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int tracer_probe(void) {
    safe_lines_t it;
    char *line;
    char tp[16];
    int hit = 0;
    const char *key = lsg_s(LSGS_TRACERPID, tp, sizeof(tp));
    if (!key) return 0;
    char _pb[24];
    const char *_p = lsg_s(LSGS_PATH_STATUS, _pb, sizeof(_pb));
    if (!_p || safe_lines_open(&it, _p) != 0) return 0;
    while ((line = safe_lines_next(&it)) != NULL) {
        if (strncmp(line, key, 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) hit = 1;
            break;
        }
    }
    safe_lines_close(&it);
    return hit;
}

/* ═══════════════════════════════════════════════════════════════════════
 * 2026-12 追加:吸收 dpt-shell 优点并超越其覆盖面(只追加,不改上方已有逻辑行)
 *   d. libc .text 内存完整性校验(CRC32):抓 inline hook / 内存补丁(借鉴 dpt_risk)
 *   e. Frida 线程名检测(/proc/self/task/<tid>/comm):抓"抹掉 maps 特征"的 Frida
 *   f. Frida unix socket 检测(/proc/net/unix):多一路抓法(dpt 无,超越)
 *   g. 常驻复查线程:保留"加载即检",另周期重检,补"启动后才挂载"窗口
 *      (dpt 只有轮询;我们两者兼得)
 * 误报兜底:以下每一项探测,任何 I/O/解析异常一律视为"未检出"(宁漏勿误伤)。
 * ═══════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════
 * 2026-11-08 追加:补 sentry / XopProtector / NativeShield 对比后发现的 2 个缺口
 *   h. 全线程 TracerPid:现有 tracer_probe 只读 /proc/self/status(主线程),
 *      Frida 挂在独立线程上时 task/<tid>/status 才有 TracerPid
 *   i. /proc/self/stat 的 state 字段:t/T = traced/stopped,比 TracerPid 难伪造
 *      (XopProtector risk.cpp:345 同款手段)
 * 纪律:只追加,不改上方任何已有逻辑行(AGENTS.md §2.4)。
 * 误报兜底:任何 I/O/解析异常一律视为"未检出"(宁漏勿误伤)。
 * ═══════════════════════════════════════════════════════════════════════ */

/* h. 全线程 TracerPid。
 *
 * 为什么需要:主线程没被 attach 不代表进程没被 attach。Frida 的 gum 线程、
 *   debugger 的 worker 线程各自有独立的 TracerPid 视角(内核按 task 记录)。
 *   现有 tracer_probe 只读 /proc/self/status,等于只看主线程。
 *
 * 为什么不全信:遍历 task 目录 + 逐线程 open/read 是重操作(线程多时几十次
 *   系统调用)。所以:
 *     · 只在 watchdog 里跑(每 5s),不进构造期一次性检测
 *     · 任一线程读失败 → continue(不判),绝不当成"检测到"
 *     · 主线程已被 tracer_probe 覆盖,这里跳过它避免重复开销
 *
 * ⚠️ 与 tracer_probe 的关系:互补不替代。tracer_probe 走 safe_lines(行解析),
 *    这里走 safe_read_alloc(整块读),两条不同的 I/O 路径 —— 与 D3/D4
 *    「Native syscall + Java exec 双通道」同一思路:一条被 hook 另一条还在。
 */
/* .ncx(2026-11-08):本探针进加密段,IDA 读到密文。 */
__attribute__((section(NC_SEC_CODE), retain))
int tracer_all_threads_probe(void) {
    char tp[16];
    char fmt[40];
    const char *key = lsg_s(LSGS_TRACERPID, tp, sizeof(tp));
    const char *pat = lsg_s(LSGS_PATH_TASK_STATUS, fmt, sizeof(fmt));
    char _pb[24];
    const char *_p = lsg_s(LSGS_PATH_TASK, _pb, sizeof(_pb));
    DIR *d;
    struct dirent *de;
    int hit = 0;

    if (!key || !pat || !_p) return 0;
    d = opendir(_p);
    if (!d) return 0;

    while ((de = readdir(d)) != NULL) {
        char p[160];
        char *buf = NULL;
        char *ln;
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        /* 主线程已由 tracer_probe 覆盖,跳过省一次 I/O */
        if (strcmp(de->d_name, "1") == 0) continue;
        snprintf(p, sizeof(p), pat, de->d_name);
        /* 走 syscall 直调读(防 fopen hook 伪造 status) */
        if (safe_read_alloc(p, &buf) < 0 || buf == NULL) continue;
        /* 逐行找 TracerPid: —— 不假设它在第几行 */
        ln = buf;
        while (ln && *ln) {
            char *nl = strchr(ln, '\n');
            if (nl) *nl = '\0';
            if (strncmp(ln, key, 10) == 0) {
                int pid = atoi(ln + 10);
                /* 排除自身与父进程:PTRACE_TRACEME 之后 tracer 常是 parent,
                 * 那是我们自己造的,不是外部调试器(与 tracer_probe 同口径) */
                if (pid != 0 && pid != getpid() && pid != getppid()) hit = 1;
                break;
            }
            ln = nl ? nl + 1 : NULL;
        }
        free(buf);
        if (hit) break;
    }
    closedir(d);
    return hit;
}

/* i. /proc/self/stat 的 state 字段。
 *
 * 格式:pid (comm) state ppid ... —— state 是【第 3 个字段】,单个字符:
 *   R 运行 / S 睡眠 / D 不可中断 / Z 僵尸 / T 停止 / t 被跟踪停止
 *   T 与 t 都表示"进程被 stopped",只有 ptrace/调试器会让它出现。
 *
 * 为什么比 TracerPid 难伪造:
 *   TracerPid 是一个可被 hook 的文本字段(hook open/read 返回假内容即可);
 *   state 由内核在调度时写入,且【comm 里可能有空格和括号】——解析必须
 *   从最后一个 ')' 往后找,不能简单按空格切分(这是常见实现错误)。
 *
 * ⚠️ 解析纪律:comm 字段格式是 "(name)",name 里可以有空格甚至 ')',
 *    所以必须 rfind(')') 而不是 find。按空格切分会把带空格的进程名判错。
 */
/* .ncx(2026-11-08):本探针进加密段,IDA 读到密文。 */
__attribute__((section(NC_SEC_CODE), retain))
int stat_state_probe(void) {
    char _pb[24];
    const char *_p = lsg_s(LSGS_PATH_STAT, _pb, sizeof(_pb));
    char *buf = NULL;
    const char *rp;
    char state;

    if (!_p) return 0;
    if (safe_read_alloc(_p, &buf) < 0 || buf == NULL) return 0;

    /* 从最后一个 ')' 往后取:stat 的第 3 字段紧跟在 ") " 之后 */
    rp = strrchr(buf, ')');
    if (rp == NULL) { free(buf); return 0; }
    rp++;                       /* 跳过 ')' */
    while (*rp == ' ') rp++;    /* 跳过空格 */
    state = *rp;
    free(buf);

    /* T = stopped by job control or debugger; t = tracing stop.
     * 两种都是"被调试器停住",正常进程不会出现。 */
    return (state == 'T' || state == 't') ? 1 : 0;
}

/* j. SIGTRAP 陷阱：验证「我们自己装的 signal handler 还能不能跑」。
 *
 * 抄自 sentry detector/trap_detector.cpp（70 行，Apache-2.0），
 * 按本仓库纪律改造：进 .ncx 密文段、走内联 svc、特征串密文化。
 *
 * ── 原理 ──────────────────────────────────────────────────────
 *   在专用线程里装一个 SIGTRAP handler，然后用 tgkill 只向【本线程】
 *   发 SIGTRAP。正常情况下信号被自家 handler 捕获、siglongjmp 跳回，
 *   handler 运行标志置 1。
 *
 *   若 handler 没跑（信号被别处吞掉 / 被重排到别的线程），说明有人动了
 *   信号链 —— 典型是 Frida 的 signal chaining（它要接管目标进程的信号
 *   才能实现「暂停/继续」），也可能是调试器或恶意 so 抢先装了 handler。
 *
 * ── 为什么这条几乎无法伪造 ──────────────────────────────────────
 *   它不是"读某个文件看有没有特征"，而是【主动发一个信号测反应】。
 *   攻击者要让它通过，必须保证我们的 handler 拿到信号 —— 而那意味着
 *   他放弃了对信号的接管。
 *
 * ── 为什么零误报 ────────────────────────────────────────────────
 *   信号只发给本线程（tgkill 的 tid 参数），不影响主线程/UI 线程。
 *   handler 内 siglongjmp 跳回本线程的 sigsetjmp 点，不会跨线程跳。
 *   所以即使攻击者没动信号链，也不会因为「别人也装了 handler」而误报 ——
 *   我们只关心【本次】信号有没有被【我们的】handler 消化。
 *
 * ── 三态语义（与 sentry 一致）──────────────────────────────────
 *    0 = NORMAL     handler 正常运行
 *    1 = DANGER     信号未送达自家 handler（疑似被劫持）
 *   -1 = SKIPPED    无法建立环境（线程创建失败 / sigaction 失败）
 *                    → 调用方必须当「未检出」处理，绝不当成命中
 *
 * ── 与 sentry 原版的差异 ────────────────────────────────────────
 *   ① sentry 用 my_getpid/my_gettid/my_tgkill 三个封装；我们用内联 svc
 *      （env_raw_syscall），比它的 libc 封装更抗 hook（无 PLT 桩）。
 *   ② sentry 的 LOGD 是明文特征串；我们不用日志（trace 里不留痕）。
 *   ③ sentry 返回 -1 由调用方判 skip；我们同样返回 -1。
 *   ④ 加了线程栈大小限制：默认 8MB 栈对一个只发信号的线程是浪费，
 *      且攻击者可能靠「线程资源耗尽」让我们建不了线程 → 静默跳过。
 *      这里显式给 64KB 栈，提高建立成功率。
 */
typedef struct {
    sigjmp_buf env;
    volatile sig_atomic_t handler_ran;
} trap_ctx_t;

static trap_ctx_t g_trap_ctx;

static void env_trap_handler(int sig) {
    (void)sig;
    g_trap_ctx.handler_ran = 1;
    siglongjmp(g_trap_ctx.env, 1);
}

static void *env_trap_thread(void *arg) {
    int *out = (int *)arg;
    struct sigaction sa, old;
    long pid, tid;
    int jumped;

    g_trap_ctx.handler_ran = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = env_trap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGTRAP, &sa, &old) != 0) {
        *out = -1;                      /* 装不上 handler → skip，不判 */
        return NULL;
    }

    jumped = sigsetjmp(g_trap_ctx.env, 1);
    if (jumped == 0) {
        /* 只向本线程发信号，避免主线程收到导致崩溃 */
        pid = env_raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        tid = env_raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
        if (pid > 0 && tid > 0) {
            (void)env_raw_syscall(__NR_tgkill, pid, tid, SIGTRAP, 0, 0, 0);
        }
        /* 走到这里说明没 longjmp 回来 —— 信号被别处消化了 */
        sigaction(SIGTRAP, &old, NULL);
        *out = 1;
        return NULL;
    }

    sigaction(SIGTRAP, &old, NULL);
    *out = g_trap_ctx.handler_ran ? 0 : 1;
    return NULL;
}

/* .ncx(2026-11-08):本探针进加密段,IDA 读到密文。 */
__attribute__((section(NC_SEC_CODE), retain))
int trap_probe(void) {
    pthread_t th;
    pthread_attr_t attr;
    int result = -1;
    int created;

    /* 显式 64KB 栈：这个线程只发一个信号，默认 8MB 是浪费，
     * 且「线程资源紧张」时应尽量建得起来（建不起来就是 skip，
     * 但那是我们自己的资源问题，不该变成漏检窗口）。 */
    if (pthread_attr_init(&attr) != 0) return -1;
    (void)pthread_attr_setstacksize(&attr, 64 * 1024);
    (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    created = pthread_create(&th, &attr, env_trap_thread, &result);
    pthread_attr_destroy(&attr);
    if (created != 0) return -1;        /* 建不了线程 → skip */

    (void)pthread_join(th, NULL);
    return result;                       /* 0 / 1 / -1 */
}



/* d1. CRC32(标准多项式 0xEDB88320,与 zlib/CRC-32 一致) */
static uint32_t env_crc32_table[256];
static int env_crc32_ready = 0;

static void env_crc32_init(void) {
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++) c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        env_crc32_table[i] = c;
    }
    env_crc32_ready = 1;
}

/* d1b. 硬件 CRC32 快速路径(2026-12 追加:与表驱动逐位等价,实测快约 65 倍)
 * arm64 的 CRC 扩展是"可选"能力:运行时用 getauxval(AT_HWCAP) 探测,
 * 不具备(32 位 armeabi-v7a / 老 SoC)则自动回落下面的表驱动,结果不变。 */
#ifndef HWCAP_CRC32
#define HWCAP_CRC32 (1ul << 7)
#endif

#if defined(__aarch64__)
__attribute__((target("crc")))
static uint32_t env_crc32_hw(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    while (len >= 8) {
        uint64_t v;
        memcpy(&v, buf, 8);
        buf += 8; len -= 8;
        crc = __crc32d(crc, v);
    }
    while (len--) crc = __crc32b(crc, *buf++);
    return crc ^ 0xFFFFFFFFu;
}

/* 探测只做一次:硬件能力在进程生命周期内恒定 */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
static int env_hw_crc_ok(void) {
    static int cached = -1;
    if (cached < 0) cached = (getauxval(AT_HWCAP) & HWCAP_CRC32) ? 1 : 0;
    return cached;
}
#endif

static uint32_t env_crc32(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
#if defined(__aarch64__)
    if (env_hw_crc_ok()) return env_crc32_hw(buf, len);
#endif
    if (!env_crc32_ready) env_crc32_init();
    for (i = 0; i < len; i++)
        crc = env_crc32_table[(crc ^ buf[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* d2. 从 /proc/self/maps 取"含 needle 的映射"的文件路径(第一个 '/' 起) */
static int env_map_path(const char *needle, char *out, size_t outlen) {
    safe_lines_t it;
    char *line;
    char _pb[24];
    const char *_p = lsg_s(LSGS_PATH_MAPS, _pb, sizeof(_pb));
    if (!_p || safe_lines_open(&it, _p) != 0) return 0;
    while ((line = safe_lines_next(&it)) != NULL) {
        char *slash;
        size_t n;
        if (!strstr(line, needle)) continue;
        slash = strchr(line, '/');
        if (!slash) continue;
        n = strcspn(slash, "\n");
        if (n >= outlen) n = outlen - 1;
        memcpy(out, slash, n);
        out[n] = '\0';
        safe_lines_close(&it);
        return 1;
    }
    safe_lines_close(&it);
    return 0;
}

/* d3. [addr,addr+len) 是否整体落在可读映射内(maps 解析,避免非法读崩溃) */
/* 判断 [addr, addr+len) 是否全部位于可读映射内。
 *
 * ⚠️ 2026-10-19 修 bug（外部实测报告 §13.1 的直接根因）：
 *   旧实现要求整个区间落在【同一条】maps 记录里（`end <= e`）。
 *   但 .text 往往与 .eh_frame / .rodata 尾部【同页】——实测 CI 产物：
 *     .eh_frame 0x18478..0x200f4 (flags=0x2, 只读不执行)
 *     .text     0x20100..0x46c18 (flags=0x6, 可执行)   ← 同页 0x20000
 *   ld.so 会把这一页拆成 `r--p` 与 `r-xp` 两条映射，于是 .text 的
 *   [start, end) 天然跨两条记录 → `end <= e` 恒假 → 本函数返回 0 →
 *   self_text_crc_probe 直接放弃校验（"读不到内存"就当没问题）。
 *   这就是报告实测"改了 3 处 .text 字节，完整性校验仍报 clean"的原因。
 *
 * 新实现：允许区间跨多条相邻记录——只要每一条被覆盖的字节都落在
 * 某条【可读】记录内即可。用「游标推进」扫描：cur 从 target 出发，
 * 每命中一条记录就把 cur 推到该记录末尾，直到 cur >= end。
 *
 * 安全性不变：仍然要求覆盖到的每条映射都是 'r' 权限；遇到空洞
 * （没有任何记录覆盖）立即返回 0。不会把"不可读"误判为"可读"。
 * 性能：maps 通常几十行，单次扫描 O(n)，且只在每 5 轮复查时跑一次。 */
static int env_mem_readable(const void *addr, size_t len) {
    safe_lines_t it;
    char *line;
    uintptr_t cur = (uintptr_t)addr;
    uintptr_t end = cur + len;
    int progressed = 0;
    if (len == 0) return 1;
    if (end < cur) return 0;                      /* 溢出保护 */
    char _pb[24];
    const char *_p = lsg_s(LSGS_PATH_MAPS, _pb, sizeof(_pb));
    if (!_p || safe_lines_open(&it, _p) != 0) return 0;
    while (cur < end && (line = safe_lines_next(&it)) != NULL) {
        unsigned long s = 0, e = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) != 3) continue;
        if ((uintptr_t)e <= cur) continue;         /* 完全在游标之前，跳过 */
        if ((uintptr_t)s > cur) break;             /* 出现空洞：cur 处无人覆盖 */
        if (perms[0] != 'r') { safe_lines_close(&it); return 0; }
        cur = (uintptr_t)e;                        /* 推进到本记录末尾 */
        progressed = 1;
    }
    safe_lines_close(&it);
    return (cur >= end && progressed) ? 1 : 0;
}

/* d4. 解析 ELF 取 .text 的 文件偏移/虚拟地址/大小(仅小端,32/64 位) */
typedef struct { uint64_t offset; uint64_t vaddr; uint64_t size; } env_text_t;

static int env_elf_text(const char *path, env_text_t *out) {
    unsigned char *file = NULL;
    long flen;
    unsigned char ident[16];
    int is64, ok = 0;
    /* 2026-10 探针可信化:ELF 也走 syscall 直调 —— 攻击者 hook fopen 后
     * 可以喂一份"原版" .text 内容,让 libc_text_crc_probe 永久通过 */
    flen = safe_read_alloc(path, (char **)&file);
    if (flen < 16 || file == NULL) { if (file) free(file); return 0; }
    memcpy(ident, file, 16);
    if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') { free(file); return 0; }
    if (ident[5] != 1) { free(file); return 0; }        /* 只处理小端 */
    is64 = (ident[4] == 2);
    if (is64) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)file;
        size_t shstr_size = 0;
        char *strtab = NULL;
        int i;
        if ((long)sizeof(Elf64_Ehdr) > flen) { free(file); return 0; }
        if (eh->e_shoff == 0 || eh->e_shnum == 0 || eh->e_shstrndx >= eh->e_shnum) { free(file); return 0; }
        if ((long)(eh->e_shoff + (uint64_t)eh->e_shstrndx * eh->e_shentsize + sizeof(Elf64_Shdr)) > flen) { free(file); return 0; }
        {
            Elf64_Shdr *shstr = (Elf64_Shdr *)(file + eh->e_shoff + (uint64_t)eh->e_shstrndx * eh->e_shentsize);
            shstr_size = (size_t)shstr->sh_size;
            if ((long)(shstr->sh_offset + shstr_size) > flen) { free(file); return 0; }
            strtab = (char *)malloc(shstr_size + 1);
            if (!strtab) { free(file); return 0; }
            memcpy(strtab, file + shstr->sh_offset, shstr_size);
            strtab[shstr_size] = '\0';
        }
        for (i = 0; i < (int)eh->e_shnum; i++) {
            Elf64_Shdr *sh;
            if ((long)(eh->e_shoff + (uint64_t)i * eh->e_shentsize + sizeof(Elf64_Shdr)) > flen) break;
            sh = (Elf64_Shdr *)(file + eh->e_shoff + (uint64_t)i * eh->e_shentsize);
            if ((size_t)sh->sh_name >= shstr_size) continue;
            if (strcmp(strtab + sh->sh_name, ".text") == 0) {
                out->offset = sh->sh_offset; out->vaddr = sh->sh_addr; out->size = sh->sh_size;
                ok = 1; break;
            }
        }
        free(strtab); free(file);
        return ok;
    }
    {
        Elf32_Ehdr *eh = (Elf32_Ehdr *)file;
        size_t shstr_size = 0;
        char *strtab = NULL;
        int i;
        if ((long)sizeof(Elf32_Ehdr) > flen) { free(file); return 0; }
        if (eh->e_shoff == 0 || eh->e_shnum == 0 || eh->e_shstrndx >= eh->e_shnum) { free(file); return 0; }
        if ((long)(eh->e_shoff + (uint32_t)eh->e_shstrndx * eh->e_shentsize + sizeof(Elf32_Shdr)) > flen) { free(file); return 0; }
        {
            Elf32_Shdr *shstr = (Elf32_Shdr *)(file + eh->e_shoff + (uint32_t)eh->e_shstrndx * eh->e_shentsize);
            shstr_size = (size_t)shstr->sh_size;
            if ((long)(shstr->sh_offset + shstr_size) > flen) { free(file); return 0; }
            strtab = (char *)malloc(shstr_size + 1);
            if (!strtab) { free(file); return 0; }
            memcpy(strtab, file + shstr->sh_offset, shstr_size);
            strtab[shstr_size] = '\0';
        }
        for (i = 0; i < (int)eh->e_shnum; i++) {
            Elf32_Shdr *sh;
            if ((long)(eh->e_shoff + (uint32_t)i * eh->e_shentsize + sizeof(Elf32_Shdr)) > flen) break;
            sh = (Elf32_Shdr *)(file + eh->e_shoff + (uint32_t)i * eh->e_shentsize);
            if ((size_t)sh->sh_name >= shstr_size) continue;
            if (strcmp(strtab + sh->sh_name, ".text") == 0) {
                out->offset = sh->sh_offset; out->vaddr = sh->sh_addr; out->size = sh->sh_size;
                ok = 1; break;
            }
        }
        free(strtab); free(file);
        return ok;
    }
}

/* d4. libc 导出函数入口指令检测(2026-10 借鉴 XopProtector libc_hook_score):
 * Inline hook 的本质是"把函数入口第一条指令改写成跳转/断点",所以不校验
 * 全部 .text(那是 d5 CRC 的活),只读 N 个攻击者最常 hook 的导出函数入口
 * 4 字节,判 arm64 的 B/BL/BRK —— 4N 字节 vs d5 的 1-2MB,纳秒级。
 * 打分制(照抄 Xop):单个被 hook 可能是 ROM 厂商特性(MIUI 某些隐藏 hook),
 * ≥2 分才报警压误报。读内存走 process_vm_readv(内核拷贝,不经本进程页表,
 * 防 XOM 设备直接解引用 SIGSEGV;Xop safe_read_u32 同款)。
 *
 * 2026-10-19 扩到 8 个函数（复测报告 §13.3 列的第一条动态路径）：
 *   报告指出「frida hook mprotect 能拿到解密后的明文 .ncx」。
 *   原 4 个（fopen/open/connect/read）只覆盖常规 hook，不含解密链关键点。
 *   新增 mprotect / mmap / dlopen / process_vm_readv ——
 *     mprotect  解密流程自己要用（切 RWX/RX），hook 它即可 dump 明文段
 *     mmap      攻击者读 /proc/self/maps 后映射明文段的替代路径
 *     dlopen    加载/枚举 so 的入口
 *     process_vm_readv 跨进程读内存的主力系统调用（dump 必用）
 * 函数名走 LSGS 密文(不然 "mprotect" 又是明文特征)。 */
static int env_pvm_read_u32(const void *addr, uint32_t *out) {
    struct iovec local, remote;
    if (addr == NULL || out == NULL) return 0;
    local.iov_base = out;             local.iov_len = sizeof(uint32_t);
    remote.iov_base = (void *)addr;   remote.iov_len = sizeof(uint32_t);
    /* ⚠️ process_vm_readv 是 6 参调用,syscall() 变参包装必须补第 7 个 0:
     * ARM64 变参寄存器传参,缺位读到的是寄存器残留 → EINVAL(errno 22)。
     * 实测 Termux dbg5:6 参包装恒失败,补 0 后正常。 */
    return safe_syscall(__NR_process_vm_readv, (long)getpid(),
                        (long)&local, 1L, (long)&remote, 1L, 0L) == (long)sizeof(uint32_t);
}

/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
#define NC_HOOK_PROBE_N 8
int libc_hook_probe(void) {
    char n1[8], n2[8], n3[12], n4[8], n5[12], n6[8], n7[8], n8[20];
    const char *names[NC_HOOK_PROBE_N];
    void *fns[NC_HOOK_PROBE_N];
    int score = 0, i;
    static const uint32_t masks[3] = { 0xFC000000u, 0xFC000000u, 0xFFE0001Fu };
    static const uint32_t hooks[3] = { 0x14000000u, 0x94000000u, 0xD4200000u };
    names[0] = lsg_s(LSGS_SYM_FOPEN,   n1, sizeof(n1));
    names[1] = lsg_s(LSGS_SYM_OPEN,    n2, sizeof(n2));
    names[2] = lsg_s(LSGS_SYM_CONNECT, n3, sizeof(n3));
    names[3] = lsg_s(LSGS_SYM_READ,    n4, sizeof(n4));
    names[4] = lsg_s(LSGS_SYM_MPROTECT, n5, sizeof(n5));
    names[5] = lsg_s(LSGS_SYM_MMAP,     n6, sizeof(n6));
    names[6] = lsg_s(LSGS_SYM_DLOPEN,   n7, sizeof(n7));
    names[7] = lsg_s(LSGS_SYM_PVMREAD,  n8, sizeof(n8));
    if (!names[0] || !names[1] || !names[2] || !names[3]
        || !names[4] || !names[5] || !names[6] || !names[7]) return 0;
    for (i = 0; i < NC_HOOK_PROBE_N; i++) {
        uint32_t w = 0;
        int j, hooked = 0;
        fns[i] = dlsym(RTLD_DEFAULT, names[i]);
        if (fns[i] == NULL) continue;
        if (!env_pvm_read_u32(fns[i], &w)) continue;
        for (j = 0; j < 3; j++) {
            if ((w & masks[j]) == hooks[j]) { hooked = 1; break; }
        }
        score += hooked;
    }
    return (score >= 2) ? 1 : 0;
}

/* d5. libc .text 内存 vs 磁盘 CRC 比对;不等=内存被改写。任一步异常→放行(未检出) */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int libc_text_crc_probe(void) {
    Dl_info info;
    char path[512];
    env_text_t ts;
    uint8_t *fb;
    uint32_t cf, cm;
    const uint8_t *mem;

    if (dladdr((const void *)&fopen, &info) == 0 || info.dli_fbase == NULL) return 0;
    path[0] = '\0';
    if (info.dli_fname != NULL) {
        if (info.dli_fname[0] == '/')
            snprintf(path, sizeof(path), "%s", info.dli_fname);
        else
            env_map_path(info.dli_fname, path, sizeof(path));
    }
    if (path[0] == '\0') {
        char _lb[16];
        const char *_l = lsg_s(LSGS_PATH_LIBC, _lb, sizeof(_lb));
        if (_l) env_map_path(_l, path, sizeof(path));
    }
    if (path[0] == '\0') return 0;

    if (!env_elf_text(path, &ts)) return 0;
    if (ts.size == 0 || ts.size > (64u << 20)) return 0;

    mem = (const uint8_t *)info.dli_fbase + ts.vaddr;
    if (!env_mem_readable(mem, (size_t)ts.size)) return 0;

    /* 磁盘副本读取走 syscall 直调(2026-10 修复):此前 fopen/fread 走 libc,
     * 攻击者假 fread 喂一份"与内存一致的伪造 libc 内容"即可让本探针永久失明
     * —— 文件头威胁模型自述过这一攻击(623 行),实现却漏网,真·自相矛盾。
     * safe_read_alloc 一次读全文件再按 offset 取段,开销多读文件头部,
     * 但 libc .text 通常在文件前段,可接受;CRC 降频后更是每 5 轮才一次。 */
    {
        char *file = NULL;
        long flen = safe_read_alloc(path, &file);
        if (flen < 0 || file == NULL) return 0;
        if ((long)ts.offset + (long)ts.size > flen) { free(file); return 0; }
        fb = (uint8_t *)file + ts.offset;
        cf = env_crc32(fb, (size_t)ts.size);
        cm = env_crc32(mem, (size_t)ts.size);
        free(file);
        return (cf != cm) ? 1 : 0;
    }
}

/* d6. 自身 so .text 内存 vs 磁盘 CRC 比对(2026-10 方案 B)——抓运行时 so 被 patch。
 *
 * 与 d5(libc)同构,目标换成"本 so 自身":
 *   攻击者把 nc_verify_t1 / derive_expected 等校验函数 InlineHook 成恒真后,
 *   内存里的机器码与磁盘文件不再一致 → 本探针检出。
 *
 * 性能设计(用户要求"性能写好点"):
 *   ① 复用 env_crc32 —— arm64 自动走 target("crc") 硬件指令(HWCAP 探测),
 *      实测比表驱动快约 65 倍;不支持则回落表驱动,结果逐位等价。
 *   ② 只 CRC 目标段(.text),不读整个 so —— 典型 300KB,硬件 CRC 约 0.1~0.3ms。
 *   ③ 磁盘侧只读该段(openat + pread 到固定缓冲),不做整文件扫描。
 *   ④ 调用频率:构造期一次 + 看门狗每 20s 一次,平均开销可忽略。
 *
 * 误报兜底(与全文件纪律一致):任一步 I/O/解析/内存权限异常 → 视为"未检出",
 *   宁漏勿误伤。特别注意:若 .text 所在页在内存中不可读(某些加固/只读映射),
 *   直接放行而不是误判。 */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int self_text_crc_probe(void) {
    Dl_info info;
    char path[512];
    env_text_t ts;
    int fd;
    uint8_t *fb;
    long n;
    uint32_t cf, cm;
    const uint8_t *mem;

    /* 用本探针自身地址定位自家 so(dladdr 对 static 函数同样有效) */
    if (dladdr((const void *)&self_text_crc_probe, &info) == 0 || info.dli_fbase == NULL) return 0;

    path[0] = '\0';
    if (info.dli_fname != NULL) {
        if (info.dli_fname[0] == '/')
            snprintf(path, sizeof(path), "%s", info.dli_fname);
        else
            env_map_path(info.dli_fname, path, sizeof(path));
    }
    if (path[0] == '\0') env_map_path("libnc.so", path, sizeof(path));
    if (path[0] == '\0') return 0;

    if (!env_elf_text(path, &ts)) return 0;
    /* 合理性守卫:自家 .text 不该是 0 或荒谬大(防解析到错误段) */
    if (ts.size < 4096 || ts.size > (32u << 20)) return 0;

    mem = (const uint8_t *)info.dli_fbase + ts.vaddr;
    if (!env_mem_readable(mem, (size_t)ts.size)) return 0;

    /* 磁盘侧只读目标段:syscall 直调(防 fopen hook 喂假内容,与方案 C 一致) */
    fd = (int)safe_syscall(__NR_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0) return 0;
    fb = (uint8_t *)malloc((size_t)ts.size);
    if (!fb) { safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0); return 0; }
    n = safe_syscall(__NR_pread64, fd, (long)fb, (long)ts.size, (long)ts.offset, 0, 0);
    safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    if (n != (long)ts.size) { free(fb); return 0; }

    cf = env_crc32(fb, (size_t)ts.size);
    cm = env_crc32(mem, (size_t)ts.size);
    free(fb);
    return (cf != cm) ? 1 : 0;
}

/* e. Frida 线程名检测(读 /proc/self/task/<tid>/comm)
 * 5 个线程名全走 LSGS 密文(线程名是最直接的 Frida 指纹之一)。
 * 注意:gum 判定改为比对解码后的 k1,不再硬编码字面量。 */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int frida_thread_probe(void) {
    char n1[16], n2[16], n3[8];
    const char *names[3];
    size_t i;
    char _pb[24];
    const char *_p = lsg_s(LSGS_PATH_TASK, _pb, sizeof(_pb));
    DIR *d = _p ? opendir(_p) : NULL;
    struct dirent *de;
    int hits = 0, gum = 0;
    names[0] = lsg_s(LSGS_THR_GUMJS,  n1, sizeof(n1));   /* gum-js-loop */
    names[1] = lsg_s(LSGS_THR_POOL,   n2, sizeof(n2));   /* pool-frida */
    names[2] = lsg_s(LSGS_THR_FRIDA,  n3, sizeof(n3));   /* frida */
    /* 任一解码失败 → 检测不完整,按"未检出"处理(宁漏勿误伤) */
    if (!names[0] || !names[1] || !names[2]) { if (d) closedir(d); return 0; }
    if (!d) return 0;
    while ((de = readdir(d)) != NULL) {
        char p[160];
        char nm[64];
        char *fb = NULL;
        size_t L;
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        snprintf(p, sizeof(p), "/proc/self/task/%s/comm", de->d_name);
        /* 线程名同样走 syscall 直调(防 fopen hook 伪造 comm) */
        if (safe_read_alloc(p, &fb) < 0 || fb == NULL) continue;
        snprintf(nm, sizeof(nm), "%s", fb);
        free(fb);
        L = strcspn(nm, "\n");
        nm[L] = '\0';
        for (i = 0; i < 3; i++) {
            if (strcmp(nm, names[i]) == 0) {
                hits++;
                if (i == 0) gum = 1;   /* 第 0 位恒为 gum-js-loop(见上方解码顺序) */
                break;
            }
        }
    }
    closedir(d);
    /* gum-js-loop 为 Frida 最特征线程名,单命中即判;
     * 其余(pool-frida / frida)要求 ≥2 个,压低误报。
     *
     * ⚠️ 2026-11-08 移除 gmain / gdbus（原 names[1] / names[2]）：
     *    这两个是 GLib 标准线程名，任何用 GLib 的合法库在干净设备上
     *    都会同时起这两个 → hits=2 → 判定命中 → 杀正常用户。
     *    两份独立参考实现的结论一致：
     *      · sentry DETECTION_SPEC.md:88「历史版本曾包含 gmain/gdbus/...
     *        但这些是 GLib 标准线程名，正常使用 GLib 的合法库会触发
     *        误报——已在本版本移除」
     *      · XopProtector risk.cpp:520「Do NOT match generic GLib names
     *        (gmain/gdbus) — common on MIUI/OEM processes and cause false
     *        positives. Keep Frida-specific markers only.」
     *    移除后仍保留 3 个 Frida 专属词，其中 gum-js-loop 单命中即判，
     *    检出能力不受影响（Frida 注入必然起 gum-js-loop）。 */
    return (gum || hits >= 2) ? 1 : 0;
}

/* f. Frida unix socket 检测(读 /proc/net/unix 的路径字段) */
/* .ncx(2026-12):本探针进加密段,IDA 读到密文。
 * retain 同探针文件——防 lib-ndk.sh 的 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), retain))
int frida_unix_probe(void) {
    char s1[12], s2[16], s3[12];
    const char *sigs[3];
    size_t i;
    safe_lines_t it;
    char *line;
    sigs[0] = lsg_s(LSGS_UNX_FRIDA,     s1, sizeof(s1));   /* "frida" */
    sigs[1] = lsg_s(LSGS_UNX_LINJECTOR, s2, sizeof(s2));   /* "linjector" */
    sigs[2] = lsg_s(LSGS_UNX_GUMJS,     s3, sizeof(s3));   /* "gum-js" */
    if (!sigs[0] || !sigs[1] || !sigs[2]) return 0;
    char _ub[16];
    const char *_u = lsg_s(LSGS_PATH_NET_UNIX, _ub, sizeof(_ub));
    if (!_u || safe_lines_open(&it, _u) != 0) return 0;
    while ((line = safe_lines_next(&it)) != NULL) {
        for (i = 0; i < 3; i++) {
            if (strstr(line, sigs[i])) { safe_lines_close(&it); return 1; }
        }
    }
    safe_lines_close(&it);
    return 0;
}
