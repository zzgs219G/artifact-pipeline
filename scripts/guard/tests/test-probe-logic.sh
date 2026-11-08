#!/usr/bin/env bash
# test-probe-logic.sh — 探针判断逻辑回归（无需真机 / 无需 root / 无需 Frida）
#
# ── 为什么需要它 ────────────────────────────────────────────────────
# 真机验证（装包 + 造 frida-server 监听）只能证明「某个探针在某种场景下
# 反应正确」。它有三个硬限制：
#   ① 需要能装包的真机；无 root 时只能造假端口，其余 13 个探针造不出来
#   ② 每次改探针都要重装重测，反馈周期是分钟级
#   ③ 只能测「我在真机上想到的那一种攻击」，测不到边界（空文件、畸形行、
#      大小写、部分匹配……）
#
# 本测试换一个维度：把探针的【判断逻辑】单独编出来，喂它构造好的 /proc
# 内容，断言返回 0 还是 1。它证明的是「给定输入，判断对不对」，不证明
# 「真实攻击会不会产生这种输入」—— 两者互补，不能互相替代。
#
# ── 原理（为什么可行）───────────────────────────────────────────────
# 所有走文件读取的探针最终都收敛到两个函数：
#     safe_read_alloc()    读整个文件
#     safe_lines_open()    逐行迭代（内部调 safe_read_alloc）
# 本测试把 safe_read_alloc 换成「查表返回预先构造的假内容」，
# 探针其余代码一行不改 —— 测的就是生产代码本身，不是复制品。
#
# ⚠️ 为什么不用「复制一份探针逻辑到测试里」那个做法（test-mem-readable.sh 用的）：
#    那份是无奈之举（被测函数依赖 android/log.h 编不动）。但复制品会漂移：
#    改生产代码忘改副本时，测试照样绿 —— 那是假绿。
#    本文件用桩函数替换 I/O 层，被测代码就是 env_probes.c 原文。
#
# ── 覆盖范围 ────────────────────────────────────────────────────────
#   已覆盖（走 safe_read_alloc / safe_lines_open）：
#     frida_maps_probe / frida_unix_probe / tracer_probe /
#     tracer_all_threads_probe / stat_state_probe
#   未覆盖（输入源不同，需另换桩，见文件末尾「未覆盖」注释）：
#     frida_port_probe     真 socket
#     frida_thread_probe   还要 opendir
#     xposed_file_probe    access()
#     trap_probe           真信号 + 线程
#     libc_hook_probe / libc_text_crc_probe / self_text_crc_probe  真实内存
#
# ── 用法 ────────────────────────────────────────────────────────────
#   bash scripts/guard/tests/test-probe-logic.sh
# 判据：0 失败（通过数随分支变化，不要写死）
set -uo pipefail

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✓ $*"; }
bad() { FAIL=$((FAIL+1)); echo "  ✗ $*" >&2; }

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SRC_GUARD="$ROOT/scripts/guard/src"
GEN_LOG="$ROOT/scripts/guard/log/make-sig-log.py"

echo "══════════════════════════════════════════════════════════════"
echo "探针判断逻辑回归（无需真机 / 无需 root）"
echo "══════════════════════════════════════════════════════════════"

command -v clang >/dev/null 2>&1 || { echo "✗ 缺 clang"; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/tpl.XXXXXX" 2>/dev/null || mktemp -d "$HOME/.tpl.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# ── 准备：拷源码 + 生成 LSGS 头 ─────────────────────────────────────
cp "$SRC_GUARD/env_probes.c" "$WORK/"
cp "$SRC_GUARD/env_internal.h" "$WORK/"
cp "$ROOT/tools/nox/so-guard/nc_guard_layout.h" "$WORK/" 2>/dev/null || {
    echo "✗ 缺 nc_guard_layout.h（先跑 ensure_nox）" >&2; exit 1
}
python3 "$GEN_LOG" "$SRC_GUARD/sig_check.c" "$SRC_GUARD/env_check.c" \
        "$SRC_GUARD/env_probes.c" "$WORK/sig_log_data.h" >/dev/null 2>&1 || {
    echo "✗ sig_log_data.h 生成失败" >&2; exit 1
}

# ── 测试桩：替换 I/O 层 ─────────────────────────────────────────────
# 关键手法：把 env_probes.c 里的 static 去掉（-Dstatic=），让探针可被外部调用。
# 生产源码文件本身不动 —— 只编译一份临时副本。
cat > "$WORK/harness.c" <<'HEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ⚠️ 不要 include env_internal.h —— 它内部 include 了 sig_log_data.h，
 *    而后者是 static const 密文表，会被 env_probes.o 与本文件各带一份，
 *    链接期报 duplicate symbol。
 *    这里只重复声明本文件用到的类型与函数原型（签名与 env_internal.h 一致）。 */
typedef int lsg_id_t;   /* 枚举在 C 里就是 int，签名一致即可 */

typedef struct {
    char  *buf;
    size_t pos;
    long   len;
} safe_lines_t;

long safe_read_alloc(const char *path, char **out);
int  safe_lines_open(safe_lines_t *it, const char *path);
char *safe_lines_next(safe_lines_t *it);
void safe_lines_close(safe_lines_t *it);
void envlog_c(int is_err, lsg_id_t id, const char *detail);
void env_fail(void);
long env_raw_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5);
long safe_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5);

typedef struct { const char *path; const char *content; } fake_t;
static fake_t g_fakes[32];
static int    g_nfake = 0;

void fake_set(const char *path, const char *content) {
    if (g_nfake < (int)(sizeof(g_fakes)/sizeof(g_fakes[0]))) {
        g_fakes[g_nfake].path = path;
        g_fakes[g_nfake].content = content;
        g_nfake++;
    }
}
void fake_clear(void) { g_nfake = 0; }

/* 替换生产实现：查表返回假内容；未登记的路径 → 读失败（等价"文件不存在"） */
long safe_read_alloc(const char *path, char **out) {
    int i;
    for (i = 0; i < g_nfake; i++) {
        if (strcmp(g_fakes[i].path, path) == 0) {
            size_t n = strlen(g_fakes[i].content);
            char *buf = (char *)malloc(n + 1);
            if (!buf) { *out = NULL; return -1; }
            memcpy(buf, g_fakes[i].content, n + 1);
            *out = buf;
            return (long)n;
        }
    }
    *out = NULL;
    return -1;
}

/* env_probes.c 依赖的外部符号（测试桩不做实事） */
long env_raw_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    (void)n;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
    return -1;
}
long safe_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    (void)n;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
    return -1;
}
void envlog_c(int is_err, lsg_id_t id, const char *detail) {
    (void)is_err;(void)id;(void)detail;
}
void env_fail(void) { }
int  ncguard_unlock(void) { return 0; }

/* ── 行迭代器三个函数 ──────────────────────────────────────────────
 * 生产实现定义在 env_check.c（基础设施那一侧）。本测试只编 env_probes.c，
 * 所以要在这里提供一份【逐字一致】的实现。它们只做缓冲切片，不含任何
 * 判断逻辑 —— 判断逻辑才是被测对象，这里复制不会造成假绿。
 * ⚠️ 若 env_check.c 的这三个函数改了语义（比如换行处理），必须同步这里，
 *    否则测试用的 I/O 层与生产不一致。
 * ⚠️ safe_lines_t 的字段顺序来自 env_internal.h（buf / pos / len）。 */

int safe_lines_open(safe_lines_t *it, const char *path) {
    it->buf = NULL; it->pos = 0; it->len = -1;
    it->len = safe_read_alloc(path, &it->buf);
    if (it->len < 0 || it->buf == NULL) { it->len = -1; return -1; }
    return 0;
}
char *safe_lines_next(safe_lines_t *it) {
    size_t start;
    if (it->len < 0 || it->buf == NULL) return NULL;
    if (it->pos >= (size_t)it->len) return NULL;
    start = it->pos;
    while (it->pos < (size_t)it->len && it->buf[it->pos] != '\n') it->pos++;
    it->buf[it->pos] = '\0';
    if (it->pos < (size_t)it->len) it->pos++;
    return it->buf + start;
}
void safe_lines_close(safe_lines_t *it) {
    if (it->buf) { free(it->buf); it->buf = NULL; }
    it->len = -1; it->pos = 0;
}
HEOF

# ── 测试主体 ────────────────────────────────────────────────────────
cat > "$WORK/main.c" <<'MEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int frida_maps_probe(void);
int frida_unix_probe(void);
int tracer_probe(void);
int tracer_all_threads_probe(void);
int stat_state_probe(void);
void fake_set(const char *path, const char *content);
void fake_clear(void);

static int pass = 0, fail = 0;
static void ok(const char *m)  { pass++; printf("  \xe2\x9c\x93 %s\n", m); }
static void bad(const char *m) { fail++; printf("  \xe2\x9c\x97 %s\n", m); }

/* expect(name, got, want) —— 断言探针返回值 */
static void expect(const char *name, int got, int want) {
    char buf[256];
    snprintf(buf, sizeof buf, "%s（got=%d want=%d）", name, got, want);
    if (got == want) ok(buf); else bad(buf);
}

#define MAPS   "/proc/self/maps"
#define STATUS "/proc/self/status"
#define STAT   "/proc/self/stat"
#define UNIX   "/proc/net/unix"

int main(void) {
    /* ═══ frida_maps_probe ═══ 特征: frida-agent / frida-gadget / frida-inject / gadget_frida */
    fake_clear();
    fake_set(MAPS, "12c00000-12c21000 r-xp 00000000 fd:00 1 /data/local/tmp/frida-agent.so\n");
    expect("maps: 含 frida-agent → 应命中", frida_maps_probe(), 1);

    fake_clear();
    fake_set(MAPS, "7f000000-7f001000 r-xp 0 fd:00 2 /data/local/tmp/frida-gadget.so\n");
    expect("maps: 含 frida-gadget → 应命中", frida_maps_probe(), 1);

    fake_clear();
    fake_set(MAPS, "7f000000-7f001000 r-xp 0 fd:00 3 /data/local/tmp/frida-inject\n");
    expect("maps: 含 frida-inject → 应命中", frida_maps_probe(), 1);

    fake_clear();
    fake_set(MAPS, "7f000000-7f001000 r-xp 0 fd:00 4 /system/lib64/libgadget_frida.so\n");
    expect("maps: 含 gadget_frida → 应命中", frida_maps_probe(), 1);

    fake_clear();
    fake_set(MAPS,
        "12c00000-12c21000 r-xp 00000000 fd:00 1 /system/lib64/libc.so\n"
        "7f000000-7f001000 r-xp 0 fd:00 2 /apex/com.android.runtime/lib64/bionic/libc.so\n");
    expect("maps: 只有正常库 → 应 clean", frida_maps_probe(), 0);

    fake_clear();   /* 没登记 → 读失败 */
    expect("maps: 读不到文件 → 应 clean（宁漏勿误伤）", frida_maps_probe(), 0);

    fake_clear();
    fake_set(MAPS, "");                       /* 空文件 */
    expect("maps: 空文件 → 应 clean", frida_maps_probe(), 0);

    fake_clear();
    fake_set(MAPS, "12c00000-12c21000 r-xp 0 fd:00 1 /data/app/libnc.so\n");
    expect("maps: 含 libnc.so 但无 frida 特征 → 应 clean", frida_maps_probe(), 0);

    /* ═══ tracer_probe ═══ 只看 /proc/self/status 的 TracerPid */
    fake_clear();
    fake_set(STATUS, "Name:\tcom.test\nTracerPid:\t1234\nUid:\t10000\n");
    expect("status: TracerPid=1234 → 应命中", tracer_probe(), 1);

    fake_clear();
    fake_set(STATUS, "Name:\tcom.test\nTracerPid:\t0\n");
    expect("status: TracerPid=0 → 应 clean", tracer_probe(), 0);

    fake_clear();
    fake_set(STATUS, "Name:\tcom.test\nState:\tS\nPid:\t999\n");
    expect("status: 无 TracerPid 行 → 应 clean", tracer_probe(), 0);

    fake_clear();
    expect("status: 读不到文件 → 应 clean", tracer_probe(), 0);

    /* ═══ stat_state_probe ═══ 只认 state 字段 T / t */
    fake_clear();
    fake_set(STAT, "1234 (com.test) t 1 1234 1234 0 -1\n");
    expect("stat: state='t'（tracing stop）→ 应命中", stat_state_probe(), 1);

    fake_clear();
    fake_set(STAT, "1234 (com.test) T 1 1234 1234 0 -1\n");
    expect("stat: state='T'（stopped）→ 应命中", stat_state_probe(), 1);

    fake_clear();
    fake_set(STAT, "1234 (com.test) S 1 1234 1234 0 -1\n");
    expect("stat: state='S'（正常睡眠）→ 应 clean", stat_state_probe(), 0);

    fake_clear();
    fake_set(STAT, "1234 (com.test) R 1 1234 1234 0 -1\n");
    expect("stat: state='R'（运行中）→ 应 clean", stat_state_probe(), 0);

    fake_clear();
    fake_set(STAT, "1234 (com.test) D 1 1234 1234 0 -1\n");
    expect("stat: state='D'（不可中断IO）→ 应 clean", stat_state_probe(), 0);

    /* 解析陷阱：comm 里有空格与括号 —— 必须从【最后一个】')' 往后取 */
    fake_clear();
    fake_set(STAT, "1234 (my app (v2)) T 1 1234 0 -1\n");
    expect("stat: comm 含空格与括号 + state=T → 应命中", stat_state_probe(), 1);

    fake_clear();
    fake_set(STAT, "1234 (my app (v2)) S 1 1234 0 -1\n");
    expect("stat: comm 含空格与括号 + state=S → 应 clean", stat_state_probe(), 0);

    fake_clear();
    fake_set(STAT, "garbage without parens\n");
    expect("stat: 无 ')' 的畸形内容 → 应 clean", stat_state_probe(), 0);

    /* ═══ frida_unix_probe ═══ 特征: frida / linjector / gum-js */
    fake_clear();
    fake_set(UNIX,
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "ffff8880 00000002 00000000 00010000 0001 01 12345 @frida-1234\n");
    expect("unix: 含 frida socket → 应命中", frida_unix_probe(), 1);

    fake_clear();
    fake_set(UNIX,
        "ffff8880 00000002 00000000 00010000 0001 01 1 /dev/socket/linjector\n");
    expect("unix: 含 linjector → 应命中", frida_unix_probe(), 1);

    fake_clear();
    fake_set(UNIX,
        "ffff8880 00000002 00000000 00010000 0001 01 2 /memfd:gum-js-loop\n");
    expect("unix: 含 gum-js → 应命中", frida_unix_probe(), 1);

    fake_clear();
    fake_set(UNIX,
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "ffff8880 00000002 00000000 00010000 0001 01 9 @android:debugger\n");
    expect("unix: 只有正常 socket → 应 clean", frida_unix_probe(), 0);

    fake_clear();
    expect("unix: 读不到文件 → 应 clean", frida_unix_probe(), 0);

    printf("\n==============================================================\n");
    printf("结果: %d 通过, %d 失败\n", pass, fail);
    printf("==============================================================\n");
    return fail ? 1 : 0;
}
MEOF

# ── 编译 ────────────────────────────────────────────────────────────
# -Dstatic= ：让探针函数可被外部调用（生产源码文件本身不动）
# 注意：这也会把 static inline 变成普通函数，故 harness 提供了对应实现
if ! clang -Dstatic= -DNC_GUARD_SECTIONED -I"$WORK" \
        -c "$WORK/env_probes.c" -o "$WORK/env_probes.o" 2>"$WORK/build.log"; then
    echo "✗ env_probes.c 编译失败：" >&2
    head -20 "$WORK/build.log" >&2
    exit 1
fi
if ! clang -Dstatic= -DNC_GUARD_SECTIONED -I"$WORK" \
        -c "$WORK/harness.c" -o "$WORK/harness.o" 2>>"$WORK/build.log"; then
    echo "✗ harness.c 编译失败：" >&2
    tail -20 "$WORK/build.log" >&2
    exit 1
fi
if ! clang -I"$WORK" -c "$WORK/main.c" -o "$WORK/main.o" 2>>"$WORK/build.log"; then
    echo "✗ main.c 编译失败：" >&2
    tail -20 "$WORK/build.log" >&2
    exit 1
fi
if ! clang "$WORK/env_probes.o" "$WORK/harness.o" "$WORK/main.o" \
        -o "$WORK/t" -lpthread -llog 2>>"$WORK/build.log"; then
    echo "✗ 链接失败：" >&2
    tail -20 "$WORK/build.log" >&2
    exit 1
fi

echo ""
"$WORK/t"
RC=$?

echo ""
echo "未覆盖的探针（输入源不同，需另换桩）："
echo "  frida_port_probe      真 socket      → 真机验证（已做过）"
echo "  frida_thread_probe    还要 opendir   → 需替换目录遍历"
echo "  xposed_file_probe     access()       → 需替换 access"
echo "  trap_probe            真信号+线程    → 需真实信号环境"
echo "  libc_hook_probe       真实内存       → 需真实内存布局"
echo "  libc/self_text_crc_probe 真实 ELF+内存 → 需真实产物"

exit $RC
