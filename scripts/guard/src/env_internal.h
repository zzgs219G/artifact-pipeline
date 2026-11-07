/* env_internal.h — env_check.c / env_probes.c 之间的共享声明（2026-11-08）
 *
 * 存在的唯一理由：`env_check.c` 已经有 1600+ 行，探针部分（13 个探针 +
 * 它们专用的 CRC / ELF / 内存读取工具）占了大半。把探针拆到独立文件后，
 * 两侧需要一份共享声明。
 *
 * ⚠️ 与 `nc_guard_internal.h` 的分工（别混）：
 *   nc_guard_internal.h   nox 设施内部（boot.c ↔ crypto.c），属加密契约范畴
 *   本文件                envcheck 模块内部（env_check.c ↔ env_probes.c）
 *                        改它不影响任何产物格式，只影响本模块这两个 TU
 *
 * ⚠️ 为什么拆的是"探针 vs 基础设施"而不是按功能拆 4 个文件：
 *   LSGS 标记的前缀由 make-sig-log.py 按【文件基名】生成
 *   （sig_check→sig / env_check→env）。拆成多个文件会让前缀规则变复杂，
 *   进而改动 sig_log_data.h 里的全部枚举名，牵动所有 envlog_c 调用点
 *   与测试断言 —— 那是"爆炸"级改动。拆两个文件则前缀不变。
 *
 * ⚠️ 本文件不参与"格式契约"，但有一条纪律：这里的函数签名两侧共享，
 *   改签名必须同时改两边 —— 编译器会拦，不会静默。
 */
#ifndef _ENV_INTERNAL_H_
#define _ENV_INTERNAL_H_

#include <stddef.h>
#include <stdint.h>
#include "sig_log_data.h"     /* lsg_id_t / lsg_s */

/* ═══════════════════════════════════════════════════════════════════
 * 一、env_check.c 提供给探针文件的基础设施
 * ═══════════════════════════════════════════════════════════════════ */

/* syscall 直调（内联 svc，无 PLT 桩）。定义在 env_check.c。 */
long env_raw_syscall(long n, long a0, long a1, long a2,
                     long a3, long a4, long a5);

/* 带返回码规整的 syscall 封装（失败返回 -errno 语义由实现决定）。
 * 探针文件里的 process_vm_readv / pread 走它。 */
long safe_syscall(long n, long a0, long a1, long a2,
                  long a3, long a4, long a5);

/* 读整个文件到堆缓冲。调用方负责 free。返回字节数，失败 -1。 */
long safe_read_alloc(const char *path, char **out);

/* 行迭代器（替代 fopen+fgets，走 syscall）。 */
typedef struct {
    char  *buf;
    size_t pos;
    long   len;
} safe_lines_t;

int   safe_lines_open(safe_lines_t *it, const char *path);
char *safe_lines_next(safe_lines_t *it);
void  safe_lines_close(safe_lines_t *it);

/* 日志（写文件，需哨兵开关；env_id 走 LSGS 密文表）。 */
void envlog_c(int is_err, lsg_id_t id, const char *detail);

/* 检出后的处置（起线程延迟自杀）。 */
void env_fail(void);

/* ═══════════════════════════════════════════════════════════════════
 * 二、env_probes.c 提供给 env_check.c 的 13 个探针
 * ═══════════════════════════════════════════════════════════════════
 * 全部返回 0=未检出 / 1=检出（trap_probe 额外有 -1=skip）。
 * 探针本体在 .ncx 密文段；本文件只有声明，属明文（不构成泄露）。 */

int frida_port_probe(void);
int frida_maps_probe(void);
int frida_tcp_table_probe(void);
int frida_thread_probe(void);
int frida_unix_probe(void);
int xposed_maps_probe(void);
int xposed_file_probe(void);
int tracer_probe(void);
int tracer_all_threads_probe(void);
int stat_state_probe(void);
int trap_probe(void);            /* 0=NORMAL 1=DANGER -1=SKIPPED */
int libc_hook_probe(void);
int libc_text_crc_probe(void);
int self_text_crc_probe(void);

#endif /* _ENV_INTERNAL_H_ */
