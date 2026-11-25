/*
 * nc_log.h — 文件日志
 *
 * 逻辑：检测文件夹是否存在 → 存在就打印；不存在，过 2 秒再打印。
 *
 * 之前 sig_check.c 和 env_check.c 各写了一份同样的日志，改 bug 时只改一半
 * 就漏了。合并成这一份。日志不是判定逻辑，共享不削弱防护。
 */
#ifndef NC_LOG_H
#define NC_LOG_H

#include <stddef.h>

/* 探测哨兵与日志目录。返回 1=可写，0=不可写。不阻塞。 */
int  nc_log_open(void);

/* 写一行日志。文件夹不存在时会起后台线程，2 秒后再打印。 */
void nc_log_line(const char *prio, const char *fmt, ...);

/* 当前可写吗。 */
int  nc_log_ready(void);

#endif /* NC_LOG_H */
