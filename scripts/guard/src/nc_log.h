/*
 * nc_log.h — 文件日志通道
 *
 * 之前 sig_check.c 和 env_check.c 各写了一份同样的日志，改 bug 时只改一半
 * 就漏了。合并成这一份。日志不是判定逻辑，共享不削弱防护（判定链仍然
 * 零共享）。
 *
 * 本模块任何函数都不 sleep：constructor 在主线程上跑，睡了 App 起不来。
 */
#ifndef NC_LOG_H
#define NC_LOG_H

#include <stddef.h>

/* 探测日志目录。返回 1=可写，0=不可写。不阻塞。 */
int  nc_log_open(void);

/* 重试探测（"饭没好过会儿再看"）。由 env_check 看门狗线程每 5 秒调用。 */
void nc_log_retry(void);

/* 写一行日志。写不了文件就打 logcat 并标 [no-file]。 */
void nc_log_line(const char *prio, const char *fmt, ...);

/* 当前可写吗。 */
int  nc_log_ready(void);

#endif /* NC_LOG_H */
