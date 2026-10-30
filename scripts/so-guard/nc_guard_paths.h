/* nc_guard_paths.h — so 加密设施自带的路径密文表（独立化，2026-10-30）
 *
 * 为什么需要本文件：
 *   设施原先从主项目生成的 sig_log_data.h 取两条 /proc 路径，导致
 *   "单独拿设施编译"直接失败（fatal error: 'sig_log_data.h' file not found）。
 *   本文件让设施自带这两条路径，从此零外部源码依赖。
 *
 * 为什么不能直接写明文：
 *   改造前这两条路径是密文（由 sig_log_data.h 提供），改成明文字符串
 *   等于防护退步 —— `strings -n 6` 一行就能扫出 /proc/self/cmdline。
 *   本文件用与既有实现同族的密钥流保持同等强度。
 *
 * ⚠️ 强度边界（如实，勿高估）：
 *   这是【混淆】不是【加密】。密钥与算法都在本设施的源码里，攻击者若
 *   愿意反汇编 ncg_path_ctr_xor 并读常量，可以还原这两条路径。
 *   它买到的是"自动扫描失效"（strings/grep 扫不到），不是"人工逆向成本"。
 *   这与 nc_guard_layout.h 里 magic seed 的诚实口径一致。
 *
 * 布局纪律：本文件零逻辑、只放接口与常量声明，故任何工具链都能编
 *   （与 nc_guard_layout.h 同款约束）。实现在 nc_guard_paths.c。
 */
#ifndef _NC_GUARD_PATHS_H_
#define _NC_GUARD_PATHS_H_

#include <stddef.h>

/* 路径 ID。数值即密钥流的 msg_id（域分离用），不要随便改数值 —— 
 * 改了要重跑 gen-paths.py 重新生成密文表。 */
typedef enum {
    NCG_PATH_CMDLINE = 0,   /* "/proc/self/cmdline" —— 取进程名（包名）*/
    NCG_PATH_MAPS    = 1,   /* "/proc/self/maps"    —— 定位自身 APK */
    NCG_PATH_COUNT   = 2
} ncg_path_id;

/* 取第 id 条路径的明文，写入调用方缓冲，返回 buf；失败返回 NULL。
 *
 * 语义与原先的 lsg_s() 一致：
 *   · 成功时返回 buf，且 buf 以 NUL 结尾（C 字符串语义）
 *   · id 越界、buf 为 NULL、cap 不足 → 返回 NULL
 *   · 调用方自备缓冲；本函数不分配内存、不做 I/O
 *
 * ⚠️ 返回的指针指向调用方缓冲（不是内部静态区），所以多线程各自持有
 *    自己的 buf 时天然安全 —— 这与 lsg_s 的用法一致。
 *
 * ⚠️ 本函数必须留在 .text（明文段）：调用它的 ncg_self_pkg /
 *    ncg_find_apk_path 都在 .ncxh 密文段内，而 .ncxh 解开之前就要能用。
 *    实现文件不加 __attribute__((section))，自然落 .text。 */
const char *ncg_path_s(int id, char *buf, size_t cap);

#endif /* _NC_GUARD_PATHS_H_ */
