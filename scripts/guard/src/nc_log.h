/*
 * nc_log.h — 文件日志通道的唯一契约（2026-11-25 抽取）
 *
 * ═══ 为什么有这个文件 ═══
 *
 * 抽取前，sig_check.c 与 env_check.c 各自实现了**几乎逐行相同**的一份日志：
 *   siglog_detect / siglog / siglog_fmt1      （sig_check.c）
 *   envlog_detect / envlog / envlog_c          （env_check.c）
 * 两份都写同一个文件 sigcheck_log.txt，各自探测哨兵、各自维护 ready 状态。
 *
 * 代价（已实测发生）：
 *   · 同一个 bug 存在两份 —— 2026-11-25 修「首次启动没日志」时，
 *     第一版只改了 sig_check.c，env_check.c 的第 78 行仍是
 *     `envlog_ready = 0`，中文文案（签名校验的绝大多数日志）照样丢。
 *     若不是测试里加了对一对函数的断言，这个"只修一半"会被漏掉。
 *   · 探测逻辑两份漂移 —— sig_check 用 access() 判可写，
 *     env_check 用 open() 预检，两者对「目录刚建好」的反应不同。
 *
 * ⚠️ 为什么不违反 AGENTS §1 的「零代码共享」纪律：
 *    那条纪律针对【判定逻辑】（sig_guard2 必须独立，否则改一处两线同废）。
 *    日志是**可观测性设施**，不是判定依据 —— 共享它不削弱任何一道防线：
 *    攻击者改掉日志模块，最多让日志消失，判定与处置照常。
 *    判定链（sig_collect_fp / derive_expected / g2_verify）仍然零共享。
 *
 * ═══ 唯一入口 ═══
 *
 *   nc_log_open()      探测开关 + 拼路径（幂等、可重试）
 *   nc_log_line()      写一行（带时间戳/pid，自动 append）
 *   nc_log_ready()     当前状态（调试用）
 *
 * ═══ 首次启动为什么需要重试（本模块的核心设计）═══
 *
 * 日志路径是 /storage/emulated/0/Android/data/<pkg>/files/<name>。
 * 这个目录由 system_server 在「应用数据目录初始化」时创建，而我们的
 * constructor 在它之前跑完 → 第一次启动必然探测失败。
 *
 * 而 <pkg>/ 这一层 App **无权自建**：父目录 /storage/emulated/0/Android/data
 * 权限是 drwxrws--x（其他用户 --x，能进不能写）→ mkdir 得 EACCES(13)。
 * 实测数据（真机 07:31）：
 *     siglog: mkdir ... failed (pkg_rc=13 files_rc=2)
 *
 * 所以本模块的设计是：**失败不落死，保留可重试状态**。
 * 任何后续 nc_log_line() 调用都会再试一次（上限 NC_LOG_MAX_TRIES 次），
 * 系统建好目录后自动恢复。配合 sig_check.c 里 constructor 末尾起的
 * 短延时线程（1~2 秒），第一次启动也能拿到日志。
 *
 * ═══ 安全边界（与抽取前一致，未放宽）═══
 * 日志内容只有路径 / 指纹哈希 / 分支结论，无密钥、无用户数据。
 * 所有 I/O 失败一律静默忽略，绝不影响判定主流程。
 */
#ifndef NC_LOG_H
#define NC_LOG_H

#include <stddef.h>

/* 探测重试上限。哨兵不存在是常态（用户没开日志），不能无限 access。
 *
 * ⚠️ 2026-11-25 真机实测后从 6 调到 12：files/ 目录可能比 constructor
 * 晚 17 秒才出现（由第一次实际写入触发），延时线程要试 8 次才能覆盖，
 * 加上 constructor 与运行期的几次调用，6 次不够。
 * 12 次 × 最多 2 秒间隔 ≈ 24 秒上限，之后放弃、零开销。 */
#define NC_LOG_MAX_TRIES 12

/* 探测开关并准备路径。幂等：已成功/已放弃时直接返回。
 * 返回 1 = 可写，0 = 当前不可写（之后可能变可用，见上）。
 *
 * ⚠️ 可重入安全：内部用静态状态，不做锁 —— 与抽取前行为一致。
 *    最坏情况是两个线程同时探测、同时成功，结果相同（都是置 1 + 同一路径）。 */
int  nc_log_open(void);

/* 写一行日志。fmt 之后是 printf 风格参数，内部按 512 字节截断。
 * prio 取 "I" / "E" / "D" / "W"（单字符，与既有日志格式一致）。
 * 未就绪时会尝试 nc_log_open()（这正是"首次启动最终能写出来"的机制）。 */
void nc_log_line(const char *prio, const char *fmt, ...);

/* 当前是否可写（1=可以，0=否）。供需要"只在可写时才做重活"的调用方用。 */
int  nc_log_ready(void);

/* 轻量轮询：目标目录当前可写吗？不消耗探测配额。
 * 供 nc_log_late_flush 的线程高频轮询用（见 nc_log.c 里的说明）。 */
int  nc_log_dir_probe(void);

/* ── 首次启动的结论摘要（可选，仅 sig_check.c 用）──────────────────────
 *
 * 为什么需要：constructor 期目录还不存在（见头注），那几十毫秒的日志
 * 必然落不了盘。但排障最需要的恰恰是它的【结论】。
 *
 * 设计取舍：只存三个整数（rc / 六路成功数 / 裁决码），不存日志文本。
 *   · 全文缓冲 ≈ 8KB 明常常驻 .bss → Frida Memory.scan 可整块读走
 *   · 摘要 ≈ 16 字节，且不含指纹/路径，泄露面小于完整日志两个数量级
 * 这是用户提出"内存缓冲不安全"后确定的方案。
 *
 * 用法（sig_check.c 里）：
 *   nc_log_summary(rc, routes_ok, verdict);   // constructor 算完就填
 *   nc_log_late_flush();                      // constructor 末尾调
 */
void nc_log_summary(int rc, int routes, int verdict);
void nc_log_late_flush(void);

/* ── 注入类排除之外，本模块需要的路径来源 ──────────────────────────────
 *
 * 哨兵路径 / 日志文件名 / /proc/self/cmdline 这三个字符串都必须密文化
 * （明文进 .so 等于告诉逆向者"日志开关在哪"）。但密文表 sig_log_data.h
 * 由 make-sig-log.py 扫 LSG 标记生成，而本文件不是被扫描的那几个源文件…
 *
 * ⚠️ 解法：本文件**自己带 LSG 标记**，由 protect.sh 把它加进生成器入参。
 *    生成器按文件基名取前缀（nc_log.c → nc_log），宏名自动不冲突
 *    （见 make-sig-log.py 第 120 行的 prefix 规则）。
 *    这样密文表仍是唯一真相源，本模块不复制任何明文常量。
 */

#endif /* NC_LOG_H */
