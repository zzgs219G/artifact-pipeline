/*
 * test-nclink-judge.c — nc_link_judge() 三角比对裁决的宿主验证
 *
 * 【为什么需要它】
 *   2026-11-25 真机根因：Java 侧 Guard.c() 用 PackageManager 取证书，而那正是
 *   去校验模块在 IPackageManager 代理层撒谎的地方。于是「加固 + 去校验」组合
 *   包里 Java 永远测到原开发者的诱饵证书（3c81b429…），与 SIG_HASH_STORED
 *   （逆向者自己的证书 d82e48da…）不符 → ncVerify=false → Guard.kill() →
 *   主人自己签的包也闪退。
 *
 *   修法：sig_check.c 的可信路线（内联 svc / 裸 syscall / 复用系统 fd）实测
 *   真实 base.apk，把 t1 发布给 nc_link.c；ncVerify 优先用它判定，Java 入参
 *   降级为风控对照数据。
 *
 * 【本测试钉住哪六条（漏一条就会退回误杀或退回漏洞）】
 *   J1 Java 值可信、可信槽未就绪     → NC_JUDGE_OK_NO_TRUSTED（旧语义）
 *   J2 Java 值不可信、可信槽未就绪   → NC_JUDGE_DENY（旧语义 fail-closed）
 *   J3 可信槽=基准、Java 值=诱饵     → NC_JUDGE_OK_PM_TAINTED ← 修复点
 *   J4 可信槽=诱饵、Java 值=基准     → NC_JUDGE_DENY ← 反作弊
 *   J5 可信槽=基准、Java 入参异形    → NC_JUDGE_OK_PM_TAINTED（不被入参拖走）
 *   J6 两源一致且等于基准            → NC_JUDGE_OK（正常包）
 *
 * 【J3 与 J4 互为反向验证】
 *   J3 是修复点：去校验环境下必须放行（否则就是这次的真机闪退）。
 *   J4 是反作弊：真被重签时不能靠 PM 申辩通关。
 *   把实现改成"可信不符时采信 PM"→ J4 红；
 *   把实现改成"永远只看 Java 值"  → J3 红。
 *
 * ⚠️ 链接的是 scripts/guard/src/nc_link.c【本身】，不在本文件里复制实现
 *    （AGENTS.md §2.2：测试替生产保密的测试等于没测）。
 *
 * 用法（由 test-javacheck.sh 调用）:
 *   clang -DNCLINK_HOST_TEST -I<dir with sig_hash.h> \
 *         nc_link.c test-nclink-judge.c -o test && ./test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int nc_verify_t1(const unsigned char *t1, int len);
int nc_link_judge(const unsigned char *java_t1, int java_len);

/* 断言用的结果码。⚠️ 不 include nc_link.c 的宏 —— 它是 .c 不是头文件；
 *    这里重抄一份值必须与生产一致，由下方 _Static_assert 无法跨文件校验，
 *    故改用"用哪条断言失败就打印名字"的方式让漂移可见：
 *    若生产把 OK_PM_TAINTED 改成 5，则 J3 会失败并打印实得值。 */
#define JUDGE_DENY          0
#define JUDGE_OK            1
#define JUDGE_OK_PM_TAINTED 2
#define JUDGE_OK_NO_TRUSTED 3

/* ── 用强定义顶掉 nc_link.c 的弱符号出口 ────────────────────────────────
 * nc_link.c 里 nc_trusted_t1_get 是 weak 声明（extern weak），没有定义；
 * 测试这里提供定义 → 链接时强符号胜出 → nc_link_judge 调到我们的版本。
 *
 * 这份定义【刻意不含任何生产逻辑】：它只是把测试想模拟的"可信实测指纹"
 * 的 t1 原样吐出来。真正的"可信指纹 → t1"换算在 sig_check.c 里，
 * 由 test-trusted-route.py 与真机日志分别覆盖。 */
static unsigned char g_trusted_t1[32];
static int g_trusted_ready = 0;

int nc_trusted_t1_get(unsigned char out[32])
{
    if (!g_trusted_ready) return 0;
    memcpy(out, g_trusted_t1, 32);
    return 1;
}

static void install_trusted(const unsigned char *t1_or_null)
{
    if (t1_or_null == NULL) {
        g_trusted_ready = 0;
        return;
    }
    memcpy(g_trusted_t1, t1_or_null, 32);
    g_trusted_ready = 1;
}

static unsigned char *slurp(const char *path)
{
    FILE *fp = fopen(path, "rb");
    unsigned char *buf;
    size_t n;
    if (!fp) { perror(path); exit(2); }
    buf = malloc(64);
    n = fread(buf, 1, 64, fp);
    fclose(fp);
    if (n != 32) { fprintf(stderr, "vector size %zu != 32\n", n); exit(2); }
    return buf;
}

static int g_fail = 0;

/* 断言辅助：失败时打印期望/实得，便于分辨"实现漂移"与"逻辑错" */
static void expect(const char *id, const char *what, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: %s（期望 %d，实得 %d）\n", id, what, want, got);
        g_fail = 1;
    }
}

int main(int argc, char **argv)
{
    unsigned char *good;    /* t1 = SHA256(基准指纹) → 应通过 */
    unsigned char *bait;    /* t1 = SHA256(诱饵指纹) → 应拒 */
    int got;

    if (argc < 3) {
        fprintf(stderr, "usage: test-nclink-judge <good.bin> <bait.bin>\n");
        return 2;
    }
    good = slurp(argv[1]);
    bait = slurp(argv[2]);

    /* J1：可信槽未就绪 → 按 Java 值判（旧语义）。
     * seccomp 把三条可信路线全拦掉时走这条。 */
    install_trusted(NULL);
    got = nc_link_judge(good, 32);
    expect("J1", "可信槽未就绪时，Java 正确值应走旧语义通过", got,
           JUDGE_OK_NO_TRUSTED);

    /* J2：可信槽未就绪 + Java 值错 → 必须拒（fail-closed 不退化） */
    install_trusted(NULL);
    got = nc_link_judge(bait, 32);
    expect("J2", "可信槽未就绪时，Java 错误值必须拒", got, JUDGE_DENY);

    /* J3：核心修复场景 —— 可信=基准、Java=诱饵（去校验环境）
     * 期望放行，且上报码标出"PM 被污染"。这就是真机上闪退的那个组合包。 */
    install_trusted(good);
    got = nc_link_judge(bait, 32);
    expect("J3", "可信实测=基准、PackageManager 报诱饵 → 应放行并标 PM 污染",
           got, JUDGE_OK_PM_TAINTED);

    /* J4：反作弊 —— 可信=诱饵（真被重签）、Java 报基准值
     * 必须拒。若实现"可信不符时参考 Java 申辩"，这条会红。 */
    install_trusted(bait);
    got = nc_link_judge(good, 32);
    expect("J4", "可信实测≠基准时，不能采信 PackageManager 的申辩（漏洞回归）",
           got, JUDGE_DENY);

    /* J5：可信槽就绪 + Java 入参为 NULL/异形 → 有可信值时不该受影响。
     * 防止实现把 Java 入参的合法性检查放在可信分支之前（那会让攻击者
     * 传个 NULL 就把判定拖进回退路径）。 */
    install_trusted(good);
    got = nc_link_judge(NULL, 0);
    expect("J5", "可信值就绪时，Java 入参异形不应影响裁决", got,
           JUDGE_OK_PM_TAINTED);

    /* J6：可信值与 Java 值一致（正常包）→ 通过且不标污染 */
    install_trusted(good);
    got = nc_link_judge(good, 32);
    expect("J6", "正常包（两源一致且等于基准）应通过且不标污染", got, JUDGE_OK);

    free(good);
    free(bait);
    printf(g_fail ? "❌ nc_link_judge 三角裁决测试失败\n"
                  : "✅ nc_link_judge 三角裁决测试通过"
                    "(J1/J2 旧语义 · J3 修复点 · J4 反作弊 · J5 异形 · J6 正常)\n");
    return g_fail;
}
