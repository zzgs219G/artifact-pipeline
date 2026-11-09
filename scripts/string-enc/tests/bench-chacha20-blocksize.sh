#!/usr/bin/env bash
# bench-chacha20-blocksize.sh — ChaCha20 块粒度 A/B 基准
#
# ## 为什么这个脚本存在
#
# 2026-11-09 我给 ChaCha20 做块粒度优化（8 字节/块 → 64 字节/块）后，
# 在 commit message 里写了「63 → 311 MB/s（4.9×）」。这两个数字**是错的**：
# 它们是两个不同时刻的绝对值相除得到的，而那台设备当时
# `load average 21.5`（4 核）、CPU 降频到 1.0 GHz。之后用同一份代码
# 重测得到 490~700 MB/s —— 连我自己的结论都复现不了。
#
# 正确的测法：**把两版实现内联进同一个程序，交替跑多轮取平均**，
# 这样负载与频率的漂移对两组影响相同，比值才可信。
#
# 本脚本就是那个正确测法。它不测真实源码（源码里 splitmix64 与 ChaCha20
# 是二选一编译的，不可能同时存在），而是把两种「块粒度」的实现都内联进来
# —— 因为要回答的问题只有一个：**每 8 字节重跑一次 20 轮，比每 64 字节
# 跑一次，慢多少**。理论上恰好是 8 倍（64/8），实测应落在 7.5~8.5。
#
# 用法：bash scripts/string-enc/tests/bench-chacha20-blocksize.sh
#
# ⚠️ 只信比值，不信绝对 MB/s。宿主是共享的移动设备，负载/降频会让
#    绝对值失真到无法复现。跑之前本脚本会打印 load average 与当前频率，
#    如果负载很高，比值仍然可用（同进程交替），但绝对值别往外报。

set -uo pipefail

CC="${CC:-clang}"
command -v "$CC" >/dev/null 2>&1 || CC=cc

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

echo "══ 环境（读数用，不参与判定）══"
echo "  load average: $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo N/A)"
for c in 0 1 2 3; do
    f="/sys/devices/system/cpu/cpu$c/cpufreq/scaling_cur_freq"
    [ -r "$f" ] && echo "  cpu$c 频率: $(( $(cat "$f") / 1000 )) MHz"
done
echo "  核心数: $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo N/A)"

cat > "$W/ab.c" <<'EOF'
/* 两版块粒度实现内联，交替跑多轮。
 * 关键：两版产出的【总字节数相同】（TOTAL），比的才是真吞吐。 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d) do {                                   \
        a += b; d ^= a; d = ROTL(d, 16);                       \
        c += d; b ^= c; b = ROTL(b, 12);                       \
        a += b; d ^= a; d = ROTL(d, 8);                        \
        c += d; b ^= c; b = ROTL(b, 7);                        \
    } while (0)

static const uint32_t K[8] = {1, 2, 3, 4, 5, 6, 7, 8};

/* ChaCha20 核心：counter=ctr 的 20 轮，输出 16 个 uint32 = 64 字节密钥流 */
static void core64(uint32_t ctr, uint32_t out[16])
{
    uint32_t s0 = 0x61707865u, s1 = 0x3320646Eu;
    uint32_t s2 = 0x79622D32u, s3 = 0x6B206574u;
    uint32_t s4 = K[0], s5 = K[1], s6 = K[2], s7 = K[3];
    uint32_t s8 = K[4], s9 = K[5], s10 = K[6], s11 = K[7];
    uint32_t s12 = ctr, s13 = 0, s14 = 0, s15 = 0;
    uint32_t x0 = s0, x1 = s1, x2 = s2, x3 = s3, x4 = s4, x5 = s5, x6 = s6, x7 = s7;
    uint32_t x8 = s8, x9 = s9, x10 = s10, x11 = s11;
    uint32_t x12 = s12, x13 = s13, x14 = s14, x15 = s15;
#define DR QR(x0,x4,x8,x12);  QR(x1,x5,x9,x13);  QR(x2,x6,x10,x14); QR(x3,x7,x11,x15); \
           QR(x0,x5,x10,x15); QR(x1,x6,x11,x12); QR(x2,x7,x8,x13);  QR(x3,x4,x9,x14)
    DR;DR;DR;DR;DR;DR;DR;DR;DR;DR;
#undef DR
    out[0] = x0+s0;   out[1] = x1+s1;   out[2] = x2+s2;   out[3] = x3+s3;
    out[4] = x4+s4;   out[5] = x5+s5;   out[6] = x6+s6;   out[7] = x7+s7;
    out[8] = x8+s8;   out[9] = x9+s9;   out[10] = x10+s10; out[11] = x11+s11;
    out[12] = x12+s12; out[13] = x13+s13; out[14] = x14+s14; out[15] = x15+s15;
}

#define TOTAL (64ull * 1024 * 1024)   /* 64 MiB 密钥流 */
static volatile uint64_t sink;

/* 旧实现：每 8 字节重跑一次 core（算了 64 字节只用前 8 字节） */
static double t_old(void)
{
    uint64_t a = 0;
    double t0 = now_ns();
    for (uint64_t blk = 0; blk < TOTAL / 8; blk++) {
        uint32_t w[16];
        core64((uint32_t)blk, w);
        a += w[0] + w[1];
    }
    double t1 = now_ns();
    sink = a;
    return TOTAL / 1e6 / ((t1 - t0) / 1e9);
}

/* 新实现：每 64 字节跑一次 core（用满整块） */
static double t_new(void)
{
    uint64_t a = 0;
    double t0 = now_ns();
    for (uint64_t blk = 0; blk < TOTAL / 64; blk++) {
        uint32_t w[16];
        core64((uint32_t)blk, w);
        a += w[0] + w[15];
    }
    double t1 = now_ns();
    sink = a;
    return TOTAL / 1e6 / ((t1 - t0) / 1e9);
}

int main(void)
{
    t_old(); t_new();                 /* 预热：让 CPU 进入稳态频率 */

    const int R = 5;
    double o = 0, n = 0, ratio_min = 1e9, ratio_max = 0;
    for (int r = 0; r < R; r++) {
        /* 交替：每一轮内 OLD 与 NEW 背靠背，环境漂移对两者影响相同 */
        double ov = t_old();
        double nv = t_new();
        o += ov; n += nv;
        double rr = nv / ov;
        if (rr < ratio_min) ratio_min = rr;
        if (rr > ratio_max) ratio_max = rr;
        printf("  轮 %d: OLD %5.0f MB/s   NEW %5.0f MB/s   比值 %.2fx\n",
               r + 1, ov, nv, rr);
    }
    o /= R; n /= R;
    printf("\n平均:  OLD %5.0f MB/s   NEW %5.0f MB/s\n", o, n);
    printf("加速比: %.2fx  (范围 %.2f~%.2f，理论值 8.00x)\n",
           n / o, ratio_min, ratio_max);
    printf("\n⚠️ 只信比值，别报绝对值：宿主负载/频率浮动会让 MB/s 失真。\n");
    return 0;
}
EOF

if ! "$CC" -O2 -std=c99 -Wall -Wextra -o "$W/ab" "$W/ab.c" 2>"$W/cc.log"; then
    echo "❌ 编译失败:"; cat "$W/cc.log"; exit 1
fi
[ -s "$W/cc.log" ] && { echo "❌ 有编译警告:"; cat "$W/cc.log"; exit 1; }

echo
echo "══ A/B 交替测量（同进程，5 轮）══"
"$W/ab" | tee "$W/out.txt"

# 判据：加速比必须落在 7.0~9.0（理论 8.0）
ratio=$(awk '/^加速比:/{gsub(/x/,"",$2); print $2}' "$W/out.txt")
if [ -z "$ratio" ]; then echo "❌ 取不到加速比"; exit 1; fi
ok=$(awk -v r="$ratio" 'BEGIN{print (r>=7.0 && r<=9.0) ? "1" : "0"}')
if [ "$ok" = "1" ]; then
    echo "✅ 加速比 ${ratio}x 落在预期区间 7.0~9.0（理论 8.0x）"
else
    echo "❌ 加速比 ${ratio}x 偏离理论值 8.0x 过多 —— 检查实现是否被改坏"
    exit 1
fi
