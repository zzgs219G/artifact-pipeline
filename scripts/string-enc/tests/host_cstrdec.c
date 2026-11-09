/* host_cstrdec.c — nc_strdec 的宿主测试驱动（2026-11-09）
 *
 * 由 tests/test-cstrdec.sh 编译运行；不参与流水线构建，不进任何产物。
 * 三种模式，全部通过 stdin/stdout 走文本协议，便于 bash 侧解析：
 *
 *   gen  <nkeys_ignored>  —— 从 stdin 读密钥 hex，输出前 N 块密钥流（hex）
 *   dec                   —— 从 stdin 读 "密钥hex payload"，输出明文 hex / ERR
 *   b64                   —— 从 stdin 读一行 Base64，输出解码后 hex / ERR
 *
 * 为什么用文本协议：bash 侧要拿 Python 算同样的值来对拍，
 * 二进制协议会让错误定位变难（历史上"静默乱码"类问题都栽在
 * "两边都对但格式不一致"上）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nc_strdec.h"

#define MAXLINE 65536

static int hex2bin(const char *hex, uint8_t *out, size_t cap)
{
    size_t hl = strlen(hex);
    if (hl % 2 != 0 || hl / 2 > cap) {
        return -1;
    }
    for (size_t i = 0; i < hl / 2; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return (int)(hl / 2);
}

static void strip_nl(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s gen|dec|b64\n", argv[0]);
        return 2;
    }

    static char line[MAXLINE];
    static char b64[MAXLINE];
    static uint8_t key[NC_STRDEC_KEYLEN];
    static uint8_t buf[MAXLINE];

    if (strcmp(argv[1], "gen") == 0) {
        /* stdin: 密钥 hex；argv[2] 无 —— 块数由第二行给 */
        if (fgets(line, sizeof line, stdin) == NULL) {
            return 2;
        }
        strip_nl(line);
        if (hex2bin(line, key, sizeof key) != (int)NC_STRDEC_KEYLEN) {
            fprintf(stderr, "gen: 密钥长度应为 %d 字节\n", NC_STRDEC_KEYLEN);
            return 2;
        }
        nc_strdec_set_key(key);

        if (fgets(line, sizeof line, stdin) == NULL) {
            return 2;
        }
        long nblk = strtol(line, NULL, 10);
        for (long b = 0; b < nblk; b++) {
            printf("%016llx\n", (unsigned long long)nc_strdec_block_ks((uint64_t)b));
        }
        return 0;
    }

    if (strcmp(argv[1], "b64") == 0) {
        if (fgets(line, sizeof line, stdin) == NULL) {
            return 2;
        }
        strip_nl(line);
        int n = nc_strdec_b64_decode(line, strlen(line), buf, sizeof buf);
        if (n < 0) {
            printf("ERR\n");
            return 0;
        }
        for (int i = 0; i < n; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");
        return 0;
    }

    if (strcmp(argv[1], "dec") == 0) {
        /* stdin 第一行：密钥 hex；第二行：payload */
        if (fgets(line, sizeof line, stdin) == NULL) {
            return 2;
        }
        strip_nl(line);
        if (hex2bin(line, key, sizeof key) != (int)NC_STRDEC_KEYLEN) {
            fprintf(stderr, "dec: 密钥长度应为 %d 字节\n", NC_STRDEC_KEYLEN);
            return 2;
        }
        nc_strdec_set_key(key);

        if (fgets(b64, sizeof b64, stdin) == NULL) {
            return 2;
        }
        strip_nl(b64);

        /* outcap 取输入长度的 3/4 + 8，足够容纳任意合法 payload */
        int n = nc_strdec_decrypt(b64, strlen(b64), buf, sizeof buf);
        if (n <= 0) {
            printf("ERR\n");
            return 0;
        }
        for (int i = 0; i < n; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");
        return 0;
    }

    if (strcmp(argv[1], "utf16") == 0) {
        /* stdin: 明文 hex（标准 UTF-8 字节）
         * stdout: UTF-16 码元序列（每码元 4 位 hex，无分隔）或 ERR
         * 用途：与 Java 的 new String(bytes,"UTF-8") 逐码元对拍。
         *       Java 侧的码元序列由 test-cstrdec-vs-java.sh 的驱动打印。 */
        if (fgets(line, sizeof line, stdin) == NULL) {
            return 2;
        }
        strip_nl(line);
        int n = hex2bin(line, buf, sizeof buf);
        if (n < 0) {
            printf("ERR\n");
            return 0;
        }
        static uint16_t u16[MAXLINE];
        int m = nc_strdec_utf8_to_utf16(buf, (size_t)n, u16,
                                        sizeof u16 / sizeof u16[0]);
        if (m < 0) {
            printf("ERR\n");
            return 0;
        }
        for (int i = 0; i < m; i++) {
            printf("%04x", u16[i]);
        }
        printf("\n");
        return 0;
    }

    if (strcmp(argv[1], "nokey") == 0) {
        /* fail-closed 探针：不设密钥，直接解一条合法 payload。
         * 期望宿主程序输出 ERR —— 证明"没密钥绝不解密"，
         * 而不是"用全零密钥凑出一个乱码明文"（后者会被业务当成合法值）。 */
        if (fgets(b64, sizeof b64, stdin) == NULL) {
            return 2;
        }
        strip_nl(b64);
        int n = nc_strdec_decrypt(b64, strlen(b64), buf, sizeof buf);
        printf("%s\n", (n <= 0) ? "ERR" : "LEAK");
        return 0;
    }

    fprintf(stderr, "未知模式: %s\n", argv[1]);
    return 2;
}
