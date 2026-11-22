/* nc_jni_selfcheck.c — RegisterNatives 表项自检（2026-11-22）
 *
 * 【为什么单独一个 TU】
 *   这段逻辑必须能被宿主测试直接编译验证（`test-nclink-selfcheck.c`），
 *   而 `nc_link_jni.c` 在 `NCLINK_HOST_TEST` 下整段被排除（宿主没有 JVM）。
 *   放在独立文件里，宿主与真机跑的是【同一份】实现 —— 复制一份到测试里
 *   就失去意义了（测试通过但生产已改，这种漂移发现不了）。
 *
 * 【为什么需要自检】
 *   2026-11-22 真机实证：`RegisterNatives` 返回 0 **不等于**绑定成功。
 *   当 JNINativeMethod 表里的 name 匹配不上 Java 侧任何方法时，
 *   ART 会【静默跳过】该项，返回值仍是 0。于是：
 *
 *     构建 ✅  链接 ✅  静态测试 ✅  CI ✅   真机调用 ❌
 *       No implementation found for ...NcLink.ncVerify(byte[])
 *     → Guard 的 catch(UnsatisfiedLinkError) → kill() → 闪退
 *
 *   既然「返回值 0」不可信，就必须在调用 RegisterNatives【之前】
 *   把能自查的全查掉，把"静默"变成"明确失败"：
 *   JNI_OnLoad 返回 JNI_ERR → loadLibrary 抛 ULE → Guard 走既有的
 *   fail-closed kill 路径（与"so 缺失"同一条处置链，语义一致）。
 */
#include <jni.h>
#include <stddef.h>

#include "nc_jni_selfcheck.h"

/* 字符串相等。不用 strcmp：本单元刻意零 libc 依赖 —— 引入 libc 会给
 * so 多一个 PLT 项（env_check.c 的验收查过 `nm -D -u` 的同类问题），
 * 也免得被混淆 pass 当外部调用改写。 */
static int nc_eq(const char *a, const char *b) {
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

int nc_jni_selfcheck(const JNINativeMethod *t, int n) {
    int i, j;

    /* 空表 = 什么都没注册，不能当成功 */
    if (t == NULL || n <= 0) return -1;

    for (i = 0; i < n; i++) {
        /* 表项没填完整 —— 写了半截的表比空表更危险（看起来像有） */
        if (t[i].name == NULL || t[i].signature == NULL || t[i].fnPtr == NULL) {
            return -1;
        }
        /* 重名 = 槽位复用 / 表项抄错。
         * 2026-11-22 那次 bug 的指纹就是这个：tab[0] 与 tab[2] 都叫
         * "selftest"，而用户报的是 ncVerify 缺失 —— "后写的覆盖先写的"。
         * 查重能把这类错误在注册前就变成明确失败。 */
        for (j = i + 1; j < n; j++) {
            if (nc_eq(t[i].name, t[j].name)) return -1;
        }
    }
    return 0;
}
