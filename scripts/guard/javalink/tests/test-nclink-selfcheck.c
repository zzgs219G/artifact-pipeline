/*
 * test-nclink-selfcheck.c — nc_jni_selfcheck() 的宿主行为验证
 *
 * 【为什么需要它】
 *   2026-11-22 的真机 bug：names/sigs 只有 2 个槽却注册 3 个方法，
 *   selftest 的还原写了 names[0] → 把 ncVerify 的名字原地覆盖成
 *   "selftest" → ART 拿到的表里没有 "ncVerify" → 静默跳过 →
 *   RegisterNatives 仍返回 0，但方法没绑上 → 调用即
 *     No implementation found for ...NcLink.ncVerify(byte[])
 *   → Guard 的 catch(UnsatisfiedLinkError) → kill() → 闪退。
 *
 *   关键事实：RegisterNatives 的返回值【不足以】判定绑定成功。
 *   既然「rc=0」不等于「成功」，就必须在调用前把能自查的全查掉。
 *
 * 【测什么 / 不测什么】
 *   测 nc_jni_selfcheck() 的判定语义：重名 / 空表 / NULL 字段必须被拒，
 *   正常表必须通过。不测真机寻址（那要 ART，见 test-javacheck.sh）。
 *
 *   ⚠️ 编译时链接的是 scripts/guard/src/nc_jni_selfcheck.c 【本身】，
 *      不在本文件里复制实现 —— 复制会让"测试绿但生产已改"无法被发现。
 *
 * 用法（由 test-javacheck.sh 调用）:
 *   clang -I<guard/src> -I<ndk jni.h> test-nclink-selfcheck.c nc_jni_selfcheck.c
 */
#include <stdio.h>

#include "nc_jni_selfcheck.h"

int main(void) {
    void *p = (void *)1;
    int fail = 0;

    /* ① 历史 bug 的真实形态：tab[0] 与 tab[2] 同名 "selftest"。
     *    用户报的症状是 ncVerify 缺失，而表里重名的却是 selftest ——
     *    这正是"覆盖"这个动作的指纹：写出者以为在填新槽，实际覆盖了旧槽。 */
    JNINativeMethod bad[] = {
        { "selftest",  "()I", p },
        { "heartbeat", "()V", p },
        { "selftest",  "()I", p },
    };
    if (nc_jni_selfcheck(bad, 3) == 0) {
        printf("FAIL: 重名表（历史 bug 形态）被放过了\n");
        fail = 1;
    } else {
        printf("  ✅ 重名表被拒绝（历史 bug 形态）\n");
    }

    /* ② 正常表不得误拒 —— 自检过严会让好包也加载失败 */
    JNINativeMethod good[] = {
        { "ncVerify",  "([B)Z", p },
        { "heartbeat", "()V",   p },
        { "selftest",  "()I",   p },
    };
    if (nc_jni_selfcheck(good, 3) != 0) {
        printf("FAIL: 正常表被误拒（自检过严）\n");
        fail = 1;
    } else {
        printf("  ✅ 正常表通过\n");
    }

    /* ③ 空表等于什么都没注册 —— 必须当失败，不能让 JNI_OnLoad 返回成功 */
    if (nc_jni_selfcheck(NULL, 3) == 0 || nc_jni_selfcheck(good, 0) == 0) {
        printf("FAIL: 空表/NULL 被放过\n");
        fail = 1;
    } else {
        printf("  ✅ 空表 / NULL 被拒绝\n");
    }

    /* ④ 字段没填完整（表项漏填 fnPtr）= 写了半截，必须当场拦下 */
    JNINativeMethod nullfn[] = { { "a", "()V", NULL } };
    if (nc_jni_selfcheck(nullfn, 1) == 0) {
        printf("FAIL: NULL fnPtr 被放过\n");
        fail = 1;
    } else {
        printf("  ✅ NULL fnPtr 被拒绝\n");
    }

    /* ⑤ 弱符号缺失时的常态组合（selftest 未编入 → 只剩两项）必须照常通过 */
    if (nc_jni_selfcheck(good, 2) != 0) {
        printf("FAIL: 两项表被误拒\n");
        fail = 1;
    } else {
        printf("  ✅ 两项表通过（弱符号缺失的常态组合）\n");
    }

    /* ⑥ 单条表也要能过（最小情形，防边界写反） */
    if (nc_jni_selfcheck(good, 1) != 0) {
        printf("FAIL: 单条表被误拒\n");
        fail = 1;
    } else {
        printf("  ✅ 单条表通过\n");
    }

    printf(fail ? "❌ nc_jni_selfcheck 判定测试失败\n"
                : "✅ nc_jni_selfcheck 判定测试通过（重名/空表/NULL/子集）\n");
    return fail;
}
