/* nc_jni_selfcheck.h — RegisterNatives 表项自检的契约（2026-11-22）
 *
 * 实现见 nc_jni_selfcheck.c。单独成 TU 的原因：宿主测试要编译【同一份】
 * 实现，而 nc_link_jni.c 在 NCLINK_HOST_TEST 下整段被排除。
 */
#ifndef _NC_JNI_SELFCHECK_H_
#define _NC_JNI_SELFCHECK_H_

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 校验即将交给 RegisterNatives 的表。返回 0 = 可以注册，非 0 = 必须中止。
 *
 * 拒绝的情形：空表 / n <= 0 / name·signature·fnPtr 有 NULL / 两项重名。
 *
 * ⚠️ 调用方必须把它放在 RegisterNatives【之前】：
 *    这个方法存在的全部理由就是「RegisterNatives 返回 0 不可信」
 *    （2026-11-22 真机实证：rc=0 但 ncVerify 从未绑上，静默闪退）。
 *    放到注册之后等于没查。
 */
int nc_jni_selfcheck(const JNINativeMethod *t, int n);

#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif /* _NC_JNI_SELFCHECK_H_ */
