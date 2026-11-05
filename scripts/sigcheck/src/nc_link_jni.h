/* nc_link_jni.h — NcLink JNI 入口的注册契约（2026-11-04）
 *
 * 本头文件只声明"谁能被注册"，不含逻辑。
 *
 * 为什么需要它：短名绑定（Java_com_nc_link_NcLink_xxx）会把方法名写进
 * .dynsym，`nm -D` 一条命令就是一张地图。改为 RegisterNatives 后方法名
 * 只在运行期以字符串形式存在，不落地为符号。
 *
 * 两个编译期开关（由 protect.sh 按模块组合二选一，见那边的注释）：
 *   NC_LINK_JNI_OWN_ONLOAD  — 未勾 dex2c：本单元提供唯一的 JNI_OnLoad
 *   未定义                   — 勾了 dex2c：Dex2C.cpp 已有 JNI_OnLoad，
 *                              由它在自己的 OnLoad 尾部调
 *                              nc_link_register_natives()
 */
#ifndef _NC_LINK_JNI_H_
#define _NC_LINK_JNI_H_

#include <jni.h>

/* 把 NcLink 的 native 方法注册到 JVM。返回 0 = 全部注册成功。
 *
 * 必须在 JNI_OnLoad 里调用（不能放 constructor）：
 * constructor 由动态链接器在 dlopen 内部执行，classloader 上下文未建立，
 * FindClass 必然失败（2026-10-19 真机实证，a7d9cbc 回退的原因）。
 * JNI_OnLoad 由 ART 的 nativeloader 回调，会临时切到发起 load 的 loader，
 * FindClass 在该位置是 JNI 规范支持的用法。
 *
 * 失败语义：返回非 0 → 调用方应返回 JNI_ERR，让 loadLibrary 抛
 * UnsatisfiedLinkError（fail-closed，与"so 缺失"同路径）。
 */
int nc_link_register_natives(JNIEnv *env);

#endif /* _NC_LINK_JNI_H_ */
