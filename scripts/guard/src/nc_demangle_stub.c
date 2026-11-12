/* nc_demangle_stub.c — 顶掉 libc++abi 里 ~98 KB 的 demangler（2026-11-12）
 *
 * ## 为什么需要这个文件
 *
 * libnc.so 只开一个 --dex2c 模块也有 660 KB，而 Dex2C 自己的 runtime 只有
 * 约 10 KB、opcode 表约 115 KB。多出来的主要是 libc++abi / libunwind：
 *
 *   交叉验证（strings + 反汇编，均为实测）：
 *     'libunwind:' 报错串          18 条
 *     'terminating due to %s exception of type %s'  ← cxa_default_handlers
 *     'std::bad_alloc' / 'std::nullptr_t'
 *     __cxxabiv1::scan_eh_tab
 *     'N12_GL' 前缀的 C++ mangled 名  89 条   ← demangler 处理的输入
 *
 * 因果链（dpt-shell 上已用同样手法验证过，见 docs/变更历史.md 2026-11-10）：
 *
 *   APP_STL := c++_static
 *     → 链接 libc++abi.a 的 cxa_default_handlers.cpp.o（导出了
 *       __cxa_terminate_handler 等全局符号，被运行时引用）
 *     → 该 .o 引用 __cxa_demangle
 *     → cxa_demangle.cpp.o（606 个符号，.text 里近 100 KB）整块被拉进 so
 *
 * 它存在的唯一目的：**未捕获异常时把 mangled 名变成可读名**。
 * 为一个崩溃提示文字付 100 KB 不值得。
 *
 * ## 为什么必须在这一层顶，不能靠编译选项
 *
 * cxa_default_handlers.cpp.o 在【预编译的 libc++abi.a】里，
 * -fno-exceptions / -fno-rtti 对它完全无效（那是编译期选项，改不了
 * 已编好的 .o）。唯一能切断的层次是链接期：本文件在目标文件层面提供
 * 同名强符号，链接器就不会再从静态库里拉 cxa_demangle.cpp.o。
 *
 * ## 行为
 *
 * __cxa_demangle 的语义是"分配一块内存放 demangled 名，返回指针"。
 * 这里返回 NULL —— 调用方（demangling_terminate_handler）对 NULL 的处理
 * 是退回原始 mangled 名，不会崩。也就是说崩溃提示从
 *   terminate called after throwing an instance of 'std::bad_alloc'
 * 变成
 *   terminate called after throwing an instance of 'St9bad_alloc'
 * 仅此而已。这个提示只给开发者看，而 libnc.so 里没有 C++ 异常抛出的路径
 * （sig_check / env_check / nc_link 全是 C；dex2c 产物用 EX_LandingPad +
 * 显式 goto 分发，不依赖 .eh_frame）。
 *
 * ⚠️⚠️ 若将来在 libnc.so 里加 try/catch 或 typeid().name()，
 *       必须删掉本文件，并同时移除 Application.mk 里的
 *       -fno-exceptions -fno-rtti —— 否则异常行为会静默不正确。
 */

#include <stddef.h>

/* 本文件是 .c（C 链接），但会被链进 C++ 的 so。
 * libc++abi 里 __cxa_demangle 是 extern "C" 符号（无 name mangling），
 * 所以这里用 C 定义即可对上；下面的 extern "C" 只是防止将来有人把
 * 文件改名成 .cpp 时符号名漂移（那样就顶不掉了，而且是静默的）。 */
#ifdef __cplusplus
extern "C" {
#endif

/* 签名来自 libc++abi 的 cxxabi.h：
 *   char *__cxa_demangle(const char *mangled_name, char *buf, size_t *n,
 *                        int *status);
 * 返回 NULL 表示失败，调用方会退回 mangled 原名继续（不崩）。 */
char *__cxa_demangle(const char *mangled_name, char *buf, size_t *n, int *status)
{
    (void) mangled_name;
    (void) buf;
    (void) n;
    if (status != NULL) {
        *status = -2;   /* -2 = invalid mangled name（libc++abi 的约定） */
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif
