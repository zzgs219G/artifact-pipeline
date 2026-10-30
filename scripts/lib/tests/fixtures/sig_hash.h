/* 由流水线自动生成: 简盒_signed_11_54_11_sign.apk 证书指纹的双轮派生形态 */
/* 攻防说明: 明文指纹不落盘。攻击面分析见 docs/流程文档.md §9(2026-10 存储混淆) */
/* 2026-10-19: 生产构建下两张表进 .ncxr 加密段(NC_GUARD_SECTIONED)。 */
#ifndef _SIG_HASH_H_
#define _SIG_HASH_H_

/* 段属性宏：只有明确开启 NC_GUARD_SECTIONED 且非宿主测试时才生效。
 * 未开启时退化为空宏 —— 宿主编译/单元测试行为完全不变。 */
#if defined(NC_GUARD_SECTIONED) && !defined(NCLINK_HOST_TEST)
/* 数据段必须是【不可执行】的独立段：clang 不允许 const 数据进 AXR 段，
 * 会报 "causes a section type conflict"。见 nc_link.c 的注释。 */
#  define SIG_HASH_SECTION __attribute__((section(".ncxr"), retain, used))
#else
#  define SIG_HASH_SECTION
#endif

#define SIG_HASH_LEN 32
#define SIG_SALT_LEN 16
SIG_HASH_SECTION
static const unsigned char SIG_SALT[SIG_SALT_LEN] = {
    0xec, 0x50, 0x34, 0xe8, 0x20, 0xb5, 0x70, 0xef,
    0x66, 0xcc, 0xe2, 0x68, 0xc4, 0x38, 0xa1, 0xb6,
};
SIG_HASH_SECTION
static const unsigned char SIG_HASH_STORED[SIG_HASH_LEN] = {
    0x4e, 0x07, 0xb2, 0x7c, 0x0f, 0xf4, 0xa3, 0x9d,
    0x45, 0x38, 0xce, 0xef, 0xf9, 0x34, 0x83, 0x40,
    0xf0, 0x7e, 0x66, 0xca, 0x51, 0x45, 0xce, 0xb9,
    0xaa, 0x8b, 0x4c, 0xe3, 0x0e, 0x37, 0xf4, 0x61,
};
#endif
