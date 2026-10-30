/* nc_guard_layout.h — so 段加密设施的【唯一契约真相源】
 *
 * 本文件不含任何逻辑，只有契约常数。存在目的：把"改一处必须同步另一处"
 * 从注释变成编译期/构建期强制。
 *
 * 背景：契约常数此前散落 4 种语言、7 个文件、24 处副本。slot 已扩过两次
 * （80→96、88→104），漏同步的症状是【运行期 SIGILL】——Java 侧只看到
 * selftest != 59，完全指不出"某个长度常量没同步"。历史报错三/九/十一/十二
 * 全是同类根因。
 *
 * ⚠️ 纪律：改本文件任何常量，必须跑 bash scripts/lib/tests/test-so-lock.sh
 *   T20 与 so-section-lock.py 逐字节对拍；T21 扫描全仓段名字面量；
 *   T22 验证不改变产物字节。任一红 = 构建期 fail-fast 而非运行期 SIGILL。
 *
 * ⚠️ 本文件会被拷进 NDK 工程，故不得 include 仓库内其它头文件
 *    （零依赖，任何工具链都能编）。
 */
#ifndef _NC_GUARD_LAYOUT_H_
#define _NC_GUARD_LAYOUT_H_

/* ═══ 一、段名（6 个）═══════════════════════════════════════════════
 * 2026-10-19 中性化改名（旧名自解释，readelf -S 即可列举加固结构）：
 *   .ncguard     → .ncx     .ncguard_ro      → .ncxr
 *   .ncguard_head→ .ncxh    .ncguard_head_ro → .ncxhr
 *   .nckey       → .nck     .nckey_stub      → .ncks
 *
 * ⚠️ 段名是 so 的指纹特征。改名会让所有历史产物的锁箱/开箱契约失效，
 *    故 2026-10-19 之后不再变动。要加新段，先在 T21 登记。
 *
 * 消费方（改名前同步检查）：
 *   C:  nc_guard_boot.c / nc_link.c / env_check.c / sig_check.c / nc_guard_probe.c
 *   Py: so-section-lock.py / so_section_mark.py
 *   Sh: make-sig-hash.sh / protect.sh
 */
#define NC_SEC_CODE      ".ncx"    /* 加密代码段（AXR，可执行）*/
#define NC_SEC_CONST     ".ncxr"   /* 加密常量表段（AWR，不可执行）*/
#define NC_SEC_HEAD      ".ncxh"   /* unlock 本体（二级锁箱对象）*/
#define NC_SEC_HEADRO    ".ncxhr"  /* master 数据段（AWR，32B）*/
#define NC_SEC_SLOT      ".nck"    /* 一级密钥槽*/
#define NC_SEC_STUBSLOT  ".ncks"   /* 二级 stub 密钥槽*/

/* ═══════════════════════════════════════════════════════════════════
 * 二、.nck 一级密钥槽：96 字节
 * ═══════════════════════════════════════════════════════════════════
 * 布局（偏移为相对 slot 起始的字节数）：
 *   [ 0:16) magic        seed + 8 个 0
 *   [16:32) decoy        诱饵（P1-a 起非真密钥，真 k_so 由运行期证书派生）
 *   [32:48) decoy_mac    诱饵（同上）
 *   [48:80) expect_mac   HMAC-SHA256(k_mac, 密文) 32B
 *   [80:88) pkg_sha8     SHA256(包名) 前 8 字节
 *   [88:96) reserved     对齐预留
 *
 * 锁箱侧：so-section-lock.py lock() 的 blob 组装
 * 开箱侧：nc_guard_boot.c ncg_head_unlock()
 * C 侧段本体：nc_guard_probe.c 的 ncg_key_slot[NC_SLOT_SIZE]
 */
#define NC_SLOT_SIZE      96
#define NC_OFF_EXPMAC     48   /* [48:80) expect_mac 起点*/
#define NC_OFF_PKG_SHA    80   /* [80:88) 包名指纹起点*/

/* ═══════════════════════════════════════════════════════════════════
 * 三、.ncks 二级 stub 密钥槽：104 字节
 * ═══════════════════════════════════════════════════════════════════
 * 布局：
 *   [ 0: 8) magic seed
 *   [ 8:24) wrapped k_stub      = k_stub ^ XOR_KEY
 *   [24:28) stub_sh_addr        .ncks 段自身链接期虚拟地址
 *   [28:32) head_sh_addr        .ncxh 链接期虚拟地址
 *   [32:36) head_size           .ncxh 字节数
 *   [36:40) code_addr           .text 段起始（自绑定 CRC 区间起点）
 *   [40:44) code_len            .text 段长度
 *   [44:48) reserved
 *   [48:64) wrapped k_mac_head  = k_mac_head ^ XOR_KEY
 *   [64:96) expect_mac_head     HMAC-SHA256(k_mac_head, head 密文)
 *   [96:100) head_ro_addr       .ncxhr 段链接期虚拟地址
 *   [100:104) head_ro_size      该段字节数
 *   [104:112) frag[4]           XOR_KEY 碎片（构建期随机，见 NC_OFF_FRAGS）
 *
 * 锁箱侧：so-section-lock.py lock_head() 的 blob 组装 + 两条 assert
 * 开箱侧：nc_guard_boot.c 明文 stub（ncg_stub_recover / ncguard_unlock）
 * C 侧段本体：nc_guard_boot.c 的 ncg_stub_slot[NC_STUB_SIZE]
 */
#define NC_STUB_SIZE        112   /* [104:112) 为碎片区，见 NC_OFF_FRAGS */
/* 碎片区：XOR_KEY 的 4 个 uint16，构建期随机生成后写进 slot。
 * 为什么放这里而不放 .data：破解复盘实测"objdump 读 .data + 反汇编
 * 5 分钟重组出 XOR_KEY"。挪进 slot 后攻击者必须先读懂 slot 布局
 * （壳的核心格式）才有重组输入——把"读常量"变成"读格式"。
 * 详细演进与反向纪律见 nc_guard_boot.c 的 XOR_KEY 碎片化注释。 */
#define NC_OFF_FRAGS        104   /* [104:112) 4×uint16 碎片（随机）*/
#define NC_OFF_CODE_ADDR    36   /* 代码自绑定 CRC 区间起始*/
#define NC_OFF_CODE_LEN     40   /* 区间长度（字节）*/
#define NC_OFF_K_MAC_HEAD   48   /* wrapped k_mac_head 起点*/
#define NC_OFF_EXPMAC_HEAD  64   /* expect_mac_head 起点*/
#define NC_OFF_HEADRO_ADDR  96   /* .ncxhr 段链接期虚拟地址*/
#define NC_OFF_HEADRO_SIZE 100   /* .ncxhr 段字节数*/

/* ═══════════════════════════════════════════════════════════════════
 * 三点五、T4：槽段加密（2026-10-28）
 * ═══════════════════════════════════════════════════════════════════
 * 动机（逆向报告实测）：.ncks / .nck 是【明文段】，攻击者 readelf 拿到
 * 偏移后 dd 读 8 字节即可拼出 XOR_KEY → 整条解密链 1 分钟内走完。
 * 这是"28 分钟摸清 90% 结构"的真因，不是段名或标准常数。
 *
 * 设计：boot_key 由 .text 内容派生，用它 RC4 加密两个槽段。
 *
 * 循环依赖的解法（关键）：
 *   boot_key 需要 .text 的 CRC，但 .text 的地址存在 .ncks 里，而 .ncks
 *   又要 boot_key 才能解 → 环。
 *   解法：stub 用 &ncg_stub_recover 作锚点（PC 相对，编译期生成 adr），
 *   （历史：曾设计成锚点±区间，后因 Python 侧无法复现 strip 后的符号
 *    地址而废弃，改用段表起点。详见 nc_guard_boot.c 的 ncg_boot_key。）
 *
 * 加密范围（解不开 magic 就无法判"未锁"，故 magic 区必须豁免）：
 *   .ncks[0:8)    不加密   —— magic seed，解密前必需
 *   .ncks[8:112)  加密     —— 全部密钥材料
 *   .nck[0:96)    加密     —— .nck 的 magic 判定发生在其后，可先解再判
 *
 * ⚠️ 攻击者仍可反汇编 stub 复现 boot_key 派生（算法在明文 .text 里）。
 *    本改动提高的是"发现与理解"成本，不是数学上的不可绕过。
 *    如实记录，避免后人高估。
 * ⚠️ 区间必须无重定位（文件内容 == 内存内容），否则正常包也解不开。
 *    test-so-lock.sh 新增 T31 断言这一点。 */
/* CRC 区间长度上限。
 * ⚠️ 2026-10-28 CI 实测踩过的坑：原写法是 BACK=0x1000 + FWD=0x3000 两个
 *    常量相加 = 16384 字节，但 armeabi-v7a 的 .text 只有 12000 字节 →
 *    锁箱直接 fail-fast（"boot_key CRC 区间 16384 > .text 段 12000"）。
 *    arm64 的 .text 更大所以本地没暴露 —— 典型的"只验证了一个 ABI"。
 * 改法：只留一个上限，锁箱期与运行期都取 min(上限, .text 实际长度)，
 *    两个 ABI 自动适配，未来 .text 变小时也不会再炸。 */
#define NC_BOOT_SPAN        0x4000   /* CRC 区间长度上限（16KB） */
#define NC_BOOT_SPAN_MIN    0x0800   /* 下限：太短则 boot_key 强度不足 */
#define NC_BOOT_SALT_INIT \
    { 0x6e, 0x63, 0x1f, 0x2b, 0x7a, 0x44, 0x91, 0xd8, \
      0x03, 0x5c, 0xe6, 0x18, 0xaf, 0x72, 0x39, 0xc4 }  /* "nc" + 16B 区分值 */
#define NC_BOOT_INFO        "nc-boot-v1"
#define NC_OFF_FRAGS_ENC    8   /* .ncks 加密区间起点（magic 之后）*/

/* ═══════════════════════════════════════════════════════════════════
 * 四、magic 种子（8 字节）
 * ═══════════════════════════════════════════════════════════════════
 * 语义：slot 前 8 字节 == 本 seed ⇒ 已锁箱；不匹配 ⇒ 未锁，放行。
 * 锁箱器落盘的就是 seed 本身（不是 seed ^ XOR_KEY），运行期直接逐字节比。
 *
 * ⚠️ 真实收益仅一条：strings 搜不到 "NCKEYLOCK"/"NCSTUBLK" 字面量。
 *    碎片密钥【不参与】magic 比较（见 ncg_magic_ok：只做 got[i]^seed[i]
 *    累或）——它只在 ncg_xor_key() 里用于恢复 k_stub / k_mac_head。
 *    攻击者 dump 到 slot 前 8 字节即可直接比对，零额外成本。
 *    写清楚这条是防止后人据此高估防御强度、少做别的加固。
 */
#define NC_SEED_SLOT_INIT \
    { 0x30, 0x72, 0xEE, 0x48, 0x91, 0xDE, 0x04, 0xB5 }
#define NC_SEED_STUB_INIT \
    { 0x30, 0x72, 0xF6, 0x59, 0x9D, 0xD0, 0x07, 0xBD }

/* ═══════════════════════════════════════════════════════════════════
 * 五、XOR_KEY 碎片表
 * ═══════════════════════════════════════════════════════════════════
 * 完整 8 字节 XOR_KEY 由 4 个 volatile uint16 在运行期拼回
 * （见 nc_guard_boot.c 的 ncg_xor_key()）。
 * 本表是"逻辑字节 i 取哪个碎片"的映射；i<4 取低位、i>=4 取高位。
 *
 * ⚠️ 与 so-section-lock.py 的 XOR_KEY 必须逐字节一致（T20 对拍）。
 *    碎片常量本体（ncg_frag_a/b/c/d）刻意【不】进本文件——它们是运行期
 *    才知道的值，集中放一个表就等于把它们重新聚成一串可被一次性读走的
 *    常量。分散在 volatile 变量里正是为了阻止编译期折叠与集中读取。
 */
#define NC_XOR_FRAG_INIT \
    { 1, 0, 2, 3, 0, 1, 3, 2 }

/* ═══════════════════════════════════════════════════════════════════
 * 六、编译期自检
 * ═══════════════════════════════════════════════════════════════════
 * 这几条 _Static_assert 挡的是"偏移重叠/越界"类手误——那是上一轮
 * 88→104 扩容时最危险的错误模式（新字段与既有 MAC 字段重叠会
 * 【静默】破坏校验，编译期完全不报）。 */
_Static_assert(NC_OFF_EXPMAC + 32 <= NC_SLOT_SIZE,
               "NC_OFF_EXPMAC+32 溢出 .nck slot");
_Static_assert(NC_OFF_PKG_SHA + 8 <= NC_SLOT_SIZE,
               "NC_OFF_PKG_SHA+8 溢出 .nck slot");
_Static_assert(NC_OFF_HEADRO_SIZE + 4 <= NC_STUB_SIZE,
               "NC_OFF_HEADRO_SIZE+4 溢出 .ncks slot");
_Static_assert(NC_OFF_EXPMAC_HEAD + 32 <= NC_OFF_HEADRO_ADDR,
               "expect_mac_head 与 head_ro 字段重叠");
_Static_assert(NC_OFF_K_MAC_HEAD + 16 <= NC_OFF_EXPMAC_HEAD,
               "k_mac_head 与 expect_mac_head 重叠");
_Static_assert(NC_OFF_FRAGS + 8 <= NC_STUB_SIZE,
               "碎片区溢出 .ncks slot");
/* T4：加密区间自洽性（magic 之后到段尾，必须非空且不越界） */
_Static_assert(NC_OFF_FRAGS_ENC == 8, "T4 加密区间起点必须紧跟 magic(8B)");
_Static_assert(NC_OFF_FRAGS_ENC < NC_STUB_SIZE, "T4 加密区间为负长度");
_Static_assert(NC_BOOT_SPAN >= NC_BOOT_SPAN_MIN,
               "T4 CRC 区间上限小于下限，配置矛盾");
_Static_assert(NC_BOOT_SPAN_MIN >= 0x400,
               "T4 CRC 区间下限过小，boot_key 强度不足");

#endif /* _NC_GUARD_LAYOUT_H_ */
