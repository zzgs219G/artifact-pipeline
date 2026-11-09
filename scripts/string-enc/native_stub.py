"""native 桩生成（--stub-impl native）

与 write_stub（Java 桩）并列的一条路：桩类只含 native 声明 + <clinit>，
算法在 libnc.so 的 nc_strdec.c 里。

为什么单独成文件而不是塞进 encrypt-strings.py：
  那个文件已经 2336 行，且被 stringenc 五套测试钉死。新逻辑放这里，
  encrypt-strings.py 只加一个 if 分支调用 —— 把"改动面"降到最小，
  也符合 AGENTS.md §4「模块 = 独立单元」的约定。

⚠️ 与 encrypt-strings.py 的耦合点（改任何一侧都要同步）：
  · STUB_DESC / STUB_PKG_DIR / STUB_FILE / STUB_DECRYPT_METHOD 四个全局
    由 encrypt-strings.py 持有（含每包随机化），本模块只读。
  · NC_STRDEC_KEYLEN / NKEYS 必须与 csrc/nc_strdec.h 一致。
"""

import os

# ── 与 csrc/nc_strdec.h 的契约（改一处必须同步另一处）────────────────
NC_STRDEC_NKEYS = 1
NC_STRDEC_KEYLEN = NC_STRDEC_NKEYS * 8

# 与 JNI 层混淆表对应的明文名（nc_strdec_jni.c 里 XOR 0x5A 存的就是这两个）
NATIVE_DEC_NAME = 'ncDec'

# 生成标记：native 桩与 Java 桩用不同标记，clean/续跑据此区分实现
NATIVE_GEN_MARK = '# nc-strdec-native v1'


class NativeStubError(Exception):
    pass


def render_native_stub(stub_desc, decrypt_method, seed_hex,
                       load_lib='nc'):
    """生成 native 桩的 smali 文本。

    stub_desc        类描述符，如 'La7x/k2m/Q9;'（已随机化）
    decrypt_method   解密方法名（已随机化，与 dex 侧调用点一致）
    seed_hex         密钥 hex（NC_STRDEC_KEYLEN 字节 → 2*KEYLEN 个字符）
    load_lib         要加载的 so 名（'nc'）

    生成的类形态：
        .class public final Lxx/yy/zz;
        .super Ljava/lang/Object;

        .field ... (无 —— native 桩零字段，密钥在 so 的 .bss 里)

        .method static constructor <clinit>()V
            const-string v0, "nc"
            invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
            # 密钥注入：new byte[] → fill-array-data → ncSetKey([B)V
            return-void
        .end method

        .method public static native <random>(Ljava/lang/String;)Ljava/lang/String;
        .end method

    为什么 <clinit> 里 loadLibrary 必须在 setKey 之前：
        setKey 是 native 方法，so 未加载时调用 = UnsatisfiedLinkError。
    为什么 loadLibrary 放在【桩自己的 <clinit>】而不是宿主类：
        JVM 规范保证"类的静态方法被调用前必须先完成该类初始化"，
        所以无论谁、何时调 decryptMethod，so 一定已就绪。
        不依赖宿主类形态（混淆改名也不影响）—— 见 encrypt-strings.py
        的 _inject_loadlib_into_stub_clinit 同款论证。
    """
    key = seed_hex.strip().lower()
    if len(key) != NC_STRDEC_KEYLEN * 2:
        raise NativeStubError(
            '密钥长度应为 %d hex 字符（NC_STRDEC_KEYLEN=%d 字节），实得 %d'
            % (NC_STRDEC_KEYLEN * 2, NC_STRDEC_KEYLEN, len(key)))
    try:
        kbytes = bytes.fromhex(key)
    except ValueError:
        raise NativeStubError('密钥不是合法 hex: %r' % seed_hex)

    # fill-array-data 的 payload：每行最多 16 字节，格式 `0xNNt`
    lines = []
    for i in range(0, len(kbytes), 16):
        chunk = kbytes[i:i + 16]
        lines.append('        ' + ' '.join('0x%02xt' % b for b in chunk))
    payload = '\n'.join(lines)

    return f'''# native 解密桩（纯 C 实现，算法在 libnc.so 的 nc_strdec.c）
# ⚠️ 本文件由 encrypt-strings.py --stub-impl native 生成，不要手改。
{NATIVE_GEN_MARK}
.class public final {stub_desc}
.super Ljava/lang/Object;

# 零字段：密钥在 so 的 .bss 里，dex 侧不留任何密钥材料。

.method static constructor <clinit>()V
    .locals 2

    # ① 先加载 so（setKey 是 native 方法，so 未加载会 ULE）
    const-string v0, "{load_lib}"

    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    # ② 密钥：不在这里注入。
    #
    # ⚠️ 为什么（2026-11-09 真机实测，连崩三轮）：
    #   第一版在本 <clinit> 里直接 invoke-static ncSetKey([B)V ——
    #   ART 对 native 方法的短名解析发生在【类链接阶段】，早于 <clinit>
    #   执行，那时 loadLibrary 还没跑 → 记下"方法不存在" → 必抛
    #     NoSuchMethodError: No static method ncSetKey([B)V
    #   （真机日志：at <clinit>:12）
    #   第二版改用反射推迟解析 —— 可行但 smali 复杂、寄存器易错。
    #
    #   最终方案：密钥【根本不经过 dex】。
    #   构建期把种子写进 nc_strdec_cfg.h（protect.sh 生成），
    #   C 侧的 nc_strdec_bootstrap() 编译进 so 并直接 set_key。
    #   dex 侧只剩 loadLibrary 一句 —— 没有 native 方法可解析，时序问题消失。
    #   收益：密钥不出现在 dex 任何位置（本来就是这个需求的核心）。
    return-void

.end method

# 解密入口：纯 native，dex 侧零算法
.method public static native {decrypt_method}(Ljava/lang/String;)Ljava/lang/String;
.end method
'''


def write_native_stub(decompiled_dir, stub_desc, stub_pkg_dir, stub_file,
                      decrypt_method, seed_hex, smali_root):
    """把 native 桩写进解包目录，返回桩文件路径。

    幂等性由调用方（encrypt-strings.py）的「整类已加密」标记保证 ——
    这里不重复实现。
    """
    stub_dir = os.path.join(smali_root, *stub_pkg_dir)
    os.makedirs(stub_dir, exist_ok=True)
    stub_path = os.path.join(stub_dir, stub_file)

    text = render_native_stub(stub_desc, decrypt_method, seed_hex)

    # 生成期自检（fail-fast，不让半成品进产物）：
    # ① 必须含 native 声明且【没有方法体】—— 有体会被 ART 判为
    #    "A native method cannot have any instructions"（报错三十九同型）
    # ② <clinit> 必须 loadLibrary（so 未加载则所有 native 方法不可用）
    # ③ 密钥【不得】出现在 dex 里（编译进 so 的 nc_strdec_cfg.h）
    bad = []
    if f'.method public static native {decrypt_method}(' not in text:
        bad.append('缺少 native 方法声明')
    if text.count('.end method') != 2:
        bad.append('.end method 数量应为 2（<clinit> + native 声明）')
    if text.count('.method') != 2:
        bad.append('.method 数量应为 2')
    if 'loadLibrary' not in text:
        bad.append('缺少 loadLibrary（so 未加载 → native 方法全部不可用）')
    # 密钥不该出现在桩里（2026-11-09 改设计后）：它编译进 so 的
    # nc_strdec_cfg.h，dex 侧零密钥材料。这条断言保证"改回老做法"会立刻红。
    if '.array-data 1' in text:
        bad.append('桩里出现 array-data（密钥又回到 dex 了 —— 本需求明确禁止）')
    _flat = text.replace('\n', '').replace(' ', '').replace('\t', '').lower()
    if seed_hex.lower() in _flat:
        bad.append('密钥以明文 hex 形态残留在桩文本里')
    # native 方法体内不允许出现指令：检查声明行与 .end method 之间
    head = text.split(f'.method public static native {decrypt_method}(')
    if len(head) == 2:
        body = head[1].split('.end method')[0]
        for ln in body.split('\n'):
            s = ln.strip()
            if s and not s.startswith(')') and not s.startswith('#'):
                # 该行是 "…)Ljava/lang/String;" 的收尾，允许
                if s.startswith('Ljava/lang/String;'):
                    continue
                bad.append('native 方法声明后有残余内容: %r' % s[:40])
                break
    if bad:
        raise NativeStubError('native 桩自检失败：' + '；'.join(bad))

    with open(stub_path, 'w', encoding='utf-8') as fp:
        fp.write(text)
    return stub_path
