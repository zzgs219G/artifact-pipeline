#!/usr/bin/env python3
"""test_nclink_dynreg.py — NcLink 动态注册的回归测试（纯 stdlib，秒级）。

【为什么补这个测试】
  2026-11-04 把 NcLink 的三个 JNI 入口从「短名绑定」改为「动态注册」，
  目的是让 `nm -D libnc.so` 不再吐出
      Java_com_nc_link_NcLink_ncVerify / _heartbeat / _selftest
  —— 那几个符号名等于给逆向者一张地图。

  改动的风险点全在「表与实际情况不同步」上，而这类错误【能编过、
  能链接、构建全绿】，只有在运行期调 Java 方法时才炸
  （NoSuchMethodError / UnsatisfiedLinkError）。所以必须用测试钉死：

    1. XOR 表还原后必须【逐字等于】NcLink.java 的声明
       （漏改一个字 → RegisterNatives 失败 → 运行期才炸）
    2. 签名必须与 Java 的返回类型/参数一致
    3. 编译期开关的组合逻辑（OWN_ONLOAD / NO_ONLOAD 互斥）
    4. 短名符号必须已从源码里消失（防止有人"顺手"改回去）

【测什么 / 不测什么】
  只测源码级不变量与表的一致性。不测真机 FindClass/RegisterNatives
  （那要 JVM + 真实 so，见 test-javacheck.sh 的 ndk-build 部分）。

用法: python3 scripts/guard/javalink/tests/test_nclink_dynreg.py
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..', '..'))
SRC = os.path.join(ROOT, 'scripts', 'guard', 'src')
JNI_C = os.path.join(SRC, 'nc_link_jni.c')
LINK_C = os.path.join(SRC, 'nc_link.c')
JNI_H = os.path.join(SRC, 'nc_link_jni.h')
JAVA = os.path.join(ROOT, 'scripts', 'guard', 'javalink', 'stub-src',
                    'NcLink.java')

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  ✅ {msg}")


def bad(msg):
    global FAIL
    FAIL += 1
    print(f"  ❌ {msg}", file=sys.stderr)


def check(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        bad(f"{name}{(' — ' + detail) if detail else ''}")


def read(p):
    with open(p, encoding='utf-8') as fp:
        return fp.read()


def parse_xor_tables(src):
    """从 nc_link_jni.c 提取所有 kName_*/kSig_* 数组 → {名: 明文字节}"""
    out = {}
    for m in re.finditer(
            r'static\s+const\s+unsigned\s+char\s+(k(?:Name|Sig)_\w+)\s*\[\s*\]\s*=\s*\{(.*?)\};',
            src, re.S):
        name, body = m.group(1), m.group(2)
        body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)      # 去注释
        vals = [int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})', body)]
        out[name] = bytes(v ^ 0x5A for v in vals)
    return out


def main():
    src = read(JNI_C)
    link = read(LINK_C)
    java = read(JAVA)

    print("[1/6] XOR 表还原后与 NcLink.java 逐字一致")
    tabs = parse_xor_tables(src)
    check(f"解析出 6 张表（实得 {len(tabs)}）", len(tabs) == 6,
          str(sorted(tabs)))

    # Java 侧声明的 (方法名, 签名) 对
    # 注意参数形态是 "byte[] t1"（类型 + 变量名），要先剥变量名再映射。
    java_decl = {}
    jt = {'boolean': 'Z', 'int': 'I', 'void': 'V', 'byte[]': '[B'}
    for m in re.finditer(r'public\s+static\s+native\s+([\w\[\]]+)\s+(\w+)\(([^)]*)\)',
                         java):
        ret, name, args = m.group(1), m.group(2), m.group(3)
        parts = []
        for a in args.split(','):
            a = a.strip()
            if not a:
                continue
            typ = a.rsplit(None, 1)[0] if ' ' in a else a   # "byte[] t1" → "byte[]"
            parts.append(jt.get(typ, ''))
        java_decl[name] = '(' + ''.join(parts) + ')' + jt.get(ret, '?')
    check(f"NcLink.java 声明了 3 个 native 方法（实得 {len(java_decl)}）",
          len(java_decl) == 3, str(java_decl))

    expect_names = {
        'ncVerify': tabs.get('kName_ncVerify'),
        'heartbeat': tabs.get('kName_heartbeat'),
        'selftest': tabs.get('kName_selftest'),
    }
    for name, got in expect_names.items():
        want = name.encode() + b'\x00'
        check(f"kName_{name} 还原 == {name!r}", got == want,
              f"实得 {got!r}，期望 {want!r}")

    print("[2/6] 签名表与 Java 返回类型一致")
    sig_pairs = [
        ('kSig_ncVerify', 'ncVerify'),
        ('kSig_void', 'heartbeat'),
        ('kSig_int', 'selftest'),
    ]
    for tab, meth in sig_pairs:
        got = tabs.get(tab)
        want = java_decl.get(meth, '').encode() + b'\x00'
        check(f"{tab} 还原 == {java_decl.get(meth)!r}（{meth}）", got == want,
              f"实得 {got!r}，期望 {want!r}")

    print("[3/6] 短名符号已从源码消失（防改回去）")
    for sym in ('Java_com_nc_link_NcLink_ncVerify',
                'Java_com_nc_link_NcLink_heartbeat',
                'Java_com_nc_link_NcLink_selftest'):
        # 只查【代码行】，注释里提到历史符号名是允许的
        hits = [ln for ln in link.splitlines() + src.splitlines()
                if sym in ln and not ln.strip().startswith(('*', '/*', '//'))]
        check(f"{sym} 不再出现在代码行中", not hits,
              f"命中 {len(hits)} 行：{hits[:2]}")

    # JNIEXPORT 是 visibility("default") 的来源，NcLink 入口不得带。
    # 注意：注释里提到 "JNIEXPORT" 是允许的（历史说明），只查代码行。
    def code_lines(text):
        return [ln for ln in text.splitlines()
                if not ln.strip().startswith(('*', '/*', '//'))]

    nc_code = '\n'.join(code_lines(link))
    check("ncVerify 实现不带 JNIEXPORT（否则对 -fvisibility=hidden 免疫）",
          not re.search(r'JNIEXPORT[^;\n{]*nc_link_jni_ncVerify', nc_code))
    check("heartbeat 实现不带 JNIEXPORT",
          not re.search(r'JNIEXPORT[^;\n{]*nc_link_jni_heartbeat', nc_code))

    # ── 槽位与表项必须由同一来源派生（2026-11-22 真机实证）──────────
    # 历史 bug：names/sigs 声明 2 个槽，却注册 3 个方法
    # （ncVerify/heartbeat/selftest），selftest 的还原写了 names[0]
    # → 把 ncVerify 的名字【原地覆盖】成 "selftest"：
    #     tab[0] = { name:"selftest", sig:"()I", fnPtr:ncVerify }
    #     tab[2] = { name:"selftest", sig:"()I", fnPtr:selftest }
    # ART 拿到的表里没有 "ncVerify" → 静默跳过 →
    # RegisterNatives 仍返回 0，但方法没绑上 → 调用即
    #   No implementation found for ...NcLink.ncVerify(byte[])
    # → Guard 的 catch(UnsatisfiedLinkError) → kill() → 真机闪退。
    #
    # 第一版修法是把 2 槽改成 3 槽 —— 修了"这一次"，没修"这一类"：
    # 加第四个方法时同样的错会原样再来。现在改成表驱动：
    # 维度全部写成 [NC_BIND_MAX]，而 NC_BIND_MAX 由 sizeof 派生。
    #
    # 所以这里的断言从"数字够不够"改成"是否无硬编码数字"：
    # 只要还有裸数字维度，就说明有人退回了手抄槽位，立刻红。
    # ⚠️ 必须排除注释行：注释里写着历史形态 `char names[2]`，
    #    裸正则会把注释当声明（这个测试自己踩过一次）。
    _code = '\n'.join(ln for ln in src.splitlines()
                      if not re.match(r'\s*(\*|/\*|//)', ln))

    _dim_names = re.search(r'char\s+names\s*\[\s*(\w+)\s*\]\s*\[\s*NC_STR_MAX\s*\]',
                           _code)
    _dim_sigs = re.search(r'char\s+sigs\s*\[\s*(\w+)\s*\]\s*\[\s*NC_STR_MAX\s*\]',
                          _code)
    check("names/sigs 槽位声明存在", bool(_dim_names and _dim_sigs))
    if _dim_names and _dim_sigs:
        check("槽位维度不是裸数字（必须由条目数派生）",
              _dim_names.group(1) == 'NC_BIND_MAX'
              and _dim_sigs.group(1) == 'NC_BIND_MAX',
              f"实得 names[{_dim_names.group(1)}] / sigs[{_dim_sigs.group(1)}]，"
              f"硬编码数字会让'加方法'与'加槽位'重新变成两件要人肉对齐的事")
        check("JNINativeMethod tab 维度同样派生",
              re.search(r'JNINativeMethod\s+tab\s*\[\s*NC_BIND_MAX\s*\]', _code)
              is not None,
              "tab 写裸数字 = 表项数与槽位数可能再次脱节")

    # NC_BIND_MAX 必须由 sizeof 派生，不能手写常量
    _bindmax = re.search(r'#define\s+NC_BIND_MAX\s+(.+)', _code)
    check("NC_BIND_MAX 由 sizeof(kBinds) 派生",
          _bindmax is not None and 'sizeof' in _bindmax.group(1),
          f"实得 {_bindmax.group(1).strip() if _bindmax else '未定义'}")

    # 注册循环必须用同一个下标索引表和槽位 —— 这是"结构上不可能错位"的核心
    check("循环用同一变量索引 kBinds[i] 与 names[i]",
          re.search(r'NC_BIND_MAX;\s*\w+\+\+', _code) is not None
          and re.search(r'nc_restore\(names\[i\]', _code) is not None
          and re.search(r'kBinds\[i\]\.name', _code) is not None,
          "分开索引就重新引入了'槽位与条目错位'的可能")

    # names/sigs 必须是 static：ART 可能在 RegisterNatives 返回后才读
    check("names/sigs 是 static（ART 返回后仍要能读到）",
          re.search(r'static\s+char\s+names\s*\[', _code) is not None
          and re.search(r'static\s+char\s+sigs\s*\[', _code) is not None)

    print("[4/6] 注册调用点与开关组合互斥")
    check("nc_link_jni.c 定义了 nc_link_register_natives",
          'int nc_link_register_natives(JNIEnv *env)' in src)
    check("头文件声明了同一签名",
          'int nc_link_register_natives(JNIEnv *env);' in read(JNI_H))

    # ⚠️ extern "C" 守卫必须存在。
    # 2026-11-05 CI run 42031354532 实测：Dex2C.cpp（C++）里本地声明
    #   extern int nc_link_register_natives(JNIEnv *env);
    # 会按 C++ 规则 mangled，而实现侧导出的是 C 符号 → 链接期报
    #   ld.lld: error: undefined symbol: nc_link_register_natives(_JNIEnv*)
    # 修法是 include 头文件（带 extern "C" 守卫），不是本地重声明。
    jh = read(JNI_H)
    check("nc_link_jni.h 有 extern \"C\" 守卫（C++ 调用方必需）",
          'extern "C"' in jh and '__cplusplus' in jh)
    check("守卫成对（open/close 各一处）",
          jh.count('extern "C"') >= 2, f"实得 {jh.count('extern \"C\"')} 处")

    # 默认开启 OWN_ONLOAD（没勾 dex2c 的常态组合要能自洽）
    check("默认识别 NC_LINK_JNI_NO_ONLOAD 并给出 OWN_ONLOAD",
          'NC_LINK_JNI_NO_ONLOAD' in src and 'NC_LINK_JNI_OWN_ONLOAD 1' in src)

    # 幂等判据必须匹配【注入行的完整形态】，不能只匹配宏名。
    # 2026-11-05 CI run 42030806689 实测：判据写成
    #   grep -q 'NC_LINK_JNI_NO_ONLOAD'
    # 而源码自身第 46 行就有 `#if !defined(NC_LINK_JNI_NO_ONLOAD)` → 恒真
    # → 永远跳过注入 → 两个 JNI_OnLoad 同时存在 →
    #   ld.lld: error: duplicate symbol: JNI_OnLoad
    protect_sh = os.path.join(ROOT, 'scripts', 'pipelines', 'protect.sh')
    if os.path.isfile(protect_sh):
        ps = read(protect_sh)
        check("protect.sh 的幂等判据匹配完整 #define 形态（防恒真）",
              re.search(r"grep\s+-qE\s+'[^']*#define[^']*NC_LINK_JNI_NO_ONLOAD", ps)
              is not None,
              "如果只 grep 宏名，会被源码里的 #if !defined(...) 命中")
        check("protect.sh 不再用裸宏名做幂等判断",
              not re.search(r"grep\s+-q\s+'NC_LINK_JNI_NO_ONLOAD'",
                            '\n'.join(ln for ln in ps.splitlines()
                                      if not ln.lstrip().startswith('#'))))

        # Dex2C.cpp 的注入必须 include 头文件，不能本地声明（C++ 会 mangled）
        code_only = '\n'.join(ln for ln in ps.splitlines()
                              if not ln.lstrip().startswith('#'))
        check("protect.sh 往 Dex2C.cpp 插的是 include 而非 extern 声明",
              'include "nc_link_jni.h"' in code_only)
        check("protect.sh 不再往 Dex2C.cpp 写本地 extern 声明",
              not re.search(r"extern\s+int\s+nc_link_register_natives", code_only),
              "本地声明的函数在 C++ 里会 mangled → undefined symbol")
    # 两个 JNI_OnLoad 必须由宏隔开，不能无条件同时存在
    own_blocks = re.findall(r'#if defined\(NC_LINK_JNI_OWN_ONLOAD\)(.*?)#endif',
                            src, re.S)
    check("JNI_OnLoad 定义被 NC_LINK_JNI_OWN_ONLOAD 条件包住",
          len(own_blocks) == 1 and 'JNI_OnLoad' in own_blocks[0])
    check("整文件中 JNI_OnLoad 定义只出现一次",
          len(re.findall(r'JNIEXPORT\s+jint\s+JNICALL\s+JNI_OnLoad', src)) == 1)

    print("[5/6] selftest 缺失时不影响主链路（报错四十九纪律）")
    check("selftest 用 weak 引用（未编入时不炸链接）",
          'nc_link_jni_selftest' in src and '__attribute__((weak))' in src)
    # 注意：表容量断言已上移到 [3/6] 的槽位段落 —— 那里查的是
    # "维度是否由 NC_BIND_MAX 派生"，比">= 3"强：后者只挡得住
    # 数字写小，挡不住"加方法时忘了加槽位"。

    # 注册前自检必须在场：RegisterNatives 返回 0 不代表绑定成功
    # （2026-11-22 实测就是 rc=0 但 ncVerify 从未绑上）。
    # 实现在独立 TU（nc_jni_selfcheck.c），因为宿主测试要编译【同一份】
    # 实现 —— nc_link_jni.c 在 NCLINK_HOST_TEST 下整段被排除。
    SELF_C = os.path.join(SRC, 'nc_jni_selfcheck.c')
    SELF_H = os.path.join(SRC, 'nc_jni_selfcheck.h')
    check("nc_jni_selfcheck.c 存在（宿主可编译的独立实现）",
          os.path.isfile(SELF_C))
    if os.path.isfile(SELF_C):
        selfc = read(SELF_C)
        selfc_code = '\n'.join(
            ln for ln in selfc.splitlines()
            if not re.match(r'\s*(\*|/\*|//)', ln))
        check("自检会拒绝重名条目", 'nc_eq(' in selfc_code)
        check("自检拒绝空表 / n<=0",
              'n <= 0' in selfc_code and 't == NULL' in selfc_code)
        check("自检拒绝 NULL 字段",
              't[i].name == NULL' in selfc_code
              and 't[i].fnPtr == NULL' in selfc_code)
    check("nc_jni_selfcheck.h 存在且声明了同一签名",
          os.path.isfile(SELF_H)
          and 'int nc_jni_selfcheck(const JNINativeMethod *t, int n);'
              in read(SELF_H))
    check("nc_link_jni.c include 了自检头文件",
          '#include "nc_jni_selfcheck.h"' in _code)
    check("自检在 RegisterNatives 之前调用",
          _code.find('nc_jni_selfcheck(tab, n)') != -1
          and _code.find('nc_jni_selfcheck(tab, n)') < _code.find('RegisterNatives'),
          "自检必须早于注册 —— 注册后才发现表有问题就晚了")
    # protect.sh 必须把新 TU 拷进 NDK 工程，否则链接期 undefined symbol
    if os.path.isfile(protect_sh):
        psh = read(protect_sh)
        check("protect.sh 拷贝 nc_jni_selfcheck.c/.h",
              'nc_jni_selfcheck.c' in psh and 'nc_jni_selfcheck.h' in psh,
              "漏拷 → ld.lld: undefined symbol: nc_jni_selfcheck")

    print("[6/6] selftest 定义必须带 retain（否则被 --gc-sections 回收）")
    # 2026-11-04 实测：改动态注册后 selftest 没有任何直接调用者，
    # 下游只有 weak 引用 → weak 不构成强依赖 → 静态库形态 + --gc-sections
    # 时链接器把整段回收 → 构建全绿但 selftest 永远 ULE（静默失效）。
    # 唯一有效的修法是在定义侧加 used+retain（属性对 extern 声明无效）。
    nox_jni = os.path.join(os.path.dirname(ROOT), 'nox', 'scripts', 'so-guard',
                           'nc_guard_jni.c')
    if not os.path.isfile(nox_jni):
        print(f"  ⚠️ 跳过：找不到上游 {nox_jni}（CI 未 clone ../nox 时正常）")
    else:
        ns = read(nox_jni)
        m = re.search(r'(__attribute__\(\([^)]*\)\)\s*)?\n?jint\s+nc_link_jni_selftest',
                      ns)
        check("nc_link_jni_selftest 定义前有 __attribute__",
              m is not None and m.group(1) is not None,
              "缺属性 → --gc-sections 下会被回收")
        if m and m.group(1):
            check("属性里同时有 used 与 retain",
                  'used' in m.group(1) and 'retain' in m.group(1),
                  m.group(1))
        check("selftest 定义不再带 JNIEXPORT",
              not re.search(r'JNIEXPORT[^;\n{]*nc_link_jni_selftest', ns))

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
