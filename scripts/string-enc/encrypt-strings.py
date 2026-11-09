#!/usr/bin/env python3
"""encrypt-strings.py — dex 层字符串常量加密(构建期异或 + 运行期 Java 解密桩)

把「用户选中类」的 const-string 字面量构建期加密,运行期由注入的纯 Java 解密桩
(Lcom/nc/strdec/StrDec;)解密。定位是防静态可见性,不是密码学安全。
模块的完整契约(密文形态/密钥流/SEED 双锚点注入/硬排除清单/L1 缓存/历史教训)
见同目录 README.md,改本文件前必读。
"""

import argparse
import base64
import importlib.util
import json
import os
import re
import secrets
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))          # scripts/string-enc → 仓库根

def _load_module(name: str, rel_path: str):
    """文件名带连字符,不能常规 import → 与 mark-native.py 同款 importlib 加载。
    (报错三教训:基于 __file__ 的路径在脚本移动后必须重算,这里从本文件位置推算)"""
    path = os.path.join(_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# 规则解析复用 dcc 侧同一脚本(用户要求"语法与 dex2c_rules 完全一致")
_RULES = _load_module('rules_to_filter', 'scripts/filter/rules-to-filter.py')
# smali 目录名约定复用 inject-loadlib 的单一真相(报错七:别处不要另写一份正则)
_INJECT = _load_module('inject_loadlib', 'scripts/inject/inject-loadlib.py')
SMALI_DIR_RE = _INJECT.SMALI_DIR_RE
# dex 容量判定(报错五十九):桩落点不能固定 smali/,大型包 classes.dex 会贴顶
_DEX_CAPACITY = _load_module('dex_capacity', 'scripts/repack/dex-capacity.py')

# 解密桩占用的方法数上界（用于 dex 容量判定）。
# 桩骨架实测 5 个方法定义 + 少量外部引用（String/Base64 等），给 30 的上界；
# dex-capacity 侧另有 2000 工程余量，这里不需要精确。
_STUB_METHOD_BUDGET = 30

# 原始 APK 路径（--apk）。给了就让容量判定读 dex header 得精确方法数；
# 由 main() 在解析参数后赋值，_pick_smali_root() 读取。
_APK_FOR_CAPACITY = None

# ── 解密桩约定 ──────────────────────────────────────────────────────
# 【桩随机化】以下 STUB_DESC/STUB_PKG_DIR/STUB_FILE/STUB_DECRYPT_METHOD 是
# 「legacy 默认值」;生产运行(未传 --stub-name)时 main() 会生成每包随机的
# 包名/类名/方法名并覆盖这四个变量,使杀毒引擎无法用固定签名
# (Lcom/nc/strdec/StrDec;->d)命中。所有下游引用必须走变量而非字面量。
# 随机名续跑复用:从组件标记(stringenc-components.json)的 desc/src 读回,
# 与种子复用同机制;字段名(SEED/CACHE 等)与私有方法名(mix64/keyByte)不随机
# —— SEED 是双锚点契约的一部分,keyByte/mix64 是 P3 对拍的反射锚点。
STUB_DESC = 'Lcom/nc/strdec/StrDec;'
STUB_PKG_DIR = ('com', 'nc', 'strdec')
STUB_FILE = 'StrDec.smali'
STUB_GEN_MARK = '# nc-strdec-gen v2'          # 桩文件内的生成标记(识别"这是我们写的")
# 解密主方法名 —— 「只盯最危险一步」的警报器只管这个方法(见 _check_stub_registers)
STUB_DECRYPT_METHOD = 'd'
# 桩实现选择（--stub-impl）：'java'（默认）| 'native'
# 默认 java = 与改动前逐字节一致，零漂移。
# native 走 csrc/nc_strdec.c（纯 C 算法编进 libnc.so），dex 侧只有声明。
STUB_IMPL = 'java'
# 解密内核方法名(2026-10 两层拆分):算法本体在 dn(),d() 只剩 try/catch 壳。
# 桩随机化只改 d 不改 dn —— dn 是 dex2c 联动要转译的目标(见 protect.sh
# --dex2c 分支),且它是真正调用系统 Base64 解码工具的方法(报错二十二锚点)。
STUB_KERNEL_METHOD = 'dn'
STUB_SRC = 'stub-src/StrDec.java'             # 解密桩唯一源码真相(本脚本相对路径)
STUB_D8_JAR = 'tools/d8.jar'                  # 固定版本 D8(报错六教训:工具版本漂移即翻车)
CLASS_MARK = '# nc-strdec-encrypted'          # 已加密类的标记注释(幂等判定)
COMPONENTS_FILE = 'stringenc-components.json'  # 组件标记(报错十八式:元数据 save/restore)

# ── 硬排除:系统类与框架依赖(规则层不可突破) ─────────────────────────
SYSTEM_CLASS_PREFIXES = (
    'android.', 'androidx.', 'android.support.', 'com.android.',
    'com.google.android.', 'dalvik.', 'java.', 'javax.',
    'kotlin.', 'kotlinx.', 'org.jetbrains.',
    'org.apache.', 'org.json.', 'org.w3c.', 'org.xml.', 'sun.',
    # xCrash(爱奇艺 native 崩溃/ANR 捕获库):其 Java 层与 native 层通过 JNI 回调
    # 互相绑定(xcrash.NativeCrashHandler 的 native 方法 + callback),字符串或
    # 类/方法名一旦被加密/改写 → 崩溃捕获失效甚至自身崩溃。属"框架依赖",必须在
    # 规则层之上硬排除(与 kotlin./androidx. 同型)。前缀 'xcrash.' 覆盖其主包。
    'xcrash.',
    # ── 常用第三方依赖包(2026-09-12 用户点名追加)──────────────────────────
    # 以下来自 jian_box(app/build.gradle.kts)实际依赖，多为反射 / 注解序列化 /
    # 网络协议 / 跨进程绑定库 —— 这些库里 const-string 承载了类名 / 字段名 /
    # 协议/序列化标记(反射与注解处理必需)，一旦被加密，运行期 `Class.forName` /
    # `getAnnotation` / 序列化/反序列化匹配、甚至 OkHttp 内部协议都会失效。
    # 加固的本意只保护自家产品代码(com.xixin.box.*)，第三方依赖字符串本就不是
    # 重要资产，且加密它们风险远大于收益 → 一律硬排除。
    'okhttp3.',            # OkHttp：HTTP 客户端(内部拦截器/协议/注解 @Url 等)
    'okio.',               # okio：OkHttp 底层 IO(ByteString/Buffer 序列化格式)
    'com.google.gson.',    # Gson：反射 + @SerializedName 注解序列化
    'org.jsoup.',          # jsoup：HTML 解析(选择器/反射)
    'org.commonmark.',     # commonmark：Markdown 解析(行解析器反射注册)
    'io.ktor.',            # Ktor：HTTP 客户端网络栈
    'coil3.',              # Coil 3：Compose 图片加载(ImageView 工厂反射)
    'moe.shizuku.',        # Shizuku：高权限跨进程服务绑定(JNI + binder)
)

IDX_MAX = (1 << 24) - 1                      # idx/offset 占 3 字节(共享表上限同源)

# ── 无价值串跳过:编译器生成的调试/内联标记(对比实验定性,2026-09) ────
# 背景:用户全量规则加密 3438 类后 app"进不去且无日志",而第三方字符串加密
# 工具同规则正常。解剖两产物发现关键差异:第三方工具内置"跳过名单",保留
# Kotlin/Compose/R8 desugar 编译器自动生成的调试标记串明文(仅 classes15 一个
# dex 就保留 1637 条 $i$f$ + 450 条 $this$ + 87 条 $changed);本工具此前
# 一个不漏全加密。这些串对 app 运行毫无作用(纯编译器/调试器记号),却让
# 解密桩为它们白付一份 keystream 成本与体积。跳过它们:体积更小、启动解密
# 更少,且不存在任何行为风险(没有人会依赖调试标记做业务判断)。
# 命中规则(逐明文串前缀判断,非类名):
#   $i$f$    — Kotlin inline 函数标记($i$f$functionName)
#   $i$a$    — Kotlin inline 匿名对象标记
#   $this$   — Kotlin 扩展/接收者标记($this$forEach 等)
#   $changed — Compose Composable 形参记号($changed / $changed\N 转义形态)
#   $stable  — Compose 稳定性记号
#   $-       — R8/D8 desugaring 合成 lambda 标记($-feat-$-lambda-... 形态)
_SKIP_STRING_PREFIXES = (
    '$i$f$', '$i$a$', '$this$', '$changed', '$stable', '$-',
)

def is_instrumentation_string(plain: str) -> bool:
    """编译器调试/内联标记串判定:命中即跳过加密(保留明文,不占 idx)。"""
    return plain.startswith(_SKIP_STRING_PREFIXES)

# ── 解密桩骨架(纯 Java 编译产物,零表零占位符) ────────────────────────
#
# SEED 双锚点注入契约(与 build-stub.sh 共同维护,勿单方面改;全文见 README.md):
#   哨兵 0x5EED… 编译 → d8 保留 .field 初值并内联到使用点 → 本脚本对两类锚点
#   做一致性改写(数量守恒,错一个 = 全包乱码)。锚点正则如下。
SENTINEL_SEED = '0x5eed000000000000L'

_FIELD_SEED_RE = re.compile(
    r'^(?P<indent>[ \t]*)\.field[ \t]+(?P<mid>[^\n]*?\bSEED:J[ \t]*)'
    r'(?:=[ \t]*(?P<val>\S+))?[ \t]*$', re.M)
# 内联常量:d8 视数值大小选 const-wide / const-wide/high16 / const-wide/16 变体
_INLINE_SEED_RE = re.compile(
    r'^(?P<indent>[ \t]*)const-wide(?P<variant>/\w+)?[ \t]+'
    r'(?P<reg>[vp]\d+)[ \t]*,[ \t]*(?P<val>0x[0-9a-fA-F]+L?)[ \t]*(?P<tail>#[^\n]*)?$',
    re.M)

def load_stub_skeleton() -> str:
    """加载 build-stub.sh 产出的桩骨架(无占位符,可直接汇编)。

    骨架来源:build-stub.sh 对 stub-src/StrDec.java 跑 javac → d8 → baksmali
    的产物(仓库内缓存为 stub-src/StrDec.smali)。smali 是中间产物、永不手写;
    改算法只改 StrDec.java,然后重跑 build-stub.sh 刷新缓存。

    本函数只做"骨架完整性"自检:SEED 字段锚点与内联锚点必须都存在且都等于
    哨兵种子(否则说明 build-stub.sh 的哨兵策略被改动,注入契约已失效)。
    """
    tpl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'stub-src', 'StrDec.smali')
    try:
        with open(tpl_path, encoding='utf-8') as fp:
            tpl = fp.read()
    except OSError as exc:
        raise SystemExit(
            f'❌ 桩骨架缺失: {tpl_path}({exc})\n'
            f'   先运行 scripts/string-enc/build-stub.sh 生成(它把 '
            f'{STUB_SRC} 编译为 smali)。')
    find_stub_seed_anchors(tpl)      # 锚点自检(失败即抛 SystemExit)
    # 防线(报错二十二):骨架必须过参数寄存器自检。锚定骨架真名 'dn' ——
    # 骨架恒为 build-stub.sh 的 legacy 编译产物,方法名随机化只发生在
    # write_stub 的文本替换(寄存器布局不变);若按全局随机名找方法,
    # 守卫找不到目标方法 → 整条防线静默失效(报错四十八)。
    # 注(2026-10 两层拆分):警报器必须盯 dn() 而非 d() —— d() 已退化为
    # 只做 try/catch 兜底的壳,真正调用系统 Base64 解码工具的是 dn();
    # 沿用旧锚点会误报壳的 move-result-object(见 tests 失败现象),
    # 且放过内核的真实风险。
    _check_stub_registers(tpl, STUB_KERNEL_METHOD)
    # 防线(报错二十五):类体顶层(非 .method 区)不许出现裸指令。
    # 骨架是编译产物,理论上不会违规;这条兜底拦住任何"把指令写进类体顶层"
    # 的回归(该形态 smali 汇编器报 no viable alternative)。
    in_method = False
    for line in tpl.split('\n'):
        s = line.strip()
        if s.startswith('.method'):
            in_method = True
        elif s == '.end method':
            in_method = False
        elif (in_method is False and s and not s.startswith(('.', '#'))
              and not s.startswith(':')):
            raise SystemExit(
                f'❌ 桩骨架自检失败:类体顶层出现裸指令 ——\n   {line}\n'
                f'   指令只允许出现在 .method .. .end method 之间(报错二十五)。')
    return tpl

def find_stub_seed_anchors(content: str, expect_sentinel: bool = True):
    """按结构定位骨架里的 SEED 锚点。
    返回 (字段行 match, 内联常量 match 列表)。缺失即 fail-fast。

    expect_sentinel=True:要求两处锚点的值都等于哨兵种子(校验"骨架是可信产物")。
    expect_sentinel=False:只要求结构存在(用于注入后的终检,那时值已是真种子)。"""
    fm = _FIELD_SEED_RE.search(content)
    if not fm:
        raise SystemExit(
            '❌ 桩骨架缺少 `.field ... SEED:J = <初值>` 锚点。\n'
            '   d8 在种子为 0 时会把它优化掉 → 无法注入种子。\n'
            '   请重跑 build-stub.sh(它用非 0 哨兵种子编译)。')
    if fm.group('val') is None:
        raise SystemExit(
            '❌ 桩骨架的 SEED 字段没有初值(.field ... SEED:J 无 "= ...")。\n'
            '   同上报错原因:哨兵种子必须非 0,否则 d8 不保留初值。')
    if expect_sentinel and fm.group('val').rstrip('Ll').lower() \
            != SENTINEL_SEED.rstrip('Ll').lower():
        raise SystemExit(
            f'❌ 桩骨架的 SEED 字段初值({fm.group("val")})与哨兵种子'
            f'({SENTINEL_SEED})不一致 —— 骨架不是 build-stub.sh 的可信产物。')
    # 内联锚点:骨架阶段必须存在且等于哨兵;注入后终检只数结构
    inlines = [m for m in _INLINE_SEED_RE.finditer(content)
               if not expect_sentinel
               or m.group('val').rstrip('Ll').lower() == SENTINEL_SEED.rstrip('Ll').lower()]
    if expect_sentinel and not inlines:
        raise SystemExit(
            f'❌ 桩骨架里找不到内联的哨兵种子常量(期望 {SENTINEL_SEED})。\n'
            f'   d8 的常量内联行为可能变了,或骨架与 build-stub.sh 不同步。\n'
            f'   重跑 build-stub.sh;若仍失败,需重审本文件的注入契约。')
    return fm, inlines

def inject_stub_seed(skeleton: str, seed_word: str) -> str:
    """把骨架里的哨兵种子【双锚点同时】改写为真种子。

    seed_word: smali 长整型字面量(如 '0x1a2b3c4d5e6f7a8bL')。
    改写后再次自检:两处锚点都等于真种子、内联锚点数量守恒、骨架行数守恒 ——
    任一不满足即 fail-fast,绝不让"半注入/被截断"的桩进产物(那是静默乱码、
    或下游 apktool 汇编失败,都不在当场暴露,更难查;见报错二十七)。
    """
    fm, inlines = find_stub_seed_anchors(skeleton)
    n_inline = len(inlines)
    n_lines = len(skeleton.split('\n'))
    sentinel = SENTINEL_SEED.rstrip('Ll').lower()
    seed_int = int(seed_word.rstrip('Ll'), 16)

    # 锚点 1:字段初值行(保留缩进,只换值)
    skeleton = skeleton[:fm.start('val')] + seed_word + skeleton[fm.end('val'):]

    # 锚点 2:全部内联常量。d8 可能内联到多处,按其实际出现次数全改。
    # 倒序替换,避免前面的替换使后面的 offset 失效。
    #
    # 【必须整行重建,不能只换字面量 —— 两个坑都在这里(报错二十七)】
    # 坑 A(指令变体):d8 为哨兵种子 0x5eed000000000000 选的变体是
    #   `const-wide/high16`,该形态只接受"低 48 位全为 0"的字面量;真种子是任意
    #   64 位随机数,只换数字会让这条指令非法(smali: Invalid literal value:
    #   Low 48 bits must be zeroed out)。故按新值重选变体:装不下即折回无后缀
    #   `const-wide`(可编码任意 64 位)。
    # 坑 B(文件截断):替换范围只能到【行尾】。m.start()..m.end() 不含换行,
    #   行尾之后的内容必须原样保留 —— 曾经把 m.end() 之后的文本整段丢弃,骨架
    #   被腰斩成 92 行(方法中途 EOF),下游 apktool 报
    #   `mismatched input '' expecting END_METHOD_DIRECTIVE`。
    #   顺带:m.end() 覆盖了行尾的十进制浮点注释(d8 为旧值生成的),它随整段
    #   一起被丢弃,无需单独判断。
    def _fits(variant, value):
        """该指令变体能否编码 value(无后缀 const-wide 恒可)。"""
        if variant == '/high16':
            return (value & 0x0000FFFFFFFFFFFF) == 0
        if variant == '/16':
            return -0x8000 <= value <= 0xFFFF
        return True

    for m in reversed(list(_INLINE_SEED_RE.finditer(skeleton))):
        if m.group('val').rstrip('Ll').lower() != sentinel:
            continue
        variant = m.group('variant') or ''
        op = 'const-wide' if not _fits(variant, seed_int) else 'const-wide' + variant
        line = f"{m.group('indent')}{op} {m.group('reg')}, {seed_word}"
        skeleton = skeleton[:m.start('indent')] + line + skeleton[m.end():]

    # 终检 1:哨兵种子必须一处不剩(残留 = 漏改,运行期会用到旧种子)
    if sentinel in skeleton.lower():
        raise SystemExit(
            f'❌ 桩种子注入终检失败:骨架里仍残留哨兵种子 {SENTINEL_SEED}\n'
            f'   (说明有锚点未被改写;绝不能带着哨兵进产物)')
    # 终检 2:改写前"值等于哨兵的锚点数"必须等于改写后"值等于真种子的锚点数"。
    # 必须用同一个口径(按值数)对比:若拿"所有 const-wide 行数"去数,会把 GAMMA
    # 等无关常量算进来 —— 旧实现在这里恰好与截断互相抵消(截断吃掉 3 条无关
    # const-wide/16 后,1 == 1 照样通过),破损桩因此静默进了产物(报错二十七)。
    _, all_after = find_stub_seed_anchors(skeleton, expect_sentinel=False)
    n_after = sum(1 for m in all_after
                  if m.group('val').rstrip('Ll').lower() == seed_word.rstrip('Ll').lower())
    if n_after != n_inline:
        raise SystemExit(
            f'❌ 桩种子注入终检失败:内联锚点数量从 {n_inline} 变为 {n_after}\n'
            f'   (注入改坏了骨架结构,拒绝写入产物)')
    # 终检 3:结构完整性 —— 注入是逐值替换,骨架行数必须严格守恒。
    # 这一条直接拦住"替换范围越界把文件吞掉"的形态(报错二十七):截断后的骨架
    # 仍能通过锚点/哨兵残留检查,却能通过汇编阶段才炸(方法中途 EOF)。
    if len(skeleton.split('\n')) != n_lines:
        raise SystemExit(
            f'❌ 桩种子注入终检失败:骨架行数从 {n_lines} 变为 '
            f'{len(skeleton.split(chr(10)))} —— 注入吞掉了骨架内容(截断)。\n'
            f'   检查内联锚点的替换范围是否只覆盖到行尾。')
    # 终检 4:字段初值必须确已变为真种子
    fm3, _ = find_stub_seed_anchors(skeleton, expect_sentinel=False)
    if fm3.group('val').rstrip('Ll').lower() != seed_word.rstrip('Ll').lower():
        raise SystemExit(
            f'❌ 桩种子注入终检失败:字段初值为 {fm3.group("val")},'
            f'期望 {seed_word}')
    return skeleton

def read_stub_seed(content: str) -> bytes:
    """从已存在的桩里读回 8 字节种子(续跑/复用桩时用,否则旧密文解不开)。"""
    fm = _FIELD_SEED_RE.search(content)
    if not fm or fm.group('val') is None:
        raise SystemExit('❌ 桩文件缺少 SEED 字段初值,无法复用其种子')
    word = fm.group('val').rstrip('Ll')
    try:
        val = int(word, 16)
    except ValueError:
        raise SystemExit(f'❌ 桩文件的 SEED 初值不是十六进制字面量: {fm.group("val")}')
    return (val & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big')

# ── 解密桩自检:参数寄存器不得被当临时槽覆盖(报错二十二) ──────────────
#
# 为什么需要它:桩的 xor 曾把内层循环临时寄存器写成 v14/v15,而 `.registers 16`
# + 双参 `([BI)` 让 p0 恰好落在 v14、p1 落在 v15 ⇒ 指令静默改写形参本身,
# 汇编通过、静态对拍也过(算法对),只有运行期才崩(SIGSEGV/无 FATAL 日志)。
# "文字警告防不住文本级重写,只有机制能"——故把这条不变量做成构建期断言:
# 桩模板展开后,任何一条【写】指令的目标寄存器都不得落在参数寄存器区间内。
_NO_DEST_OPCODES = (
    'invoke-', 'if-', 'goto', 'return', 'throw', 'nop', 'move-exception',
    'monitor-', 'check-cast',          # check-cast 目标即源,不产生新值
)
_DEST_FIRST_RE = re.compile(
    r'^(?P<op>[a-z][a-z0-9/\-]*)'
    r'(?:\s+(?P<first>v\d+|p\d+))?')
_METHOD_HDR_RE = re.compile(
    r'^\.method\b[^\n]*?\b([A-Za-z_$][\w$]*|<init>|<clinit>)?\s*'
    r'\((?P<args>[^)]*)\)[^\n]*$')
_REGS_RE = re.compile(r'^[ \t]*\.(?P<kind>registers|locals)[ \t]+(?P<n>\d+)[ \t]*$')

def _param_reg_count(arg_desc: str, is_static: bool) -> int:
    """方法形参占用的寄存器数(J/D 占 2 个,this 占 1 个)。"""
    n = 0 if is_static else 1
    i = 0
    while i < len(arg_desc):
        c = arg_desc[i]
        if c == 'L':
            end = arg_desc.find(';', i)
            if end < 0:
                return -1
            i = end + 1
            n += 1
        elif c == '[':
            while i < len(arg_desc) and arg_desc[i] == '[':
                i += 1
            if i < len(arg_desc) and arg_desc[i] == 'L':
                end = arg_desc.find(';', i)
                if end < 0:
                    return -1
                i = end + 1
            else:
                i += 1
            n += 1
        elif c in 'JD':
            n += 2
            i += 1
        elif c in 'ZBSCIF':
            n += 1
            i += 1
        else:
            return -1
    return n

def _check_stub_registers(smali_text: str, decrypt_method: str = None) -> None:
    """构建期断言:桩内无指令把参数寄存器当目标覆盖。违反即 fail-fast。

    decrypt_method:被守卫锚定的解密主方法名,缺省跟随全局 STUB_DECRYPT_METHOD。
    检查【骨架】时必须显式传 'd':骨架是 build-stub.sh 的 legacy 编译产物,
    方法名随机化只发生在 write_stub 的文本替换(寄存器布局不变);若按全局
    随机名找方法,骨架里不存在该方法,整条守卫静默失效(报错四十八)。"""
    if decrypt_method is None:
        decrypt_method = STUB_DECRYPT_METHOD
    lines = smali_text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        hdr = _METHOD_HDR_RE.match(line.strip()) if line.strip().startswith('.method') else None
        if not hdr:
            i += 1
            continue
        method = hdr.group(1) or '(anonymous)'
        args = hdr.group('args')
        is_static = bool(re.search(r'\bstatic\b', line))
        nparams = _param_reg_count(args, is_static)
        # 收集方法体到 .end method
        j = i + 1
        body = []
        while j < n and not lines[j].strip() == '.end method':
            body.append(lines[j])
            j += 1
        # 找 .registers / .locals
        # 【易错】两者语义不同(报错二十二 自检曾因此误报):
        #   .registers N → N 是【总寄存器数】(含参数)
        #   .locals N    → N 是【局部寄存器数】,总寄存器数 = N + 参数数
        # 桩由 javac 生成,用的是 .locals;把 .locals 的 N 当总数会导致
        # param_lo 偏小、误报"局部槽覆盖形参"。
        total = None
        for bl in body:
            m = _REGS_RE.match(bl)
            if m:
                n_val = int(m.group('n'))
                total = n_val if m.group('kind') == 'registers' \
                    else n_val + max(nparams, 0)
                break
        if total is None or nparams < 0:
            i = j + 1
            continue
        # 参数寄存器边界(限于 v 编号):p0..pK 映射到 v(total-nparams)..v(total-1)。
        # 注意:这里不再用它拦"写形参"——那会误伤编译器产物(见下方 _param_* 说明)。
        # 保留 total/param_lo 的解析仅为兼容旧行为审计,实际判定见 _param_overwritten_before_use。
        _ = total - nparams
        for bl in body:
            s = bl.strip()
            # 显示跳过:空行 / 指令外元素(.directive)/ label(:x)/ 注释(#)—— 注释里
            # 出现 "aget-byte v14" 这类说明文字不得被当真实指令(否则说明文案会误伤自检)
            if not s or s.startswith(('.', ':', '#')):
                continue
            op = s.split()[0]
            if op.startswith(_NO_DEST_OPCODES):
                continue
            m = _DEST_FIRST_RE.match(s)
            if not m:
                continue
            dst = m.group('first')
            if not dst:
                continue
            # 「警报器」范围(按用户裁决:只盯最危险的那一步):
            #   * 只对【解密主方法 d()】保持 fail-fast —— 它是唯一会调用系统
            #     Base64 解码工具的方法,形参被弄脏 → 解码拿到脏数据
            #     (报错二十二的真身:闪退且无 FATAL 日志)。
            #   * 对 mix64/keyByte 这类【纯算数内部方法】放行 —— 它们不调用任何
            #     外部工具,形参读写是编译器正常产物(如 `seed += ...`),
            #     拦它只会误伤,不带来任何安全性。
            if method != decrypt_method:
                continue
            if dst.startswith('p') or dst.startswith('v'):
                vnum = total - nparams if dst.startswith('p') else int(dst[1:])
                if vnum >= total - nparams:
                    raise SystemExit(
                        f'❌ 解密桩自检失败:{method} 里 `{s}` 以参数寄存器 {dst} 为目标,\n'
                        f'   而 d() 随后还要用这些形参调用系统解码工具 → 运行期会传脏参数\n'
                        f'   (报错二十二:闪退且无 FATAL 日志)。\n'
                        f'   请改用方法内确无依赖的局部寄存器槽。')
        i = j + 1

# ── smali 字符串字面量转义表(与 smali 汇编器的 unescape 对齐) ──────────
_UNESCAPE = {
    'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f',
    "'": "'", '"': '"', '\\': '\\',
}
_HEX = set('0123456789abcdefABCDEF')

# const-string 指令行:抓缩进 / jumbo / 目标寄存器 / 字面量起始
_INSTR_RE = re.compile(
    r'^(?P<indent>[ \t]*)const-string(?P<jumbo>/jumbo)?[ \t]+'
    r'(?P<dst>v\d+|p\d+)[ \t]*,[ \t]*"(?P<rest>.*)$')

# field 行携带的字符串字面量(R8 把 static final 常量折叠成 @value 注解形态)。
# 例: .field public static final URL:Ljava/lang/String; = "https://x"
# 类型必须以字段名后的 ':' 为锚(否则 [^;\s]+; 会把名字末尾的字符吞进类型)
_FIELD_RE = re.compile(
    r'^(?P<indent>[ \t]*)\.field(?P<mid>.*?)(?P<name>[A-Za-z_$][\w$]*):'
    r'(?P<type>[L\[][^\s]*?;)[ \t]*=[ \t]*"(?P<rest>.*)$')

# 值得加密的字段类型:String 本身,以及 String 数组(元素值同样是明文)
FIELD_STRING_TYPES = ('Ljava/lang/String;', '[Ljava/lang/String;')

def smali_unescape(text: str) -> str:
    """解码 smali 字符串字面量内容(两侧引号已剥掉)。

    识别不了转义时抛 ValueError(调用方跳过该条,绝不猜)——
    宁可漏一条也不静默改错字符串值。"""
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch != '\\':
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= n:
            raise ValueError('结尾孤立反斜杠')
        esc = text[i]
        if esc == 'u':
            if i + 4 >= n:
                raise ValueError('\\u 转义不完整')
            hexs = text[i + 1:i + 5]
            if len(hexs) != 4 or any(c not in _HEX for c in hexs):
                raise ValueError('\\u 转义非 4 位十六进制')
            cp = int(hexs, 16)
            i += 5
            # baksmali 按 UTF-16 code unit 逐个转义:非 BMP 字符(emoji 等)
            # 输出成 \uD83D\uDE00 代理对。必须在这里合并成单个码点,
            # 否则 chr() 产生的孤立代理项后续 .encode('utf-8') 直接炸
            # (报错十九: UnicodeEncodeError: surrogates not allowed)。
            if 0xD800 <= cp <= 0xDBFF:                       # 高代理 → 必须跟低代理
                if i + 1 < n and text[i] == '\\' and text[i + 1] == 'u' \
                        and i + 6 <= n:
                    lo_hexs = text[i + 2:i + 6]
                    if len(lo_hexs) != 4 or any(c not in _HEX for c in lo_hexs):
                        raise ValueError('代理对低半 \\u 转义非法')
                    lo = int(lo_hexs, 16)
                    if not (0xDC00 <= lo <= 0xDFFF):
                        raise ValueError(f'高代理 \\u{cp:04X} 后未跟低代理(孤立代理项)')
                    out.append(chr(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)))
                    i += 6
                else:
                    raise ValueError(f'高代理 \\u{cp:04X} 后未跟低代理(孤立代理项)')
            elif 0xDC00 <= cp <= 0xDFFF:
                raise ValueError(f'孤立低代理 \\u{cp:04X}')
            else:
                out.append(chr(cp))
        elif esc in _UNESCAPE:
            out.append(_UNESCAPE[esc])
            i += 1
        else:
            raise ValueError(f'未知转义 \\{esc}')
    return ''.join(out)

def parse_const_string(line: str):
    """解析一条 const-string 指令行。
    返回 (match, literal_text, tail) 或 None(不是该指令/引号不闭合)。"""
    m = _INSTR_RE.match(line)
    if not m:
        return None
    rest = m.group('rest')
    i = 0
    while i < len(rest):
        c = rest[i]
        if c == '\\':
            i += 2
            continue
        if c == '"':
            break
        i += 1
    else:
        return None                                   # 引号不闭合,当异常行跳过
    return m, rest[:i], rest[i + 1:]

def parse_field_string(line: str):
    """解析携带字符串字面量的 .field 行(R8 折叠的 static final 常量)。
    返回 (match, literal_text, tail) 或 None。"""
    m = _FIELD_RE.match(line)
    if not m:
        return None
    if m.group('type') not in FIELD_STRING_TYPES:
        return None                                   # 只处理 String / String[] 字段
    rest = m.group('rest')
    i = 0
    while i < len(rest):
        c = rest[i]
        if c == '\\':
            i += 2
            continue
        if c == '"':
            break
        i += 1
    else:
        return None
    return m, rest[:i], rest[i + 1:]

def _strip_field_literal(line: str, m) -> 'str | None':
    """字段去初值(2026-09-12):`.field ... X:Ljava/lang/String; = "明文"` → `.field ... X:...;`

    只删"初值那一段",字面量之后保留(兼容 R8 的 `# annotations` 尾注与 `.field`
    自身的其它修饰)。无法安全定位(如行尾有引号转义)时返回 None,调用方保持原样。

    为什么不用计划书 §3.4 那种 sub 写法:① 字面量类用 [^"]* 时遇到转义引号会提前
    收尾;② 非贪婪 + 行尾锚点在同一行有多个 等号引号 时会吃掉错的一段。
    这里复用 parse_field_string 已经算好的引号区间,精确到字符。"""
    rest = m.group('rest')                  # 初值所在区间(从第一个 `"` 之后开始)
    lit_len = 0                             # 字面量在 rest 里的长度(可含转义)
    i = 0
    while i < len(rest):
        c = rest[i]
        if c == '\\':
            i += 2
            continue
        if c == '"':
            break
        i += 1
    if i > len(rest):
        return None
    lit_len = i
    if lit_len >= len(rest) or rest[lit_len] != '"':
        return None                         # 引号不闭合
    head = line[:m.start('rest') - 1]       # 去掉开引号(leftover = "   = ")
    tail = rest[lit_len + 1:]               # 闭合引号之后的一切(R8 注解尾注等)
    # 把 "= <可选空白>" 一并去掉(head 形如 '.field ... X:Ljava/lang/String;   = ')
    head = re.sub(r'[ \t]*=[ \t]*$', '', head)
    return head.rstrip() + tail

# ── splitmix64 密钥流(Python 侧参考实现;与 StrDec.java 逐字节一致) ──────
# 【易错点,改这两行前先读】
#  ① Python 的 >> 是算术右移,必须保证操作数是已掩码的非负数(每步 & MASK64);
#     Java 用 >>>(无符号右移),long 溢出天然 = mod 2^64。
#  ② 字节序:b = (w >> ((i & 7) * 8)) & 0xFF —— 低位在前,Java 侧同式。
# 这两条由 scripts/string-enc/tests/test-keystream-crosscheck.sh 逐字节钉死。
MASK64 = (1 << 64) - 1
GAMMA = 0x9E3779B97F4A7C15
_M1 = 0xBF58476D1CE4E5B9
_M2 = 0x94D049BB133111EB

def _mix64(z: int) -> int:
    z = (z ^ (z >> 30)) & MASK64
    z = (z * _M1) & MASK64
    z = (z ^ (z >> 27)) & MASK64
    z = (z * _M2) & MASK64
    return (z ^ (z >> 31)) & MASK64

def key_byte(seed: int, i: int) -> int:
    """虚拟密钥流第 i 个字节,O(1) 现算(对应 StrDec.keyByte)。"""
    w = _mix64((seed + (i >> 3) * GAMMA) & MASK64)
    return (w >> ((i & 7) * 8)) & 0xFF


# ── ChaCha20 密钥流(Python 侧参考实现;与 nc_strdec.c 逐字节一致) ──────
# 为什么需要第二套算法(2026-11-09):
#   splitmix64 + XOR 都是可逆的 —— 攻击者拿到任意一条明文就能反解出 seed,
#   进而解开全包所有字符串。ChaCha20 的密钥流是 PRF 输出,不可逆:
#   猜中一条只泄漏那一条。
#
# 与 C 侧的对应关系(改任一侧必须同步另一侧,否则全包乱码且构建期不报错):
#   C:     nc_chacha20_block_head(blk)  取 64 字节块的前 8 字节
#   Python: _chacha20_block_head(blk)   同上
#   blk   = 全包虚拟密钥流的位置 >> 3   (与 splitmix64 的块号定义完全相同)
#   nonce = 全零(blk 本身就是全包唯一的 counter,无需额外存 nonce → 体积零增长)
#
# ⚠️ 这些常量与轮函数直接照 RFC 8439 §2.1/§2.3 写,且由 RFC 官方测试向量
#   (全零 key/nonce,counter=0/1)钉死,见 tests/test-cstrdec.sh 的 ChaCha20 组。
#   不要"优化"成普通左移 —— 那会丢高位,自己跟自己对拍永远发现不了。

_CHACHA_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _chacha20_block_head(seed: int, blk: int) -> int:
    """ChaCha20 第 blk 块的前 8 字节(uint64,低位在前)。

    seed 是 8 字节密钥材料:按 C 侧口径展开成 8 个 uint32 语义 —— C 侧
    nc_key[0] 是"大端序读 8 字节",再按小端拆成两个 uint32
    (lo = k & 0xFFFFFFFF, hi = k >> 32)。这里必须完全照做。
    """
    k = seed & MASK64
    st = list(_CHACHA_CONST) + [
        k & 0xFFFFFFFF, (k >> 32) & 0xFFFFFFFF,
    ]
    # 只用了 8 字节密钥材料 → 密钥区剩下的 6 个 uint32 补零。
    # 与 C 侧一致：C 的 nc_chacha20_derive_key() 只填前 2 个 uint32，
    # 其余保持静态零初始化。
    st += [0] * 6
    st += [0, 0, 0, 0]             # counter + nonce，下面再填 counter
    st[12] = blk & 0xFFFFFFFF      # counter
    st[13] = st[14] = st[15] = 0   # nonce 全零
    x = st[:]
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF
            x[d] = _rotl32(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF
            x[b] = _rotl32(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF
            x[d] = _rotl32(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF
            x[b] = _rotl32(x[b] ^ x[c], 7)
    lo = (x[0] + st[0]) & 0xFFFFFFFF
    hi = (x[1] + st[1]) & 0xFFFFFFFF
    return (hi << 32) | lo


# 算法选择(构建期决定,与 C 侧 -DNC_STRDEC_ALGO 必须同源)
ALGO_SPLITMIX = "splitmix64"
ALGO_CHACHA20 = "chacha20"


def key_byte_algo(seed: int, i: int, algo: str = ALGO_SPLITMIX) -> int:
    """按算法取虚拟密钥流第 i 个字节。i 是【全包虚拟密钥流】的绝对下标。"""
    if algo == ALGO_SPLITMIX:
        return key_byte(seed, i)
    if algo == ALGO_CHACHA20:
        w = _chacha20_block_head(seed, i >> 3)
        return (w >> ((i & 7) * 8)) & 0xFF
    raise SystemExit(f"❌ 未知的密钥流算法: {algo!r}(只支持 {ALGO_SPLITMIX} / {ALGO_CHACHA20})")

def read_seed_bytes() -> bytes:
    """新构建的种子:8 字节随机。"""
    return secrets.token_bytes(8)

def encrypt_payload_v2(seed: int, offset: int, plain: bytes,
                       algo: str = ALGO_SPLITMIX) -> str:
    """v2 明文 → Base64( offset_be24 || cipher ),cipher[k] = plain[k] ^ key_byte(offset+k)。

    algo 决定密钥流来源(splitmix64 / chacha20),默认 splitmix64 保现状。
    密文格式两种算法完全相同 —— offset 直接当 ChaCha20 的 counter,
    所以体积零增长,且解密主循环无需区分算法。
    """
    head = bytes(((offset >> 16) & 0xFF, (offset >> 8) & 0xFF, offset & 0xFF))
    cipher = bytes(p ^ key_byte_algo(seed, offset + k, algo)
                   for k, p in enumerate(plain))
    return base64.b64encode(head + cipher).decode('ascii')

def desc_to_dot(desc: str) -> str:
    """Lcom/x/Y; → com.x.Y"""
    return desc[1:-1].replace('/', '.')

def build_matchers(rules_path: str, classes_file):
    """规则文件 → (include 正则表, exclude 正则表)。语法与 dcc 侧完全一致。"""
    with open(rules_path, encoding='utf-8') as fp:
        raw_rules = [line.strip() for line in fp]

    includes, excludes = [], []
    activity_mode = False
    for rule in raw_rules:
        if not rule or rule.startswith('#'):
            continue
        negate = rule.startswith('!')
        body = rule[1:].strip() if negate else rule
        if not body:
            continue
        if body == 'activity*':
            activity_mode = True
            if not classes_file:
                raise SystemExit('❌ 规则含 activity*,必须提供 --classes 类列表文件')
            for cls in _RULES.expand_activity_keyword(classes_file):
                pat = _RULES.class_rule_to_filter(cls[1:-1], False)
                (excludes if negate else includes).append(re.compile(pat))
            continue
        pat = _RULES.class_rule_to_filter(body, _RULES.has_wildcard(body))
        (excludes if negate else includes).append(re.compile(pat))
    return includes, excludes, activity_mode

def parse_compiled_methods(path: str):
    """compiled_methods.txt → {(类名, 方法名, 原型)}(格式同 §4.2,无箭头)。"""
    result = set()
    with open(path, encoding='utf-8') as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            m = re.match(r'^(L[^;]+;)([^(]+)(\(.*\)\S+)$', line)
            if m:
                result.add((m.group(1), m.group(2), m.group(3)))
    return result

def iter_smali_files(decompiled_dir: str):
    for root, _dirs, files in os.walk(decompiled_dir):
        parts = root[len(decompiled_dir):].lstrip(os.sep).split(os.sep)
        if any(SMALI_DIR_RE.match(p) for p in parts if p):
            for f in files:
                if f.endswith('.smali'):
                    yield os.path.join(root, f)

def class_desc_of(content: str):
    """取 .class 行的类描述符(同 mark-native.py 的取法)。"""
    for line in content.split('\n'):
        if line.startswith('.class'):
            m = re.search(r'L[^;\s]+;', line)
            if m:
                return m.group(0)
    return None

def _rebuild_desc_derived():
    """由当前 STUB_DESC/STUB_DECRYPT_METHOD 重建 import 期派生物(报错四十八)。

    【为什么必须存在】STUB_DOT 与下面三个正则都是从"主变量"派生的,而主变量
    会被 apply_stub_identifiers(桩随机化)在运行期改写——派生物若不同源重建,
    全部停留在 legacy 名上:续跑水位线失明(_PAYLOAD_RE/_FIELD_REF_RE 认不出
    随机名密文 → offset 复用 → 静默乱码)、** 规则下桩被当业务类二次加密
    (STUB_DOT 失明)、报错二十四断言失明。模块加载时建一次(legacy 名),
    apply_stub_identifiers 改名后再建一次。"""
    global STUB_DOT, _PAYLOAD_RE, _FIELD_REF_RE, _ILLEGAL_FIELD_INIT_RE
    STUB_DOT = STUB_DESC[1:-1].replace('/', '.')

    # 已加密条目的形态:const-string 紧跟本桩的 invoke-static(用于续跑时续 offset)。
    # 必须同时认 `invoke-static {..}` 与 `invoke-static/range {.. .. ..}` 两种形态
    # (报错二十一改注入形态后,/range 是新产物;若这里只认旧形态,max_existing_idx
    # 会漏算 → 续跑 offset 从 0 重来 → 共享密钥表区段复用)
    _PAYLOAD_RE = re.compile(
        r'const-string(?:/jumbo)?[ \t]+(?:v\d+|p\d+)[ \t]*,[ \t]*"([^"\n]*)"\n'
        r'[ \t]*invoke-static(?:/range)? \{[^}\n]*\}, ' + re.escape(STUB_DESC)
        + r'->' + re.escape(STUB_DECRYPT_METHOD) + r'\(')

    # 字段常量回填引用(报错二十四改形态后):<clinit> 里的
    #   sget-object vX, 本桩 ->F\d+
    # (续跑时字段占用的表区间也要计入,否则新字段 offset 从 0 重来 → 密钥区段复用。
    # 旧形态 `= StrDec;->F\d+:` 是报错二十四的非法 FIELD 型 static_value,已废弃,
    # 且被 _ILLEGAL_FIELD_INIT_RE 构建期断言拦截。v2 里 F 编号与表 offset 同源递增,
    # F(\d+) 读出的编号本身即"该字段占用的下一个 offset 下界"——字段名在分配时
    # 用占用前的 offset 命名,故引用计数语义 = offset+len 由分配器统一维护)
    _FIELD_REF_RE = re.compile(
        # 回填引用形态(报错二十四):<clinit> 里的 sget-object vX, StrDec;->FNNNNNN
        r'sget-object[ \t]+(?:v\d+|p\d+),[ \t]*' + re.escape(STUB_DESC) + r'->F(\d+):')

    # 非法形态断言(报错二十四):.field 初值绝不允许是 StrDec 字段引用。
    # 该形态会被 smali 汇编成 FIELD 型(0x19) encoded static_value —— dex 规范
    # 不允许的初值类型,ART 类初始化阶段(字节码执行之前)即失败 → 秒闪退且无日志。
    _ILLEGAL_FIELD_INIT_RE = re.compile(
        r'^[ \t]*\.field[^\n]*=[ \t]*' + re.escape(STUB_DESC) + r'->F\d+:', re.M)

_rebuild_desc_derived()

# 字段去初值断言(2026-09-12):目标类的 String/String[] 字段初值绝不允许是
# 明文字面量 —— 否则 `strings` 扫产物照样命中(本次改动的存在理由)。
# 只扫"我们处理过的类"(含 CLASS_MARK)与解密桩自身:没被规则命中的类(硬排除的
# androidx/kotlin 等)本就不归本模块管,不能拿它们的字段去 fail 构建。
# 桩自身的 `.field ... SEED:J` 是 long,不在扫描面内。
_FIELD_STRING_LITERAL_RE = re.compile(
    r'^[ \t]*\.field[^\n]*[A-Za-z_$][\w$]*:(?:Ljava/lang/String;|\[Ljava/lang/String;)'
    r'[ \t]*=[ \t]*"')

def _scope_allows_field_scan(content: str) -> bool:
    """该文件是否属于"本模块的加密面"(据此决定字段初值断言是否适用)。"""
    return CLASS_MARK in content or STUB_DESC in content

def field_literal_is_skipped(plain: str) -> bool:
    """字段分支【按设计保留明文初值、不进加密面】的判定(只看已解析出的明文值)。
    值解析失败(孤立代理项等)另属一类,由 `_scan_illegal_field_literals` 放行。

    ⚠️ 这是字段分支与构建期断言【唯一共享】的真相来源,两处必须调用同一函数 ——
    任何一边单独改判定,都会让断言把"设计内跳过"判成"去初值漏改"而 fail-fast
    (2026-09-12 云端事故:`**` 全量规则下 okhttp3/HttpUrl 的 FRAGMENT_ENCODE_SET=""
    → 整包构建被误拦),或反过来让真漏改逃过断言。

    两类跳过(与 process_file 字段分支逐条对应):
      ① 空串 —— 无信息量;桩对 3 字节 payload 走"原样返回"兜底会把 Base64 串
         本身当明文返回(语义错误),故不能加密
      ② 编译器调试/内联标记串($i$f$/$changed/…)—— 见 _SKIP_STRING_PREFIXES

    本函数【只判值本身】,"值解析不出来"的情况见 `_field_literal_parse_failed`。
    """
    return (not plain) or is_instrumentation_string(plain)

def _scan_illegal_field_literals(content: str):
    """加密面内的"去初值漏改"字段行(逐行判定,与字段分支同源)。

    为什么不能直接用 `_FIELD_STRING_LITERAL_RE.search(content)` 一票否决:
    字段分支有【按设计保留明文初值】的类别,全文件粗扫会把它们一起判成漏改 →
    误拦整包构建(2026-09-12 云端事故,`**` 规则命中 okhttp3/HttpUrl、
    guava CharMatcher$Invisible 时必现)。

    三类"设计内保留"(与 process_file 字段分支逐条对应):
      ① 空串、② 编译器调试/内联标记串   → field_literal_is_skipped()
      ③ 解析失败(孤立代理项等 ValueError)→ 本函数单独放行,见下方注释

    返回 [(行文本, 命中正则), ...];命中即"该去掉的初值还在",调用方 fail-fast。
    判定流程与 process_file 字段分支逐条对齐:
      解析不出字面量      → 不是本断言的管辖对象(字段分支同样不处理)
      值解析失败          → 设计内保留(跳过),见下方【决策 A】
      值被跳过类别命中    → 设计内保留(跳过)
      其余一律算漏改
    """
    hits = []
    for line in content.split('\n'):
        m = _FIELD_STRING_LITERAL_RE.match(line)
        if not m:
            continue
        fparsed = parse_field_string(line)
        if not fparsed:
            # 引号不闭合等异常形态 —— 字段分支也不会去初值,不算漏改
            continue
        _fm, fliteral, _ftail = fparsed
        try:
            fplain = smali_unescape(fliteral)
        except (ValueError, UnicodeDecodeError):
            # 【决策 A(2026-09-12,用户拍板)】无法安全解析(孤立代理项等)
            # → 字段分支跳过并保留明文初值,断言【同样放行】,判定与实现同源。
            #
            # 为什么这一类就该放行(而非"漏改"):
            #   与 ①② 同源 —— 加密这条路对它是【走不通】而不是【没走】:
            #   smali_unescape 确定性拒绝,去初值后无法构造回填链(回填链要先
            #   把明文加密成 Base64,前提是能拿到明文),强行处理只会更糟。
            #   已知实例 guava `CharMatcher$Invisible.RANGE_STARTS` 含 \ud800,
            #   值是字符区间查表用的控制字符,非敏感数据,留明文无风险。
            #
            # ⚠️ 此前这里【刻意判为漏改】以防"本该处理却因解析失败留下明文"
            # 被静默放掉。改为放行后,该风险由 process_file 的告警行兜底:
            # 解析失败时字段分支会打印
            # `⚠️ 跳过无法安全解析的字段字面量(...)`(见该分支),
            # 产物里出现该类明文【必定伴随告警】,不是静默失败。
            continue
        if field_literal_is_skipped(fplain):
            continue
        hits.append((line, m))
    return hits

def is_system_class(cls_dot: str) -> bool:
    """系统类/框架依赖前缀判定(带点号前缀,不误伤 androidXxx 这种同前缀类)。"""
    return cls_dot.startswith(SYSTEM_CLASS_PREFIXES)

def classify(cls_dot: str, cls_desc: str, includes, excludes) -> str:
    """给类定性:no-match / system / excluded / stub / target。
    判定顺序:未命中 include → system(硬排除,规则层不可突破)→ stub →
    用户 ! 排除 → target。system 与 excluded 结果同为不加密,仅日志统计
    口径不同:命中系统前缀的类计入 skipped_system(即使用户 ! 排除行也
    拦不住硬排除的优先地位)。"""
    if not any(r.search(cls_desc) for r in includes):
        return 'no-match'
    if is_system_class(cls_dot):
        return 'system'
    if cls_dot == STUB_DOT:
        return 'stub'
    if any(r.search(cls_desc) for r in excludes):
        return 'excluded'
    return 'target'

def max_existing_idx(content: str) -> int:
    """v2: 已加密类里占用过的最大表区间末尾(续跑时接着分配,避免密钥区段复用)。
    同时扫两类形态:指令密文(_PAYLOAD_RE)与回填引用(_FIELD_REF_RE)。
    返回值语义 = "下一个可用 offset 下界"(最大 offset + len)。"""
    biggest = -1
    for m in _PAYLOAD_RE.finditer(content):
        try:
            raw = base64.b64decode(m.group(1), validate=True)
        except Exception:
            continue
        if len(raw) >= 3:
            off = int.from_bytes(raw[:3], 'big')
            biggest = max(biggest, off + (len(raw) - 3))
    for m in _FIELD_REF_RE.finditer(content):
        biggest = max(biggest, int(m.group(1), 10))
    return biggest

def _rand_ident(rng) -> str:
    """1-2 字符 R8 混淆风标识符(小写字母开头,可带数字)。

    业务 App 通常过 R8/proguard,包名类名本就是短混淆名 —— 桩伪装成混淆产物
    的一部分比随机长名更隐蔽。"""
    first = rng.choice('abcdefghijklmnopqrstuvwxyz')
    tail = rng.choice('abcdefghijklmnopqrstuvwxyz0123456789')
    return first + tail

def generate_stub_identifiers() -> tuple:
    """生成每包随机的桩标识:(点分包名, 类名, 方法名)。

    包名 3 段、类名/方法名各 1 段,全部 R8 混淆风。组合空间 >10^5,
    防的是引擎【精确签名】(固定 desc+method 哈希命中),不是暴力枚举。"""
    import random as _random
    rng = _random.SystemRandom()
    pkg = '.'.join(_rand_ident(rng) for _ in range(3))
    cls = _rand_ident(rng)
    method = _rand_ident(rng)
    return pkg, cls, method

def apply_stub_identifiers(pkg_dot: str, cls: str, method: str) -> None:
    """把随机桩名写进模块级四个变量(全部下游引用自动跟随)。"""
    global STUB_DESC, STUB_PKG_DIR, STUB_FILE, STUB_DECRYPT_METHOD
    parts = tuple(pkg_dot.split('.'))
    STUB_PKG_DIR = parts
    STUB_FILE = cls + '.smali'
    STUB_DESC = 'L' + '/'.join(parts) + '/' + cls + ';'
    STUB_DECRYPT_METHOD = method
    _rebuild_desc_derived()   # 报错四十八:派生物必须与主变量同源重建

def parse_stub_name(spec: str) -> tuple:
    """解析 --stub-name 'pkg.Cls:method'(method 可省,省略即 'd')。
    返回 (点分包名, 类名, 方法名),与 generate_stub_identifiers 同构。"""
    if ':' in spec:
        name, method = spec.split(':', 1)
    else:
        name, method = spec, 'd'
    if '.' not in name or not name.split('.')[-1]:
        raise SystemExit(f"❌ --stub-name 形态必须是 '包名.类名[:方法名]',收到: {spec}")
    pkg_dot, cls = name.rsplit('.', 1)
    return pkg_dot, cls, method

def read_components_stamp(decompiled_dir: str):
    """读组件标记(报错十八式元数据)。不存在/损坏返回 None。"""
    path = os.path.join(decompiled_dir, COMPONENTS_FILE)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding='utf-8') as fp:
            data = json.load(fp)
        cls = (data.get('classes') or [None])[0]
        if not cls or 'desc' not in cls or 'src' not in cls:
            return None
        return cls
    except (OSError, ValueError):
        return None

def recover_identifiers_from_stamp(decompiled_dir: str) -> bool:
    """续跑复用:从组件标记 + 桩文件内容恢复随机桩名。

    返回 True=已恢复(下游全部走恢复名);False=标记缺失/损坏(首次跑或旧产物)。
    标记在但恢复失败 → raise(fail-fast,绝不悄悄换名 —— 换名=旧调用点全部
    指向不存在的类,运行期 NoClassDefFoundError)。"""
    cls = read_components_stamp(decompiled_dir)
    if cls is None:
        return False
    desc = cls['desc']
    m = re.match(r'^L(.+)/([^/]+);$', desc)
    if not m:
        raise SystemExit(f'❌ 组件标记里的桩描述符无法解析: {desc}')
    pkg_slash, cls_name = m.group(1), m.group(2)
    src = os.path.join(decompiled_dir, cls['src'])
    if not os.path.isfile(src):
        # 桩已被搬进壳 dex（--emit-stub-dex 的预期结果，标记里有 moved_to_shell_dex）。
        # 此时用【标记里记录的类名+主方法名】恢复标识符即可，无需读文件内容。
        # 若标记没记这个状态，说明解包目录被外部重建过 → 仍 fail-fast。
        if cls.get('moved_to_shell_dex'):
            method = cls.get('decrypt_method') or 'd'
            apply_stub_identifiers(pkg_slash.replace('/', '.'), cls_name, method)
            return True
        raise SystemExit(f'❌ 组件标记指向的桩文件不存在: {src}\n'
                         f'   解包目录可能被重建过,请 clean 后重新加密。')
    with open(src, encoding='utf-8') as fp:
        content = fp.read()
    if STUB_GEN_MARK not in content:
        raise SystemExit(f'❌ 组件标记指向的文件不是本工具生成的桩: {src}')
    mm = re.search(r'^\.method public static (\S+)\(Ljava/lang/String;\)Ljava/lang/String;',
                   content, re.M)
    if not mm:
        raise SystemExit(f'❌ 桩文件里找不到解密主方法(签名形态变了?): {src}')
    apply_stub_identifiers(pkg_slash.replace('/', '.'), cls_name, mm.group(1))
    return True

def find_stub_path(decompiled_dir: str):
    """在 smali*/ 里找桩文件(只有解包目录下、且位于桩包路径中的才算)。

    定位顺序:组件标记(随机名续跑的唯一可靠依据)→ 固定名兜底(旧产物/测试)。"""
    cls = read_components_stamp(decompiled_dir)
    if cls is not None:
        src = os.path.join(decompiled_dir, cls['src'])
        if os.path.isfile(src):
            return src
    for root, _dirs, files in os.walk(decompiled_dir):
        parts = root[len(decompiled_dir):].lstrip(os.sep).split(os.sep)
        if not any(SMALI_DIR_RE.match(p) for p in parts if p):
            continue
        if STUB_FILE in files and root.endswith(os.path.join(*STUB_PKG_DIR)):
            return os.path.join(root, STUB_FILE)
    return None

def _make_stub_methods_native(stub_smali: str, work_dir: str) -> str:
    """把桩里【已交给 dex2c 的 4 个方法】改成 native 壳，返回改写后的副本路径。

    改哪些：STUB_DECRYPT_METHOD（随机名，即 d）、STUB_KERNEL_METHOD（dn）、
            mix64、keyByte —— 正是 --emit-stub-filter 产出的那四条。
    不改哪些：<clinit>（建 L1 缓存，dex2c 没转译它）、SEED 等字段。

    为什么必须保留方法【签名与访问标志】：native 方法靠 JNI 短名绑定
    （Java_<pkg>_<Cls>_<method>__<proto>），签名变了 libnc.so 里就找不到实现。

    安全边界：
      · 只改 .method 头为 .method native，方法体整段丢弃，保留 .end method
        （原 mark-native 的教训：吞掉 .end method 会报 missing END_METHOD_DIRECTIVE）
      · 若某个方法没找到，返回原路径（不静默报错）：说明该包没走 dex2c 联动，
        此时保留明文是正确的（桩是唯一实现）。
    """
    import re as _re
    import shutil as _shutil

    target_names = {STUB_DECRYPT_METHOD, STUB_KERNEL_METHOD, 'mix64', 'keyByte'}

    with open(stub_smali, encoding='utf-8') as fp:
        content = fp.read()

    lines = content.split('\n')
    out = []
    i = 0
    n_native = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        if not s.startswith('.method'):
            out.append(line)
            i += 1
            continue
        m = _re.match(r'\.method\s+(.*\S)\s*(\(.*\)\S+)\s*$', s)
        if not m:
            out.append(line)
            i += 1
            continue
        toks = m.group(1).split()
        name, proto = toks[-1], m.group(2)
        flags = ' '.join(toks[:-1])
        if name not in target_names:
            out.append(line)
            i += 1
            continue
        # 找本方法的 .end method
        j = i
        while j < len(lines) and lines[j].strip() != '.end method':
            j += 1
        if j >= len(lines):
            out.append(line)
            i += 1
            continue
        out.append(f'.method native {flags} {name}{proto}'.rstrip())
        out.append('.end method')
        i = j + 1
        n_native += 1

    if n_native == 0:
        # 一个都没改 → 没有 dex2c 联动，保持原样（明文是唯一实现）
        return stub_smali

    new_path = os.path.join(work_dir, 'StubNative.smali')
    with open(new_path, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(out))
    return new_path


def read_app_package_name(decompiled_dir: str):
    """从解包目录的 AndroidManifest.xml 取应用包名（二进制 AXML / 文本 XML 都支持）。

    为什么要它：壳包名规则是【应用包名 + ".shell"】（dpt 的
    resolveDefaultShellPackageName），桩要调 JniBridge.gseed() 就必须知道
    这个包名才能拼出 Lcom/<pkg>/shell/JniBridge;。

    失败返回 None（调用方按"未启用联动"处理，不静默拼一个错包名）。
    """
    manifest = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    if not os.path.isfile(manifest):
        return None
    with open(manifest, 'rb') as fp:
        head = fp.read(4)
    text = None
    if head == b'\x03\x00\x08\x00':          # 二进制 AXML
        try:
            # 复用 inject-loadlib 的 androguard 导入路径（含 dcc 载体定位）
            import importlib.util as _ilu
            spec = _ilu.spec_from_file_location(
                'inject_loadlib',
                os.path.join(_HERE, '..', 'inject', 'inject-loadlib.py'))
            mod = _ilu.module_from_spec(spec)
            spec.loader.exec_module(mod)
            ag_dir = mod._ensure_dcc_dir()
            if ag_dir not in sys.path:
                sys.path.insert(0, ag_dir)
            from androguard.core.bytecodes.axml import AXMLPrinter
            with open(manifest, 'rb') as fp:
                xml = AXMLPrinter(fp.read()).get_xml()
            text = xml.decode('utf-8', 'replace') if isinstance(xml, bytes) else str(xml)
        except Exception as e:
            print(f'⚠️ 读 Manifest 包名失败: {type(e).__name__}: {e}', file=sys.stderr)
            return None
    else:                                     # 文本 XML
        with open(manifest, encoding='utf-8', errors='replace') as fp:
            text = fp.read()
    m = re.search(r'<manifest[^>]*\bpackage\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else None


def _inject_loadlib_into_stub_clinit(stub_smali: str, work_dir: str) -> str:
    """在桩的 <clinit> 最前面插入 System.loadLibrary("nc")。

    为什么必须有这一步（2026-10-31 真机 logcat 实证的崩溃）：
      · 桩的 md()/dn()/mix64()/keyByte() 被 _make_stub_methods_native 改成 native
      · 真实 Application 的 <clinit> 里有被 stringenc 加密的字符串 → 调 md()
      · 而 so 的加载点原来只在 MainActivity.<clinit>（inject-loadlib 插的），
        Application 比 Activity 早 → 此刻 so 还没加载
      · → UnsatisfiedLinkError: No implementation found for ...md()
      · → 启动即闪退

    为什么插在【桩自己的 <clinit>】而不是宿主 Application 的 <clinit>：
      1. JVM 规范保证：类的静态方法被调用前，JVM 必须先完成该类初始化。
         所以无论谁、在什么时候调 md()，这个 <clinit> 一定已经跑完 ——
         不依赖插入位置，也不依赖宿主类形态（混淆改名也不影响）。
      2. 覆盖所有调用点，不只 Application 那一段。
      3. 插在宿主 <clinit> 里还可能踩「静态字段初始化器先于静态块执行」
         的顺序陷阱（字段初始化调 md() 时 loadLibrary 还没跑）。

    为什么 <clinit> 本身不会被 dex2c 抽走：filter 首行恒为 `!<clinit|init>`
    （rules-to-filter.py / make-filter-from-apk.py 都硬写），所以它有实体可改。

    ⚠️ 与 _patch_stub_seed_from_shell 的分工：
      那个负责 SEED 从壳取（可选特性），本函数负责 so 加载（**无条件必需**）。
      历史 bug 的成因就是这两件事被绑在一起——只有开 --stub-seed-from-shell
      时才插 loadLibrary，于是不开就闪退。

    幂等：已含 loadLibrary("nc") 时原样返回。
    失败：<clinit> 缺失 → 返回原内容（桩骨架变了，交给上层日志/断言暴露）。
    """
    if 'loadLibrary' in stub_smali:
        return stub_smali

    clinit_re = re.compile(
        r'(\.method static constructor <clinit>\(\)V\s*\n)([ \t]*)\.locals\s+(\d+)')
    m = clinit_re.search(stub_smali)
    if not m:
        return stub_smali

    nlocals = int(m.group(3))
    need = max(nlocals, 1)   # 只需 v0 放 "nc" 字符串

    inject = (
        f'{m.group(1)}{m.group(2)}.locals {need}\n\n'
        f'{m.group(2)}const-string v0, "nc"\n\n'
        f'{m.group(2)}invoke-static {{v0}}, Ljava/lang/System;'
        f'->loadLibrary(Ljava/lang/String;)V\n\n'
    )
    return stub_smali[:m.start()] + inject + stub_smali[m.end():]


def _patch_stub_seed_from_shell(stub_smali: str, shell_jni_desc: str,
                                work_dir: str) -> str:
    """把桩的 SEED 改成运行期从壳取（`SEED = <shellJni>->gseed()`）。

    改什么：
      · `.field private static final SEED:J = 0x...L` → 去掉 final 与初值
        （`final` + `<clinit>` 赋值是合法的，但去掉 final 更稳：避免 d8 把它
        当编译期常量再内联一份回去）。
      · `<clinit>` 开头插 `invoke-static {}, <jni>->gseed()J` + `move-result-wide`
        + `sput-wide ... SEED:J`。

    为什么必须放在 <clinit>【最前面】：CACHE 的 new-instance 也在 <clinit> 里，
    顺序无所谓；但 SEED 必须在任何 dn() 调用前就绪 —— dn() 由业务代码在
    类初始化之后调用，所以 <clinit> 内任意位置都行，取最前最直观。

    返回改写后的副本路径；找不到锚点返回原路径（不静默毁掉桩）。
    """
    with open(stub_smali, encoding='utf-8') as fp:
        content = fp.read()

    # 1) SEED 字段：去 final、去初值
    field_re = re.compile(
        r'^([ \t]*)\.field private static final SEED:J = [^\n]*$', re.M)
    if not field_re.search(content):
        return stub_smali
    content = field_re.sub(
        r'\1.field private static SEED:J', content, count=1)

    # 2) <clinit> 最前插 gseed 调用
    clinit_re = re.compile(
        r'(\.method static constructor <clinit>\(\)V\s*\n)([ \t]*)\.locals\s+(\d+)')
    m = clinit_re.search(content)
    if not m:
        # 没有 <clinit> → 不擅自造一个（桩骨架必定有，缺了说明骨架变了）
        return stub_smali
    nlocals = int(m.group(3))
    # 需要 2 个 wide 寄存器（v0/v1）；不够就抬 .locals
    need = max(nlocals, 2)
    # ⚠️ 本函数【只负责 SEED 从壳取】，不负责 so 加载 ——
    #   loadLibrary("nc") 已由 _inject_loadlib_into_stub_clinit 无条件插入
    #   （那是 native 方法能跑的前提，与"SEED 藏不藏"无关）。
    #   历史 bug：这两件事曾绑在一起，只有开 --stub-seed-from-shell 才插
    #   loadLibrary → 不开就闪退。现已解耦。
    inject = (
        f'{m.group(1)}{m.group(2)}.locals {need}\n\n'
        f'{m.group(2)}invoke-static {{}}, {shell_jni_desc}->gseed()J\n\n'
        f'{m.group(2)}move-result-wide v0\n\n'
        f'{m.group(2)}sput-wide v0, {STUB_DESC}->SEED:J\n'
    )
    content = content[:m.start()] + inject + content[m.end():]

    out = os.path.join(work_dir, 'StubFromShell.smali')
    with open(out, 'w', encoding='utf-8') as fp:
        fp.write(content)
    return out


def _stub_transpiled(compiled_methods: str, stub_path: str,
                     stub_filter: str = "") -> bool:
    """判断 dex2c 是否真的会转译桩类。

    两条判据，任一成立即为 True：

    ① **filter 规则命中桩类**（首选，2026-11-02 新增）
       联动时 protect.sh 用 `--emit-stub-filter` 产出 filter，
       dex2c 就是按这份 filter 转译的 —— 只要 filter 里有桩类规则，
       dex2c 就必然会转译那 4 个方法。这是【输入侧】判据，
       在 dex2c 跑之前就能确定，不依赖 compiled_methods.txt 是否存在。
       `--emit-stub-dex` 在前置轮（dex2c 之前）调用，
       那时 compiled_methods.txt 尚不存在 → 旧判据恒 False → 桩永远
       不 native 化 → 勾了「解密桩也抽进 so」也白勾（CI 41447382614 实证：
       日志同时出现「桩未被 dex2c 转译」与「compiled_methods 剔除桩条目 4 条」
       两句自相矛盾的话）。

    ② **compiled_methods.txt 里有桩类条目**（原判据，保留作兼容）
       用于 dex2c 已经跑完的场合（STEP5 复用同一解包目录等）。

    为什么必须判断而不是"有桩就 native 化"：
      不勾 --dex2c-stub 时 dex2c 的 filter 里没有桩类 → 桩不会进 so
      → native 化 = 声明了 native 却没有实现 → 运行期 ULE（真机实证）。

    边界：两条判据都不成立 → 返回 False（不 native 化）。代价是桩以明文
      留在壳 dex（少了"算法进 so"的收益），但绝不会闪退 —— 正确性优先于强度。
    """
    # stub_path: .../smali_classes2/el/za/jl/yh.smali → Lel/za/jl/yh;
    norm = stub_path.replace('\\', '/')
    m = re.search(r'/(smali[^/]*)/(.+)\.smali$', norm)
    if not m:
        return False
    desc = 'L' + m.group(2) + ';'

    # ① filter 规则判据（输入侧，前置于 dex2c）
    if stub_filter and os.path.isfile(stub_filter):
        try:
            with open(stub_filter, encoding='utf-8') as fp:
                for line in fp:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # filter 行形如 `Lel/za/jl/yh;dn(.*)` / `Lel/za/jl/yh;.*`
                    if line.startswith(desc):
                        return True
        except OSError:
            pass

    # ② compiled_methods 判据（输出侧，dex2c 跑完之后才有效）
    if not compiled_methods or not os.path.isfile(compiled_methods):
        return False
    try:
        with open(compiled_methods, encoding='utf-8') as fp:
            for line in fp:
                if line.startswith(desc):
                    return True
    except OSError:
        return False
    return False


def emit_stub_dex(decompiled_dir: str, out_path: str, repo_root: str,
                  seed_from_shell: bool = False,
                  compiled_methods: str = "",
                  stub_filter: str = "",
                  assume_transpiled: bool = False) -> bool:
    """把【注入后的解密桩类】单独汇编成一个 dex 文件（packer 联动用）。

    为什么需要单独一个 dex：
      dpt 加壳会把业务 dex 的方法体全部抽空/搬进 xixin_data，只留下 00 0e 填充。
      解密桩若留在业务 dex 里，脱壳者 dump 出来就能直接读它的算法与种子。
      把桩合并进【壳 dex】(dpt --extra-dex) 后，业务 dex 里只剩
      `invoke-static Lcom/xxx/StrDec;->d(...)` 这种指向壳内类的调用点。

    为什么走 apktool.jar 内置的 SmaliBuilder 而不是 `apktool b`：
      `apktool b` 要求目录里先有 apktool.yml（必须是 apktool d 的产物），
      而我们只有一个裸 smali 文件（桩名每包随机，只有这一份权威形态）。
      SmaliBuilder.buildFile(File, DexBuilder) 恰好是"单文件 smali → dex"。
      不引入新依赖：apktool.jar 已是本仓库冻结资产（tools/apktool.jar）。

    返回 True = 已写出 dex；False = 桩不存在（调用方据此判定联动不成立）。
    任何汇编失败都 fail-fast：静默产出空/坏 dex 会让 dpt 合并进一个垃圾类。
    """
    stub_path = find_stub_path(decompiled_dir)
    if stub_path is None:
        return False

    apktool = os.path.join(repo_root, 'tools', 'apktool.jar')
    if not os.path.isfile(apktool):
        raise SystemExit(f'❌ --emit-stub-dex 需要 tools/apktool.jar，未找到: {apktool}')

    import shutil
    import subprocess
    import tempfile

    work = tempfile.mkdtemp(prefix='stubdex-')
    try:
        # ── 先把 4 个已交给 dex2c 的方法改成 native 壳（2026-10-26）──────
        # 为什么要做：桩类进壳 dex 时若保留方法体，脱壳者反编译壳 dex 就能
        # 直接读到 mix64/dn 的完整算法 —— 与"把桩搬进壳"的初衷相悖。
        # dex2c 已把这 4 个方法转译进 libnc.so（实测 .dynsym 有对应
        # Java_<桩>_dn/mix64/keyByte/lu 符号），所以 dex 侧只需留 native 声明。
        #
        # 为什么在【汇编前】改 smali 而不是改 dex：
        #   smali 是桩的唯一权威形态，改它可以复用 apktool 的汇编器做语法校验；
        #   直接改 dex 字节要自己维护 code_item/class_data 的偏移，风险高。
        #
        # 只 native 化 filter 命中的 4 个方法（由 --emit-stub-filter 的固定
        # 列表决定），<clinit> 必须保留 —— 它建 L1 缓存，dex2c 没转译它。
        #
        # ⚠️⚠️ 关键前置判断（2026-10-31 修严重静默 bug）：
        #   只有当【dex2c 真的转译了桩】时才 native 化。
        #   判据 = compiled_methods.txt 里有桩类的方法条目。
        #
        #   不判断的后果（真机实测，构建全绿但装上去启动即闪退）：
        #     dex2c + stringenc + packer（不勾 --dex2c-stub）
        #     → 桩被摘到壳 dex、4 个方法被改成 native
        #     → 但 dex2c 从未转译桩，libnc.so 里没有实现
        #     → 启动调 md() → UnsatisfiedLinkError
        #
        #   不 native 化时桩保持明文 Java 方法，在壳 dex 里自给自足，
        #   根本不需要 libnc.so —— 这是「不勾联动」的正确行为。
        stub_native_ok = assume_transpiled or _stub_transpiled(
            compiled_methods, stub_path, stub_filter)
        if stub_native_ok:
            stub_smali = _make_stub_methods_native(stub_path, work)
            stub_methods_native = os.path.isfile(stub_smali)
        else:
            stub_smali = stub_path
            stub_methods_native = False
            print('  ℹ️ 桩未被 dex2c 转译 → 保持明文 Java（不 native 化，不需要 libnc.so）')
        if not stub_methods_native:
            # 没 native 化（未走 dex2c 联动）→ 汇编要用原始文件路径。
            stub_smali = stub_path

        # ── ⚠️ native 化后必须让桩自己加载 libnc.so（2026-10-31 修真 bug）──
        # 因果链（真机 logcat 实证）：
        #   1. 桩的 md()/dn()/mix64()/keyByte() 被改成 native
        #   2. 真实 Application 的 <clinit> 里有加密字符串 → 调 md()
        #   3. 此刻 so 尚未 loadLibrary（原来只有 MainActivity.<clinit> 插了）
        #      → UnsatisfiedLinkError → 启动即闪退
        # 修法：插进【桩自己的 <clinit> 最前面】。JVM 规范保证「类的静态方法
        #   被调用前必须先完成该类初始化」，所以无论谁在什么时候调 md()，
        #   so 一定已经加载完 —— 不依赖宿主类形态，也不依赖插入位置。
        #
        # 为什么不只依赖 inject-loadlib 插在 Application.<clinit>：
        #   · 依赖宿主类形态（混淆改名后可能插不上）
        #   · 静态字段初始化器可能先于静态块执行，插错位置照样崩
        #   · 覆盖面只到 Application，别处（ContentProvider 等）仍可能踩到
        if stub_methods_native:
            with open(stub_smali, encoding='utf-8') as fp:
                _native_src = fp.read()
            _patched = _inject_loadlib_into_stub_clinit(_native_src, work)
            if _patched != _native_src:
                with open(stub_smali, 'w', encoding='utf-8') as fp:
                    fp.write(_patched)
                print('  🔗 桩 <clinit> 已插入 loadLibrary("nc")'
                      '（native 方法需 so 先就绪）')
            else:
                print('  ⚠️ 桩 <clinit> 插入 loadLibrary 未生效'
                      '（骨架无 <clinit>？）', file=sys.stderr)

        # ── SEED 改为运行期从壳取（packer 联动，可选）────────────────────
        # 为什么：桩的 4 个算法方法已 native 化进 libnc.so，此时 SEED 若还是
        # dex 里的字面量常量，脱壳者读壳 dex 就拿到密钥 —— 前两步白做。
        # 改成 `<clinit>` 里调壳的 JniBridge.gseed()：删掉壳（assets/xixin 下
        # 的 so/配置 + 壳 dex）→ NoClassDefFoundError → App 直接崩。
        # 这才是"必须带着壳运行"的联动。
        if seed_from_shell:
            pkg = read_app_package_name(decompiled_dir)
            if not pkg:
                raise SystemExit(
                    '❌ --stub-seed-from-shell：读不到应用包名，无法定位壳的 JniBridge。\n'
                    '   壳包名规则 = <应用包名>.shell（dpt 的 resolveDefaultShellPackageName）')
            shell_pkg_slash = pkg.replace('.', '/') + '/shell'
            jni_desc = 'L' + shell_pkg_slash + '/JniBridge;'
            # ⚠️ 该函数收【路径】、返回【路径】（内部自己 open/写文件），
            #    不能传内容。
            patched = _patch_stub_seed_from_shell(stub_smali, jni_desc, work)
            if patched == stub_smali:
                raise SystemExit(
                    '❌ --stub-seed-from-shell：桩骨架里找不到 SEED 字段或 <clinit>，\n'
                    '   无法改成从壳取（骨架形态变了？）。拒绝产出"以为改了其实没改"的桩。')
            stub_smali = patched
            print(f'  🔑 SEED 改为运行期从壳取: {jni_desc}->gseed()')
        # 驱动类：用 apktool.jar 自带的 SmaliBuilder 把单个 smali 汇编成 dex。
        # 走独立 JVM 而不是在同一进程里反射，避免污染本进程的 smali 状态。
        driver = os.path.join(work, 'StubDex.java')
        with open(driver, 'w', encoding='utf-8') as fp:
            fp.write('''
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.writer.builder.DexBuilder;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import brut.androlib.smali.SmaliBuilder;
import java.io.File;

public class StubDex {
    public static void main(String[] a) throws Exception {
        int api = 26;
        DexBuilder dexBuilder = new DexBuilder(new Opcodes(api));
        new SmaliBuilder(api).buildFile(new File(a[0]), dexBuilder);
        dexBuilder.writeTo(new FileDataStore(new File(a[1])));
    }
}
''')

        src_dir = os.path.join(work, 'src')
        os.makedirs(src_dir, exist_ok=True)
        shutil.copy2(driver, src_dir)

        dex_out = os.path.join(work, 'stub.dex')
        proc = subprocess.run(
            ['javac', '-cp', apktool, '-d', os.path.join(work, 'classes'), driver],
            capture_output=True, text=True)
        if proc.returncode != 0:
            raise SystemExit('❌ --emit-stub-dex 编译驱动失败:\n'
                             + (proc.stderr or proc.stdout or '')[-2000:])

        cp = os.path.join(work, 'classes') + os.pathsep + apktool
        proc = subprocess.run(
            ['java', '-cp', cp, 'StubDex', stub_smali, dex_out],
            capture_output=True, text=True)
        if proc.returncode != 0 or not os.path.isfile(dex_out):
            raise SystemExit('❌ --emit-stub-dex 汇编桩失败（SmaliBuilder）:\n'
                             + (proc.stderr or proc.stdout or '')[-2000:])

        with open(dex_out, 'rb') as fp:
            data = fp.read()
        if len(data) < 112 or data[:4] != b'dex\n':
            raise SystemExit('❌ --emit-stub-dex 产物不是合法 dex')

        os.makedirs(os.path.dirname(os.path.abspath(out_path)) or '.', exist_ok=True)
        with open(out_path, 'wb') as fp:
            fp.write(data)
        return True
    finally:
        shutil.rmtree(work, ignore_errors=True)

def remove_stub_by_scan(decompiled_dir: str) -> str:
    """按【结构特征】扫出解密桩并摘除（不依赖组件标记，也不依赖注释）。

    为什么不能用 STUB_GEN_MARK 识别：
      那是 smali 注释（`# nc-strdec-gen v2`），而注释不进 dex ——
      LINK_STUB 路径下桩要跨一次 apktool 回编/解包，注释在这一步被丢弃
      （实测：回编再解包后桩文件里没有该行）。

    为什么不能用组件标记：
      `stringenc-components.json` 是普通文件，apktool b 不把它打进 APK，
      重新解包后标记就没了；且 STUB_FILE/STUB_PKG_DIR 此时还是 legacy 默认
      值（随机名只活在上一轮进程内存里）。

    所以只认桩的【结构不变量】——这些是 S2 桩骨架的固定成员，
    桩随机化只改类名与解密主方法名，不会动它们：
      · `.field private static final SEED:J`
      · `.field private static final CACHE:Ljava/util/concurrent/ConcurrentHashMap;`
      · `.field private static final GAMMA:J`
      · 方法 mix64 / keyByte
      四条全中才算桩。用户类要同时命中这四项几乎不可能（且我们只在
      smali*/ 里扫，范围最小）。

    安全边界：命中多个即 fail-fast 拒绝猜（宁可人工确认，不误删用户类）。
    返回被删除路径（空串 = 没找到）。
    """
    NEEDLES = (
        'SEED:J',
        'CACHE:Ljava/util/concurrent/ConcurrentHashMap;',
        'GAMMA:J',
        'mix64',
        'keyByte',
    )
    candidates = []
    for root, _dirs, files in os.walk(decompiled_dir):
        parts = root[len(decompiled_dir):].lstrip(os.sep).split(os.sep)
        if not any(SMALI_DIR_RE.match(p) for p in parts if p):
            continue
        for name in files:
            if not name.endswith('.smali'):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, encoding='utf-8') as fp:
                    content = fp.read()
            except OSError:
                continue
            if all(n in content for n in NEEDLES):
                candidates.append(path)
    if not candidates:
        return ''
    if len(candidates) > 1:
        raise SystemExit(
            '❌ remove-stub 扫到多个疑似桩文件，拒绝猜：\n  '
            + '\n  '.join(candidates)
            + '\n   请人工确认后删除多余项。')
    path = candidates[0]
    try:
        os.remove(path)
    except OSError as e:
        raise SystemExit(f'❌ 摘除桩失败（{path}）: {e}')
    d = os.path.dirname(path)
    try:
        while d and os.path.abspath(d) != os.path.abspath(decompiled_dir):
            if os.path.isdir(d) and not os.listdir(d):
                os.rmdir(d)
                d = os.path.dirname(d)
            else:
                break
    except OSError:
        pass
    return path


def remove_stub_from_business(decompiled_dir: str) -> str:
    """把解密桩类文件从解包目录摘除（桩已搬进壳 dex）。

    为什么必须删：
      只产出 stub.dex 而不删业务侧，桩会同时存在于业务 dex 与壳 dex 两处。
      业务 dex 那一份会被 dpt 抽空、方法体搬进 xixin_data —— 脱壳者拿到的
      是完整的桩结构（算法 + 调用形态），联动价值归零。

    为什么删了还能回编：
      smali 汇编允许引用不存在的类（multidex 常态：跨 dex 引用本就靠运行期
      解析）。实测 apktool.jar 的 SmaliBuilder 对
      `invoke-static Lcom/x/StrDec;->d(...)` 指向缺失类时正常产出 dex。
      运行期由壳 dex 提供该类，类加载器能跨 dex 解析。

    幂等性关键：
      摘除前把 moved_to_shell_dex / decrypt_method 写进组件标记。
      否则第二次运行时 recover_identifiers_from_stamp 会认为"标记指向的桩
      文件不见了"→ fail-fast（实测踩过）。标记仍在 = clean 的依据仍在。

    返回被删除的路径（空串 = 没找到桩）。
    """
    stub_path = find_stub_path(decompiled_dir)
    if stub_path is None:
        return ''
    # 先记状态再删文件：删成功但标记没写上，就变成不可恢复的中间态
    cls = read_components_stamp(decompiled_dir)
    if cls is not None:
        try:
            with open(stub_path, encoding='utf-8') as fp:
                content = fp.read()
            mm = re.search(
                r'^\.method public static (\S+)\(Ljava/lang/String;\)Ljava/lang/String;',
                content, re.M)
            method = mm.group(1) if mm else STUB_DECRYPT_METHOD
        except OSError:
            method = STUB_DECRYPT_METHOD
        mark_stub_moved_to_shell_dex(decompiled_dir, method)

    try:
        os.remove(stub_path)
    except OSError as e:
        raise SystemExit(f'❌ 摘除桩失败（{stub_path}）: {e}\n'
                         f'   桩若留在业务 dex，联动等于没做，故此处 fail-fast。')
    # 顺手清掉空的包目录（不留空目录，避免 apktool 产出空 dex）
    d = os.path.dirname(stub_path)
    try:
        while d and os.path.abspath(d) != os.path.abspath(decompiled_dir):
            if os.path.isdir(d) and not os.listdir(d):
                os.rmdir(d)
                d = os.path.dirname(d)
            else:
                break
    except OSError:
        pass
    return stub_path


def mark_stub_moved_to_shell_dex(decompiled_dir: str, decrypt_method: str) -> None:
    """在组件标记里登记"桩已搬进壳 dex"（幂等续跑的依据，见 remove_stub_from_business）。"""
    cls = read_components_stamp(decompiled_dir)
    if cls is None:
        return
    path = os.path.join(decompiled_dir, COMPONENTS_FILE)
    try:
        with open(path, encoding='utf-8') as fp:
            payload = json.load(fp)
    except (OSError, ValueError):
        return
    classes = payload.get('classes') or []
    if not classes:
        return
    classes[0]['moved_to_shell_dex'] = True
    classes[0]['decrypt_method'] = decrypt_method
    with open(path, 'w', encoding='utf-8') as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
        fp.write('\n')

def read_existing_salt(decompiled_dir: str):
    """已存在且是本工具生成的桩 → 复用其 SEED(否则旧密文解不开)。
    返回 (seed_bytes 或 None, 是否需要写桩)。同名非本工具文件 → fail-fast。"""
    stub_path = find_stub_path(decompiled_dir)
    if not stub_path:
        return None, True
    with open(stub_path, encoding='utf-8') as fp:
        content = fp.read()
    if STUB_GEN_MARK not in content:
        raise SystemExit(f'❌ 已存在同名类但非本工具生成,拒绝覆盖: {stub_path}\n'
                         f'   请改名或移走用户的 {STUB_DESC} 后重试')
    return read_stub_seed(content), False

def _pick_smali_root(decompiled_dir: str) -> str:
    """桩落在哪个 smali 目录（报错五十九：按容量选，不再固定优先 smali/）。

    旧实现固定优先 `smali/`（= classes.dex）。真实大型包经 R8 编译后
    classes.dex 方法数贴顶（实测囤次元包 65519/65536，余量 17），桩写进去
    会让 smali 汇编期报 "Unsigned short value out of range: 65536"。
    （dex-capacity.py 文档有完整实测过程。）

    现在：够写就仍用 smali/（与改动前逐字节一致）；不够就复用/新建注入
    dex。返回值仍是绝对路径，调用方逻辑不变。
    """
    chosen = _DEX_CAPACITY.pick_target_dir(
        decompiled_dir, need_methods=_STUB_METHOD_BUDGET,
        apk_path=_APK_FOR_CAPACITY)
    return os.path.join(decompiled_dir, chosen)

def write_components_stamp(decompiled_dir: str, cls_desc: str) -> str:
    """记录本次注入的组件(类名 + 源文件路径)。

    报错十八教训:流水线中途会丢失信息(回编降级抹掉 dex 版本),必须在丢失前 save。
    这里同理 —— apktool 重打包会重新分派 dex 号,唯一稳定的定位依据是
    "描述符 + 源文件路径"对。落盘后,`clean` 子命令可长期正确清理残留的桩类
    (例如本次运行一条都没加密、旧桩却还在)。"""
    root = _pick_smali_root(decompiled_dir)
    payload = {
        'version': 1,
        'classes': [{
            'desc': cls_desc,
            'src': os.path.relpath(
                os.path.join(root, *STUB_PKG_DIR, STUB_FILE), decompiled_dir),
        }],
    }
    path = os.path.join(decompiled_dir, COMPONENTS_FILE)
    with open(path, 'w', encoding='utf-8') as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
        fp.write('\n')
    return path

def clean_components(decompiled_dir: str) -> int:
    """按组件标记删除残留的注入物(解密桩)。幂等,清完删标记文件。

    只删标记里登记的路径,且要求两者同时满足「路径在本解包目录内」+
    「文件内容带本工具生成标记」—— 绝不误删用户自己的类。

    fail-fast(报错二十):删桩前先扫全解包目录,若存在仍引用桩的已加密类
    (CLASS_MARK + ->d( / ->F\\d+: 引用),说明上一轮加密产物没被恢复/重建,
    此时删桩会留下半加密目录 → 汇编失败或运行期 NoClassDefFoundError。
    正常流水线每次全新解包不会触发;本地反复调试会踩,拒绝优于静默坏产物。"""
    path = os.path.join(decompiled_dir, COMPONENTS_FILE)
    if not os.path.isfile(path):
        return 0
    # 半加密目录探测:带 CLASS_MARK 且引用本桩的类
    tainted = []
    for cls_path in iter_smali_files(decompiled_dir):
        try:
            with open(cls_path, encoding='utf-8') as fp:
                content = fp.read()
        except OSError:
            continue
        if CLASS_MARK in content and (STUB_DESC + '->' + STUB_DECRYPT_METHOD + '(' in content
                                      or _FIELD_REF_RE.search(content)):
            tainted.append(cls_path)
    if tainted:
        sample = os.path.relpath(tainted[0], decompiled_dir)
        raise SystemExit(
            f'❌ 解包目录存在仍引用解密桩的已加密类({len(tainted)} 个,如 {sample}),\n'
            f'   删除桩会留下半加密目录。请重新解包(全新 mktemp 目录)或先用 git '
            f'恢复原始 smali,\n   再跑本命令。加密类必须在桩存在的前提下进产物。')
    with open(path, encoding='utf-8') as fp:
        payload = json.load(fp)
    root_abs = os.path.abspath(decompiled_dir)
    removed = 0
    for entry in payload.get('classes', []):
        target = os.path.abspath(os.path.join(decompiled_dir, entry.get('src', '')))
        if not target.startswith(root_abs + os.sep):
            continue                                # 标记被篡改 → 绝不越界删除
        if not os.path.isfile(target):
            continue
        with open(target, encoding='utf-8') as fp:
            if STUB_GEN_MARK not in fp.read():
                continue                            # 不是我们的文件 → 不删
        os.remove(target)
        removed += 1
    os.remove(path)
    return removed

def write_stub(decompiled_dir: str, seed: bytes) -> str:
    """写 v2/S2 解密桩。

    S2 的桩是构建期编译产物(build-stub.sh 出的骨架),注入只有一件事:
    把骨架里的哨兵种子替换为本次构建的 8 字节真种子(双锚点同时改)。
    没有 KEYS 表、没有 <clinit>、没有字段回填链 —— 这些在 S2 里全部不存在。

    seed: 8 字节。
    """
    if len(seed) != 8:
        raise SystemExit(f'❌ 内部错误:种子必须是 8 字节,收到 {len(seed)} 字节')
    root = _pick_smali_root(decompiled_dir)
    stub_dir = os.path.join(root, *STUB_PKG_DIR)
    os.makedirs(stub_dir, exist_ok=True)
    stub_path = os.path.join(stub_dir, STUB_FILE)

    skeleton = load_stub_skeleton()
    seed_word = f'0x{int.from_bytes(seed, "big"):016x}L'
    content = inject_stub_seed(skeleton, seed_word)

    # 桩随机化:骨架(缓存产物)固定名 → 本次构建的随机/指定名。
    # 只改 .class 描述符(含桩内全部自引用:CACHE/mix64 共 6 处)与解密主方法名;
    # 字段名(SEED/CACHE)与私有方法名(mix64/keyByte)是锚点/对拍契约,不动。
    # 计数守恒:描述符替换前后总次数必须相等(全量同改,不多不少),
    # 否则说明骨架形态漂移,拒绝产物。
    legacy_method = re.search(
        r'^\.method public static (\S+)\(Ljava/lang/String;\)Ljava/lang/String;',
        content, re.M)
    if legacy_method is None:
        raise SystemExit('❌ 桩骨架自检失败:找不到解密主方法定义(形态漂移?)')
    old_method = legacy_method.group(1)
    n_desc = content.count('Lcom/nc/strdec/StrDec;')
    if n_desc == 0:
        raise SystemExit('❌ 桩骨架自检失败:找不到 legacy 描述符(骨架形态漂移?)')
    if STUB_DESC != 'Lcom/nc/strdec/StrDec;':   # legacy 固定名(--stub-name)时无需改名
        content = content.replace('Lcom/nc/strdec/StrDec;', STUB_DESC)
        if content.count(STUB_DESC) != n_desc \
                or 'Lcom/nc/strdec/StrDec;' in content:
            raise SystemExit('❌ 桩随机化替换终检失败:描述符没换干净/误伤')
    content = content.replace(
        f'.method public static {old_method}(Ljava/lang/String;)Ljava/lang/String;',
        f'.method public static {STUB_DECRYPT_METHOD}(Ljava/lang/String;)Ljava/lang/String;',
        1)
    if f'.method public static {STUB_DECRYPT_METHOD}(' not in content:
        raise SystemExit('❌ 桩随机化替换终检失败:方法名没换干净')

    # 生成标记(非注释行的行首注释即可,注释不进 dex)。必须存在:
    # 续跑时靠它区分"本工具生成的桩"与"用户同名类",决定是复用还是拒绝。
    content = content + f'\n{STUB_GEN_MARK}\n'
    if STUB_GEN_MARK not in content:
        raise SystemExit('❌ 解密桩渲染终检失败:缺少生成标记')
    # 终检:哨兵种子绝不许进产物(否则运行期与构建期密钥流不一致 → 全包乱码)
    if SENTINEL_SEED.rstrip('Ll').lower() in content.lower():
        raise SystemExit('❌ 解密桩渲染终检失败:产物残留哨兵种子')
    with open(stub_path, 'w', encoding='utf-8') as fp:
        fp.write(content)
    return stub_path

def process_file(path: str, cls_desc: str, includes, excludes,
                 exclude_methods, seed: int, next_off: int,
                 algo: str = ALGO_SPLITMIX):
    """就地加密一个 .smali 文件。返回 (改动字符串数, 新 next_off, field_backfills)。

    S2: next_off 是全包虚拟密钥流的下一个可用 offset;每条密文按需消耗
    offset..offset+len 区段,分配器保证不重叠。种子是唯一的构建期密钥材料。
    field_backfills: [{owner_cls, field, type, payload}] —— R8 折叠的
    static final String 常量,初值保持明文,值由 <clinit> 运行期回填(报错二十四/D4)。
    """
    with open(path, encoding='utf-8') as fp:
        content = fp.read()
    if CLASS_MARK in content:
        # 幂等:整类已处理。但仍要把它占用的区段计入,续跑时不重复分配
        return 0, max(next_off, max_existing_idx(content)), []

    lines = content.split('\n')
    out = []
    cur_method = None
    hits = 0
    idx = next_off
    field_backfills = []      # 报错二十四/D4:<clinit> 回填登记
    li = 0
    n_lines = len(lines)
    while li < n_lines:
        line = lines[li]
        li += 1
        stripped = line.strip()
        if stripped.startswith('.method'):
            # 同 mark-native.py:名字取括号前紧邻一段,防参数里嵌方法引用的贪婪误判
            m = re.match(r'\.method\s+(.*\S)\s*(\(.*\)\S+)\s*$', stripped)
            if m:
                toks = m.group(1).split()
                cur_method = (toks[-1], m.group(2))
            else:
                cur_method = None
            out.append(line)
            continue
        if stripped == '.end method':
            cur_method = None
            out.append(line)
            continue

        # R8 折叠的 static final String 常量: .field ... = "明文"
        # (报错二十四)字段初值【保持原字面量不动】—— 绝不允许改成
        # `= StrDec;->FNNNNNN` 引用形态:那会被汇编成 FIELD 型(0x19)
        # encoded static_value,dex 规范不允许 → ART 类初始化阶段
        # (字节码执行之前)即失败,秒闪退且无任何日志。
        # 明文的"隐藏"改由回填实现:在所属类 <clinit> 里注入
        # sget-object(桩字段) + sput-object(本字段),运行期用解密结果
        # 覆盖字面量初值。桩自身 <clinit> 填 F 字段用的就是同一套合法形态。
        fparsed = parse_field_string(line)
        if fparsed and cur_method is None:
            fm, fliteral, ftail = fparsed
            try:
                fplain = smali_unescape(fliteral)
            except ValueError as exc:
                print(f'⚠️ 跳过无法安全解析的字段字面量({exc}): {path}', file=sys.stderr)
                out.append(line)
                continue
            if idx > IDX_MAX:
                raise SystemExit(f'❌ 加密字符串数超过 {IDX_MAX}(idx 3 字节上限),请缩小规则范围')
            if field_literal_is_skipped(fplain):
                # ① 空串:无信息量,且桩对 3 字节 payload 走"原样返回"兜底会返回
                #    Base64 串本身(语义错误)
                # ② 编译器调试/内联标记串:保留明文,不占 idx
                # 两类都【按设计】保留明文初值,断言侧靠同一函数识别(见
                # field_literal_is_skipped 的说明),不会被判成"去初值漏改"。
                out.append(line)
                continue
            fenc = fplain.encode('utf-8')
            # 【报错二十四/D4 + 字段去初值(2026-09-12)】
            # 初值从"明文字面量"改为"无初值":明文不再出现在任何字段声明里,
            # `strings` 扫产物对字段值零命中。字段值仍由 <clinit> 回填链写入
            # (inject_clinit_backfills),链里含 intern(),是字段值的唯一来源。
            #
            # 【与报错二十四的区别(为什么这次允许去初值)】
            # 报错二十四的非法形态是 `.field ... = StrDec;->FNNNNNN`(引用型
            # encoded static_value,FIELD 型 0x19)—— dex 规范不允许。而"无初值"
            # 是 STRING 型初值 offset=0(NO_INDEX),dex 规范明确允许(static
            # final 字段由 <clinit> 赋值是 javac 的常规产物),两者机制不同。
            # 注意:这仍属静态数据区改写,只有 `apktool b` 真汇编 + androguard
            # 读回才能证明合法 —— 冒烟测试⑨/断言 A9 就是干这个的(报错二十四
            # "汇编器宽容 ≠ 产物合法"教训)。
            #
            # 【幂等】初值已去掉的行不匹配 parse_field_string(需要 '= "..."'),
            # 故重跑时自然不重复回填;代价是"初值永远拆不回明文"——这正是本改动
            # 的意图(明文不该留在产物里)。用 git 恢复源码重跑才是重回明文的正路。
            new_field = _strip_field_literal(line, fm)
            if new_field is None:
                print(f'⚠️ 字段行形态无法安全去初值,保持原样: {path}', file=sys.stderr)
                out.append(line)
                continue
            out.append(new_field)
            field_backfills.append({
                'owner_cls': cls_desc,            # Lcom/x/Y; 形式
                'field': fm.group('name'),
                'type': fm.group('type'),
                'payload': encrypt_payload_v2(seed, idx, fenc, algo),
            })
            idx += len(fenc)
            hits += 1
            continue

        excluded_by_dex2c = bool(
            cur_method and (cls_desc, cur_method[0], cur_method[1]) in exclude_methods)

        # 已加密条目(解密桩可能来自上一次运行)→ 跳过,并续用表区段,
        # 避免把密文当明文再加密一次
        if STUB_DESC + '->' + STUB_DECRYPT_METHOD + '(' in line:
            out.append(line)
            midx = max_existing_idx(line + '\n')
            if midx >= 0:
                idx = max(idx, midx)
            continue

        parsed = parse_const_string(line)
        if not parsed:
            out.append(line)
            continue
        # 逐行前瞻防二次加密(报错二十式双保险):即使类标记被外部工具删掉,
        # 密文 const-string 的下一行必是本桩的 invoke-static ...->d(...),
        # 命中即连同密文行原样保留(与上方 ->d( 分支同样的续 offset 语义)
        if li < n_lines and STUB_DESC + '->' + STUB_DECRYPT_METHOD + '(' in lines[li]:
            out.append(line)
            midx = max_existing_idx(line + '\n' + lines[li] + '\n')
            if midx >= 0:
                idx = max(idx, midx)
            continue
        if excluded_by_dex2c:
            out.append(line)                            # 该方法将被 dex2c 抽走 → 不浪费体积
            continue

        m, literal, tail = parsed
        try:
            plain = smali_unescape(literal)
        except ValueError as exc:
            print(f'⚠️ 跳过无法安全解析的字符串({exc}): {path}', file=sys.stderr)
            out.append(line)
            continue

        enc = plain.encode('utf-8')
        if idx + len(enc) > IDX_MAX + 1:
            raise SystemExit(f'❌ 加密字符串总字节数超过密钥流区段上限 {IDX_MAX + 1},'
                             f'请缩小规则范围')
        if is_instrumentation_string(plain) or not enc:
            # 编译器调试/内联标记:保留明文 const-string(见常量区说明)
            # 空串:无信息量,且桩对 3 字节 payload 会走"原样返回"兜底,
            # 把 Base64 串本身当明文返回(语义错误)→ 一律跳过
            out.append(line)
            continue

        payload = encrypt_payload_v2(seed, idx, enc, algo)
        jumbo = m.group('jumbo') or ''
        indent = m.group('indent')
        dst = m.group('dst')
        out.append(f'{indent}const-string{jumbo} {dst}, "{payload}"{tail}')
        # 寄存器宽度陷阱(报错二十一):const-string 是 21c 格式(8 位寄存器,
        # v0–v255),而 invoke-* 是 35c 格式(寄存器列表仅 4 位,上限 v15)。
        # 原 const-string 的目标寄存器可合法取到 v16+(大方法/Compose),或写成
        # pN 而换算后编号 ≥16 → 直接 {dst} 会被 smali 汇编器拒绝,整个重打包
        # 失败("Invalid register: vNN. Must be between v0 and v15" /
        # "The maximum allowed register in this context is list of registers is v15")。
        # 统一用 /range:单寄存器 range 恒连续、dex 中同为 3 个 code unit(无体积
        # 代价),且对 v/p 两种写法都合法 → 无需解析 .registers/.locals 做换算。
        out.append(f'{indent}invoke-static/range {{{dst} .. {dst}}}, '
                   f'{STUB_DESC}->{STUB_DECRYPT_METHOD}(Ljava/lang/String;)Ljava/lang/String;')
        out.append(f'{indent}move-result-object {dst}')
        idx += len(enc)                     # 消费对应表区段(不重叠分配)
        hits += 1

    if hits == 0:
        # 没有新加密,但可能只命中了"已加密条目跳过"分支(类标记丢失 +
        # 三行形态)—— 此时 idx 已被续到旧密文之后,必须带回去,
        # 否则续跑时新条目从 0 分配 → 密钥区段复用(报错二十式)
        return 0, max(next_off, idx), []

    # 插幂等标记注释(注释不进 dex)
    final = []
    marked = False
    for ln in out:
        final.append(ln)
        if not marked and ln.lstrip().startswith('.class'):
            final.append(f'{CLASS_MARK} (do not remove)')
            marked = True
    with open(path, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(final))
    return hits, idx, field_backfills

def inject_clinit_backfills(path: str, backfills) -> bool:
    """报错二十四/D4:在 path 所属类的 <clinit> 末尾(return-void 之前)注入:

        const-string v0, "<密文>"
        invoke-static/range {v0 .. v0}, Lcom/nc/strdec/StrDec;->d(...)...
        move-result-object v0
        sput-object v0, <owner>;-><field>:<type>

    为什么必须回填而不能直接改初值:
      static final String 的初值在 dex 里是【字符串常量引用】,若把初值改成
      密文,ART 不会自动解密 → 业务读到密文(错值,且不报错)。而 FIELD 型
      0x19 static_value 直接指向本桩字段在 ART 类初始化时会秒闪退且无日志
      (报错二十四)。唯一合法形态就是"初值保持明文 + <clinit> 运行期覆盖"。

    S2 形态比 v1 更轻: 不再需要每个字段一个桩字段 FNNNNNN,密文直接内联在
    <clinit> 的 const-string 里 —— 桩里零字段、零表。

    <clinit> 不存在则新建(.locals 1,只用 v0,恒在 21c/35c 上限内)。
    返回是否发生了注入。"""
    with open(path, encoding='utf-8') as fp:
        content = fp.read()

    lines = content.split('\n')
    clinit_idx = None          # '.method static constructor <clinit>()V' 行号
    clinit_end = None
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('.method') and 'constructor' in s and '<clinit>' in s:
            clinit_idx = i
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == '.end method':
                    clinit_end = j
                    break
            break
    has_clinit = clinit_idx is not None and clinit_end is not None

    # 回填体:全部走 v0(自依赖链,任何 <clinit> 都容得下一个 v0)
    fill_lines = []
    for bf in backfills:
        payload = bf['payload']
        ty = bf['type']
        fill_lines.append(f'    const-string v0, "{payload}"')
        fill_lines.append(f'    invoke-static/range {{v0 .. v0}}, '
                          f'{STUB_DESC}->{STUB_DECRYPT_METHOD}(Ljava/lang/String;)Ljava/lang/String;')
        fill_lines.append('    move-result-object v0')
        # 【intern (2026-09-12)】字段去初值后,常量的 interned 实例来自这里,
        # 必须保持"解密结果 == 编译期字面量"的引用语义(历史 §3.7.4 曾依赖它)。
        fill_lines.append('    invoke-virtual {v0}, '
                          'Ljava/lang/String;->intern()Ljava/lang/String;')
        fill_lines.append('    move-result-object v0')
        fill_lines.append(f'    sput-object v0, {bf["owner_cls"]}->{bf["field"]}:{ty}')

    if has_clinit:
        # <clinit> 的 .locals/.registers 至少要能容纳 v0
        for j in range(clinit_idx, clinit_end):
            mm = re.match(r'[ \t]*\.(?P<kind>registers|locals)[ \t]+(?P<n>\d+)[ \t]*$',
                          lines[j])
            if mm and int(mm.group('n')) < 1:
                lines[j] = re.sub(r'\.(?P<k>registers|locals)[ \t]+\d+',
                                  lambda mo: f'.{mo.group("k")} 1', lines[j], count=1)
                break
        insert_at = clinit_end
        for j in range(clinit_end - 1, clinit_idx, -1):
            if lines[j].strip() == 'return-void':
                insert_at = j
                break
        lines[insert_at:insert_at] = fill_lines
    else:
        # 无 <clinit> → 追加一个最小的(放在最后一个 .method 之后、类体末尾)
        last_end = 0
        for j, ln in enumerate(lines):
            if ln.strip() == '.end method':
                last_end = j
        new_clinit = ['', '.method static constructor <clinit>()V', '    .locals 1', '']
        new_clinit += fill_lines
        new_clinit += ['', '    return-void', '.end method']
        lines[last_end + 1:last_end + 1] = new_clinit

    with open(path, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(lines))
    return True

def main():
    argv = sys.argv[1:]
    # 子命令:clean(按组件标记清残留,幂等) | encrypt(默认)
    if argv and argv[0] == 'clean':
        if len(argv) != 2:
            print('用法: encrypt-strings.py clean <解包目录>', file=sys.stderr)
            return 1
        removed = clean_components(argv[1])
        print(f'✅ 清理残留解密桩: {removed} 个')
        return 0

    # 子命令:emit-stub-decl（2026-11-09）
    #   只【算出】本次要用的随机桩名并写出去，不加密、不注入、不碰 smali。
    #   为什么需要它：纯 C 桩的 RegisterNatives 需要真实类名，而类名是
    #   本模块在 STEP5 才生成的（每包随机）。STEP3 编 so 时必须先知道它。
    #   解法不是"把 stringenc 整体提前"（那会破坏 STEP2 的 dex2c 顺序），
    #   而是把【名字】这一个信息提前算出来 —— 名字的生成规则不依赖
    #   解包目录内容（除了撞名检查，而撞名检查用的是同一批随机序列）。
    #
    #   输出格式（一行一字段，供 bash 用 IFS 读）：
    #     <斜杠分隔类名>	<方法名>	<点分包名>	<类名>
    #   固定名（--stub-name）与随机名都支持；给出 --seed-hex 时不使用。
    if argv and argv[0] == 'emit-stub-decl':
        if len(argv) < 3:
            print('用法: encrypt-strings.py emit-stub-decl <解包目录> '
                  '<种子hex> [--stub-name 包.类[:方法]]', file=sys.stderr)
            return 1
        _dec = argv[1]
        _seed_hex = argv[2]
        _spec = None
        if '--stub-name' in argv:
            _i = argv.index('--stub-name')
            if _i + 1 < len(argv):
                _spec = argv[_i + 1]
        if len(_seed_hex) != 16:
            print(f'❌ 种子必须是 16 位 hex（本次 {len(_seed_hex)} 位）', file=sys.stderr)
            return 1
        # 与主流程同源：先看组件标记（续跑复用），再 --stub-name，最后随机
        if not recover_identifiers_from_stamp(_dec):
            if _spec:
                apply_stub_identifiers(*parse_stub_name(_spec))
            else:
                # 撞名检查需要解包目录；无解包目录时退化为"不检查"
                # （随机名撞现有类的概率 <10^-5，且真正写入时会再查一次）
                apply_stub_identifiers(*generate_stub_identifiers())
        print('%s\t%s\t%s\t%s' % (
            STUB_DESC[1:-1], STUB_DECRYPT_METHOD,
            '.'.join(STUB_PKG_DIR), STUB_FILE[:-len('.smali')]))
        return 0

    # 子命令:remove-stub(只摘除桩,不加密不注入)
    #   dex2c 联动的前置轮必须保住桩（--keep-stub-in-dex）让 dex2c 能转译
    #   dn()/mix64()/keyByte() 进 libnc.so；摘除推迟到 STEP5 解包之后再执行。
    #   早摘 = dex2c 抽不到内核；晚摘（回编后）= 桩已经进产物。
    if argv and argv[0] == 'remove-stub':
        if len(argv) != 2:
            print('用法: encrypt-strings.py remove-stub <解包目录>', file=sys.stderr)
            return 1
        removed = remove_stub_by_scan(argv[1])
        print(f"  🚚 桩已从业务 dex 摘除: {removed}" if removed
              else '  ℹ️  本解包目录没有桩（已搬走或本次未注入）')
        return 0

    ap = argparse.ArgumentParser(
        description='dex 层字符串常量加密(按 dcc 同款规则选类,注入 Java 解密桩)')
    ap.add_argument('decompiled', help='apktool 解包目录(含 smali*/)')
    ap.add_argument('rules', help='类名规则文件(语法同 dex2c_rules)')
    ap.add_argument('--classes', help='activity* 展开所需类列表(make-filter-from-apk 产物)')
    ap.add_argument('--exclude-methods',
                    help='compiled_methods.txt:这些方法将被 dex2c 抽走,跳过不加密')
    ap.add_argument('--seed-hex', help='固定种子(8 字节 hex),仅供测试/复现')
    ap.add_argument('--stub-name',
                    help="固定桩名 '包名.类名[:方法名]'(如 com.nc.strdec.StrDec:d),"
                         "仅供测试/复现;不传 = 每包随机生成(生产默认,防引擎固定签名)")
    ap.add_argument('--stub-impl', choices=('java', 'native'), default='java',
                    help="解密桩实现：java（默认，现有 Java 桩 + 可选 dex2c 联动）"
                         "或 native（纯 C，算法在 libnc.so，dex 侧只有 native 声明）。"
                         "native 模式下 --emit-stub-filter / --emit-stub-dex "
                         "无意义（不存在 Java 内核可转译），会被显式拒绝。")
    ap.add_argument('--algo', choices=(ALGO_SPLITMIX, ALGO_CHACHA20),
                    default=ALGO_SPLITMIX,
                    help="密钥流算法（仅对 --stub-impl native 有意义）："
                         "splitmix64（默认，速度优先，可逆 —— 猜中一条明文可反推"
                         "密钥解全包）或 chacha20（安全优先，不可逆 —— 猜中一条"
                         "只泄漏那一条）。密文格式两者相同，体积零增长。"
                         "⚠️ 必须与 C 侧 -DNC_STRDEC_ALGO 同源，否则全包乱码")
    ap.add_argument('--assume-stub-transpiled', action='store_true',
                    help='声明"本次 dex2c 会转译桩内核"（由 protect.sh 在'
                         '--dex2c-stub 联动时传入）。用于 --emit-stub-dex '
                         '在前置轮（dex2c 之前）调用时判断是否 native 化 —— '
                         '那时 compiled_methods.txt 还不存在')
    ap.add_argument('--emit-stub-filter',
                    metavar='OUT_PATH',
                    help="把解密桩内核的 dex2c/dcc filter 规则写入该路径(仅一行,"
                         "形如 Lcom/a/b/c/StrDec;dn.*)。供 protect.sh 的 stringenc↔"
                         "dex2c 联动的 filter 追加使用;不传则不产出。桩未注入时不写文件。")
    ap.add_argument('--emit-stub-dex',
                    metavar='OUT_PATH',
                    help="把【注入后的解密桩类】单独汇编成一个 dex 文件写入该路径。"
                         "供 protect.sh 的 packer 联动使用:桩会被 dpt 合并进壳 dex"
                         "(dpt --extra-dex),从而脱离业务 dex。"
                         "桩未注入时不写文件(调用方据此判定联动是否成立)。")
    ap.add_argument('--compiled-methods', metavar='PATH', default='',
                    help='配合 --emit-stub-dex:dex2c 的 compiled_methods.txt。'
                         '用于判断【桩是否真的被转译进 so】—— 只有转了才把桩方法'
                         '改成 native。不传或桩不在其中 → 桩保持明文 Java'
                         '（不需要 libnc.so，避免"声明 native 却无实现"的闪退）。')
    ap.add_argument('--emit-seed', metavar='OUT_PATH',
                    help='把本次的 SEED（16 位 hex）写入该文件。'
                         '供 protect.sh 传给 packer.sh → dpt --stub-seed，'
                         '使壳 config 里的 stub_seed 与桩密文一致。')
    ap.add_argument('--stub-seed-from-shell', action='store_true',
                    help='配合 --emit-stub-dex：把桩的 SEED 改成运行期从壳取'
                         '（<壳包>.shell.JniBridge.gseed()），dex 里不再有字面量。'
                         '删掉壳 → NoClassDefFoundError → App 崩，即"必须带着壳运行"。'
                         '壳包名由 AndroidManifest 的应用包名 + ".shell" 推出。')
    ap.add_argument('--keep-stub-in-dex', action='store_true',
                    help='配合 --emit-stub-dex：只产出桩 dex，不把桩从业务 dex 摘除。'
                         '用于 dex2c 联动的前置轮——桩必须留在 dex 里让 dex2c 转译内核，'
                         '摘除由 STEP5 的 --remove-stub-only 单独完成。')
    ap.add_argument('--quiet', action='store_true', help='只打错误')
    ap.add_argument('--apk', metavar='PATH', default=None,
                    help='原始 APK(报错五十九): 给了就从 dex header 读权威方法数,'
                         '据此决定解密桩落在哪个 dex;不给则按扫描估算(保守上浮)')
    args = ap.parse_args(argv)

    global STUB_IMPL
    STUB_IMPL = args.stub_impl

    # ── native 桩与 Java 专属参数互斥（fail-fast，不静默忽略）──────────
    # 理由：native 桩没有 Java 内核可转译/可搬壳，这些参数若被静默接受，
    # 用户会以为联动生效了，实际什么都没发生（历史上"以为防了其实没防"
    # 的假绿都是这种形态）。
    if STUB_IMPL == 'native':
        _conflict = []
        if args.emit_stub_filter:
            _conflict.append('--emit-stub-filter（dex2c 联动需要 Java 内核）')
        if args.emit_stub_dex:
            _conflict.append('--emit-stub-dex（搬壳需要可汇编的 Java 桩）')
        if args.compiled_methods:
            _conflict.append('--compiled-methods（仅用于判断 Java 桩是否被转译）')
        if args.stub_seed_from_shell:
            _conflict.append('--stub-seed-from-shell（native 桩的密钥注入走 '
                             'ncSetKey，不经 Java 静态字段）')
        if args.assume_stub_transpiled:
            _conflict.append('--assume-stub-transpiled')
        if _conflict:
            print('❌ --stub-impl native 与以下参数不兼容：', file=sys.stderr)
            for c in _conflict:
                print('     · ' + c, file=sys.stderr)
            print('   native 模式下算法在 libnc.so，dex 侧只有 native 声明 —— '
                  '上述参数所依赖的 Java 内核不存在。', file=sys.stderr)
            return 1

    if not os.path.isdir(args.decompiled):
        print(f'❌ 解包目录不存在: {args.decompiled}', file=sys.stderr)
        return 1

    if not os.path.isfile(args.rules):
        print(f'❌ 规则文件不存在: {args.rules}', file=sys.stderr)
        return 1

    includes, excludes, activity_mode = build_matchers(args.rules, args.classes)
    if not includes:
        print('❌ 规则文件没有产生任何包含规则(只有排除/注释?)', file=sys.stderr)
        return 1

    # 报错五十九:把原始 APK 交给容量判定(读 dex header 得权威方法数)。
    # 存放在模块级变量,供 _pick_smali_root() 取用;不设 = 回落扫描估算。
    global _APK_FOR_CAPACITY
    _APK_FOR_CAPACITY = args.apk

    exclude_methods = set()
    if args.exclude_methods:
        if not os.path.isfile(args.exclude_methods):
            print(f'❌ --exclude-methods 文件不存在: {args.exclude_methods}', file=sys.stderr)
            return 1
        exclude_methods = parse_compiled_methods(args.exclude_methods)

    # ── 桩随机化:确定本次的包名/类名/方法名 ──────────────────────────
    # 优先级:组件标记里的既有名(续跑复用,与种子同机制)> --stub-name(测试)
    # > 每包随机(生产默认)。冲突检查:随机名目标文件已存在 = 与用户类撞名,
    # 换一批重试;多次撞名(几乎不可能)fail-fast。
    stub_name_explicit = None
    if args.stub_name:
        stub_name_explicit = parse_stub_name(args.stub_name)
    recovered = recover_identifiers_from_stamp(args.decompiled)
    if recovered:
        if stub_name_explicit:
            pkg_dot, cls, _m = stub_name_explicit
            want_desc = 'L' + pkg_dot.replace('.', '/') + '/' + cls + ';'
            if want_desc != STUB_DESC:
                raise SystemExit(
                    f'❌ --stub-name({stub_name_explicit[0]})与已有桩({STUB_DESC})不一致 ——\n'
                    f'   旧密文的调用点指向已有桩,换名即全包乱码。'
                    f'要改名请先 clean 再重新加密。')
        if not args.quiet:
            print(f'  🔁 复用已有桩: {STUB_DESC}->{STUB_DECRYPT_METHOD}()')
    elif stub_name_explicit:
        apply_stub_identifiers(*stub_name_explicit)
    else:
        for _ in range(16):
            pkg_dot, cls, method = generate_stub_identifiers()
            apply_stub_identifiers(pkg_dot, cls, method)
            target = os.path.join(_pick_smali_root(args.decompiled), *STUB_PKG_DIR, STUB_FILE)
            if not os.path.exists(target):
                break
        else:
            raise SystemExit('❌ 随机桩名连续 16 次与解包目录现有文件冲突,请人工检查解包目录')
        if not args.quiet:
            print(f'  🎲 桩随机化: {STUB_DESC}->{STUB_DECRYPT_METHOD}()')

    if args.seed_hex:
        try:
            seed = bytes.fromhex(args.seed_hex)
        except ValueError:
            print('❌ --seed-hex 不是合法 hex', file=sys.stderr)
            return 1
        if len(seed) != 8:
            print('❌ --seed-hex 必须是 8 字节(16 位 hex)', file=sys.stderr)
            return 1
    else:
        seed = secrets.token_bytes(8)

    # 幂等/复用:已有桩则沿用其 seed(否则旧密文解不开)
    existing_seed, need_write_stub = read_existing_salt(args.decompiled)
    if existing_seed is not None:
        seed = existing_seed

    # S2:密钥流是 O(1) 现算的,不存在"表"也就没有表长/扩容概念;
    # 全局 offset 只是"已分配区段"的水位线(每条密文按需消耗 len 字节)。
    seed_int = int.from_bytes(seed, 'big')

    total_str, total_cls, idx = 0, 0, 0
    skipped_system = skipped_excluded = skipped_stub = 0
    for path in sorted(iter_smali_files(args.decompiled)):
        with open(path, encoding='utf-8') as fp:
            content = fp.read()
        cls_desc = class_desc_of(content)
        if not cls_desc:
            continue
        cls_dot = desc_to_dot(cls_desc)
        verdict = classify(cls_dot, cls_desc, includes, excludes)
        if verdict == 'no-match':
            continue
        if verdict == 'system':
            skipped_system += 1
            continue
        if verdict == 'excluded':
            skipped_excluded += 1
            continue
        if verdict == 'stub':
            skipped_stub += 1
            continue
        n, idx, backfills = process_file(path, cls_desc, includes, excludes,
                                         exclude_methods, seed_int, idx,
                                         args.algo)
        if n:
            total_str += n
            total_cls += 1
        if backfills:
            # 报错二十四/D4:字段初值保持明文,值由 <clinit> 运行期回填。
            # process_file 已重写并加幂等标记,这里重读注入,两条链互不干扰。
            inject_clinit_backfills(path, backfills)

    if need_write_stub and total_str > 0:
        if STUB_IMPL == 'native':
            # ── 纯 C 桩路径（--stub-impl native）─────────────────────
            # 算法在 libnc.so（csrc/nc_strdec.c），dex 侧只有 native 声明
            # + <clinit>（loadLibrary + setKey）。
            # 桩名/方法名已由上面的随机化逻辑写进 STUB_DESC 等全局变量。
            import native_stub as _ns
            stub_path = _ns.write_native_stub(
                args.decompiled, STUB_DESC, STUB_PKG_DIR, STUB_FILE,
                STUB_DECRYPT_METHOD, seed.hex(), _pick_smali_root(args.decompiled))
            stamp = write_components_stamp(args.decompiled, STUB_DESC)
            # 把"本次用的是 native 实现"写进标记 —— 续跑时据此判断是否
            # 需要重新生成 C 侧的头文件（Java/native 两种桩互不兼容）。
            try:
                with open(stamp, encoding='utf-8') as _fp:
                    _d = json.load(_fp)
                _d['stub_impl'] = 'native'
                _d['nkeys'] = _ns.NC_STRDEC_NKEYS
                with open(stamp, 'w', encoding='utf-8') as _fp:
                    json.dump(_d, _fp, ensure_ascii=False, indent=2)
                    _fp.write('\n')
            except (OSError, ValueError) as _e:
                raise SystemExit(f'❌ 写 stub_impl 标记失败: {_e}')
            if not args.quiet:
                print(f'  🔧 注入 native 解密桩: '
                      f'{os.path.relpath(stub_path, args.decompiled)}'
                      f' (组件标记 {os.path.basename(stamp)})')
        else:
            stub_path = write_stub(args.decompiled, seed)
            stamp = write_components_stamp(args.decompiled, STUB_DESC)
            if not args.quiet:
                print(f'  🔧 注入解密桩: {os.path.relpath(stub_path, args.decompiled)}'
                      f' (组件标记 {os.path.basename(stamp)})')
    # 复用桩的场景 S2 无需任何字段合并:桩里只有种子,续跑时种子原样保留,
    # 新密文用同一种子 + 新区段即可解 —— 这正是 S2 相对 v1/S1 的幂等优势。

    # ── 联动(stringenc↔dex2c):输出桩内核的 filter 规则 ─────────────────
    # 为什么要单独产出:桩名是每包随机的(STUB_DESC),protect.sh 无法预知,
    # 只能由本脚本(唯一知道桩名的环节)反向写出来给 dex2c 的 filter 追加。
    # 规则覆盖 d()/dn()/mix64()/keyByte() 四个方法(2026-12 全抽:dex2c 已实测
    # 支持异常表,故含 try/catch 的 d() 也一并转译进 so;详见 README「两层拆分」)。
    # 只在桩确实存在时写文件(本次新注入 或 续跑复用),否则 dex2c 追加一条
    # 命中不存在类的规则只是空转,还掩盖"没加密却勾了联动"的配置错误。
    if args.emit_stub_filter:
        if find_stub_path(args.decompiled) is not None:
            # full_name = Lcom/pkg/Cls;method(args)ret；filter 是正则、按 search 匹配。
            # 【必须覆盖四个方法】dex2c 只转译 filter 命中的方法,
            # 未命中的方法即使被调用也只是留一个 JNI 反调(实测:只写 dn 时
            # mix64/keyByte 留在 dex 被 D2C_RESOLVE_STATIC_METHOD 反调,
            # splitmix64 常量与密钥流逻辑仍可读)。四者一并抽走,
            # 算法才真正整体进 so。
            #    d()      解密入口(含 try/catch 兜底壳)
            #    dn()     解密内核(控制流/偏移/XOR)
            #    mix64()  splitmix64 混合函数(核心常量在这里)
            #    keyByte() 密钥流单字节(README 记为对拍契约,运行期不调用,
            #             但一起抽走可避免"半截算法"形态)
            # d() 曾刻意不写:理由是"dex2c 不支持异常表"。该理由已被实测证伪——
            # 2026-12 用 T1~T8 八个 try/catch 形态(简单/两段不连续/finally/
            # JNI引用+NPE/多类型分发/循环内)验证 dex2c v1.0.2 对异常表的支持:
            # 全部转译成功且能生成 EX_LandingPad + d2c_is_instance_of 分发,
            # catch(Throwable) 兜底在 C 侧完整保留(goto L2 返回原密文)。
            # 故改为全抽。全抽后失败兜底由 Java catch 变为 C 侧
            # d2c_is_instance_of(Throwable) 分发,降级语义等价。
            lines = [STUB_DESC + m + r'(.*)'
                     for m in (STUB_DECRYPT_METHOD, STUB_KERNEL_METHOD,
                               'mix64', 'keyByte')]
            with open(args.emit_stub_filter, 'w', encoding='utf-8') as fp:
                fp.write('\n'.join(lines) + '\n')
            if not args.quiet:
                print(f'  🔗 联动 filter 已写出: {len(lines)} 条规则')
                for l in lines:
                    print(f'       {l}')
        else:
            # 桩不存在(本次零加密且无旧桩):联动的前提不成立,显式告警而非静默。
            # protect.sh 侧据此 fail-fast,避免用户以为联动已生效。
            with open(args.emit_stub_filter, 'w', encoding='utf-8') as fp:
                fp.write('\n')
            if not args.quiet:
                print('⚠️ 未发现解密桩,联动 filter 为空(本次无加密且无旧桩)',
                      file=sys.stderr)

    # ── packer 联动:把解密桩单独汇编成 dex(供 dpt --extra-dex 合并进壳 dex)──
    # 与 --emit-stub-filter(stringenc↔dex2c 联动)是两条独立通道,可同时开启:
    #   · emit-stub-filter → 桩内核进 libnc.so(实现藏进 so)
    #   · emit-stub-dex    → 桩类进壳 dex(类本身藏进壳,业务 dex 只剩调用点)
    # 桩不存在时不写文件,protect.sh 据此判定"本次没有桩可搬"。
    if args.emit_stub_dex:
        if args.emit_seed:
            os.makedirs(os.path.dirname(os.path.abspath(args.emit_seed)) or '.', exist_ok=True)
            with open(args.emit_seed, 'w', encoding='utf-8') as fp:
                fp.write(f'{seed_int:016x}\n')
            print(f'  🌱 SEED 已写出: {args.emit_seed} ({seed_int:016x})')
        wrote = emit_stub_dex(args.decompiled, args.emit_stub_dex, _ROOT,
                              seed_from_shell=args.stub_seed_from_shell,
                              compiled_methods=args.compiled_methods,
                              stub_filter=getattr(args, 'emit_stub_filter', '') or '',
                              assume_transpiled=bool(getattr(args, 'assume_stub_transpiled', False)))
        if not args.quiet:
            if wrote:
                size = os.path.getsize(args.emit_stub_dex)
                print(f'  📦 桩 dex 已写出: {args.emit_stub_dex} ({size} 字节)')
            else:
                # 桩文件不在 = 上一轮已搬进壳 dex。此时无法再汇编出 dex，
                # 流水线若继续会让 packer 拿不到桩 → 壳 dex 少了那个类。
                # 全新解包不会走到这里；只有"复用同一解包目录"才会。
                cls = read_components_stamp(args.decompiled)
                if cls and cls.get('moved_to_shell_dex'):
                    raise SystemExit(
                        '❌ 桩已在上一轮搬进壳 dex，本解包目录无法再产出桩 dex。\n'
                        '   流水线每轮应使用全新解包目录；请 clean 后重新加密。')
                print('⚠️ 未发现解密桩,桩 dex 未产出', file=sys.stderr)
        if wrote and not args.keep_stub_in_dex:
            # ── 把桩从业务 dex 里摘除 ──────────────────────────────────
            # 只写 dex 而不删业务侧，桩会【同时存在两处】：业务 dex 里那份会被
            # dpt 抽空/搬进 xixin_data，等于没搬；且脱壳者照样能读到桩结构。
            # 删掉后业务 dex 只剩 invoke-static 调用点（实测 smali 允许引用
            # 不存在的类，回编不报错），运行期由壳 dex 提供实现。
            #
            # 顺序要求：必须在【所有加密改写完成之后】删——否则 process_file
            # 后续还会引用桩路径。
            #
            # --keep-stub-in-dex：dex2c 联动的前置轮用。那时不摘，因为紧接着的
            # dex2c 必须能看到桩类才能把内核转译进 libnc.so；摘除由 STEP5 的
            # `remove-stub` 子命令补做。
            removed = remove_stub_from_business(args.decompiled)
            if not args.quiet:
                print(f'  🚚 桩已从业务 dex 摘除: {removed}')

    # 报错二十四 构建期防线:任何产物 .field 初值都不允许是 StrDec 字段引用
    # (FIELD 型 0x19 encoded static_value,ART 类初始化即失败 → 秒闪退无日志)。
    # 此前版本曾把字段初值改写成该形态且 apktool 编译器宽容放行,教训:
    # 汇编器宽容 ≠ 产物合法。每次跑完都复读全包做硬断言,违反即 fail-fast。
    illegal = []
    literal = []
    for cls_path in iter_smali_files(args.decompiled):
        try:
            with open(cls_path, encoding='utf-8') as fp:
                c = fp.read()
        except OSError:
            continue
        if _ILLEGAL_FIELD_INIT_RE.search(c):
            illegal.append(cls_path)
        elif _scope_allows_field_scan(c):
            # 【与字段分支同源判定】逐行过滤"按设计保留明文初值"的类别
            # (空串 / 编译器调试标记串),只把真漏改算进来 —— 见
            # _scan_illegal_field_literals 的说明(2026-09-12 云端误拦事故)。
            for line, _m in _scan_illegal_field_literals(c):
                literal.append((cls_path, line))
                break
    if illegal:
        sample = os.path.relpath(illegal[0], args.decompiled)
        raise SystemExit(
            f'❌ 构建期断言失败:{len(illegal)} 个文件出现非法字段初值形态 '
            f'(.field ... = {STUB_DESC}->F...):\n   {sample}\n'
            f'   该形态会被汇编成 FIELD 型(0x19) static_value,ART 类初始化即闪退'
            f'(报错二十四)。字段常量回填必须走 <clinit> 的 sget/sput 链。')
    if literal:
        cls_path, line = literal[0]
        sample = os.path.relpath(cls_path, args.decompiled)
        raise SystemExit(
            f'❌ 构建期断言失败:{len(literal)} 个文件的 String 字段初值仍是字面量 '
            f'(去初值漏改):\n   {sample}\n   {line.strip()}\n'
            f'   该初值会原样进 dex 字符串池,`strings` 一扫即命中字段值明文 —— '
            f'字段分支必须走 _strip_field_literal 去掉初值 + <clinit> 回填。\n'
            f'   (注:空串、编译器调试标记串、解析失败(孤立代理项)三类属设计内保留,'
            f'由 field_literal_is_skipped()/_scan_illegal_field_literals() 识别,'
            f'不会触发本断言)')

    if not args.quiet:
        if activity_mode:
            print('ℹ️ 规则含 activity*,已按 --classes 展开')
        if skipped_system:
            print(f'ℹ️ 命中规则但被硬排除(系统/框架依赖类)跳过: {skipped_system} 个类')
        if skipped_excluded:
            print(f'ℹ️ 被用户 ! 规则排除跳过: {skipped_excluded} 个类')
        if skipped_stub:
            print(f'ℹ️ 解密桩自身跳过: {skipped_stub} 个')
        print(f'✅ 字符串加密完成: {total_str} 条 / {total_cls} 个类'
              f' (seed={seed.hex()}, '
              f'桩={"已注入" if (need_write_stub and total_str) else "复用/未用"})')
        if total_str == 0:
            print('⚠️ 没有任何字符串被加密 —— 检查规则是否命中(系统/依赖类会被硬排除)',
                  file=sys.stderr)
    return 0

if __name__ == '__main__':
    sys.exit(main())
