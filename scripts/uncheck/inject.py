#!/usr/bin/env python3
"""inject.py — 通用去签名校验注入器（在解包目录上操作）

CLI 契约:
  inject.py <解包目录> --apk <原始.apk> [--dry-run]
  inject.py clean <解包目录>

它做四件事:
  1. 从原始 APK 提取第一张签名证书 DER（复用 guard/hash/extract-cert-fp.py 的算法，
     纯 stdlib，不依赖 apksigner/keytool）
  2. 把证书 Base64 烘焙进 SigFix.smali 的哨兵位置
  3. 用 dex-capacity.pick_target_dir() 选落点（n+1，不碰已有 dex）
  4. 往 LAUNCHER 的 attachBaseContext 与 Application 的 attachBaseContext/onCreate
     注入 install(Context) 调用（多保险，install 内部幂等）

为什么注入生命周期方法而不改 AndroidManifest 的 android:name:
  - 改 android:name 需要「写二进制 AXML」（加属性=改长度=全 chunk 偏移重算），
    本仓库没有这个能力，只有等长原位替换（patch-extractnativelibs.py）。
  - 注入生命周期方法用现成的 inject-javacheck.py 机制，零 AXML 改动。
  - 代价: 时序略晚（LAUNCHER.attachBaseContext 晚于 Application.onCreate）。
    所以对「Application 存在」的包，同时往 Application 注入，覆盖更早的时机。

覆盖边界（不覆盖时必须明确告知，不许静默产出坏包）见 README.md。

⚠️ 本文件的 smali 是手工生成的（与 inject-javacheck.py 同一纪律）：
   生成后过三道渲染防线（占位符残留 / 类体顶层裸指令 / 方法体结构），
   并由 tests/test-inject.py 做结构断言。
"""
import base64
import importlib.util
import json
import os
import re
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))       # uncheck → scripts → 仓库根

MARKER = '# nc-uncheck-applied v1'
CALL_MARKER = '# nc-uncheck-call'
COMPONENTS_JSON = 'uncheck-components.json'
SIGFIX_DESC = 'Lcom/nc/uncheck/SigFix;'

# 与 payload/build.sh 的 SENTINEL 必须逐字一致
SENTINEL = 'NCSIGFIXSENTINELCERTB64PLACEHOLDER0000000000000000000000000000000'

# SigFixApp 里"原 Application 类名"占位符，与 payload/src/.../SigFixApp.java 一致
ORIGINAL_APP_PH = '__NC_ORIGINAL_APP__'

# 我们的 Application 挂载类（全限定名）
SIGFIX_APP = 'com.nc.uncheck.SigFixApp'

# 注入点：(方法名, 签名, 说明)。按「跑得早 → 晚」排，全部注入（install 幂等）
# 注入点：按「优先尝试」排序。全部尝试，install 幂等。
#
# ⚠️ 顺序有讲究（2026-11-21 实测事故后调整）：
#   原先把 attachBaseContext 放第一，因为时序最早。但它在很多父类上是
#   **final**（JMComic 的父类链 Lcom/getcapacitor/g; → Lg/i;
#   把 attachBaseContext 声明为 final），无法覆写，硬覆写 =
#   LinkageError 闪退。
#   改为主选 onCreate：绝大多数 Activity 自己就 override 了它（或父类
#   没有声明 final），注入点稳定；时序只比 attachBaseContext 晚
#   「一次 Application.onCreate」，对校验类 App 完全够用
#   （它们的检查通常在 MainActivity.onCreate）。
#   attachBaseContext 保留为备选：只在父类链允许覆写时才用。
ACTIVITY_POINTS = [
    ('onCreate', '(Landroid/os/Bundle;)V', '最常用，界面创建前；多数包可注入'),
    ('attachBaseContext', '(Landroid/content/Context;)V', '最早，但父类常声明 final，需检查'),
]
APPLICATION_POINTS = [
    ('onCreate', '()V', 'Application 初始化，早于一切 Activity'),
    ('attachBaseContext', '(Landroid/content/Context;)V', 'Application 挂 Context，更早但可能 final'),
]


# ───────────────────────── 依赖加载（沿用既有模式）─────────────────────────

def _load_module(name, relpath):
    """加载文件名带连字符、不能常规 import 的模块（报错三教训：路径按本文件位置推算）。"""
    path = os.path.join(_ROOT, *relpath)
    if not os.path.isfile(path):
        raise RuntimeError(f'找不到依赖模块: {path}')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ───────────────────────── 证书提取（纯 stdlib）─────────────────────────

SIG_BLOCK_MAGIC = b'APK Sig Block 42'
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0


def _find_eocd(data):
    """从尾部 64KB+22 范围找最后一个合法 EOCD。"""
    search_start = max(0, len(data) - 65557)
    pos = len(data) - 22
    while pos >= search_start:
        idx = data.rfind(b'PK\x05\x06', search_start, pos + 4)
        if idx < 0:
            break
        comment_len = struct.unpack_from('<H', data, idx + 20)[0]
        if idx + 22 + comment_len == len(data):
            return idx
        pos = idx - 1
    raise ValueError('未找到 EOCD（不是合法 ZIP/APK，或文件不完整）')


def extract_cert_der(apk_path):
    """取第一张签名者证书 DER。

    与 scripts/guard/hash/extract-cert-fp.py 同算法（那边只输出指纹，这里要 DER），
    刻意只实现必要部分，不复制那个文件 —— 两者用途不同：
      extract-cert-fp.py → 指纹（给 so 侧硬编码标准答案）
      本函数            → DER（要原样塞给 App 让它算出同一个指纹）
    """
    with open(apk_path, 'rb') as f:
        data = f.read()

    eocd_off = _find_eocd(data)
    cd_off = struct.unpack_from('<I', data, eocd_off + 16)[0]
    if cd_off in (0, 0xFFFFFFFF):
        raise ValueError('ZIP 为空或是 zip64（不支持）')
    if cd_off < 32 or cd_off > len(data):
        raise ValueError('central directory 偏移异常')

    if data[cd_off - 16:cd_off] != SIG_BLOCK_MAGIC:
        raise ValueError(
            '未找到 APK Signing Block（无 v2/v3 签名）。\n'
            '  v1-only（JAR 签名）的包无法从中提取证书 —— 请用 v2+ 签名的包，'
            '或先用 apksigner 重签一次。')
    size_total = struct.unpack_from('<Q', data, cd_off - 24)[0]
    if size_total + 8 > cd_off:
        raise ValueError('Signing Block 大小异常')
    block_start = cd_off - 8 - size_total

    pairs_end = cd_off - 24
    pos = block_start + 8
    block_value = None
    while pos + 12 <= pairs_end:
        pair_len = struct.unpack_from('<Q', data, pos)[0]
        block_id = struct.unpack_from('<I', data, pos + 8)[0]
        if pair_len < 4 or pos + 8 + pair_len > pairs_end:
            break
        if block_id in (V2_BLOCK_ID, V3_BLOCK_ID):
            block_value = data[pos + 12: pos + 8 + pair_len]
            if block_id == V3_BLOCK_ID:
                break
        pos += 8 + pair_len
    if block_value is None:
        raise ValueError('Signing Block 里没有 v2/v3 签名数据')

    def read_len_prefixed(buf, off):
        if off + 4 > len(buf):
            raise ValueError('signer 结构越界')
        n = struct.unpack_from('<I', buf, off)[0]
        off += 4
        if off + n > len(buf):
            raise ValueError('signer 结构长度异常')
        return buf[off:off + n], off + n

    signers, _ = read_len_prefixed(block_value, 0)
    first_signer, _ = read_len_prefixed(signers, 0)
    signed_data, _ = read_len_prefixed(first_signer, 0)
    _digests, off = read_len_prefixed(signed_data, 0)
    certs, off = read_len_prefixed(signed_data, off)
    first_cert, _ = read_len_prefixed(certs, 0)
    if not first_cert:
        raise ValueError('证书为空')
    return first_cert


# ───────────────────────── Manifest 解析 ─────────────────────────

def _read_manifest_text(decompiled_dir):
    """解包目录的 AndroidManifest.xml 是【二进制 AXML】。

    apktool 默认（不带 -r）会解成文本；带 -r 时保持二进制。
    两种都要能处理：文本直接读，二进制只做「够用的」字符串扫描。
    返回 None 表示无法解析 —— 调用方必须 fail-fast，不许猜。
    """
    path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    if not os.path.isfile(path):
        return None
    with open(path, 'rb') as f:
        raw = f.read()
    # 二进制 AXML 头：0x0003 0x0008
    if len(raw) >= 8 and struct.unpack_from('<H', raw, 0)[0] == 0x0003:
        return None
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        return None


def parse_manifest_text(text):
    """从文本 Manifest 取 package / application name / launcher。

    与 inject-javacheck.py 的 parse_manifest 同一语义，但独立实现：
    本模块不 import 其他模块的内部函数（AGENTS.md §4 模块化契约）。
    """
    if text is None:
        raise RuntimeError(
            'AndroidManifest.xml 是二进制 AXML 或不存在。\n'
            '  本注入器需要文本 Manifest：解包时不要带 -r，'
            '或先 `apktool d -f -o <dir> <apk>`（默认会解成文本）。')

    m = re.search(r'\bpackage="([^"]+)"', text)
    package = m.group(1) if m else ''
    if not package:
        raise RuntimeError('Manifest 里找不到 package 属性')

    def to_desc(java_name):
        if not java_name:
            return None
        if java_name.startswith('L') and java_name.endswith(';'):
            return java_name
        if java_name.startswith('.'):
            java_name = package + java_name
        elif '.' not in java_name:
            java_name = package + '.' + java_name
        return 'L' + java_name.replace('.', '/') + ';'

    app_desc = None
    am = re.search(r'<application\b[^>]*>', text, re.S)
    if am:
        nm = re.search(r'android:name="([^"]+)"', am.group(0))
        if nm:
            app_desc = to_desc(nm.group(1))

    launchers = []
    for act in re.finditer(r'<activity\b[^>]*?(?:/>|>(.*?)</activity>)', text, re.S):
        tag = act.group(0)
        nm = re.search(r'android:name="([^"]+)"', tag)
        if not nm:
            continue
        if re.search(r'android:enabled="false"', tag):
            continue
        body = act.group(1) or ''
        if ('android.intent.action.MAIN' in body
                and 'android.intent.category.LAUNCHER' in body):
            launchers.append(to_desc(nm.group(1)))

    return {'package': package, 'app_class': app_desc, 'launchers': launchers}


# ───────────────────────── smali 定位与插桩 ─────────────────────────

SMALI_DIR_RE = re.compile(r'^smali(?:_classes\d+)?$')


def iter_smali_dirs(decompiled_dir):
    for entry in sorted(os.listdir(decompiled_dir)):
        if SMALI_DIR_RE.match(entry):
            yield entry


def find_smali_file(decompiled_dir, desc):
    """按类描述符找 .smali（可能在任何 smali_classesN/ 下）。"""
    rel = desc[1:-1] + '.smali'
    for d in iter_smali_dirs(decompiled_dir):
        p = os.path.join(decompiled_dir, d, rel)
        if os.path.isfile(p):
            return p
    return None


def _method_info(lines, start_idx):
    """解析 .method 头，返回 (is_static, proto, 参数槽数)。"""
    header = lines[start_idx].strip()
    m = re.search(r'\.method\s+(.*)$', header)
    if not m:
        return None
    rest = m.group(1)
    is_static = ' static ' in ' ' + rest + ' '
    proto_m = re.search(r'(\([^)]*\)\S+)$', rest)
    if not proto_m:
        return None
    proto = proto_m.group(1)
    # 参数槽：J/D 占 2 槽
    params = proto[1:proto.index(')')]
    slots = 0
    i = 0
    while i < len(params):
        if params[i] in 'JD':
            slots += 2
            i += 1
        elif params[i] == '[':
            slots += 1
            while i < len(params) and params[i] == '[':
                i += 1
            if i < len(params) and params[i] == 'L':
                i = params.index(';', i) + 1
            else:
                i += 1
        elif params[i] == 'L':
            slots += 1
            i = params.index(';', i) + 1
        else:
            slots += 1
            i += 1
    return is_static, proto, slots


def _first_instruction_idx(lines, start_idx):
    """跳过 .method 头之后的所有指令性行（.registers/.locals/.param/.line/#注释）。"""
    i = start_idx + 1
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith('.end method'):
            return None
        if s and not s.startswith('.') and not s.startswith('#'):
            return i
        i += 1
    return None


def _method_has_marker(lines, method_name, method_sig):
    """指定方法的方法体内是否已经有我们的注入标记。

    ⚠️ 为什么必须按方法粒度判定（2026-11-21 修）：
    原实现是在**整个文件**里查 CALL_MARKER —— 同一个类注入第一个方法后，
    第二个方法就永远被判成 already 而跳过。
    实测表现：MainActivity 先注入 onCreate，随后 attachBaseContext
    报 "already" 被跳过，看起来像"已经注过了"，实际根本没注。
    这种假幂等比重复注入更危险：它让"多注入点保险"静默退化成单点。
    """
    import re as _re
    in_target = False
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith('.method'):
            m = _re.search(r'\.method\s+(.*)$', s)
            in_target = False
            if m:
                nm = _re.search(r'([^\s(]+)(\([^)]*\)\S+)$', m.group(1))
                if nm and nm.group(1) == method_name and nm.group(2) == method_sig:
                    in_target = True
            continue
        if s.startswith('.end method'):
            in_target = False
            continue
        if in_target and CALL_MARKER in line:
            return True
    return False


def _register_ok(lines, start_idx, param_index):
    """判断参数寄存器物理编号是否 ≤ v15（invoke-static 是 35c，上限 v15）。

    param_index: 0 表示 p0。
    """
    # 找 .registers 或 .locals
    reg_total = None
    locals_n = None
    for i in range(start_idx, min(start_idx + 40, len(lines))):
        s = lines[i].strip()
        m = re.match(r'\.registers\s+(\d+)', s)
        if m:
            reg_total = int(m.group(1))
            break
        m = re.match(r'\.locals\s+(\d+)', s)
        if m:
            locals_n = int(m.group(1))
            break
    if reg_total is not None:
        # pN 的物理编号 = reg_total - 参数槽数 + N；这里只知道 p0 起点
        # 保守做法：p0 物理编号 = reg_total - slots，需要 slots
        return None  # 调用方会用 proto 重算
    if locals_n is not None:
        return ('locals', locals_n)
    return None


def _param_physical_index(lines, start_idx, is_static, slots, param_index):
    """算出 pN 的物理寄存器编号。返回 None 表示无法确定（此时必须放弃该点）。"""
    reg_total = None
    locals_n = None
    for i in range(start_idx, min(start_idx + 60, len(lines))):
        s = lines[i].strip()
        m = re.match(r'\.registers\s+(\d+)', s)
        if m:
            reg_total = int(m.group(1))
            break
        m = re.match(r'\.locals\s+(\d+)', s)
        if m:
            locals_n = int(m.group(1))
            break
    if reg_total is not None:
        base = reg_total - (0 if is_static else slots)
        # p0 在实例方法时是 this，位于 locals 之后
        if not is_static:
            # p0 = this，p1 = 第一个参数
            # 物理编号：reg_total - slots - 1 (this) ... 实际：p0 = reg_total - slots - 1
            first = reg_total - slots - 1
        else:
            first = reg_total - slots
        return first + param_index
    if locals_n is not None:
        # .locals N 表示局部寄存器数，参数从 vN 开始
        return locals_n + param_index
    return None


def _find_super_chain(decompiled_dir, start_desc):
    """沿 .super 走父类链，返回 [desc, super, super.super, ...]（不含 Object）。

    ⚠️ 为什么需要它：新建方法覆写前必须确认父类链上没有 **final 同名方法**。
    实测事故（JMComic / run 03:17 装机闪退）：
      MainActivity 的父类链是 Lcom/getcapacitor/g; → Lg/i; → Landroid/app/Activity;
      而 Lg/i; 里 `.method public final attachBaseContext(Context)V`
      → 我们新建 `protected attachBaseContext` 覆写它
      → ART 抛 java.lang.LinkageError: overrides final method in class Lg/i;
      → App 连 Application.onCreate 都到不了，直接闪退。
    """
    chain = []
    cur = start_desc
    seen = set()
    for _ in range(32):                      # 深度上限，防畸形包死循环
        if not cur or cur in seen or cur == 'Ljava/lang/Object;':
            break
        seen.add(cur)
        path = find_smali_file(decompiled_dir, cur)
        if not path:
            break
        with open(path, encoding='utf-8') as f:
            sup = None
            for line in f:
                s = line.strip()
                if s.startswith('.super '):
                    sup = s[len('.super '):].strip()
                    break
        if not sup:
            break
        chain.append(sup)
        cur = sup
    return chain


def _is_final_in_super_chain(decompiled_dir, start_desc, method_name, method_sig):
    """父类链上是否有 `final` 的同名同签名方法。有则不能覆写。"""
    import re as _re
    for desc in _find_super_chain(decompiled_dir, start_desc):
        path = find_smali_file(decompiled_dir, desc)
        if not path:
            continue
        with open(path, encoding='utf-8') as f:
            lines = f.read().split('\n')
        for i, line in enumerate(lines):
            s = line.strip()
            if not s.startswith('.method'):
                continue
            m = _re.search(r'\.method\s+(.*)$', s)
            if not m:
                continue
            rest = m.group(1)
            nm = _re.search(r'([^\s(]+)(\([^)]*\)\S+)$', rest)
            if not nm or nm.group(1) != method_name or nm.group(2) != method_sig:
                continue
            # 访问标志里有 final 即不可覆写
            if _re.search(r'\bfinal\b', rest):
                return desc
            return None
    return None


def _create_method_override(path, desc, super_desc, method_name, method_sig, install_desc):
    """类里没有这个方法时，新建一个覆写：super 调用 + install 调用。

    为什么必须新建而不是「换个注入点将就」：
      LAUNCHER 不 override attachBaseContext 是常态（JMComic 就是）。
      退到 onCreate 也能工作，但时序晚；attachBaseContext 越早越安全。
      新建覆写的代价极小（一个方法、零新增字段），且语义完全合法。

    ⚠️ 调用方必须先确认父类链上没有 final 同名方法（见 _is_final_in_super_chain）。
       本函数自己也防御性再查一次 —— 覆写 final 方法是 LinkageError 级别的
       致命错误，不能只靠调用方记得检查。
    """
    with open(path, encoding='utf-8') as f:
        text = f.read()
    lines = text.split('\n')

    # 幂等：这个类里已经新建过同名方法就不再建（按方法粒度，不看全文件）。
    if _method_has_marker(lines, method_name, method_sig):
        return False, 'already'

    # 找一个存活的 .method 块末尾不是好位置（方法顺序无关），
    # 直接插在类尾部（最后一个 .end method 之后），smali 对方法顺序无要求。
    insert_at = None
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip().startswith('.end method'):
            insert_at = i + 1
            break
    if insert_at is None:
        return False, 'no-anchor'

    if method_sig == '(Landroid/content/Context;)V':
        # attachBaseContext(Context)：p0=this, p1=context
        # 顺序：先 super（父类要先完成 attach），再装 hook。
        block = [
            '',
            '.method protected attachBaseContext(Landroid/content/Context;)V',
            '    .locals 1',
            '',
            '    invoke-super {p0, p1}, ' + super_desc + '->attachBaseContext(Landroid/content/Context;)V',
            '',
            f'    {CALL_MARKER}',
            f'    invoke-static {{p1}}, {install_desc}->install(Landroid/content/Context;)V',
            '',
            '    return-void',
            '.end method',
        ]
    elif method_sig == '()V':
        # onCreate()：p0=this（Activity/Application 本身是 Context）
        block = [
            '',
            '.method public onCreate()V',
            '    .locals 1',
            '',
            '    invoke-super {p0}, ' + super_desc + '->onCreate()V',
            '',
            f'    {CALL_MARKER}',
            f'    invoke-static {{p0}}, {install_desc}->install(Landroid/content/Context;)V',
            '',
            '    return-void',
            '.end method',
        ]
    else:
        return False, 'unsupported-sig'

    lines[insert_at:insert_at] = block
    new_text = '\n'.join(lines)
    # 宿主类只校验「我们插进去的那段结构合法」，不做整类扫描：
    # 宿主 smali 里合法存在 `%02x` 这类格式串、注解块等，
    # 用载荷那一套严格断言会误报（本模块实测踩过）。
    assert_injected_block(new_text, os.path.basename(path))
    open(path, 'w', encoding='utf-8').write(new_text)
    return True, f'{method_name}{method_sig}(新建)'


def inject_call_site(path, install_desc, method_name, method_sig):
    """在指定类的指定方法首条指令前插入 install 调用。

    返回 (changed: bool, note: str)。
    """
    with open(path, encoding='utf-8') as f:
        text = f.read()
    lines = text.split('\n')

    target = None
    for i, line in enumerate(lines):
        s = line.strip()
        if not s.startswith('.method'):
            continue
        m = re.search(r'\.method\s+(.*)$', s)
        if not m:
            continue
        rest = m.group(1)
        nm = re.search(r'([^\s(]+)(\([^)]*\)\S+)$', rest)
        if not nm:
            continue
        if nm.group(1) != method_name or nm.group(2) != method_sig:
            continue
        target = i
        break

    if target is None:
        return False, 'no-method'

    info = _method_info(lines, target)
    if info is None:
        return False, 'bad-header'
    is_static, proto, slots = info

    if 'native' in lines[target]:
        return False, 'native'

    # 幂等：只判定「这个目标方法」是否已注入，不看整个文件。
    if _method_has_marker(lines, method_name, method_sig):
        return False, 'already'

    # 传哪个寄存器给 install(Context)？
    #
    # ⚠️ 必须是 this（p0），不是方法的第一个参数。踩过的坑（2026-11-21）：
    #   onCreate(Landroid/os/Bundle;)V 的第一参数 p1 是 **Bundle**，不是 Context。
    #   原实现按「第一个参数」取值，于是注入的是
    #     invoke-static {p1}, Lcom/nc/uncheck/SigFix;->install(Landroid/content/Context;)V
    #   smali 不校验参数类型，能汇编通过、能装、能跑，
    #   但 install() 里 ctx.getPackageName() 抛异常被 catch 吞掉 →
    #   载荷静默什么都不做。表现是「注入成功、装机无效果」，极难排查。
    #
    #   而 Activity 与 Application 都继承 Context，p0（this）永远是合法 Context，
    #   且不需要关心方法签名有几个参数。
    param_reg_index = 0   # p0 = this

    phys = _param_physical_index(lines, target, is_static, slots, param_reg_index)
    if phys is None:
        return False, 'no-register-info'
    if phys > 15:
        # 35c 格式寄存器上限 v15。宁可不插，也不要产出回编失败的 smali。
        return False, f'register-v{phys}>v15'

    first = _first_instruction_idx(lines, target)
    if first is None:
        return False, 'empty-method'

    reg = f'v{phys}'
    inject_lines = [
        f'    {CALL_MARKER}',
        f'    invoke-static {{{reg}}}, {install_desc}->install(Landroid/content/Context;)V',
    ]
    lines[first:first] = inject_lines
    open(path, 'w', encoding='utf-8').write('\n'.join(lines))
    return True, f'{method_name}{method_sig}'


# ───────────────────────── 渲染防线 ─────────────────────────

def assert_injected_block(text, name):
    """校验「我们插进去的那段」结构合法（不扫整个宿主类）。

    只检查两件事：
      1. 标记行与紧随其后的 invoke 行必须成对存在
      2. invoke 行的目标必须是 SigFix->install(Landroid/content/Context;)V
    """
    lines = text.split('\n')
    hits = [i for i, l in enumerate(lines) if CALL_MARKER in l]
    if not hits:
        raise AssertionError(f'{name}: 插桩后找不到标记行（写入逻辑有 bug）')
    for i in hits:
        if i + 1 >= len(lines):
            raise AssertionError(f'{name}: 标记行后没有 invoke 行')
        nxt = lines[i + 1].strip()
        if 'invoke-static' not in nxt or 'SigFix;->install(Landroid/content/Context;)V' not in nxt:
            raise AssertionError(f'{name}: 标记行后不是预期的 install 调用: {nxt!r}')


def assert_rendered(text, name):
    """三道渲染防线（同 inject-javacheck.py 的 _render_asserts 纪律）。

    注意 .annotation 块：类体顶层合法的块内行形如 `    value = "..."`、
    `    name = "..."`、`    visibility = ...`，它们不以 '.' 开头但属于注解，
    不是裸指令。判定时必须把注解块整体跳过，否则会误报（本模块第一个误报就来自这里）。
    """
    if '%' in text:
        raise AssertionError(f'{name}: 渲染产物含 % 占位符残留')

    in_method = False
    in_annotation = False
    for line in text.split('\n'):
        s = line.strip()
        if s.startswith('.annotation'):
            in_annotation = True
            continue
        if s.startswith('.end annotation'):
            in_annotation = False
            continue
        if in_annotation:
            continue
        if s.startswith('.method'):
            in_method = True
        elif s.startswith('.end method'):
            in_method = False
        if in_method or not s or s.startswith('.') or s.startswith('#'):
            continue
        raise AssertionError(f'{name}: 类体顶层出现裸指令: {s!r}')


# ───────────────────────── 主流程 ─────────────────────────

def _super_desc_of(path):
    """读 .super 行（新建覆写方法时的 invoke-super 目标）。"""
    with open(path, encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if s.startswith('.super '):
                return s[len('.super '):].strip()
    return None


def do_inject(decompiled_dir, apk_path, dry_run=False):
    dex_capacity = _load_module('dex_capacity', ('scripts', 'repack', 'dex-capacity.py'))
    axml_edit = _load_module('axml_edit', ('scripts', 'uncheck', 'axml_edit.py'))

    # 1) 证书
    cert_der = extract_cert_der(apk_path)
    cert_b64 = base64.b64encode(cert_der).decode('ascii')
    print(f'✅ 原证书 DER: {len(cert_der)} 字节 → Base64 {len(cert_b64)} 字符')

    # 2) Manifest
    # 优先用二进制 AXML 解析（run.py 解包时带了 -r，Manifest 保持二进制）。
    # 退回文本解析是为了兼容手工解包（apktool d 不带 -r）的调试场景。
    manifest = None
    _mpath = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    if os.path.isfile(_mpath):
        try:
            with open(_mpath, 'rb') as _f:
                _head = _f.read(2)
            if _head == b'\x03\x00':
                manifest = axml_edit.parse_manifest(_mpath)
        except Exception as _e:
            print(f'⚠️ AXML 解析失败，退回文本解析: {_e}')
    if manifest is None:
        manifest = parse_manifest_text(_read_manifest_text(decompiled_dir))
    print(f"✅ 包名: {manifest['package']}")
    print(f"   Application: {manifest['app_class'] or '(无自定义)'}")
    print(f"   LAUNCHER: {manifest['launchers']}")

    # 3b) 改写 AndroidManifest：把 android:name 指向 SigFixApp，
    #     并把原类名记下来供 SigFixApp 反射接管。
    #
    # 为什么要挂到 Application（而不是只注入 Activity.onCreate）：
    #   Application 是系统最早实例化的应用类，覆盖 Application.onCreate /
    #   attachBaseContext / ContentProvider.onCreate 等所有更早的时机。
    #   只挂 Activity 会漏掉在 Application 里校验的 App。
    original_app_java = None
    if manifest['app_class']:
        # smali 描述符 Lcom/x/Y; → com.x.Y
        d = manifest['app_class']
        if d.startswith('L') and d.endswith(';'):
            original_app_java = d[1:-1].replace('/', '.')
    if not dry_run:
        manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
        axml_edit.set_app_name(manifest_path, SIGFIX_APP)
        now = axml_edit.get_app_name(manifest_path)
        if now != SIGFIX_APP:
            raise RuntimeError(
                f'AndroidManifest 改写后回读不一致：期望 {SIGFIX_APP}，实际 {now}')
        print(f'✅ AndroidManifest: android:name → {SIGFIX_APP}')
        if original_app_java:
            print(f'   原 Application 将由其接管: {original_app_java}')
        else:
            print('   原包无 android:name，SigFixApp 不接管任何原 Application')

    # 3) 载荷 smali（主类 + 内部类）
    payload_dir = os.path.join(_HERE, 'payload')
    payload_files = sorted(
        f for f in os.listdir(payload_dir) if f.startswith('SigFix') and f.endswith('.smali'))
    if not payload_files:
        raise RuntimeError(
            f'载荷 smali 不存在: {payload_dir}\n'
            f'  先跑 bash scripts/uncheck/payload/build.sh')
    if not any(f == 'SigFix.smali' for f in payload_files):
        raise RuntimeError('载荷缺主类 SigFix.smali')

    # 4) 选落点：**永远新建 dex**（n+1），不写进任何已有 dex。
    #
    # ⚠️ 为什么强制新建（2026-11-21 用户实测反馈后改）：
    #   dex-capacity.pick_target_dir() 的默认策略是「首选目录够用就用」，
    #   那是给加固流水线设计的（加固要改业务 smali，本来就得重编那些 dex）。
    #   去校验不同：载荷类与原包毫无关系，没有任何理由塞进 classes.dex。
    #   塞进去的代价：
    #     · 原 classes.dex 被整体重新汇编，所有类都重写一遍，
    #       汇编器的细微差异都可能改变原包行为（本次闪退排查就分不清
    #       是载荷的问题还是重编的问题）；
    #     · 无法回滚：出问题没法「只去掉载荷」回到原状做二分；
    #     · 大包必撞 65536 上限。
    #   新建 classesN.dex 后，原 dex 逐字节不变，
    #   排查时删掉那一个 dex 就回到原始状态。
    #
    #   实现上不改 pick_target_dir（它是加固侧的公共模块），
    #   而是把 prefer 指向一个必然不存在的目录名 → 必然走 n+1 分支。
    if dry_run:
        print('ℹ️ dry-run：跳过落点选择与写盘')
        return {'payload_files': payload_files, 'manifest': manifest,
                'cert_b64_len': len(cert_b64)}

    NO_SUCH_DIR = '__nc_uncheck_force_new_dex__'
    target_dir = dex_capacity.pick_target_dir(
        decompiled_dir,
        need_methods=40,          # 载荷方法数（SigFix + 内部类，含构造器等）
        apk_path=apk_path,
        prefer=NO_SUCH_DIR)
    if target_dir == NO_SUCH_DIR:
        raise RuntimeError(
            'pick_target_dir 意外返回了占位目录名 —— '
            'dex-capacity.py 的 prefer 语义可能变了，请核对后修正本调用。')
    target_root = os.path.join(decompiled_dir, target_dir)
    pkg_dir = os.path.join(target_root, 'com', 'nc', 'uncheck')
    os.makedirs(pkg_dir, exist_ok=True)
    print(f'✅ 落点: {target_dir}/ → com/nc/uncheck/')

    # 5) 写载荷 smali，把哨兵换成真实证书
    written = []
    for fname in payload_files:
        with open(os.path.join(payload_dir, fname), encoding='utf-8') as f:
            text = f.read()
        if fname.startswith('SigFixApp'):
            if ORIGINAL_APP_PH in text:
                text = text.replace(ORIGINAL_APP_PH,
                                    original_app_java or SIGFIX_APP)
        if fname == 'SigFix.smali':
            if SENTINEL not in text:
                raise RuntimeError(
                    'SigFix.smali 里找不到哨兵证书串。\n'
                    '  payload/build.sh 与 inject.py 的 SENTINEL 常量必须逐字一致。')
            text = text.replace(SENTINEL, cert_b64)
            if SENTINEL in text:
                raise RuntimeError('证书替换不完整，仍有哨兵残留')
        assert_rendered(text, fname)
        out = os.path.join(pkg_dir, fname)
        with open(out, 'w', encoding='utf-8') as f:
            f.write(text)
        written.append(out)
    print(f'✅ 写入载荷 {len(written)} 个文件（证书已烘焙）')

    # 6) 注入调用点
    injected = []

    for launcher in manifest['launchers']:
        smali = find_smali_file(decompiled_dir, launcher)
        if not smali:
            print(f'⚠️ 找不到 LAUNCHER smali: {launcher}')
            continue
        super_desc = _super_desc_of(smali)
        for name, sig, _why in ACTIVITY_POINTS:
            ok, note = inject_call_site(smali, SIGFIX_DESC, name, sig)
            if ok:
                injected.append(f'{launcher}->{note}')
                continue
            if note == 'no-method' and super_desc:
                # LAUNCHER 不 override attachBaseContext 是常态（JMComic 就是），
                # 新建覆写而不是退回更晚的注入点。
                #
                # ⚠️ 但必须先查父类链：若父类把它声明成 final，覆写 =
                #    LinkageError，App 直接闪退（实测 JMComic：
                #    父类链 Lcom/getcapacitor/g; → Lg/i; 里 attachBaseContext 是 final）。
                blocker = _is_final_in_super_chain(decompiled_dir, launcher, name, sig)
                if blocker:
                    print(f'   · {launcher}->{name}{sig}: 跳过'
                          f'（父类 {blocker} 声明为 final，不能覆写）')
                    continue
                ok2, note2 = _create_method_override(
                    smali, launcher, super_desc, name, sig, SIGFIX_DESC)
                if ok2:
                    injected.append(f'{launcher}->{note2}')
                    continue
                print(f'   · {launcher}->{name}{sig}: 跳过（no-method，新建失败：{note2}）')
            else:
                print(f'   · {launcher}->{name}{sig}: 跳过（{note}）')

    if manifest['app_class']:
        app_smali = find_smali_file(decompiled_dir, manifest['app_class'])
        if app_smali:
            super_desc = _super_desc_of(app_smali)
            for name, sig, _why in APPLICATION_POINTS:
                ok, note = inject_call_site(app_smali, SIGFIX_DESC, name, sig)
                if ok:
                    injected.append(f"{manifest['app_class']}->{note}")
                    continue
                if note == 'no-method' and super_desc:
                    blocker = _is_final_in_super_chain(
                        decompiled_dir, manifest['app_class'], name, sig)
                    if blocker:
                        print(f"   · {manifest['app_class']}->{name}{sig}: 跳过"
                              f'（父类 {blocker} 声明为 final，不能覆写）')
                        continue
                    ok2, note2 = _create_method_override(
                        app_smali, manifest['app_class'], super_desc, name, sig, SIGFIX_DESC)
                    if ok2:
                        injected.append(f"{manifest['app_class']}->{note2}")
                        continue
                    print(f"   · {manifest['app_class']}->{name}{sig}: 跳过（no-method，新建失败：{note2}）")
                else:
                    print(f"   · {manifest['app_class']}->{name}{sig}: 跳过（{note}）")
        else:
            print(f"⚠️ 找不到 Application smali: {manifest['app_class']}")

    if not injected:
        raise RuntimeError(
            '没有任何可用调用点 —— 载荷装进去也不会被执行。\n'
            '  常见原因：\n'
            '    · LAUNCHER/Application 的方法体是 native（加固壳）\n'
            '    · 参数寄存器物理编号 > v15（超大方法）\n'
            '    · Manifest 解析不到 LAUNCHER\n'
            '  这不是「静默降级」能接受的情况，因此直接失败。')

    print(f'✅ 注入 {len(injected)} 个调用点:')
    for s in injected:
        print(f'   · {s}')

    # 7) 组件标记（供 clean 精确回滚，绝不越界）
    comp = {'payload': written, 'calls': injected, 'target_dir': target_dir}
    with open(os.path.join(decompiled_dir, COMPONENTS_JSON), 'w', encoding='utf-8') as f:
        json.dump(comp, f, ensure_ascii=False, indent=2)

    return comp


def do_clean(decompiled_dir):
    """按标记精确回滚：只删自己写的文件、只删自己插的行。"""
    comp_path = os.path.join(decompiled_dir, COMPONENTS_JSON)
    if not os.path.isfile(comp_path):
        print('ℹ️ 无 uncheck-components.json，跳过 clean')
        return

    with open(comp_path, encoding='utf-8') as f:
        comp = json.load(f)

    for p in comp.get('payload', []):
        if os.path.isfile(p):
            os.remove(p)
            print(f'   删除载荷 {os.path.basename(p)}')

    # 删调用点：按 CALL_MARKER 定位，成对删掉下一行 invoke
    for d in iter_smali_dirs(decompiled_dir):
        for root, _dirs, files in os.walk(os.path.join(decompiled_dir, d)):
            for fn in files:
                if not fn.endswith('.smali'):
                    continue
                p = os.path.join(root, fn)
                with open(p, encoding='utf-8') as f:
                    lines = f.read().split('\n')
                if not any(CALL_MARKER in l for l in lines):
                    continue
                out = []
                i = 0
                while i < len(lines):
                    if CALL_MARKER in lines[i]:
                        i += 2          # 跳过标记行 + invoke 行
                        continue
                    out.append(lines[i])
                    i += 1
                with open(p, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(out))
                print(f'   清理调用点 {fn}')

    os.remove(comp_path)
    print('✅ clean 完成')


def main(argv):
    if len(argv) >= 2 and argv[1] == 'clean':
        if len(argv) != 3:
            print('用法: inject.py clean <解包目录>', file=sys.stderr)
            return 2
        do_clean(argv[2])
        return 0

    if len(argv) < 4:
        print(__doc__)
        return 2

    decompiled_dir = argv[1]
    apk_path = None
    dry_run = False
    i = 2
    while i < len(argv):
        if argv[i] == '--apk':
            apk_path = argv[i + 1]
            i += 2
        elif argv[i] == '--dry-run':
            dry_run = True
            i += 1
        else:
            print(f'未知参数: {argv[i]}', file=sys.stderr)
            return 2

    if not apk_path:
        print('❌ 必须用 --apk 指定原始 APK（用于提取原证书）', file=sys.stderr)
        return 2
    if not os.path.isdir(decompiled_dir):
        print(f'❌ 解包目录不存在: {decompiled_dir}', file=sys.stderr)
        return 2
    if not os.path.isfile(apk_path):
        print(f'❌ APK 不存在: {apk_path}', file=sys.stderr)
        return 2

    try:
        do_inject(decompiled_dir, apk_path, dry_run)
    except (RuntimeError, ValueError, AssertionError) as e:
        print(f'❌ {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
