#!/usr/bin/env python3
"""inject-excludes.py — 从注入器留下的组件清单，推导「必须排除在字符串加密之外」的类

═══ 为什么需要它（2026-11-25，用户发现的架构级死锁）═══

加固 + 去校验组合包（protect.sh 勾 --stringenc，源包已被 uncheck 注入）里：

  SigFixApp.attachBaseContext()
    └─ SigFix.install()                     ← 装「去校验」的 native hook
         └─ 要打日志 → 用到 TAG 字段
              └─ TAG 在 <clinit> 里由 stringenc 桩 aw() 解密
                   └─ 桩类 static { System.loadLibrary("nc") }
                        └─ libnc.so constructor 立即跑 sig_verify
                             └─ 六路读证书（此时 libusign 的 hook 还没装）
                                  → 六路全读真 base.apk → 诱饵失效

即：**要装去校验的 hook，必须先解密字符串；要解密字符串，必须先加载 nc
（我们的加固 so）；一加载 nc，签名校验就跑完了。**

结果是加固包里 `open/openat/openat64` 三条路永远读不到 origin.apk，
「诱饵 vs 真身」的交叉验证场景退化成六路一致。

═══ 为什么是「排除」而不是「改执行顺序」═══

  · 改 constructor 延后 → 破坏 fail-closed（删 loadLibrary 即静默通关），
    那是加固的承重墙，不能动；
  · 改 uncheck 的注入时机 → 它已被 dex2c/antidiff 改写，动它就动整条流水线；
  · 排除这几类的字符串加密 → 代价最小：它们是【我们自己的注入类】，
    字符串是给排障看的日志文案，不是业务逻辑，明文与否不影响防护强度
    （业务类照常加密）。

═══ 为什么不硬编码白名单（用户明确要求）═══

类名有三重动态性，硬编码必错：
  1. javalink 的包装类名是**自适应**的（R8 包 → f5.aa 这种短名）；
  2. stringenc 的桩名是**每包随机**的（包名 3 段 + 类名 1 段）；
  3. 去校验的载荷类名虽固定（com.nc.uncheck.*），但将来可能改。

所以本脚本【读注入器自己写的清单】，从那里推导 —— 清单是注入时的真实产物，
不是猜的。三个来源，全部可选（哪个清单在就吃哪个）：

  javacheck-components.json   → wrapper / bridge / generated[]
  uncheck-components.json     → payload[] / calls[] / target_dir
  （扩展位：将来别的注入器只要写同类清单即可被自动纳入）

═══ 输出 ═══

按 encrypt-strings.py 的规则文件语法输出排除行（`!` 前缀 = 排除）：

    !f5.aa
    !f5.aa$Hb
    !com.nc.link.NcLink
    !com.nc.uncheck.**

═══ 用法 ═══

    inject-excludes.py <解包目录> [-o 输出规则文件]

  无清单 → 输出空文件、退出 0（不是错误：说明这个包没有注入类）。
  设计成可管道：`encrypt-strings.py <dir> <(inject-excludes.py <dir>)` 也行，
  但为了可调试（cat 一下看排除了什么）默认写文件。
"""
import json
import os
import re
import sys

# 注入器的清单文件名。新增注入器只需把文件名加到这里。
#
# ⚠️ 不做「扫描任意 *-components.json」：那样一个来历不明的同名文件就能让
#    攻击者把任意类排除出加密（等于关掉字符串加密）。清单必须来自本仓库
#    已知的注入器，名字定死在这里 = 一份显式契约，改动留痕。
MANIFESTS = (
    'javacheck-components.json',   # scripts/guard/javalink/inject-javacheck.py
    'uncheck-components.json',     # scripts/uncheck/inject.py
)

# smali 路径 → 点分类名：smali_classes3/com/nc/uncheck/SigFixApp.smali
#                          → com.nc.uncheck.SigFixApp
_SMALI_RE = re.compile(r'^smali(?:_classes\d+)?/(.+)\.smali$')


def _desc_to_dot(desc):
    """'Lcom/nc/link/NcLink;' → 'com.nc.link.NcLink'；非描述符原样返回。"""
    if isinstance(desc, str) and desc.startswith('L') and desc.endswith(';'):
        return desc[1:-1].replace('/', '.')
    return desc


def _from_smali_path(path, decompiled_dir):
    """smali 文件路径（相对或绝对）→ 点分类名。取不到返回 None。

    ⚠️ 两种形态都要吃：清单里 generated[] 存的是【绝对路径】（注入时拼的），
    而 payload[] 存的是【相对解包目录的 smali 路径】。只处理一种会漏。

    ⚠️ 2026-11-25 加兜底：绝对路径的前缀与当前解包目录不一致时（清单在
    别的目录生成、或解包目录被移动/重新解包），不能直接判失败 ——
    从路径里第一个 `smali*/` 段开始切。宁可多认一个类，
    也不要因为"路径对不上"而漏排除（漏排除 = 那个类的字符串被加密
    = SigFix 死锁复现）。"""
    p = path.replace(os.sep, '/')
    # ① 常规：砍掉解包目录前缀
    base = decompiled_dir.replace(os.sep, '/').rstrip('/') + '/'
    if p.startswith(base):
        p = p[len(base):]
    else:
        # ② 兜底：绝对路径前缀对不上 → 从第一个 smali 段起切
        m_any = re.search(r'(?:^|/)(smali(?:_classes\d+)?/.+\.smali)$', p)
        rel = m_any.group(1) if m_any else p
        if m_any or p.startswith('smali'):
            p = rel
    m = _SMALI_RE.match(p)
    if not m:
        return None
    return m.group(1).replace('/', '.')


def collect(decompiled_dir):
    """返回 (classes:set, sources:dict)。sources 记「哪个清单贡献了什么」，便于排障。"""
    classes = set()
    sources = {}

    for name in MANIFESTS:
        path = os.path.join(decompiled_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding='utf-8') as f:
                comp = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            # 清单坏了不静默：它决定要不要加密，读错等于防护静默降级。
            print(f'⚠️ {name} 读不出（{e}）—— 该清单贡献的排除项将缺失',
                  file=sys.stderr)
            continue

        got = set()

        # javacheck：wrapper/bridge 是【类描述符】，generated 是文件路径
        for key in ('wrapper', 'bridge'):
            if comp.get(key):
                got.add(_desc_to_dot(comp[key]))
        for g in comp.get('generated') or []:
            c = _from_smali_path(g, decompiled_dir)
            if c:
                got.add(c)
        # 内部类（Guard$Hb 这类）：wrapper 的每个 $X 子类也必然被注入
        if comp.get('wrapper'):
            w = _desc_to_dot(comp['wrapper'])
            for extra in comp.get('inner') or []:
                got.add(f'{w}${extra}')

        # uncheck：payload 是 smali 路径列表
        for p in comp.get('payload') or []:
            if isinstance(p, str):
                c = _from_smali_path(p, decompiled_dir)
                if c:
                    got.add(c)
        # calls 是调用点（LAUNCHER/Application 的 smali 路径）—— 那些是【目标
        # App 自己的类】，绝不能排除（排除了等于不加密业务类）。故意不吃。

        got.discard(None)
        if got:
            sources[name] = sorted(got)
            classes |= got

    return classes, sources


def to_rules(classes):
    """点分类名集合 → encrypt-strings 规则行（`!` = 排除）。

    ⚠️ 内部类要单独列：smali 里 Guard$Hb 是独立文件、独立类，
    规则匹配的是类名字符串，`!f5.aa` 不会顺带覆盖 `f5.aa$Hb`。
    这里靠 collect() 已把每个类都收进来，不做前缀展开 ——
    展开会误伤（`!f5.aa` 前缀匹配到 `f5.aaron` 这种无关类）。
    """
    return [f'!{c}' for c in sorted(classes)]


def main(argv):
    if len(argv) < 2:
        print('用法: inject-excludes.py <解包目录> [-o 输出文件]', file=sys.stderr)
        return 2
    decompiled = argv[1]
    if not os.path.isdir(decompiled):
        print(f'❌ 不是目录: {decompiled}', file=sys.stderr)
        return 2

    out_path = None
    if '-o' in argv:
        i = argv.index('-o')
        if i + 1 >= len(argv):
            print('❌ -o 需要参数', file=sys.stderr)
            return 2
        out_path = argv[i + 1]

    classes, sources = collect(decompiled)
    rules = to_rules(classes)

    if out_path:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rules))
            if rules:
                f.write('\n')
        # 排障可见：排除了什么、依据是哪个清单
        for name, cs in sources.items():
            print(f'  排除（{name}）: {", ".join(cs)}')
        print(f'✅ 注入类排除规则: {len(rules)} 条 → {out_path}')
    else:
        print('\n'.join(rules))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
