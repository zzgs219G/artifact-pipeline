#!/usr/bin/env python3
"""extract-derive.py — 从 make-sig-hash.sh 抽取【真实的】派生公式并执行。

【为什么需要这个工具】
  签名校验有两条独立派生线，公式各在 make-sig-hash.sh 里写了一遍：
     线1  sig_hash.h   → sig_check.c  的 derive_expected()
     线2  sig_guard2.h → sig_guard2.c 的 g2_derive()

  生成侧（python）与校验侧（C）必须【逐字节一致】。不一致的后果不是报错，
  而是"正确签名的包被判失败" → delayed_kill / tgkill watchdog → 全量闪退。

  而 2026-11-22 实测发现：test-sig-guard2.sh 里把公式【手抄了一份】，
  并标注"与 make-sig-hash.sh 内嵌的完全一致"。实测把生成侧系数
  0x5B 改成 0x5C 后 —— 该测试依旧 3/3 全绿。也就是说，
  生成侧公式漂移时，测试替它保密。

  本工具改成从 make-sig-hash.sh 里【抽取】那段 python 源码执行，
  测试于是跟随生产侧变化：改一处，测试立刻红。

【做了什么 / 不做什么】
  只做一件事：抽取 + 把 os.urandom 换成固定盐（为了可复现）。
  ⚠️ 不重写公式本身 —— 公式来自生产文件，本工具一个字都不参与计算。

用法:
  python3 extract-derive.py <make-sig-hash.sh> <line: 1|2> [--salt HEX] [--fp HEX]

  输出 JSON: {"salt": "<hex>", "stored": "<hex>", "domain": "..."}

  固定盐：不给 --salt 时用 range(len)，可复现。
  固定指纹：不给 --fp 时用 range(32)；给了就按 32 字节十六进制解析。
"""
import json
import os
import re
import sys


def extract_block(sh_text, which):
    """抽取 make-sig-hash.sh 里第 which 段 python heredoc。

    识别方式：heredoc 前一行含 DERIVED_JSON（线1）或 DERIVED2_JSON（线2）。
    不按"第几个 heredoc"数 —— 文件里将来可能加别的 heredoc，
    按序号取会静默取错段（这正是本工具要消灭的那类脆弱性）。
    """
    marker = 'DERIVED_JSON' if which == 1 else 'DERIVED2_JSON'
    lines = sh_text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if marker in ln and '<<' in ln and 'python3' in ln:
            start = i
            break
    if start is None:
        raise SystemExit(
            f"❌ 在 make-sig-hash.sh 里找不到 {marker} 的 python heredoc。\n"
            f"   本工具依赖该锚点；找不到说明生成侧结构变了，"
            f"需要同步更新本工具（而不是让测试悄悄退回手抄公式）。")

    # heredoc 正文从 start+1 起，到 PYEOF 行为止
    #
    # ⚠️ 不能用 for...else：循环里 break 之后 else 分支【不执行】，
    #    于是"没找到 PYEOF"这种情况被静默吞掉，body 一路吃到文件末尾 ——
    #    抽取器会把后面几十行 bash 当 python 执行，报出来的错与真正原因
    #    （heredoc 未闭合）毫不相干。这是 2026-11-22 自己的测试抓到的
    #    第一个 bug（test-derive-extract.py 的"缺 PYEOF → 非零退出"）。
    body = []
    closed = False
    for ln in lines[start + 1:]:
        if ln.strip() == 'PYEOF':
            closed = True
            break
        body.append(ln)
    if not closed:
        raise SystemExit(
            f"❌ {marker} 的 heredoc 没有 PYEOF 结束行 ——\n"
            f"   生成侧文件结构损坏，或 PYEOF 被改名/缩进。\n"
            f"   拒绝继续（否则会把后续 bash 行当 python 执行，"
            f"报出的错误与真正原因无关）。")
    if not body:
        raise SystemExit(f"❌ {marker} 的 heredoc 是空的")
    return '\n'.join(body)


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    sh_path = sys.argv[1]
    which = int(sys.argv[2])
    fixed_salt = None
    fixed_fp = None
    if '--salt' in sys.argv:
        fixed_salt = sys.argv[sys.argv.index('--salt') + 1]
    if '--fp' in sys.argv:
        fixed_fp = sys.argv[sys.argv.index('--fp') + 1]
    if '--out' in sys.argv:
        out_json = sys.argv[sys.argv.index('--out') + 1]
    else:
        out_json = None

    with open(sh_path, encoding='utf-8') as f:
        sh_text = f.read()

    code = extract_block(sh_text, which)

    # ── 把随机盐换成固定盐（唯一允许的改写）────────────────────────
    # 目标形态：salt = os.urandom(16)
    m = re.search(r'(\w+)\s*=\s*os\.urandom\(\s*(\d+)\s*\)', code)
    if not m:
        raise SystemExit(
            "❌ 抽取到的公式里没有 `xxx = os.urandom(N)` ——\n"
            "   本工具靠它定位盐长度并替换成固定值。找不到就不替换，\n"
            "   否则测试每次结果不同，无法对拍。\n"
            "   生成侧结构变了？请同步更新本工具。")
    var, nbytes = m.group(1), int(m.group(2))
    if fixed_salt is None:
        salt_bytes = bytes(range(nbytes))
    else:
        salt_bytes = bytes.fromhex(fixed_salt)
        if len(salt_bytes) != nbytes:
            raise SystemExit(
                f"❌ --salt 长度 {len(salt_bytes)} 与生成侧的 {nbytes} 不符")
    code = code[:m.start()] + \
        f'{var} = bytes({list(salt_bytes)})' + code[m.end():]

    # 抽取到的代码用 argv[1] 作指纹输入；这里喂固定测试指纹
    if fixed_fp is None:
        fp_bytes = bytes(range(32))
    else:
        fp_bytes = bytes.fromhex(fixed_fp)
    fp_hex = fp_bytes.hex()

    # 执行抽取来的代码。命名空间隔离，避免污染本工具。
    ns = {'__name__': '__extracted__'}
    old_argv = sys.argv
    sys.argv = ['extracted', fp_hex]
    try:
        # 它最后一句是 print(json.dumps({...}))
        import io
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            exec(compile(code, f'<make-sig-hash.sh:{which}>', 'exec'), ns)
        finally:
            sys.stdout = old_stdout
        out = buf.getvalue().strip().splitlines()
    finally:
        sys.argv = old_argv

    if not out:
        raise SystemExit("❌ 抽取的公式没有产生输出")
    data = json.loads(out[-1])
    data['domain'] = 'sig_hash' if which == 1 else 'sig_guard2'
    data['extracted_from'] = os.path.basename(sh_path)
    data['fp'] = fp_hex
    text = json.dumps(data)
    if out_json:
        with open(out_json, 'w', encoding='utf-8') as f:
            f.write(text + '\n')
    print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
