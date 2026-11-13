#!/usr/bin/env python3
"""test-toolkit-version.py — tools/ 下的分发包版本与登记表必须一致

## 为什么需要

2026-11-13 实测发现：`tools/工具包版本.md` 里 `nox.zip` 登记的是
`v0.9.12-obf`，而 `tools/nox.zip` 里 `VERSION` 实际是 `v0.9.37-plain`
—— **落后 25 个版本**。

这类"版本表与实物不符"没有任何现有机制能拦住：
`test-docs-paths.py` 只验证路径存在，验证不了版本号。

而不一致的后果是实打实的：读文档的人（或 AI）会以为用的是老版本，
据此推出完全错误的结论。本项目已因此误判过多次。

## 检查什么

对每个 zip 形态的工具包：
  ① 包内 `VERSION` 文件能读到
  ② 登记表里该行包含这个版本号
  ③ 若登记表写了 sha256，实际 sha256 必须一致

## 用法

    python3 scripts/actions/tests/test-toolkit-version.py
"""
import hashlib
import pathlib
import re
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
TOOLS = ROOT / 'tools'
MANIFEST = TOOLS / '工具包版本.md'

# zip 包 → 包内标识文件路径
# ⚠️ dpt-shell 没有 VERSION 文件，它的版本靠 build-key 识别
#    （登记表里写作 `Dpt-Build-Key` = xxx）。
ZIPS = {
    'nox.zip': 'nox/VERSION',
    'dex2c.zip': 'Dex2C/VERSION',
    'dpt-shell.zip': 'executable/shell-files/build-key',
}

pass_n = fail_n = skip_n = 0


def check(name, ok, detail=''):
    global pass_n, fail_n
    if ok:
        print('  ✅ %s' % name)
        pass_n += 1
    else:
        print('  ❌ %s' % name)
        if detail:
            print('     %s' % detail)
        fail_n += 1


def skip(name):
    global skip_n
    print('  ⏭ %s' % name)
    skip_n += 1


def main():
    if not MANIFEST.is_file():
        print('❌ 找不到 %s' % MANIFEST)
        return 1
    text = MANIFEST.read_text(encoding='utf-8', errors='replace')

    for zname, vpath in ZIPS.items():
        zp = TOOLS / zname
        print('\n[%s]' % zname)
        if not zp.is_file():
            skip('%s 不存在（该模块未启用）' % zname)
            continue

        # ① 读包内 VERSION
        try:
            with zipfile.ZipFile(zp) as z:
                actual = z.read(vpath).decode('utf-8', 'replace').strip()
        except (KeyError, zipfile.BadZipFile, OSError) as e:
            skip('%s 无 %s（%s）' % (zname, vpath, type(e).__name__))
            continue

        # ② 登记表里该行必须包含这个版本
        row = None
        for line in text.split('\n'):
            if line.startswith('| `%s`' % zname):
                row = line
                break
        if row is None:
            check('%s 在登记表里有对应行' % zname, False,
                  '工具包版本.md 里找不到 `| `%s` |` 开头的行' % zname)
            continue

        check('%s 登记版本包含包内实际版本 %s' % (zname, actual),
              actual in row,
              '登记行里没有 "%s" —— 换版后忘了更新工具包版本.md' % actual)

        # ③ 写了 sha256 的话要对拍
        m = re.search(r'sha256\s*`([0-9a-f]{64})`', row)
        if m:
            want = m.group(1)
            got = hashlib.sha256(zp.read_bytes()).hexdigest()
            check('%s sha256 与登记一致' % zname, want == got,
                  '登记=%s\n     实际=%s' % (want, got))
        else:
            skip('%s 登记行未写 sha256（无法校验内容）' % zname)

    # 末行的"作者:当前"汇总也必须包含各包【版本号】
    #
    # ⚠️ 这里只校验有 VERSION 文件的包。dpt-shell 用 build-key 标识，
    #    汇总行写的是它的 tag（1.6.1-strkey）而不是 build-key —— 两种
    #    标识不该混用，强求一致会造出恒假的断言。
    print('\n[汇总行]')
    tail = [l for l in text.split('\n') if l.startswith('作者:当前')]
    if not tail:
        skip('无"作者:当前"汇总行')
    else:
        line = tail[0]
        ok = True
        detail = []
        for zname, vpath in ZIPS.items():
            if not vpath.endswith('/VERSION'):
                continue          # 非 VERSION 标识的包不参与本项
            zp = TOOLS / zname
            if not zp.is_file():
                continue
            try:
                with zipfile.ZipFile(zp) as z:
                    v = z.read(vpath).decode('utf-8', 'replace').strip()
            except Exception:
                continue
            if v not in line:
                ok = False
                detail.append('%s 实际 %s，汇总行里没有' % (zname, v))
        check('汇总行包含所有分发包的实际版本', ok, '\n     '.join(detail))

    print('\n通过 %d，失败 %d，跳过 %d' % (pass_n, fail_n, skip_n))
    return 0 if fail_n == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
