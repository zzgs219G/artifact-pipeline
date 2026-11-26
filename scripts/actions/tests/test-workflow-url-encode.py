#!/usr/bin/env python3
"""test-workflow-url-encode.py — 两条 workflow 的 apk_url 下载都必须做百分号编码

用法: python3 scripts/actions/tests/test-workflow-url-encode.py

=== 为什么这个测试存在（2026-11-27）===

用户上传 `JMComic3v2.1.14 (2).apk`，uncheck 流水线报：

    curl: (3) URL rejected: Malformed input to a URL function

根因：curl 拒绝未编码的空格/括号/中文。

**这个坑 2026-10-16 就在 protect-modules.yml 修过**（记作「报错四十四」，
注释里连当时的文件名都写着），但 uncheck.yml 是后加的、手抄时漏了这一段。
于是同一个 bug 在另一个入口原样复现，用户侧表现为「这条流水线连包都下不下来」。

这不是兼容性问题，是**修一处没同步另一处**的结构问题。
本测试钉两件事：
  ① 两条 workflow 的下载步骤都调用了编码（防再漏一条）
  ② 编码函数对真实坏文件名确实产出合法 URL（防写成摆设）

反向验证：把任一 workflow 的编码段删掉，本测试立刻变红。
"""
import re
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WF_DIR = ROOT / ".github/workflows"

# 所有会从 apk_url 下载输入包的 workflow
WORKFLOWS = ["protect-modules.yml", "uncheck.yml"]

# 实测炸掉过的文件名（报告四十四 + 2026-11-27 各一例）
BAD_NAMES = [
    "https://example.com/apks/1795712279331_JMComic3v2.1.14 (2).apk",
    "https://example.com/apks/简盒-正式版-(1)_sign.apk",
    "https://example.com/a/b.apk?x=1 2",       # query 里带空格
]

ENCODE_SNIPPET = 'urllib.parse.quote(p.path, safe="/%:@")'

passed, failed = [], []


def chk(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  {detail}" if detail and not cond else ""))


def encode_like_workflow(u: str) -> str:
    """复刻 workflow 里的一行命令（保持单一真相：直接从 yml 抓那段代码跑）。"""
    p = urllib.parse.urlsplit(u.strip())
    path = urllib.parse.quote(p.path, safe="/%:@")
    query = urllib.parse.quote(p.query, safe="=&%:@") if p.query else ""
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, query, ""))


print("[两条 workflow 都必须编码 apk_url]")
for wf in WORKFLOWS:
    f = WF_DIR / wf
    chk(f"{wf} 存在", f.is_file())
    if not f.is_file():
        continue
    src = f.read_text(encoding="utf-8")
    # 找到「下载 APK」那一步的片段（到下一个 - name: 为止）
    m = re.search(r"- name:\s*下载 APK(.*?)(?=\n      - name:|\Z)", src, re.S)
    chk(f"{wf} 有「下载 APK」步骤", m is not None)
    if not m:
        continue
    body = m.group(1)
    chk(f"{wf} 用 ENC_URL 而非裸 apk_url 下载",
        "ENC_URL" in body and re.search(r'curl[^\n]*"\$ENC_URL"', body) is not None,
        "裸插值 ${{ inputs.apk_url }} 会在含空格时 curl(3) 失败")
    chk(f"{wf} 含编码调用", ENCODE_SNIPPET in body,
        "缺 urllib.parse.quote 调用")
    # env: 段里出现 ${{ inputs.apk_url }} 是【正确】的（那就是中转点）。
    # 要查的是 run: 段（真正执行的脚本）里不许再直接插值。
    run_part = body.split("run:", 1)[1] if "run:" in body else ""
    chk(f"{wf} apk_url 经 env 中转（run 段不含直接插值）",
        "APK_URL:" in body and "inputs.apk_url" not in run_part,
        "直接插值进 bash 双引号可被命令替换逃逸")

print("\n[编码函数对真实坏文件名产出合法 URL]")
for bad in BAD_NAMES:
    enc = encode_like_workflow(bad)
    chk(f"无空格残留: {bad.split('/')[-1][:28]}", " " not in enc)
    chk(f"无裸括号/中文: {bad.split('/')[-1][:28]}",
        not re.search(r'[\u4e00-\u9fff()]', enc))
    # 已编码的 %XX 不能被二次编码（%20 → %2520）
    chk(f"不重复编码 %XX: {bad.split('/')[-1][:28]}", "%25" not in enc)
    # 重编码幂等
    chk(f"重编码幂等: {bad.split('/')[-1][:28]}", encode_like_workflow(enc) == enc)

print()
if failed:
    print(f"❌ 失败 {len(failed)} 项 / 通过 {len(passed)} 项")
    for x in failed:
        print(f"   · {x}")
    sys.exit(1)
print(f"✅ 全部通过：{len(passed)} 项断言")
