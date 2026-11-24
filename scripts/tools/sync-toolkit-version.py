#!/usr/bin/env python3
"""sync-toolkit-version.py — 换分发包后自动同步 tools/工具包版本.md

==== 为什么存在（2026-11-24）====
换一次 nox.zip 要人工同步登记表 4 处（条目行的版本/sha256/大小/自报、
汇总行），当天手工 sed 连错两次（替换串错位、新旧两段黏连成一行），
全靠 CI 的 test-toolkit-version.py 拦截后返工。本脚本把"读实物 → 改表"
变成一条命令，字段级精确替换，不再有 sed 转义地狱。

用法：
    python3 scripts/tools/sync-toolkit-version.py tools/nox.zip
    python3 scripts/tools/sync-toolkit-version.py tools/nox.zip --check  # 只校验不改

支持的分发包：nox.zip（v0.9.49 起的条目形态；含"v0.9.49 变更"等描述）。
其他包（dex2c/dpt-shell）换得少，暂未接入——沿用人工核对。
"""
import hashlib
import os
import re
import subprocess
import sys
import zipfile

TABLE = "tools/工具包版本.md"


def die(msg):
    print(f"❌ {msg}", file=sys.stderr)
    sys.exit(1)


def zip_facts(zip_path):
    """读 zip：VERSION 自报、sha256、大小。"""
    try:
        with zipfile.ZipFile(zip_path) as z:
            names = z.namelist()
            ver_entry = next(
                (n for n in names if n.rstrip("/").endswith("VERSION")), None)
            if not ver_entry:
                die(f"{zip_path} 里没有 VERSION 条目")
            ver = z.read(ver_entry).decode("ascii", "replace").strip()
    except zipfile.BadZipFile as e:
        die(f"{zip_path} 不是合法 zip: {e}")
    sha = hashlib.sha256(open(zip_path, "rb").read()).hexdigest()
    size = len(open(zip_path, "rb").read())
    return ver, sha, size


def sync_nox(zip_path, check_only):
    ver, sha, size = zip_facts(zip_path)
    table = open(TABLE, encoding="utf-8").read()

    # 条目行：定位 "| `nox.zip` |" 开头的行，字段级重写头部
    lines = table.split("\n")
    idx = next((i for i, l in enumerate(lines)
                if l.startswith("| `nox.zip` |")), None)
    if idx is None:
        die(f"{TABLE} 里找不到 nox.zip 条目行")

    row = lines[idx]
    # 条目行头部字段（版本/sha256/大小/自报）——尾部描述原样保留
    new_head = (f"| `nox.zip` | **`{ver}`**（静态库形态；sha256 `{sha}`，"
                f"{size} B；包内 `VERSION` 自报 `{ver}`）")
    # 行头模式：| `nox.zip` | **`<旧版本>`**（...）—— "）" 后可能有空格再接描述列
    m = re.match(
        r"\| `nox\.zip` \| \*\*`[^`]+`\*\*（[^）]*）(\s*\|.*)?$", row)
    if not m:
        die("nox.zip 条目行头部形态与预期不符（上次手工改坏？），"
            "请人工核对该行后重跑")
    tail = (m.group(1) or "|").strip()
    # tail 形如 "| so 段加密设施（...）。 |"——原样保留描述，规范左缘
    if not tail.startswith("|"):
        tail = "| " + tail
    lines[idx] = new_head + " " + tail

    # 汇总行：nox vX.Y.Z
    for i, l in enumerate(lines):
        if l.startswith("作者:") and "nox " in l:
            lines[i] = re.sub(r"nox v[0-9][0-9a-zA-Z.\-]*",
                              f"nox {ver}", l)

    new_table = "\n".join(lines)
    if new_table == table:
        print(f"✅ {zip_path}: 登记表已是最新（{ver}），无需修改")
        return 0

    if check_only:
        print(f"❌ {zip_path}: 登记表过期（应为 {ver}，sha256 {sha[:12]}…）"
              "—— 去掉 --check 以自动同步")
        return 1

    open(TABLE, "w", encoding="utf-8").write(new_table)
    # 自证：跑既有的登记一致性断言（CI 同款）
    r = subprocess.run(
        ["python3", "scripts/actions/tests/test-toolkit-version.py"],
        capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, file=sys.stderr)
        die("同步后自检失败——回滚：git checkout tools/工具包版本.md")
    print(f"✅ {zip_path}: 登记表已同步（{ver}，{size} B，sha256 {sha[:12]}…）"
          "  且 test-toolkit-version 通过")
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    zip_path = argv[1]
    check = "--check" in argv[2:]
    if "nox.zip" in zip_path:
        return sync_nox(zip_path, check)
    die(f"尚未支持 {zip_path}（目前只接入 nox.zip；其他包换得少，沿用人工核对）")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
