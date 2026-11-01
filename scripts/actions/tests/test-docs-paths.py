#!/usr/bin/env python3
"""test-docs-paths.py — 文档里引用的仓库内路径必须真实存在。

为什么需要（2026-11-01）：
  重新接手本仓库时发现 AGENTS.md 的冻结表列着 6 个【不存在】的文件
  （scripts/so-guard/nc_guard_boot.c 等，2026-10-30 已迁到上游 nox），
  流程文档 §0.2 目录树同样列着 7 个已不存在的 nc_guard_* 条目。
  后果：按文档找文件只能扑空，或误以为还要维护它。

  这类失真不是一次性的疏忽——**每次拆仓库/删模块都会重演**，因为
  文档是手写的、代码是自动的，两者没有任何机器校验。本测试补上这一环。

检查范围：
  · AGENTS.md、README.md（仓库根）
  · docs/*.md（不含 docs/备份/ 归档、不含 so层防御/ 的历史复盘——
    那些是"当时的事实"档案，路径本就该保持原样）

判定规则：
  只校验"看起来像仓库内路径"的反引号内容：必须含 `/` 且以已知扩展名结尾。
  以 `../` 开头的跳过（跨仓库引用，如 ../nox/scripts/so-guard）。
  `<xxx>` 等占位符跳过。

用法: python3 scripts/actions/tests/test-docs-paths.py
"""
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# 需要校验的文档
DOC_FILES = ["AGENTS.md", "README.md"]
DOC_DIRS = ["docs"]

# 归档 / 历史 / 计划类文档：内容是"当时的事实"或"待办设想"，
# 路径不跟随迁移。判定依据是它们自己的头注（变更历史.md 明写"路径都是当时的"）。
SKIP_FILES = {"变更历史.md", "计划-so-guard独立化.md", "报错速查.md"}

# 归档目录
SKIP_DIRS = {"备份", "so层防御"}

# 只校验以这些【仓库顶层目录】开头的路径。
# 不这么做的话会把大量"相对简写"（表格里的 lib/common.sh 指 scripts/lib/common.sh）
# 和"说明性示例"（jni/nc/compiled_methods.txt 是构建产物路径）判成失效，全是假阳性。
TOP_DIRS = ("scripts/", "tools/", "configs/", "docs/", ".github/")

# 只校验这些扩展名——避免把 "and/or"、"CI/CD" 之类误判成路径
EXTS = (
    ".c", ".h", ".py", ".sh", ".jar", ".zip", ".md", ".yml", ".yaml",
    ".json", ".smali", ".java", ".toml", ".txt",
)

# 构建期解压产物（.gitignore 忽略，本地有 / CI 无）。
# 文档引用它们是【正常】的：它们是构建链路的一部分，只是不入库。
# 必须在 CI 里也跳过，否则本地绿、CI 红（首次上 CI 实测撞到过：
# tools/Dex2C/requirements.txt 与 tools/Dex2C/dcc.py 两处）。
BUILD_ARTIFACT_PREFIXES = (
    "tools/Dex2C/",       # dex2c.zip 解压产物
    "tools/executable/",  # dpt-shell.zip 解压产物
    "tools/nox/",         # nox.zip 解压产物
    "tools/nox-src/",
    "tools/perftrace/",
    "build/",
)

# 反引号包裹的内容；允许带后缀说明，如 `scripts/foo.sh:12`
TICK_RE = re.compile(r"`([^`\n]+)`")

# 行级豁免：这些行是在【说明某文件已删除/已迁移】，
# 路径本身故意保留以保留可追溯性（"旧 X 已删"读起来必须带旧名）。
# ⚠️ 关键词必须足够"声明性"：早期版本用了裸 "不存在"，结果
#    「`tools/不存在的文件.py`」这种失效路径也被豁免掉了（自造假阴性，
#    已用反向验证抓到）。所以一律用带主语结构的措辞。
NEGATION_MARKERS = (
    "已删除", "已下架", "已迁", "此前列", "原文讲", "已废",
    "不再保存", "不再存在", "已移出", "已退出", "时已删",
    "均已不存在", "该目录已不存在", "未随仓库保留", "尚未创建",
)


def collect_docs():
    """返回待校验的文档绝对路径列表。"""
    out = []
    for name in DOC_FILES:
        p = os.path.join(ROOT, name)
        if os.path.isfile(p):
            out.append(p)
    for d in DOC_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            # 原地裁剪，避免走进归档目录
            dirnames[:] = [x for x in dirnames if x not in SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(".md") and fn not in SKIP_FILES:
                    out.append(os.path.join(dirpath, fn))
    return sorted(out)


def looks_like_repo_path(tok: str) -> bool:
    """判断反引号内容是否是【仓库内真实文件路径】。"""
    tok = tok.strip()
    if not tok or " " in tok or "\n" in tok:
        return False
    # 去掉行号后缀  foo.py:12
    tok = re.sub(r":\d+(-\d+)?$", "", tok)
    if not tok.endswith(EXTS):
        return False
    # 必须从仓库顶层目录开始——相对简写与产物路径一律不判
    if not tok.startswith(TOP_DIRS):
        return False
    # 占位符 / 通配
    if "<" in tok or ">" in tok or "*" in tok:
        return False
    return True


def main() -> int:
    docs = collect_docs()
    if not docs:
        print("✗ 没找到任何待校验文档，路径推导有问题", file=sys.stderr)
        return 1

    bad = []
    checked = 0
    for doc in docs:
        rel_doc = os.path.relpath(doc, ROOT)
        with open(doc, encoding="utf-8") as fp:
            text = fp.read()
        for lineno, line in enumerate(text.splitlines(), 1):
            # 跳过代码块围栏本身
            if line.strip().startswith("```"):
                continue
            # 说明"某文件已删除/已迁移"的行：路径故意保留，不判
            if any(m in line for m in NEGATION_MARKERS):
                continue
            for tok in TICK_RE.findall(line):
                if not looks_like_repo_path(tok):
                    continue
                path = re.sub(r":\d+(-\d+)?$", "", tok.strip())
                # 构建期解压产物：本地可能有、CI 一定没有，不算失效
                if path.startswith(BUILD_ARTIFACT_PREFIXES):
                    continue
                checked += 1
                if not os.path.exists(os.path.join(ROOT, path)):
                    bad.append(f"{rel_doc}:{lineno}  {tok}")

    if bad:
        print(f"✗ 文档引用了 {len(bad)} 个不存在的路径"
              f"（共校验 {checked} 个）：", file=sys.stderr)
        for b in bad:
            print(f"    {b}", file=sys.stderr)
        print("\n  修法：① 路径已迁移 → 改成新位置；"
              "② 文件已删除 → 从文档删掉该行；"
              "③ 跨仓库引用 → 写成 ../<repo>/... 形式（本检查会跳过）。",
              file=sys.stderr)
        return 1

    print(f"docs paths OK（{len(docs)} 份文档，{checked} 个路径全部存在）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
