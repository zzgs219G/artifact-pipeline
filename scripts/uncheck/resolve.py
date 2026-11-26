#!/usr/bin/env python3
"""resolve.py — configs/v2（去签名校验）卡片的解释器

CLI 契约:
  resolve.py -              # 从 stdin 读配置 JSON（workflow 用这条）
  resolve.py <配置文件.json>
  resolve.py --defaults     # 按 schema 默认值
  resolve.py --print-json   # 打印 schema（给 App 生成 UI 用）

## 为什么这个文件这么短

去签名校验只有一件事可做，**没有可选子项**：勾了这条流水线就是要做这件事，
不该再问「要不要 PackageManager 代理」「要不要出包前体检」——
那些是实现细节，问了只会让用户配错（实测踩过：`file_redirect` 是个
未实现的选项，勾了就必然构建失败）。

所以这里的逻辑极简：
  配置里 uncheck 为 true → 输出 --uncheck
  否则 → 报错退出

## 与 scripts/actions/resolve-config.py 的关系

那个读 configs/v1（加固，7 个模块，复杂结构），这个读 configs/v2。
刻意不共用：两份 schema 的形状完全不同（这份是单 leaf 模块），
强行抽象会让两边都变难懂。
"""
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
SCHEMA_PATH = os.path.join(_ROOT, 'configs', 'v2', 'config-schema.json')


def die(msg):
    print(f'❌ {msg}', file=sys.stderr)
    sys.exit(1)


def load_schema():
    if not os.path.isfile(SCHEMA_PATH):
        die(f'schema 不存在: {SCHEMA_PATH}')
    try:
        with open(SCHEMA_PATH, encoding='utf-8') as f:
            d = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        die(f'schema 读取失败: {e}')

    # 版本号必须等于所在目录名（与 scripts/actions/check-schema.py 同一规则）。
    # 目录名与 schema_version 背离会让 App 按 version 拼路径时 404。
    dirname = os.path.basename(os.path.dirname(SCHEMA_PATH))
    if not re.fullmatch(r'v\d+', dirname):
        die(f'schema 必须放在 configs/v<N>/ 下，实际 {dirname!r}')
    expect = int(dirname[1:])
    if d.get('schema_version') != expect:
        die(f"schema_version 应为 {expect}（目录 {dirname}），"
            f"实际 {d.get('schema_version')!r}")

    mods = d.get('modules')
    if not isinstance(mods, list) or not mods:
        die('schema.modules 缺失或为空')
    return d


def build_args(schema, cfg):
    """配置 → 参数列表。

    形状：{ "schema_version": 2,
             "uncheck": { "enabled": true, "layer": "java" } }

    `layer`（2026-11-27 新增）：
      both（默认）/ java —— java 会追加 --java-only，不投放 libusign.so。
    为什么加这个：WebView / Capacitor / Flutter 类 App 的图片与网络走
    Chromium 或自带 IO 栈，被全局 libc 重定向（open/stat/readlink）影响后
    会出现资源加载失败。这类 App 通常只用 PackageManager 校验，Java 层够用。

    兼容：`uncheck` 允许是布尔（旧 App 快照只发 true/false），
    布尔时按 schema default（both）处理。
    """
    if not isinstance(cfg, dict):
        die('配置顶层必须是 JSON 对象')

    version = schema['schema_version']
    if cfg.get('schema_version') != version:
        die(f'配置 schema_version={cfg.get("schema_version")!r} '
            f'与 schema 的 {version} 不一致（这条流水线只接受 v{version} 配置）')

    module = schema['modules'][0]
    key = module['key']
    arg = module['arg']
    children = {c['key']: c for c in module.get('children', [])}

    known = {key, 'schema_version'}
    unknown = sorted(set(cfg) - known)
    if unknown:
        # 已下线/从未存在的键一律拒绝（file_redirect 那类未实现选项
        # 曾经勾了就必然失败，宁可报错也不静默忽略）。
        die(f'出现 schema 未定义的顶层 key: {unknown}（拒绝执行）')

    if key not in cfg:
        die(f'配置缺少 {key} 字段')

    # ── 归一化：布尔 → {enabled, <子项默认值>} ──────────────────────
    raw = cfg[key]
    if isinstance(raw, bool):
        sub = {ck: c.get('default') for ck, c in children.items()}
        enabled = raw
    elif isinstance(raw, dict):
        enabled = raw.get('enabled', True)
        if not isinstance(enabled, bool):
            die(f'{key}.enabled 必须是布尔，实际 {enabled!r}')
        unknown_sub = sorted(set(raw) - {'enabled'} - set(children))
        if unknown_sub:
            die(f'{key} 出现未定义的子项: {unknown_sub}'
                f'（已定义: {sorted(children) or "无"}）')
        sub = dict(raw)
    else:
        die(f'{key} 必须是布尔或对象，实际 {type(raw).__name__}')

    if not enabled:
        die('配置里 uncheck 关掉了 —— 这条流水线没有别的能力，'
            '关掉它就没有任何作用，不应出包')

    out = [arg]

    # ── layer：both（默认）| java ─────────────────────────────────
    layer_item = children.get('layer')
    if layer_item is not None:
        val = sub.get('layer', layer_item.get('default'))
        opts = {o['value']: o for o in layer_item.get('options', [])}
        if val not in opts:
            die(f'{key}.layer={val!r} 不是合法选项（可选: {sorted(opts)}）')
        extra = opts[val].get('arg_on', '')
        if extra:
            out.append(extra)

    return out


def main(argv):
    schema = load_schema()

    if len(argv) >= 2 and argv[1] == '--print-json':
        print(json.dumps(schema, ensure_ascii=False, indent=2))
        return 0

    if len(argv) >= 2 and argv[1] == '--defaults':
        m0 = schema['modules'][0]
        cfg = {'schema_version': schema['schema_version'],
               m0['key']: {'enabled': True,
                           **{c['key']: c.get('default')
                              for c in m0.get('children', [])}}}
    elif len(argv) == 2 and argv[1] == '-':
        try:
            cfg = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            die(f'stdin 不是合法 JSON: {e}')
    elif len(argv) == 2:
        try:
            with open(argv[1], encoding='utf-8') as f:
                cfg = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            die(f'配置读取失败: {e}')
    elif len(argv) == 1:
        # 无参数 = 读 stdin。
        #
        # 为什么不强制要求写 `-`：workflow 里用 `<<<` here-string 重定向
        # 是最自然的写法，忘写 `-` 时本可以正常工作，却会因为"参数个数不对"
        # 打出整篇 usage 然后 exit 2 —— 那个报错完全没提示真正原因
        # （实测踩过：run 44800089327 失败在「解析配置」，日志里只有
        #   exit code 1，看不到任何有用信息）。
        # 默认读 stdin 让两种写法都成立，且不会误伤「传了文件路径」的情形。
        try:
            cfg = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            die(f'stdin 不是合法 JSON: {e}')
    else:
        print(__doc__)
        return 2

    for a in build_args(schema, cfg):
        print(a)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
