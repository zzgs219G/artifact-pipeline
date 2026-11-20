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
    """配置 → 参数列表。单模块，没有子项，逻辑只有一条分支。"""
    if not isinstance(cfg, dict):
        die('配置顶层必须是 JSON 对象')

    version = schema['schema_version']
    if cfg.get('schema_version') != version:
        die(f'配置 schema_version={cfg.get("schema_version")!r} '
            f'与 schema 的 {version} 不一致（这条流水线只接受 v{version} 配置）')

    module = schema['modules'][0]
    key = module['key']
    arg = module['arg']

    known = {key, 'schema_version'}
    unknown = sorted(set(cfg) - known)
    if unknown:
        # 已下线/从未存在的键一律拒绝。这里不再为历史配置做兼容 ——
        # v2 卡片从上线就只有一个开关，不存在"老配置"这个概念。
        die(f'出现 schema 未定义的顶层 key: {unknown}（拒绝执行）')

    if key not in cfg:
        die(f'配置缺少 {key} 字段')
    enabled = cfg[key]
    if not isinstance(enabled, bool):
        die(f'{key} 必须是布尔，实际 {enabled!r}')
    if not enabled:
        die('配置里 uncheck=false —— 这条流水线没有别的能力，'
            '关掉它就没有任何作用，不应出包')

    return [arg]


def main(argv):
    schema = load_schema()

    if len(argv) >= 2 and argv[1] == '--print-json':
        print(json.dumps(schema, ensure_ascii=False, indent=2))
        return 0

    if len(argv) >= 2 and argv[1] == '--defaults':
        cfg = {'schema_version': schema['schema_version'],
               schema['modules'][0]['key']: True}
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
    else:
        print(__doc__)
        return 2

    for a in build_args(schema, cfg):
        print(a)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
