#!/usr/bin/env python3
"""resolve.py — configs/uncheck/v1/schema.json 的解释器

CLI 契约:
  resolve.py --print-json                 # 打印 schema 摘要（给 App 端生成 UI 用）
  resolve.py <配置文件.json>               # 校验并输出 run.py 参数（一行一个）
  resolve.py --defaults                   # 按 schema 默认值生成配置并输出参数

为什么独立于 scripts/actions/resolve-config.py:
  那边是【加固】的 schema 解释器，其「保险丝 a」是顶层 key 白名单，
  只认 configs/v1/config-schema.json 里定义的模块。把去校验的 key 塞进去
  会被当成未知 key 直接 die。
  两份职责不同：
    resolve-config.py → protect.sh 参数
    resolve.py        → run.py 参数
  刻意不共用代码：schema 结构不同（这份没有 rules_file / required 那套），
  强行抽象会让两边都变难改。

配置格式（与 configs/v1 同一套约定，降低学习成本）:
  leaf 模块  → true / false
  parent 模块 → {"enabled": true, "子项key": true, ...}
  schema_version 必填
"""
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))          # uncheck → scripts → 仓库根
# configs/v2 = 去校验卡片（v1 是加固，本文件不碰）
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

    # 版本号必须等于所在目录名（configs/v2/ → 2）。
    # 与 scripts/actions/check-schema.py 同一条规则（§10.6）：
    # 目录名与 schema_version 背离会让 App 按 version 拼路径时 404。
    _dir = os.path.basename(os.path.dirname(SCHEMA_PATH))
    if not re.fullmatch(r'v\d+', _dir):
        die(f'schema 必须放在 configs/v<N>/ 下，实际 {_dir!r}')
    _expect_ver = int(_dir[1:])
    if d.get('schema_version') != _expect_ver:
        die(f"schema_version 应为 {_expect_ver}（目录 {_dir}），"
            f"实际 {d.get('schema_version')!r}")
    mods = d.get('modules')
    if not isinstance(mods, list) or not mods:
        die('schema.modules 缺失或为空')

    seen = set()
    for m in mods:
        k = m.get('key')
        if not k:
            die('模块缺 key')
        if k in seen:
            die(f'模块 key 重复: {k}')
        seen.add(k)
        if m.get('type') not in ('leaf', 'parent'):
            die(f'{k}: type 非法 {m.get("type")!r}')
        if not re.fullmatch(r'--[a-z0-9-]+', m.get('arg', '')):
            die(f'{k}: arg 非法 {m.get("arg")!r}')
        if m['type'] == 'parent':
            kids = m.get('children')
            if not isinstance(kids, list) or not kids:
                die(f'{k}: parent 模块必须有 children')
            kseen = set()
            for c in kids:
                ck = c.get('key')
                if not ck:
                    die(f'{k}: 子项缺 key')
                if ck in kseen:
                    die(f'{k}: 子项 key 重复 {ck}')
                kseen.add(ck)
                if c.get('type') not in ('checkbox', 'radio', 'select', 'text'):
                    die(f'{k}.{ck}: type 非法 {c.get("type")!r}')
                if 'arg_on' not in c and c.get('type') != 'text':
                    die(f'{k}.{ck}: 非 text 子项必须有 arg_on')
    return d


def defaults_of(schema):
    """按 schema 默认值造一份配置。"""
    cfg = {'schema_version': schema['schema_version']}
    for m in schema['modules']:
        if m['type'] == 'leaf':
            cfg[m['key']] = bool(m.get('default', False))
        else:
            node = {'enabled': bool(m.get('default', False))}
            for c in m['children']:
                if c['type'] in ('checkbox',):
                    node[c['key']] = bool(c.get('default', False))
                elif c['type'] in ('radio', 'select'):
                    node[c['key']] = c.get('default')
                else:
                    node[c['key']] = c.get('default', '')
            cfg[m['key']] = node
    return cfg


def build_args(schema, cfg):
    """配置 → run.py 参数列表。返回 (args, notes)。"""
    if not isinstance(cfg, dict):
        die('配置顶层必须是 JSON 对象')
    if cfg.get('schema_version') != schema['schema_version']:
        die(f"配置 schema_version={cfg.get('schema_version')!r} "
            f"与 schema 的 {schema['schema_version']} 不一致")

    known = {m['key'] for m in schema['modules']} | {'schema_version'}
    unknown = sorted(set(cfg) - known)
    if unknown:
        die(f'出现 schema 未定义的顶层 key: {unknown}（拒绝执行）')

    args = []
    notes = []

    for m in schema['modules']:
        key = m['key']
        arg = m['arg']
        # 未在配置里出现的模块一律跳过。
        # cfg 由 defaults_of() 生成时包含所有模块，所以 --defaults 不受影响；
        # 用户手写的配置里没写的模块就是「没选」，跳过。
        if key not in cfg:
            continue

        if m['type'] == 'leaf':
            if cfg.get(key) is True:
                args.append(arg)
            elif cfg.get(key) not in (False, None):
                die(f'{key} 是 leaf，值必须是布尔，实际 {cfg.get(key)!r}')
            continue

        # parent
        node = cfg.get(key)
        if node is None:
            continue
        if not isinstance(node, dict):
            die(f'{key} 是 parent，值必须是对象 {{enabled: ...}}')
        if 'enabled' not in node:
            die(f'{key}.enabled 必填')
        enabled = node['enabled']
        if not isinstance(enabled, bool):
            die(f'{key}.enabled 必须是布尔，实际 {enabled!r}')

        child_keys = {c['key'] for c in m['children']}
        stray = sorted(set(node) - child_keys - {'enabled'})
        if stray:
            # 已下线的子 key 兼容（2026-11-21）：file_redirect 曾出现在 schema 里，
            # 但功能未实现，勾了就必然构建失败。已从 schema 移除。
            # App 可能缓存了旧 schema 并在配置里带上它 —— 这里**静默忽略**而不是
            # die：用户没做错什么（他勾的是当时界面允许的选项），
            # 报错只会让人困惑「为什么昨天能提交今天不行」。
            # 但要打警告，免得「勾了没生效」变成静默劣化。
            RETIRED_CHILD_KEYS = {'file_redirect'}
            retired = [k for k in stray if k in RETIRED_CHILD_KEYS]
            remaining = [k for k in stray if k not in RETIRED_CHILD_KEYS]
            if retired:
                notes.append(
                    f'⚠️ {key} 忽略了已下线的选项 {retired}（该功能未实现，'
                    f'此前勾选会导致构建失败；已从 schema 移除）')
            if remaining:
                die(f'{key} 出现未定义的子 key: {remaining}')

        if not enabled:
            continue

        # 收集本模块子项 → 参数
        for c in m['children']:
            ck = c['key']

            # visible_when：不满足则该项在 UI 上不存在，出现即视为非法
            vw = c.get('visible_when')
            if vw:
                dep = node.get(vw['key'])
                if dep != vw['equals']:
                    if ck in node:
                        die(f'{key}.{ck}: 依赖 {vw["key"]}={vw["equals"]!r}，'
                            f'当前 {vw["key"]}={dep!r}，该项不应存在')
                    continue

            if c['type'] == 'checkbox':
                v = node.get(ck, bool(c.get('default', False)))
                if not isinstance(v, bool):
                    die(f'{key}.{ck} 必须是布尔，实际 {v!r}')
                if v:
                    args.append(c['arg_on'])
            elif c['type'] in ('radio', 'select'):
                v = node.get(ck, c.get('default'))
                opts = {o['value']: o for o in c.get('options', [])}
                if v not in opts:
                    die(f'{key}.{ck}: 值 {v!r} 不在 options {sorted(opts)}')
                on = opts[v].get('arg_on', '')
                if on:
                    args.append(on)
            elif c['type'] == 'text':
                v = node.get(ck, c.get('default', ''))
                if not isinstance(v, str):
                    die(f'{key}.{ck} 必须是字符串')
                if c.get('required', {}).get('when') == 'always' and not v.strip():
                    die(f'{key}.{ck}: 必填，不能为空')
                if v.strip():
                    notes.append(f'{key}.{ck} 需要写文件（本 schema 暂无此类子项）')

    # 去重但保序（同一 arg 可能被多个入口产生）
    seen = set()
    out = []
    for a in args:
        if a not in seen:
            seen.add(a)
            out.append(a)

    # 互斥检查：axml 与 inject_point 是两条独立挂载路径，不冲突；
    # 但 pms 全关且没有别的载荷时等于什么都不做，必须拦住。
    if '--pms' not in out:
        notes.append('⚠️ 未启用 pms：本版本没有别的载荷，产物不会改变任何校验行为')

    return out, notes


def main(argv):
    schema = load_schema()

    if len(argv) >= 2 and argv[1] == '--print-json':
        print(json.dumps(schema, ensure_ascii=False, indent=2))
        return 0

    if len(argv) >= 2 and argv[1] == '--defaults':
        cfg = defaults_of(schema)
        args, notes = build_args(schema, cfg)
    elif len(argv) == 2 and argv[1] == '-':
        # 从 stdin 读：workflow 里把 config JSON 经环境变量喂进来，不落盘
        try:
            cfg = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            die(f'stdin 不是合法 JSON: {e}')
        args, notes = build_args(schema, cfg)
    elif len(argv) == 2:
        try:
            with open(argv[1], encoding='utf-8') as f:
                cfg = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            die(f'配置读取失败: {e}')
        args, notes = build_args(schema, cfg)
    else:
        print(__doc__)
        return 2

    for n in notes:
        print(f'ℹ️ {n}', file=sys.stderr)
    # 空参数 = 配置没启用任何手段。这里直接失败，而不是让下游
    # 靠 `test -s args.txt` 兜底：那样报错位置离真正原因（配置错了）太远。
    if not args:
        die('配置未启用任何实际操作，产物不会改变任何行为')
    for a in args:
        print(a)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
