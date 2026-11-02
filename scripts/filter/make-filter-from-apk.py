#!/usr/bin/env python3
"""make-filter-from-apk.py — 从 APK 的 AndroidManifest.xml 动态解析 LAUNCHER
activity,生成 dcc filter 文件(联合方案的"自动获取类名"环节)。

原理:
  1. 用 androguard 解析 Manifest,取带 MAIN+LAUNCHER intent-filter 的 activity
     (复用 dcc 内置 androguard,不引入新依赖);相对类名 .Foo / Foo 自动补全包名。
  2. 找不到唯一 LAUNCHER activity 时,按失败策略处理(--on-fail)。
  3. 输出 dcc filter(一行一个类),供 dcc.py --filter 使用。
  4. 顺带产出所有 Activity 类列表(供 activity* 通配符展开,--emit-classes)。

用法:
  make-filter-from-apk.py <apk> <输出filter> [--classes 类列表输出文件]
                         [--on-fail error|skip] [--all-activities]
"""
import os
import re
import sys

# 本脚本位于 scripts/filter/,dcc 从 tools/dcc.zip 分发 → 解压产物在
# <仓库根>/tools/dcc(单层;缺失时从 zip 幂等解压)
# (更早教训 0f80c69: 移动脚本后基于 __file__ 的相对路径必须重算,
#  否则云端 ModuleNotFoundError: androguard)
DCC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '..', '..', 'tools', 'Dex2C')


def _ensure_dcc_dir():
    """androguard 供应目录缺失时从 dex2c.zip 幂等解压（2026-10-21 起
    供应源由 dcc.zip 换为 dex2c.zip，原 tools/dcc 已退役删除）。"""
    dcc_dir = os.path.abspath(DCC_DIR)
    if not os.path.isfile(os.path.join(dcc_dir, 'androguard', 'core', 'bytecodes', 'apk.py')):
        ag_zip = os.path.normpath(os.path.join(dcc_dir, '..', 'dex2c.zip'))
        if not os.path.isfile(ag_zip):
            raise FileNotFoundError(f'dex2c 分发包缺失: {ag_zip}')
        import zipfile
        os.makedirs(os.path.dirname(dcc_dir), exist_ok=True)
        with zipfile.ZipFile(ag_zip) as zf:
            zf.extractall(os.path.dirname(dcc_dir))
        if not os.path.isfile(os.path.join(dcc_dir, 'androguard', 'core', 'bytecodes', 'apk.py')):
            raise FileNotFoundError(f'dex2c.zip 解压后缺 androguard: {dcc_dir}')
    return dcc_dir


def load_apk(apk_path):
    dcc_dir = _ensure_dcc_dir()
    sys.path.insert(0, dcc_dir)
    from androguard.core.bytecodes.apk import APK
    return APK(apk_path)


def _read_manifest_text(apk_path):
    """读 APK 内 AndroidManifest.xml 并转成文本 XML。失败返回空串。

    为什么不用 androguard 的 get_main_activities()：见 main() 里
    `_resolve_launchers` 的注释——它不处理 activity-alias、也不判 enabled。
    这里直接拿 AXMLPrinter 转文本，自己做解析。

    ⚠️ 必须收【路径字符串】而不是 APK 对象：androguard 的 APK 对象
    不保证暴露原始文件路径（实测 getattr(filename) 拿不到），
    传对象会导致静默返回空串 → 修正逻辑被跳过 → 又抽回 alias 类。
    """
    import zipfile
    dcc_dir = _ensure_dcc_dir()
    if dcc_dir not in sys.path:
        sys.path.insert(0, dcc_dir)          # ← 漏了这行会 ModuleNotFoundError
    from androguard.core.bytecodes.axml import AXMLPrinter
    with zipfile.ZipFile(apk_path) as zf:
        raw = zf.read('AndroidManifest.xml')
    out = AXMLPrinter(raw).get_xml()
    return out.decode('utf-8', 'replace') if isinstance(out, bytes) else str(out)


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        return 1
    apk_path = args[0]
    out_path = args[1] if len(args) > 1 else 'dcc_filter.auto.txt'

    on_fail = 'error'
    all_activities = False
    classes_out = None
    argv = args[2:] if len(args) > 2 else []
    i = 0
    while i < len(argv):
        if argv[i] == '--on-fail' and i + 1 < len(argv):
            on_fail = argv[i + 1]
            i += 2
        elif argv[i] == '--all-activities':
            all_activities = True
            i += 1
        elif argv[i] == '--classes' and i + 1 < len(argv):
            classes_out = argv[i + 1]
            i += 2
        else:
            i += 1

    if not os.path.exists(apk_path):
        print(f'❌ APK 不存在: {apk_path}', file=sys.stderr)
        return 1

    a = load_apk(apk_path)
    main_acts = set()
    try:
        main_acts = set(a.get_main_activities() or [])
    except Exception as e:
        print(f'⚠️ Manifest 解析异常: {e}', file=sys.stderr)

    package = a.get_package()
    # 补全相对类名(.Foo / Foo → 完整类名)
    def full_name(name: str) -> str:
        if name.startswith('.'):
            return package + name
        if '.' not in name:
            return package + '.' + name
        return name

    # ── activity-alias / enabled=false 修正（2026-11-02）──────────────
    # androguard 的 get_main_activities() 有两处会抽错类，实测样本
    # com.app.lxkd20251026（「换图标」型 App）：
    #
    #   FirstActivity   enabled=false        ← 真正的业务入口
    #   AliasIcon1~6    <activity-alias> target=FirstActivity
    #   其中 AliasIcon1 enabled=true         ← 实际生效的图标入口
    #
    # get_main_activities() 返回 AliasIcon1，它是【alias 不是实现】：
    # 本身没有任何方法，dex2c 去里面找 → "No methods compiled!"
    # → dcc-project.zip 不生成 → 构建失败（CI 41430277787 实证）。
    #
    # 修法：解析 AXML 原始文本，把 alias 换成其 targetActivity，
    # 并跳过 enabled="false"。不依赖 androguard 的那两个 API。
    def _resolve_launchers() -> list:
        try:
            xml_text = _read_manifest_text(apk_path)
        except Exception as e:                      # noqa: BLE001
            print(f'⚠️ Manifest 原文读取失败，回退 androguard 结果: {e}',
                  file=sys.stderr)
            return []
        if not xml_text:
            return []
        found = []
        for m in re.finditer(r'<(activity-alias|activity)(?=[\s>/])[^>]*?/?>',
                             xml_text, re.S):
            kind, tag = m.group(1), m.group(0)
            if tag.rstrip().endswith('/>'):
                continue
            nm = re.search(r'android:name="([^"]+)"', tag)
            if not nm:
                continue
            en = re.search(r'android:enabled="([^"]+)"', tag)
            if en and en.group(1).strip().lower() == 'false':
                continue
            start = m.end()
            close = '</%s>' % kind
            end = xml_text.find(close, start)
            seg = xml_text[start:end] if end != -1 else xml_text[start:start + 4000]
            if not (re.search(r'android\.intent\.action\.MAIN', seg)
                    and re.search(r'android\.intent\.category\.LAUNCHER', seg)):
                continue
            name = nm.group(1)
            if kind == 'activity-alias':
                tg = re.search(r'android:targetActivity="([^"]+)"', tag)
                if not tg:
                    continue                        # 无 target 的畸形 alias
                name = tg.group(1)
            found.append(full_name(name))
        return sorted(set(found))

    resolved = _resolve_launchers()
    if resolved:
        if set(resolved) != set(full_name(x) for x in main_acts):
            print(f'ℹ️ launcher 解析修正: androguard={sorted(full_name(x) for x in main_acts)}'
                  f' → 实际={resolved}（已处理 activity-alias / enabled=false）',
                  file=sys.stderr)
        mains = resolved
    else:
        mains = sorted(full_name(x) for x in main_acts)

    if not mains:
        if on_fail == 'skip':
            print('⚠️ 未找到 LAUNCHER activity,跳过(--on-fail=skip)', file=sys.stderr)
            return 0
        print('❌ 未从 Manifest 解析到唯一 LAUNCHER activity;'
              '请在任务中手动指定类名(一行一个,支持通配符)', file=sys.stderr)
        return 2

    if len(mains) > 1:
        print(f'ℹ️ 检测到 {len(mains)} 个 LAUNCHER activity,全部纳入: {mains}',
              file=sys.stderr)

    # 产出 Activity 类列表(供 activity* 展开)
    if classes_out:
        try:
            acts = sorted(set(a.get_activities() or []))
            with open(classes_out, 'w') as fp:
                fp.write('# activity 类列表(由 Manifest 提取)\n')
                for act in acts:
                    fp.write(full_name(act) + ' # activity\n')
        except Exception as e:
            print(f'⚠️ Activity 类列表提取失败: {e}', file=sys.stderr)

    # 生成 filter:每行一个类
    # ⚠️ dcc full_name 的类名是 smali 斜杠格式(Lcom/demo/app/Main;),
    #    而 Manifest 是点号 → 转换后再写入
    lines = ['!<clinit|init>']
    if all_activities and classes_out and os.path.exists(classes_out):
        # 展开所有 Activity 为具体类规则
        with open(classes_out) as fp:
            for line in fp:
                line = line.strip()
                if line and not line.startswith('#'):
                    cls = line.split('#')[0].strip().rstrip(';')
                    lines.append('L' + cls.replace('.', '/') + ';.*')
    else:
        for m in mains:
            lines.append('L' + m.replace('.', '/') + ';.*')

    with open(out_path, 'w') as fp:
        fp.write('\n'.join(lines) + '\n')

    print(f'✅ 主 Activity: {", ".join(mains)}')
    print(f'✅ 已生成 dcc filter: {out_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
