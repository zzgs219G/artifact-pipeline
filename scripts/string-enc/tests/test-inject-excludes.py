#!/usr/bin/env python3
"""test-inject-excludes.py — inject-excludes.py 的回归测试

═══ 钉住什么 ═══
本脚本决定「哪些类不参与字符串加密」。判错的两个方向后果完全不同：
  · 多排除（把业务类也排除）→ 字符串加密静默失效，用户以为加密了其实没有
  · 少排除（漏掉注入类）    → SigFix 死锁复现，去校验的诱饵永远失效

所以两个方向都要断言，而且都用【注入器真实产出的清单格式】做夹具 ——
不用手写的理想格式（那样测的是自己的想象，不是生产的现实）。

═══ 反向验证（必做，AGENTS.md §2.2）═══
每条断言写明"改坏什么会让它红"，见各处注释。
"""
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))          # scripts/string-enc/tests
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))  # 仓库根
SCRIPT = os.path.join(ROOT, "scripts", "string-enc", "inject-excludes.py")

spec = importlib.util.spec_from_file_location("inject_excludes", SCRIPT)
ie = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ie)

fails = []


def ok(m):
    print(f"  ✅ {m}")


def bad(m):
    fails.append(m)
    print(f"  ❌ {m}")


def make_dir(tmp, javacheck=None, uncheck=None):
    """造一个解包目录形态：smali*/ 目录 + 注入器清单。"""
    for d in ("smali", "smali_classes2"):
        os.makedirs(os.path.join(tmp, d), exist_ok=True)
    if javacheck is not None:
        with open(os.path.join(tmp, "javacheck-components.json"), "w") as f:
            json.dump(javacheck, f)
    if uncheck is not None:
        with open(os.path.join(tmp, "uncheck-components.json"), "w") as f:
            json.dump(uncheck, f)


def main():
    print("== inject-excludes.py 回归 ==")

    # ── T1 两个清单同时在场：类全部收齐，且含内部类 ──────────────────
    with tempfile.TemporaryDirectory() as tmp:
        hb = os.path.join(tmp, "smali_classes2", "f5", "aa$Hb.smali")
        make_dir(tmp,
                 javacheck={
                     "bridge": "Lcom/nc/link/NcLink;",
                     "wrapper": "Lf5/aa;",
                     # generated 用【绝对路径】—— 与 inject-javacheck.py 实际写的一致
                     "generated": [
                         os.path.join(tmp, "smali_classes2", "f5", "aa.smali"),
                         os.path.join(tmp, "smali", "com", "nc", "link", "NcLink.smali"),
                         hb,
                     ],
                     # sites 是【目标 App 的类】—— 绝不能进排除集
                     "sites": [{"kind": "launcher",
                                "desc": "Lcom/nivii/app/ui/activity/HomeActivity;"}],
                 },
                 uncheck={
                     "payload": ["smali/com/nc/uncheck/SigFix.smali",
                                 "smali/com/nc/uncheck/SigFixImpl.smali",
                                 "smali/com/nc/uncheck/SigFixApp.smali"],
                     "calls": ["smali/com/nivii/app/App.smali"],
                     "target_dir": "smali",
                 })
        classes, sources = ie.collect(tmp)
        want = {"com.nc.link.NcLink", "f5.aa", "f5.aa$Hb",
                "com.nc.uncheck.SigFix", "com.nc.uncheck.SigFixImpl",
                "com.nc.uncheck.SigFixApp"}
        (ok if classes == want
         else bad)(f"T1 两个清单的注入类全收齐（缺: {want - classes} 多: {classes - want}）")
        # 反向：若 collect() 只吃一种清单（比如删掉 MANIFESTS 里的 uncheck 项），
        # 上面这行会因缺 com.nc.uncheck.* 而红。

        # T2 内部类必须单列（`!f5.aa` 不会覆盖 `f5.aa$Hb`）
        (ok if "f5.aa$Hb" in classes
         else bad)("T2 内部类 f5.aa$Hb 单独出现（smali 里是独立文件独立类）")

        # T3 目标 App 的类绝不能被排除
        leaked = [c for c in classes if c.startswith("com.nivii")]
        (ok if not leaked
         else bad)(f"T3 目标 App 的类未被排除（越界: {leaked}）")
        # 反向：若 collect() 把 comp['sites'][*]['path'] 也吃进来（那是被注入的
        # 目标类，不是我们的类），这行会红。

        # T4 规则行格式：`!` 前缀 = encrypt-strings.py 的排除语法
        rules = ie.to_rules(classes)
        (ok if all(r.startswith("!") for r in rules) and len(rules) == len(classes)
         else bad)("T4 每条规则以 ! 开头（排除语法）且数量一致")

    # ── T5 无清单 → 空集，不报错 ──────────────────────────────────────
    with tempfile.TemporaryDirectory() as tmp:
        make_dir(tmp)          # 两个清单都不写
        classes, sources = ie.collect(tmp)
        (ok if classes == set() and sources == {}
         else bad)("T5 无注入清单 → 空排除集（未注入的包不该排除任何类）")

    # ── T6 坏清单 → 不静默：该清单贡献缺失，但另一个照常生效 ──────────
    with tempfile.TemporaryDirectory() as tmp:
        make_dir(tmp, javacheck={"wrapper": "Lf5/aa;", "generated": []})
        with open(os.path.join(tmp, "uncheck-components.json"), "w") as f:
            f.write("{ 这不是合法 JSON")
        classes, sources = ie.collect(tmp)
        (ok if "f5.aa" in classes
         else bad)("T6a 坏清单不连累好清单（javacheck 的排除仍生效）")
        (ok if "uncheck-components.json" not in sources
         else bad)("T6b 坏清单不进 sources（不以残缺内容骗人）")

    # ── T7 绝对路径前缀对不上时，仍能从 smali 段切出类名 ──────────────
    # 真实场景：清单在别的目录生成 / 解包目录被移动 / 重新解包
    got = ie._from_smali_path("/somewhere/else/smali_classes3/com/x/Y.smali",
                              "/totally/different/dir")
    (ok if got == "com.x.Y"
     else bad)(f"T7 路径前缀不匹配时兜底切 smali 段（实得 {got!r}）")
    # 反向：若删掉 _from_smali_path 里的 ② 兜底分支，这行会得 None 而红。

    # ── T8 内部类用 $ 而不是 /，别被路径分隔符带偏 ────────────────────
    got = ie._from_smali_path("smali_classes2/f5/aa$Hb.smali", "/d")
    (ok if got == "f5.aa$Hb"
     else bad)(f"T8 内部类 $ 保留（实得 {got!r}）")

    # ── T9 非 smali 路径 → None（不瞎猜）────────────────────────────
    for p in ("AndroidManifest.xml", "res/layout/a.xml", "smali/f5/aa.txt"):
        got = ie._from_smali_path(p, "/d")
        (ok if got is None else bad)(f"T9 非 smali 路径 {p!r} → None（实得 {got!r}）")

    print(f"\n=== 结果: {9 + 4 - len(fails)} 通过, {len(fails)} 失败 ===")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
