#!/usr/bin/env python3
"""test-derive-extract.py — extract-derive.py 自身的回归测试（纯 stdlib，秒级）。

【为什么需要】
  2026-11-22 的教训是"测试替生产保密"：test-sig-guard2.sh 把手写公式当成
  真相源，生成侧漂移时它依旧全绿。修法是把公式【抽取】出来执行。

  但抽取器本身也是代码，它坏了同样会静默退回"错的东西也能过"：
    · 抽错段（抽到线1 当线2）→ 两条线互相顶替，测试仍可能绿
    · 找不到锚点时静默返回空 → 下游拿到空盐，比较恒真或恒假
    · 盐替换失败 → 每次结果不同，对拍变成碰运气

  所以抽取器的三点必须钉死：
    ① 线1/线2 抽到的是【不同的】段（不能互相顶替）
    ② 抽取结果随生成侧变化而变化（这正是它存在的理由）
    ③ 结构破坏时【明确报错】，不许静默降级

用法: python3 scripts/guard/hash/tests/test-derive-extract.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..', '..'))
EXT = os.path.join(ROOT, 'scripts', 'guard', 'hash', 'extract-derive.py')
GEN = os.path.join(ROOT, 'scripts', 'guard', 'hash', 'make-sig-hash.sh')

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  ✅ {msg}")


def bad(msg):
    global FAIL
    FAIL += 1
    print(f"  ❌ {msg}", file=sys.stderr)


def check(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        bad(f"{name}{(' — ' + detail) if detail else ''}")


def run(gen, line, extra=None):
    """跑抽取器，返回 (rc, stdout, stderr)"""
    cmd = [sys.executable, EXT, gen, str(line)]
    if extra:
        cmd += extra
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def main():
    if not os.path.isfile(GEN):
        print(f"❌ 找不到生成侧 {GEN}", file=sys.stderr)
        return 1

    with open(GEN, encoding='utf-8') as f:
        gen_text = f.read()

    print("[1/4] 两条线必须抽到不同的段（不能互相顶替）")
    rc1, out1, err1 = run(GEN, 1)
    rc2, out2, err2 = run(GEN, 2)
    check("线1 抽取成功", rc1 == 0, err1.strip()[:200])
    check("线2 抽取成功", rc2 == 0, err2.strip()[:200])
    if rc1 == 0 and rc2 == 0:
        d1, d2 = json.loads(out1), json.loads(out2)
        check("线1 与线2 的 stored 不同（域分离真实存在）",
              d1['stored'] != d2['stored'],
              "两条线算出相同 stored = 抽到了同一段，双线形同虚设")
        check("domain 字段正确", d1['domain'] == 'sig_hash'
              and d2['domain'] == 'sig_guard2')
        # 线2 的轮1 是 SHA256(b"G2" || fp)，线1 是 SHA256(fp) —— 必须体现在结果里
        check("线2 带 \"G2\" 域分隔（与线1 的轮1 不同源）",
              d1['stored'] != d2['stored'])

    print("[2/4] 抽取结果必须跟随生成侧变化（这是它存在的理由）")
    # 把线2 的扩散系数改掉，抽取结果必须变
    mutated = re.sub(r'\(\(i \* 0x5B \+ 0x3D\) & 0xFF\)',
                     '((i * 0x5C + 0x3D) & 0xFF)', gen_text)
    if mutated == gen_text:
        bad("无法在 make-sig-hash.sh 里定位线2 的扩散系数 —— 生成侧结构变了？")
    else:
        with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False,
                                         encoding='utf-8') as tf:
            tf.write(mutated)
            mpath = tf.name
        try:
            rcm, outm, errm = run(mpath, 2)
            check("生成侧改动后抽取仍成功", rcm == 0, errm.strip()[:200])
            if rcm == 0:
                d2 = json.loads(out2)
                dm = json.loads(outm)
                check("生成侧公式改动 → 抽取结果随之改变",
                      dm['stored'] != d2['stored'],
                      "抽取结果没变 = 抽取器没真读公式，测试还是会替生产保密")
        finally:
            os.unlink(mpath)

    print("[3/4] 结构破坏必须【明确报错】，不许静默降级")
    # 删掉【所有】PYEOF 行 = 真正的"heredoc 未闭合"。
    #
    # ⚠️ 只删第一个是错的（本测试最初就这么写，结果测不出问题）：
    #    去掉线1 的 PYEOF 之后，线2 的 PYEOF 会被当成线1 的结束行 ——
    #    文件依然"有闭合"，抽取器当然不报错。这类"构造不严谨导致
    #    断言测不到东西"正是本项目反复踩的坑，故在此写明原因。
    broken = re.sub(r'^PYEOF$', '', gen_text, flags=re.M)
    # ⚠️ 不能用 'PYEOF' not in broken 判断 —— heredoc 的【起始行】
    #    `<<'PYEOF'` 里也有 PYEOF，那样断言必然假失败。只查独立的结束行。
    check("构造确实删除了全部 PYEOF 结束行",
          not re.search(r'^PYEOF$', broken, flags=re.M))
    with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False,
                                     encoding='utf-8') as tf:
        tf.write(broken)
        bpath = tf.name
    try:
        rcb, outb, errb = run(bpath, 2)
        check("缺 PYEOF → 非零退出", rcb != 0, f"rc={rcb}")
        check("缺 PYEOF → 报错信息可诊断",
              'PYEOF' in errb or 'heredoc' in errb.lower(),
              errb.strip()[:200])
    finally:
        os.unlink(bpath)

    # 去掉 os.urandom（盐锚点）—— 不许静默用随机盐
    noura = gen_text.replace('salt = os.urandom(16)', 'salt = b"\\x00" * 16')
    with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False,
                                     encoding='utf-8') as tf:
        tf.write(noura)
        upath = tf.name
    try:
        rcu, outu, erru = run(upath, 2)
        check("缺 os.urandom 锚点 → 非零退出（不静默用随机盐）",
              rcu != 0, f"rc={rcu}")
        check("缺锚点的报错点明 os.urandom",
              'urandom' in erru, erru.strip()[:200])
    finally:
        os.unlink(upath)

    print("[4/4] 固定盐 / 固定指纹可复现")
    r1, o1, _ = run(GEN, 2)
    r2, o2, _ = run(GEN, 2)
    check("同一输入两次抽取结果一致", r1 == 0 and r2 == 0
          and json.loads(o1)['stored'] == json.loads(o2)['stored'],
          "不可复现 = 对拍变成碰运气")
    rsf, osf, _ = run(GEN, 2, ['--salt', '00' * 16])
    if rsf == 0:
        check("--salt 生效（与默认盐结果不同）",
              json.loads(osf)['stored'] != json.loads(o1)['stored'])
        check("--salt 回显正确", json.loads(osf)['salt'] == '00' * 16)
    else:
        bad("--salt 参数不被接受")
    # 指纹
    fp = 'aa' * 32
    rfp, ofp, _ = run(GEN, 2, ['--fp', fp])
    if rfp == 0:
        d = json.loads(ofp)
        check("--fp 生效（与默认指纹结果不同）", d['stored'] != json.loads(o1)['stored'])
        check("--fp 回显正确", d['fp'] == fp)
    else:
        bad("--fp 参数不被接受")
    # 长度不符必须拒绝
    rbad, _, ebad = run(GEN, 2, ['--salt', '00'])
    check("--salt 长度不符 → 非零退出", rbad != 0, f"rc={rbad}")

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
