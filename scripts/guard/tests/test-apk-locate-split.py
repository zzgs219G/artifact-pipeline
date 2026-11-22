#!/usr/bin/env python3
"""test-apk-locate-split.py — APK 定位的拆分契约（纯 stdlib，秒级）。

【为什么需要它】
  2026-11-22 重构：`find_apk_path` 原本是【一个 205 行、25 个分支】的函数，
  四路探测（env / maps / so 路径反推 / data-app 遍历）连同各自的报错史
  全糊在一起。改一路要在 200 行里找，且四段共享 `line`/`p`/`fp` 这些
  可变量 —— 读代码时无法确认"这处修改会不会影响下一段"。

  拆成 4 个探测器 + 1 个调度器之后，有四个契约必须钉住，否则拆分会被
  悄悄破坏（而且破坏后能编过、能链接、测试全绿，只有真机才出问题）：

    S1 顺序：env → maps → so_dir → scan。maps 与 so_dir 有依赖关系
       （后者兜底时重读 maps），顺序变了行为就变。
    S2 每段都带段标记：漏标 → 该段掉出 .ncx 加密段 → 防御静默变弱。
    S3 不共享可变量：每个探测器自己声明 `line`/`fp`/`p`，
       不能靠外层变量的副作用传递。
    S4 返回语义：各探测器成功返回 0、失败返回 -1；
       调度器任一成功即 0，全失败才 -1。

  ⚠️ 还有一条【最重要但无法静态测】的：
     日志标记的源码出现顺序 = sig_log_data.h 的枚举编号。
     顺序变了会让跨 TU 密文错位（2026-11-22 那次闪退的根因）。
     本测试只能验"标记在预期函数的预期区内"，完整顺序对拍由
     test-javacheck / lsgs-strings 间接覆盖。

用法: python3 scripts/guard/tests/test-apk-locate-split.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
SRC = os.path.join(ROOT, 'scripts', 'guard', 'src', 'sig_check.c')

PASS = 0
FAIL = 0


def ok(m):
    global PASS
    PASS += 1
    print(f"  ✅ {m}")


def bad(m):
    global FAIL
    FAIL += 1
    print(f"  ❌ {m}", file=sys.stderr)


def check(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        bad(f"{name}{(' — ' + detail) if detail else ''}")


def main():
    if not os.path.isfile(SRC):
        print(f"❌ 找不到 {SRC}", file=sys.stderr)
        return 1
    src = open(SRC, encoding='utf-8').read()

    # ── 提取各函数体 ──────────────────────────────────────────────
    # 按 "static int 名字(" 定位，向后找到列 0 的 "}" 为止。
    def func_body(name):
        m = re.search(r'static int %s\s*\([^)]*\)\s*\{' % re.escape(name), src)
        if not m:
            return None
        i = m.end()
        depth = 1
        while i < len(src) and depth:
            ch = src[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            i += 1
        return src[m.start():i]

    probes = ['apk_locate_hosttest', 'apk_locate_env', 'apk_locate_maps',
              'apk_locate_so_dir', 'apk_locate_scan']
    bodies = {}
    print("[S1] 四个探测器都在，且顺序是 env → maps → so_dir → scan")
    for p in probes:
        bodies[p] = func_body(p)
        check(f"{p} 存在", bodies[p] is not None)

    disp = func_body('find_apk_path')
    check("find_apk_path 存在", disp is not None)

    if disp:
        # 调度器里的调用顺序
        order = re.findall(r'(apk_locate_\w+)\s*\(\s*out', disp)
        check(f"调度顺序 = {order}",
              order == ['apk_locate_hosttest', 'apk_locate_env',
                        'apk_locate_maps', 'apk_locate_so_dir',
                        'apk_locate_scan'],
              "顺序改变会改变行为：maps 与 so_dir 有依赖（后者兜底时重读 maps），"
              "scan 只在旧机型兜底")
        # hosttest 只应在 #ifdef SIGCHECK_HOST_TEST 下生效
        check("主机测试入口只在 SIGCHECK_HOST_TEST 下生效",
              '#ifdef SIGCHECK_HOST_TEST' in (bodies.get('apk_locate_hosttest') or ''),
              "否则真机也会去读那个环境变量")

    print("[S2] 每段都带段标记（漏标 → 掉出 .ncx 加密段）")
    for p in probes:
        if bodies[p] is None:
            continue
        # 标记在函数定义【之前】
        idx = src.index(bodies[p])
        head = src[max(0, idx - 300):idx]
        check(f"{p} 前有 SIG_SEC_MARKED_NOVMP",
              'SIG_SEC_MARKED_NOVMP' in head.split('static int')[-1]
              or re.search(r'SIG_SEC_MARKED_NOVMP\s*$',
                           head.rstrip()),
              "不带标记 = 该段代码不在加密段里，防御静默变弱")

    print("[S3] 各探测器自己声明缓冲，不靠外层变量传值")
    # maps / so_dir 都用到 line[]，必须各自声明（拆分前的写法是共享的）
    if bodies['apk_locate_maps']:
        check("apk_locate_maps 自己声明 line[]",
              re.search(r'char\s+line\s*\[', bodies['apk_locate_maps']) is not None)
    if bodies['apk_locate_so_dir']:
        check("apk_locate_so_dir 自己声明 line[]",
              re.search(r'char\s+line\s*\[', bodies['apk_locate_so_dir']) is not None,
              "so_dir 的兜底分支要重读 maps，需要自己的 line 缓冲")
    if bodies['apk_locate_maps']:
        check("apk_locate_maps 自己声明 FILE *fp",
              re.search(r'FILE\s*\*\s*fp', bodies['apk_locate_maps']) is not None)
    if bodies['apk_locate_scan']:
        check("apk_locate_scan 自己声明 pkg[]",
              re.search(r'char\s+pkg\s*\[', bodies['apk_locate_scan']) is not None)
        check("apk_locate_scan 自己声明 DIR *",
              re.search(r'DIR\s*\*\s*d', bodies['apk_locate_scan']) is not None)

    print("[S4] 返回语义：探测器 0/-1，调度器任一成功即 0")
    for p in probes:
        if bodies[p] is None:
            continue
        check(f"{p} 成功时返回 0",
              re.search(r'return\s+0\s*;', bodies[p]) is not None)
        check(f"{p} 失败时返回 -1",
              re.search(r'return\s+-1\s*;', bodies[p]) is not None)
    if disp:
        check("find_apk_path 不自己杀进程（只返回，由调用方处置）",
              'kill' not in disp and 'abort' not in disp,
              "定位失败不等于签名不过，杀进程的决定权在调用方")
        check("find_apk_path 全失败才返回 -1",
              disp.rstrip().endswith('return -1;\n}')
              or re.search(r'==\s*0\)\s*return\s+0;[\s\S]*return\s+-1;', disp) is not None)

    print("[S5] 单函数体量（防有人合并回去）")
    if disp:
        n = len(disp.splitlines())
        check(f"find_apk_path 只有 {n} 行（调度器，应 < 80）", n < 80,
              "超过 80 行说明又把探测逻辑塞回来了")
    for p in probes:
        if bodies[p] is None:
            continue
        n = len(bodies[p].splitlines())
        check(f"{p} 体量 {n} 行（应 < 90）", n < 90,
              "单个探测器过大 = 该再拆（但也不宜过碎，见 AGENTS.md 的拆分纪律）")

    # ── 第二线（sig_guard2.c）的同类拆分 ──────────────────────────
    print("[G] 第二线 g2_find_apk 也必须是「探测器 + 调度」（零共享约束下各自拆）")
    L2 = os.path.join(ROOT, 'scripts', 'guard', 'src', 'sig_guard2.c')
    check("sig_guard2.c 存在", os.path.isfile(L2))
    if os.path.isfile(L2):
        s2 = open(L2, encoding='utf-8').read()

        def func2(name):
            m = re.search(r'static int %s\s*\([^)]*\)\s*\{' % re.escape(name), s2)
            if not m:
                return None
            i, depth = m.end(), 1
            while i < len(s2) and depth:
                if s2[i] == '{':
                    depth += 1
                elif s2[i] == '}':
                    depth -= 1
                i += 1
            return s2[m.start():i]

        g2probes = ['g2_locate_hosttest', 'g2_locate_maps', 'g2_locate_so_dir']
        g2bodies = {}
        for p2 in g2probes:
            g2bodies[p2] = func2(p2)
            check(f"{p2} 存在", g2bodies[p2] is not None)

        g2disp = func2('g2_find_apk')
        check("g2_find_apk 存在", g2disp is not None)
        if g2disp:
            order2 = re.findall(r'(g2_locate_\w+)\s*\(\s*out', g2disp)
            check(f"第二线调度顺序 = {order2}",
                  order2 == ['g2_locate_hosttest', 'g2_locate_maps',
                             'g2_locate_so_dir'],
                  "顺序改变会改变行为：maps 是主路，so_dir 是 extractNativeLibs=true 时的兜底")
            n2 = len(g2disp.splitlines())
            check(f"g2_find_apk 只有 {n2} 行（调度器，应 < 30）", n2 < 30,
                  "超过 30 行说明又把探测逻辑塞回来了")
            # 第二线刻意没有 /data/app 扫描（Android 11+ 必失败）。
            # ⚠️ 只查【代码行】：注释里解释"为什么不做"是允许的（本轮
            #    拆分的注释就写着原因），拿全文件搜会把它自己算成违规。
            s2_code = '\n'.join(ln for ln in s2.splitlines()
                                 if not ln.lstrip().startswith(('*', '/*', '//')))
            check("第二线【代码里】没有 /data/app 扫描（刻意的精简）",
                  '/data/app' not in s2_code,
                  "那是第一线的旧机型兜底；第二线是精简版，不复制已知无效分支")

        for p2 in g2probes:
            if g2bodies[p2] is None:
                continue
            idx = s2.index(g2bodies[p2])
            head = s2[max(0, idx - 200):idx]
            check(f"{p2} 前有 G2_SEC_MARKED_NOVMP",
                  'G2_SEC_MARKED_NOVMP' in head.split('static int')[-1]
                  or re.search(r'G2_SEC_MARKED_NOVMP\s*$', head.rstrip()),
                  "不带标记 = 掉出 .ncx 加密段")
            n = len(g2bodies[p2].splitlines())
            check(f"{p2} 体量 {n} 行（应 < 90）", n < 90)

        # 两条线必须仍是两份独立实现（AGENTS.md §1 零共享约束）。
        # ⚠️ 判据是"各自文件里不出现【对方】的函数名"，不是"不出现自己的"。
        #    第一版写成 g2_locate_maps not in src —— 方向反了，
        #    永远为真（第一线当然不含 g2_*），是条什么都没测的断言。
        # ⚠️ 只查代码行。注释里互相提名字是【好事】（说明写清了为什么
        #    两条线各写一份），拿全文件搜会把解释本身判成违规。
        src_code = '\n'.join(ln for ln in src.splitlines()
                             if not ln.lstrip().startswith(('*', '/*', '//')))
        check("第一线代码里不调用第二线的定位器",
              'g2_locate_' not in src_code,
              "共享 = 单点，改一处两线同废")
        check("第二线代码里不调用第一线的定位器",
              'apk_locate_' not in s2_code,
              "共享 = 单点，改一处两线同废")

        # ── g2_extract_cert 的两处漏洞修复点必须还在（2026-11-22）──────
        #
        # ⚠️ 这里只钉【漏洞修复点】，不再钉"函数拆没拆"。
        #    2026-11-22 我曾把 g2_extract_cert（117 行）拆成三段，
        #    理由是"太长"。用户指出这是错的：
        #      · 它三段各用各的局部变量，不是共享可变状态 → 本来就干净
        #      · 原来的 goto fail 是【单点收口】：所有错误路径在一处 free，
        #        结构上不可能漏。拆成跨函数后，free 的责任散到调度器，
        #        变成"靠人记得"
        #    也就是说拆分【制造】了原本不存在的风险。已回退。
        #
        #    保留这两条断言的理由与"拆不拆"无关：它们防的是真漏洞
        #    （整数回绕 / 少一层长度检查），是这套测试存在的初衷。
        print("[C] g2_extract_cert 的两处边界检查仍在（漏洞修复点）")
        m_cert = re.search(r'static int g2_extract_cert\s*\(', s2)
        check("g2_extract_cert 存在", m_cert is not None)
        cert_body = ''
        if m_cert:
            brace = s2.index('{', m_cert.end())
            i, depth = brace + 1, 1
            while i < len(s2) and depth:
                if s2[i] == '{':
                    depth += 1
                elif s2[i] == '}':
                    depth -= 1
                i += 1
            cert_body = s2[m_cert.start():i]

        check("g2_extract_cert 里仍有 certs_len 边界检查",
              'certs_len == 0 || sd + certs_len > end' in cert_body,
              "这是 2026-11-22 修的真漏洞（少查一层长度 = 允许指针越界）")
        check("g2_extract_cert 里仍有 block_size 回绕检查",
              'block_size + 8 > (uint64_t)cd_off' in cert_body,
              "这是 2026-11-22 修的整数回绕（UINT64_MAX + 8 回绕成 7）")
        # 单点收口：解析段的 13 条错误路径全部 goto fail，
        # 只在 fail: 标签处 free 一次。这比"每个 return 前都 free"安全得多
        # —— 后者漏一个就是泄漏，且新增错误分支时容易忘记。
        #
        # ⚠️ free(value) 全文有 3 处，都是必要的：
        #   ① malloc 失败后（此时 value 为 NULL，但代码里是提前 return）
        #   ② 读 pair 内容失败（value 已分配，必须立刻释放）
        #   ③ fail: 标签（解析段所有 goto 的汇聚点）
        #   判据不是"次数少"，而是"解析段的错误路径走 goto 而非各自 return"。
        _parse_seg = cert_body[cert_body.find('const unsigned char *p = value'):
                               cert_body.find('fail:')]
        _goto_n = _parse_seg.count('goto fail')
        _ret_n = _parse_seg.count('return -1')
        check("g2_extract_cert 解析段用 goto fail 单点收口",
              _goto_n >= 10 and _ret_n == 0 and 'goto fail' in cert_body,
              f"解析段实得 goto={_goto_n} / return -1={_ret_n}。"
              "free 散到多个 return 出口 = 迟早漏一个；"
              "goto fail 让所有错误路径汇聚一处（拆分时被我破坏、现已恢复的结构）")

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
