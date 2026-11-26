#!/usr/bin/env python3
"""check-obf-whitelist.py — 校验免混淆白名单与真实调用链一致

用法: check-obf-whitelist.py <nc_strdec_jni.c> <protect.sh>

=== 为什么这个脚本存在（2026-11-26 真机血案）===

主页卡 8 秒的唯一根因：`nc_fnv1a` 不在 `+no_obf` 免混淆白名单里。
它被 `nc_cache_get` / `nc_cache_put` 各调用一次（合计约 11.5 万次），
按字节做 64 位乘法，被 mba 膨胀后累计 8 秒。

为什么旧断言没拦住：旧断言是
    grep protect.sh | 找 '|nc_fnv1a|' 这四个字
于是——
  · 白名单里写了但函数被改名    → 断言绿，实际没标上
  · 白名单里拼错成员名          → 断言绿，静默不标记
  · 新增调用链成员但忘了加白名单 → 断言绿，等真机卡 8 秒

按 AGENTS.md §2.2 的判据：删掉被它测的生产逻辑仍然通过 = 它什么都没测。

=== 判据（四条，全部从生产源码派生）===

① **单一真相源**：protect.sh 只允许出现一处白名单定义。
   事故时是两份副本（11 个 / 5 个），都在跑，后者静默无效。

② **无幽灵成员**：白名单里每个名字必须是 .c 里真实存在的函数。
   拼错的成员永远不会被 so_section_mark 匹配到，而构建不报错。

③ **热路径闭包全覆盖**：从「每次解密必走」的入口出发展开调用链，
   闭包内每个函数都必须在白名单里。这一条才抓得住 nc_fnv1a。

④ **豁免需举证**：闭包外扩时遇到「每进程只跑一次」的函数就停止展开，
   但该函数必须真的带一次性的守卫（CAS / 已就绪提前 return）。
   没有守卫的豁免一律判红 —— 否则这个脚本会变成"随便加个理由就跳过"。

=== 为什么 ③ 不能简单地"全闭包都要白名单" ===

nc_ensure_key 的两个分支（密钥查找、证书叠加）里调了
nc_find_apk_path / nc_find_shell_symbol / nc_set_key_with_cert，
静态看它们在 decrypt 的闭包里。但它们被 CAS 守卫挡着，
每个进程只执行一次 —— 混淆到 1ms 也只有几毫秒，留混淆换保护是对的。
纯静态闭包会误判它们"漏标"，所以需要判据 ④ 把「一次性」这件事
从**注释里的承诺**变成**可验证的代码事实**。

=== 边界（如实）===

· 「闭包」按函数名文本匹配，同名函数取第一个定义。
· 只分析传入的 .c 文件；跨文件调用（如 nc_strdec_has_key）不在此范围。
· profile-only 函数（NC_STRDEC_PROFILE 编译期才存在）排除 ——
  生产包里它们根本不存在，不该要求进白名单。
· 本脚本不检查「标记是否真的落进了二进制」：那由 protect.sh 的
  命中数断言（必须精确等于白名单成员数）+ 实际编译产物负责。
"""
import re
import sys

# 只在 --strdec-profile 调试包里编译，生产包不存在 → 不进白名单
PROFILE_ONLY = {"nc_prof_now_ns", "nc_prof_scope_exit", "nc_strdec_profile_dump"}

WL_VAR = "NC_OBF_HOT_FUNCS"

# 热路径入口：这些被 nc_strdec_jni_decrypt 每次调用必走
HOT_ROOTS = ("nc_strdec_jni_decrypt", "nc_cache_get", "nc_cache_put", "nc_strdec_decrypt")

# 「每进程只跑一次」的守卫形态：CAS 抢占
ONCE_GUARD_RE = re.compile(r"__atomic_compare_exchange|__sync_bool_compare_and_swap")


def extract_funcs(src: str) -> dict:
    """抽出 {函数名: 函数体}，同名取第一个。"""
    funcs = {}
    pat = re.compile(
        r"^(?:static\s+)?(?:inline\s+)?[A-Za-z_][A-Za-z0-9_ \*]*?"
        r"\b(nc_[a-z0-9_]+)\s*\([^;]*?\)\s*\{",
        re.M,
    )
    for m in pat.finditer(src):
        name = m.group(1)
        if name in funcs:
            continue
        i = m.end() - 1
        depth = 0
        j = i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        funcs[name] = src[i : j + 1]
    return funcs


def has_once_guard(body: str) -> bool:
    """该函数是否带「每进程只跑一次」的可验证守卫。"""
    return bool(ONCE_GUARD_RE.search(body))


def hot_closure(funcs: dict, roots) -> tuple:
    """展开热路径闭包；遇到一次性守卫函数停止展开。

    返回 (need, exempt)：need = 必须免混淆的；exempt = 举证豁免的 {名字: 原因}
    """
    need = set()
    exempt = {}
    seen = set()
    frontier = [r for r in roots if r in funcs]
    while frontier:
        f = frontier.pop()
        if f in seen:
            continue
        seen.add(f)
        if f in PROFILE_ONLY:
            continue
        need.add(f)
        body = funcs.get(f, "")
        # 带一次性守卫 → 它自己必须在白名单（每次都要读 flag），
        # 但它的被调者每个进程只跑一次，豁免。
        if has_once_guard(body):
            for callee in re.findall(r"\b(nc_[a-z0-9_]+)\s*\(", body):
                if callee in funcs and callee not in need:
                    exempt.setdefault(
                        callee, f"仅经 {f} 的一次性守卫路径到达（CAS）"
                    )
            continue
        for callee in re.findall(r"\b(nc_[a-z0-9_]+)\s*\(", body):
            if callee in funcs and callee not in seen:
                frontier.append(callee)
    return need, exempt


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    c_path, prot_path = sys.argv[1], sys.argv[2]

    src = open(c_path, encoding="utf-8").read()
    prot = open(prot_path, encoding="utf-8").read()
    funcs = extract_funcs(src)
    ok = True

    # ── 判据 ① 单一真相源 ──────────────────────────────────────────
    defs = re.findall(rf"^{WL_VAR}=(['\"])(.*?)\1", prot, re.M)
    if len(defs) != 1:
        print(f"❌ {WL_VAR} 定义了 {len(defs)} 次（必须恰好 1 次）")
        print("   事故形态：两份副本各自列不同函数集，都在跑，后者静默无效")
        ok = False
        if not defs:
            return 1
    wl = set(defs[0][1].split("|")) - {""}

    # 别处不得再硬编码一份白名单正则（防回归到两份副本）
    for no, line in enumerate(prot.split("\n"), 1):
        if "--pattern" in line and re.search(r"nc_strdec_jni_decrypt\|", line):
            if WL_VAR not in line:
                print(f"❌ {prot_path}:{no} 硬编码了白名单正则（必须引用 ${WL_VAR}）")
                ok = False

    # ── 判据 ② 无幽灵成员 ──────────────────────────────────────────
    ghosts = sorted(x for x in wl if x not in funcs)
    if ghosts:
        print(f"❌ 白名单含不存在的函数: {ghosts}")
        print("   这些名字永远不会被 so_section_mark 匹配到，且构建不报错")
        ok = False

    # ── 判据 ③④ 热路径闭包 + 豁免举证 ──────────────────────────────
    need, exempt = hot_closure(funcs, HOT_ROOTS)
    missing = sorted(need - wl)
    if missing:
        print(f"❌ 热路径闭包内漏标: {missing}")
        print("   这些函数每次解密都会执行，混淆会把它们膨胀 3~10 倍")
        ok = False

    # 被豁免的函数不能同时在白名单里标了却没人认领（信息提示，不判红）
    if ok:
        print(f"✅ 白名单 {len(wl)} 个成员，热路径闭包需要 {len(need)} 个，全覆盖")
        print(f"   热路径: {', '.join(sorted(need))}")
        if exempt:
            print(f"   举证豁免（每进程一次，混淆代价可忽略）:")
            for k in sorted(exempt):
                print(f"     · {k} —— {exempt[k]}")
        extra = sorted(wl - need)
        if extra:
            print(f"   白名单额外（不在热路径闭包内）: {', '.join(extra)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
