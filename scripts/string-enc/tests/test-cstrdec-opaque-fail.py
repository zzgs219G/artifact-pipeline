#!/usr/bin/env python3
"""test-cstrdec-opaque-fail.py — 解密失败【不暴露】的契约测试。

【为什么需要这个测试】
  2026-11-22 用户需求的原话：
    「一旦解密失败，他就知道是哪里有问题；但如果解密成功了、
      但是明文是脏的（就定位不到）」

  也就是说：失败必须【伪装成成功】。返回原样的 Base64 密文 =
  直接告诉攻击者"这里坏了、密钥错了"。

  这类需求没有行为测试就必然退化 —— 没人会注意到某次重构把
  "返回脏明文"改回了"返回原密文"，因为所有功能测试都还是绿的。

【测什么】
  静态检查 nc_strdec_jni.c 的两个失败出口：
    F1 UTF-8 转换失败时，必须映射成可见字符后返回，
       不能 return 原 payload
    F2 映射结果必须落在可见 ASCII 区间（不留控制字符/0x00）
    F3 失败路径不能计入 nc_fail_count（那个通道会暴露"正在解错"）

  并做反向验证：把实现改回"返回原密文"，断言必须变红。

【不测什么】
  不测真机行为（要真机 + 换签名包）。真机验证见 docs/变更历史。
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
SRC = os.path.join(ROOT, 'scripts', 'string-enc', 'csrc', 'nc_strdec_jni.c')

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

    print("[F1] UTF-8 转换失败时必须伪装成成功（返回可见字符，不是原密文）")
    # 找到 utf8_to_utf16 那段之后的失败分支
    m = re.search(
        r'int ulen = nc_strdec_utf8_to_utf16\((?:[^;]*?)\);(.*?)'
        r'(?:\n    jstring out)',
        src, re.S)
    check("能定位到 utf8 转换后的分支", m is not None)
    seg = m.group(1) if m else ''

    check("失败时【不】直接 return nc_jni_fail(..., payload)",
          not re.search(r'if \(ulen <= 0\)\s*\{[^}]*return nc_jni_fail\(env, payload\);\s*\}\s*$',
                        seg, re.S),
          "返回原 payload = Base64 密文 = 一眼看出密钥错了")

    check("失败时有字节到可见字符的映射循环",
          re.search(r'for \([^\n]*\)\s*\{', seg) is not None
          and 'decoded[i]' in seg
          and '0x20' in seg,
          "需要逐个字节映射到可见 ASCII，保证长度不变且看起来像正常文本")

    print("[F2] 映射结果落在可见 ASCII（不留控制字符）")
    mm = re.search(r'u16\[i\]\s*=\s*\(uint16_t\)\(([^;]+)\)', seg)
    check("能定位到映射表达式", mm is not None)
    if mm:
        expr = mm.group(1)
        check("映射基址是 0x20（可见 ASCII 起点）",
              '0x20' in expr, f"实得 {expr.strip()}")
        # 0x20 + (x % 95) 覆盖 0x20..0x7E，共 95 个可见字符
        check("用模运算收敛到 95 个可见字符（0x20..0x7E）",
              re.search(r'%\s*95', expr) is not None,
              f"实得 {expr.strip()}；范围超出会产出控制字符或 UTF-8 高位")

    print("[F3] 失败路径不计入 nc_fail_count（那个通道会暴露）")
    # nc_fail_count++ 只应出现在 nc_jni_fail 里
    n_inc = len(re.findall(r'(?:\+\+\s*nc_fail_count|nc_fail_count\s*\+\+)', src))
    check("nc_fail_count++ 只在一处（nc_jni_fail）", n_inc == 1,
          f"实得 {n_inc} 处；多处递增会让『解错』这件事通过计数暴露")

    print("[F4] 正常解密路径未被破坏（防修过头）")
    check("正常路径仍然 NewString 返回",
          re.search(r'NewString\(env, \(const jchar \*\)u16', src) is not None)
    check("正常路径仍然写缓存",
          re.search(r'nc_cache_put\(env, payload, out\)', src) is not None)
    check("脏化分支不写缓存",
          not re.search(r'ulen <= 0\)\s*\{[^}]*nc_cache_put', src, re.S),
          "把脏结果写进缓存 = 之后所有相同密文都拿到脏值，会放大问题")

    print()
    print(f"通过 {PASS}，失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
