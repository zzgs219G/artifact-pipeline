#!/usr/bin/env python3
"""trigger_build.py — 命令行触发 EdgeRelay 构建（不经过 APP）

用途：改完 nox / 流水线代码后，一条命令跑完「上传 APK → 触发构建 → 等结果」，
不用打开 APP 手动勾模块、手选文件。

为什么走 EdgeRelay 而不是直接调 GitHub API：
  · 和 APP 完全同一条路，触发逻辑只有一份，不会出现「脚本能跑但 APP 挂」
  · GitHub token 只在网关侧，本地不需要持有
  · 任务记录落在 KV，面板与 APP 都能看到

用法：
  python3 scripts/trigger_build.py <apk文件> [选项]

  # 最简：只勾签名校验
  python3 scripts/trigger_build.py app.apk

  # 指定模块
  python3 scripts/trigger_build.py app.apk --sigcheck --dex2c --stringenc

  # 全量
  python3 scripts/trigger_build.py app.apk --all

  # 只看会发什么请求，不真发
  python3 scripts/trigger_build.py app.apk --sigcheck --dry-run

令牌来源（按优先级）：
  1. --token 参数
  2. 环境变量 RELAY_TOKEN
  3. 交互输入

⚠️ 令牌不要写进本文件、不要提交进 git。
"""
import argparse
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = "https://relay.614118.xyz"
DEFAULT_WORKFLOW = "protect-modules.yml"
# 默认下载目录：Android 系统「下载」目录。Termux 有存储权限时可写；
# 没有则退回 $HOME/Download（见 resolve_download_dir）。
DEFAULT_DOWNLOAD_DIR = "/storage/emulated/0/Download"


def die(msg: str) -> "None":
    print(f"✗ {msg}", file=sys.stderr)
    sys.exit(1)


def http(method: str, url: str, token: str, body=None, raw: bytes = None,
         content_type: str = "application/json", timeout: int = 60,
         retries: int = 3, fatal: bool = True):
    """发一个请求，返回 (status, parsed_json_or_text)。

    网络层错误（连接重置/超时）自动重试 —— 移动网络下 Termux 出口不稳，
    实测单次轮询就可能 Connection reset by peer。业务错误（4xx/5xx）不重试。

    fatal=True（默认）：重试耗尽后 die()（触发/上传这类"一次性"请求，失败即无意义）。
    fatal=False：重试耗尽后返回 (None, None)，把"这次没拿到"交给调用方决定。
      ⚠️ 轮询类请求必须用 False：轮询本来就是高频重复请求，单次网络抖动
      不该终止整个等待（实测踩过：构建 122s 已成功，但轮询撞上一次握手超时
      → die() → 用户拿不到产物，必须重新上传 4.8MB 重跑）。
    """
    data = None
    # ⚠️ 必须带 User-Agent：Cloudflare 的 Browser Integrity Check 会把
    #    python-urllib 的默认 UA 拦成 403 error 1010（真机实测）。
    #    curl 的 UA 在白名单里所以能过 —— 这正是"curl 能通、脚本不能"的根因。
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "relay-build-cli/1.0",
        "Accept": "application/json",
    }
    if raw is not None:
        data = raw
        headers["Content-Type"] = content_type
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"

    last_err = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                payload = r.read()
                try:
                    return r.status, json.loads(payload)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return r.status, payload.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            try:
                return e.code, json.loads(text)
            except json.JSONDecodeError:
                return e.code, text
        except Exception as e:  # noqa: BLE001
            # 网络层：可重试
            last_err = e
            if attempt < retries:
                wait = 2 * attempt
                print(f"  ⚠ 网络错误（{e}），{wait}s 后重试 {attempt}/{retries - 1}",
                      file=sys.stderr)
                time.sleep(wait)
                continue
    if not fatal:
        return None, None
    die(f"请求失败 {method} {url}: {last_err}")


def _read_rules_file(path: str) -> str:
    """读规则文件内容。不存在则 die（人话），不静默返回空。"""
    if not os.path.isfile(path):
        die(f"规则文件不存在: {path}")
    with open(path, encoding="utf-8") as f:
        return f.read()


def build_config(args) -> str:
    """按开关拼 protect_config JSON。结构见 configs/v1/config-schema.json。

    预设优先级：--all > --std > --fast > 逐个开关。
    --fast 是默认：没给任何模块开关时只跑 sigcheck（最快，约 1-2 分钟）。

    为什么默认不含 packer / antidiff（用户 2026-10-31 明确要求）：
      · packer（dpt 加壳）本身要跑 1-2 分钟且最容易出兼容问题
      · antidiff 只加结构噪声，对"验证加固链路是否通"没有价值
      测试场景要的是"改完代码尽快知道有没有坏"，不是出厂强度。
      需要出厂强度时显式加 --packer / --antidiff 或 --all。
    """
    any_switch = any([args.sigcheck, args.dex2c, args.stringenc,
                      args.antidiff, args.envcheck, args.packer])
    if args.all:
        # 「全量」= 所有保护强度项全开，含 --dex2c-stub（桩内核也抽进 so）。
        # 2026-11-01 用户定：全模块就该勾满；+30~60s 的代价不该写进「全量」预设。
        on = dict(sigcheck=True, dex2c=True, stringenc=True,
                  antidiff=True, envcheck=True, packer=True)
    elif args.std:
        on = dict(sigcheck=True, dex2c=True, stringenc=True,
                  antidiff=False, envcheck=False, packer=False)
    elif not any_switch:
        # 默认 = 快速档，只 sigcheck
        on = dict(sigcheck=True, dex2c=False, stringenc=False,
                  antidiff=False, envcheck=False, packer=False)
    else:
        on = dict(sigcheck=args.sigcheck, dex2c=args.dex2c,
                  stringenc=args.stringenc, antidiff=args.antidiff,
                  envcheck=args.envcheck, packer=args.packer)

    cfg = {
        "schema_version": 1,
        "sigcheck": on["sigcheck"],
        "dex2c": {"enabled": on["dex2c"]},
        "stringenc": {"enabled": on["stringenc"]},
        "antidiff": on["antidiff"],
        "envcheck": on["envcheck"],
        "packer": {"enabled": on["packer"]},
    }

    # ── packer 子选项：--all / --packer 时显式带上（2026-11-02）────────
    # 为什么显式写而不依赖 schema default：
    #   · 用户明确要求「体积优化」与「排除模拟器架构」都默认勾上；
    #   · schema default 只是 resolve-config 的兜底，CLI 不写会让
    #     `--dry-run` 打印的 payload 与实际生效项不一致 —— 而 payload
    #     正是用户/CI 用来核对"我到底勾了什么"的唯一可见载体。
    # smaller       → --packer-smaller（体积优化）
    # exclude_x86   → --exclude-abi x86,x86_64（剔除模拟器 so 目录）
    if on["packer"]:
        cfg["packer"]["smaller"] = True
        cfg["packer"]["exclude_x86"] = True

    # ── 规则文件：值是【文件内容】而非路径 ───────────────────────────
    # resolve-config.py 的 value_kind=rules_file 语义：非空 → 写
    # schema_rules/<module>_<child>.txt，把路径追加在 arg 后；
    # 空 → 只吐 arg。
    #
    # ⚠️ 字段名必须是 schema 里的 child key（rules_file），不是 "rules"。
    #    schema 的 required 规则：
    #      dex2c.rules_file      always，但 sigcheck=true 时豁免 → 留空即
    #                            "自动解析 Manifest 的 LAUNCHER 主类"
    #      stringenc.rules_file  always，无豁免 → 必须给内容
    #
    # 默认（用户 2026-10-31 确认的测试常态）：
    #   dex2c 留空 → 自动主类（覆盖启动路径）
    #   stringenc "**" → 全量（漏类等于没加密）
    #
    # ⚠️ dex2c 不能填 "**"：schema hint 明确写"勿填 ** 全量
    #    （整个App转译，上游不支持）"。
    #
    # ⚠️ dex2c 规则留空时【必须】勾 sigcheck：schema 的 required.unless
    #    只在 sigcheck=true 时豁免（否则 resolve-config 直接 fail）。
    #    这里提前人话报错，别等云端跑 40 秒才告诉你。
    if on["dex2c"]:
        dex_rules = args.dex2c_rules
        if args.dex2c_rules_file:
            dex_rules = _read_rules_file(args.dex2c_rules_file)
        if not dex_rules.strip() and not on["sigcheck"]:
            die("dex2c 规则为空时必须同时勾 --sigcheck（否则上游无法确定抽哪些类）。\n"
                "  要么加 --sigcheck（自动抽 Manifest 主类），\n"
                "  要么用 --dex2c-rules 'com.example.**' 指定类名。")
        cfg["dex2c"]["rules_file"] = dex_rules

    if on["stringenc"]:
        enc_rules = args.stringenc_rules
        if args.stringenc_rules_file:
            enc_rules = _read_rules_file(args.stringenc_rules_file)
        if not enc_rules.strip():
            die("stringenc 规则不能为空：用 --stringenc-rules '**' 全量，"
                "或 --stringenc-rules-file <文件>")
        cfg["stringenc"]["rules_file"] = enc_rules
        # 联动子选项：把桩内核也抽进 so（对应 schema 的 dex2c_stub）
        # --all 隐含打开它：这是保护强度项，不是可选优化
        # ── 桩实现选择（2026-11-09）──────────────────────────────────
        # stub_impl 与 dex2c_stub 互斥：前者把算法编进 libnc.so（不需要
        # dex2c 转译），后者靠 dex2c 转译 Java 内核。同时勾 = 没有可转译
        # 的对象，protect.sh 会 fail-fast；这里提前拦，省一次云端构建。
        if args.stringenc_native:
            if args.dex2c_stub:
                die("--stringenc-native 与 --dex2c-stub 互斥："
                    "前者把算法编进 libnc.so（无需 dex2c），"
                    "后者靠 dex2c 转译 Java 内核。只保留一个。")
            if args.all:
                # --all 里 dex2c_stub 是硬编码 True（出厂强度），与 native
                # 互斥 —— 明确报错而不是静默让步，否则用户以为 native 生效了。
                die("--all 预设含 dex2c_stub（Java 内核转译），与 "
                    "--stringenc-native 互斥。请改用逐个开关，例如：\n"
                    "    --sigcheck --dex2c --stringenc --stringenc-native "
                    "--antidiff --envcheck --packer")
            cfg["stringenc"]["stub_impl"] = "native"
        elif args.dex2c_stub or args.all:
            cfg["stringenc"]["dex2c_stub"] = True

    return json.dumps(cfg, ensure_ascii=False, separators=(",", ":"))


def describe_plan(cfg_json: str) -> str:
    """把 config JSON 翻成人类可读的模块列表（触发前确认用）。

    ⚠️ 2026-11-06 改成"全量列出 + 明确标注开关"的表格格式。
    原因：原来只输出一行「A + B + C」，看不出【哪些没开】——
    用 --all 时用户以为全开了，实际 obfuscate 根本不在这个 config 里
    （它是另一条链路），而日志里不写、界面上不显示，只能翻构建日志才知道。
    这正是用户反馈的「可视化缺失」：正常人不会为了看勾了什么去读 6KB 日志。

    现在：已开的打 ✅、未开的打 ⬜，最后一行给数量小结。
    """
    c = json.loads(cfg_json)

    # (显示名, 是否启用, 补充说明)
    # 顺序刻意与 APP 端面板一致，便于两边对照
    rows = [
        ("签名校验", bool(c.get("sigcheck")), ""),
        ("Dex2C",
         bool(c.get("dex2c", {}).get("enabled")),
         ("规则: %s" % (c["dex2c"].get("rules_file") or "自动抽主类"))
         if c.get("dex2c", {}).get("enabled") else ""),
        ("字符串加密",
         bool(c.get("stringenc", {}).get("enabled")),
         ("规则: %s%s" % (
             c["stringenc"].get("rules_file", ""),
             "，解密桩=纯C（算法进 libnc.so）"
             if c["stringenc"].get("stub_impl") == "native"
             else ("，解密桩抽进 so" if c["stringenc"].get("dex2c_stub") else "")))
         if c.get("stringenc", {}).get("enabled") else ""),
        ("防对比混淆", bool(c.get("antidiff")), ""),
        ("环境检测", bool(c.get("envcheck")), ""),
        ("基础加壳",
         bool(c.get("packer", {}).get("enabled")),
         ("体积优化%s" % ("，排除模拟器架构" if c["packer"].get("exclude_x86") else ""))
         if c.get("packer", {}).get("enabled") else ""),
        # ⚠️ obfuscate 不在 protect_config 的 schema 里（它是独立 input），
        #    这里显式列出来并说明"本脚本无法设置"，避免用户以为 --all 包含了它。
        ("代码混淆(Amice)",
         bool(c.get("obfuscate", {}).get("enabled")),
         "本脚本不控制；VMP 已烧进 libnox.a，与此项无关"
         if not c.get("obfuscate", {}).get("enabled") else ""),
    ]

    out = []
    on = 0
    for name, enabled, note in rows:
        mark = "✅" if enabled else "⬜"
        if enabled:
            on += 1
        line = "  %s %-16s" % (mark, name)
        if note:
            line += "  (%s)" % note
        out.append(line.rstrip())
    out.append("")
    out.append("  → 共 %d/%d 项启用" % (on, len(rows)))
    return "\n".join(out)


def _report_signature(path: str, requested: bool) -> None:
    """检查产物签名状态，明确告知「请求了但没签上」这种最危险的情况。

    为什么要主动查：--sign 只是"请求"流水线签名，Secrets 缺失/密码错/
    apksigner 缺失都会让签名步骤失败或跳过，而产物照样下载得到、照样能打开。
    用户装不上或发现证书不对时才察觉，排查成本高。这里下载后立刻验证。
    """
    tool = shutil.which("apksigner")
    if not tool:
        if requested:
            print("   ⚠ 本机无 apksigner，无法验证签名（产物可能未签名）")
        return
    r = subprocess.run([tool, "verify", path], capture_output=True, text=True)
    if r.returncode == 0:
        c = subprocess.run([tool, "verify", "--print-certs", path],
                           capture_output=True, text=True)
        fp = ""
        for line in c.stdout.split("\n"):
            if "SHA-256 digest" in line:
                fp = line.split(":")[-1].strip()
                break
        print(f"   ✅ 已签名（证书 {fp[:16]}...）" if fp else "   ✅ 已签名")
    elif requested:
        print("   ❌ 请求了 --sign 但产物未签名！")
        print("      检查 Secrets 是否配齐、流水线「签名产物」步骤日志")
        print("      详见 docs/AI接手文档.md")
    else:
        print("   ℹ 未签名（本次未请求 --sign，符合默认契约）")


def resolve_download_dir(preferred: str) -> str:
    """选一个可写的下载目录。

    优先用调用方指定的（默认 Android 系统 Download）；不可写时退回
    $HOME/Download。不 fail-fast —— 产物下载失败不应该让整个流程算失败，
    拿不到就只打印链接，用户自己点。
    """
    for cand in (preferred, os.path.join(os.path.expanduser("~"), "Download")):
        try:
            os.makedirs(cand, exist_ok=True)
            probe = os.path.join(cand, ".write-probe")
            with open(probe, "w") as f:
                f.write("x")
            os.remove(probe)
            return cand
        except OSError:
            continue
    return ""


def _clean_app_name(raw: str) -> str:
    """提取纯净应用名：去 .apk/.zip 后缀与版本号后缀。

    与 jian_box 的 TaskArtifactHelper.extractCleanAppName 同规则
    （app/src/main/java/com/xixin/box/wrapper/common/apk/TaskArtifactHelper.kt），
    目的是让脚本下载的文件名与 APP 下载的完全一致 —— 同一份产物在两个
    入口拿到的名字相同，用户不会以为下了两个包。

    版本号后缀只认 ·v / _v / -v 且紧跟数字，避免误伤 Apex_virtual 这类名字。
    """
    base = raw
    for suf in (".apk", ".zip"):
        if base.lower().endswith(suf):
            base = base[: -len(suf)]
    base = base.strip()

    # 与 Kotlin 侧同一条正则：(?i)(·v|_v|-v)\d
    m = re.search(r"(?i)(?:·v|_v|-v)\d", base)
    if m:
        base = base[: m.start()]

    return base.strip() or "app"


def _check_source_apk(apk_path: str) -> None:
    """上传前检查源 APK 是否【已经加固过】，已加固则拒绝。

    ⚠️ 为什么必须查（2026-11-06 实际踩坑）：
    拿一个已经加固过的产物再加固一遍，构建照样成功、日志全绿、
    产物照样下载得到 —— 只是装到手机上卡在启动页。二次加固不会报错，
    因为两遍加密各自都是"成功"的，只有运行期解一次才发现还是密文。

    两个判据（任一命中即拒绝）：
      ① lib/<abi>/libnc.so 里有 .ncx / .ncxh 段 —— 说明 be 加固过
      ② 有 assets/xixin/libxixin.so —— 说明被加过壳
    """
    import zipfile
    try:
        z = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as e:
        die(f"读不了 APK: {apk_path}（{e}）")

    names = z.namelist()
    reasons = []

    # ② 加壳痕迹（最快，先查）
    packed = [n for n in names if "xixin" in n.lower() and n.endswith(".so")]
    if packed:
        reasons.append("含加壳产物: %s" % ", ".join(packed[:2]))

    # ① 加固段：解出 libnc.so 读段表
    ncs = [n for n in names if n.endswith("/libnc.so")]
    if not ncs:
        # 没有 libnc.so 也可能正常（首次加固、包里本就没这个 so），
        # 但如果有壳就已经拒绝在前面了，这里只提示不阻断。
        if not reasons:
            print("   ℹ 源包无 libnc.so（首次加固属正常）")
    else:
        import struct
        for n in ncs[:2]:                      # 只看前两个 abi，够判断
            try:
                data = z.read(n)
            except (KeyError, OSError):
                continue
            if len(data) < 64 or data[:4] != b"\x7fELF":
                continue
            try:
                is64 = data[4] == 2
                if is64:
                    sh_off = struct.unpack_from("<Q", data, 0x28)[0]
                    sh_es = struct.unpack_from("<H", data, 0x3A)[0]
                    sh_num = struct.unpack_from("<H", data, 0x3C)[0]
                    sh_str = struct.unpack_from("<H", data, 0x3E)[0]
                    str_off_pos, size_pos = 0x18, 0x20
                else:
                    sh_off = struct.unpack_from("<I", data, 0x20)[0]
                    sh_es = struct.unpack_from("<H", data, 0x2E)[0]
                    sh_num = struct.unpack_from("<H", data, 0x30)[0]
                    sh_str = struct.unpack_from("<H", data, 0x32)[0]
                    str_off_pos, size_pos = 0x10, 0x14
                o = sh_off + sh_str * sh_es
                strtab = (struct.unpack_from("<Q", data, o + str_off_pos)[0] if is64
                          else struct.unpack_from("<I", data, o + str_off_pos)[0])
                segs = []
                for i in range(sh_num):
                    oo = sh_off + i * sh_es
                    name_off = struct.unpack_from("<I", data, oo)[0]
                    end = data.find(b"\0", strtab + name_off)
                    if end < 0:
                        continue
                    nm = data[strtab + name_off:end].decode("utf-8", "replace")
                    if nm in (".ncx", ".ncxh", ".nck", ".ncks"):
                        segs.append(nm)
                if segs:
                    reasons.append("%s 已含加固段 %s" % (n, ",".join(sorted(set(segs)))))
                    break
            except (struct.error, IndexError):
                continue

    if reasons:
        print("")
        print("✗ 源 APK 看起来【已经加固过】，拒绝二次加固：")
        for r in reasons:
            print("    · %s" % r)
        print("")
        print("  二次加固不会报错，但产物会卡在启动页 —— 因为第一次加密的")
        print("  业务代码被当明文又加密了一遍，运行期解一次仍是密文。")
        print("")
        print("  请改用【原始未加固】的 APK。判据（二选一命中即已加固）：")
        print("    unzip -l app.apk | grep -c 'assets/xixin'      # 有壳")
        print("    unzip -p app.apk lib/arm64-v8a/libnc.so > x.so && \\")
        print("      readelf -S x.so | grep -c '\\.ncx'            # 有加固段")
        print("")
        print("  确实要强行二次加固（不推荐，仅供测试）：加 --allow-reprotect")
        sys.exit(1)


def artifact_filename(source_apk: str) -> str:
    """生成规范产物名：[App名]_signed_[HH_mm_ss].apk

    ⚠️ 刻意与 APP 保持一致（TaskArtifactHelper.generateSignedApkName），
    【不加模块名】：同一应用不同模块的产物靠时间戳区分；加了模块反而让
    APP 侧「找本地最新一版」的匹配规则（前缀 [App名]_signed_）失效。

    例：简盒-正式版-v2.1.2_样本.apk → 简盒-正式版_signed_14_36_22.apk
    """
    clean = _clean_app_name(os.path.basename(source_apk))
    return f"{clean}_signed_{time.strftime('%H_%M_%S')}.apk"


def download_file(url: str, dest_dir: str, token: str,
                  save_as: str = "") -> str:
    """下载产物到 dest_dir，返回本地路径（失败返回空串）。

    save_as 给定时用它做文件名（不用 URL 里的原名）——R2 侧的文件名是
    workflow 生成的 "<run_id>_模块勾选包.apk"，信息量低且每次不同，
    本地保存要换成可读的名字（见 artifact_filename）。

    产物在 R2 公开域名下，不需要 token；但同一套 UA 更保险
    （Cloudflare 的 Browser Integrity Check 对裸 urllib 会 403）。
    """
    if not dest_dir or not url:
        return ""
    if save_as:
        name = save_as
    else:
        name = os.path.basename(urllib.parse.urlsplit(url).path) or "protected.apk"
    # 只挡路径分隔符，防 url 里带 ../ 之类
    name = name.replace("/", "_").replace("\\", "_")
    dest = os.path.join(dest_dir, name)

    print(f"  下载到: {dest}")
    headers = {"User-Agent": "relay-build-cli/1.0"}
    # ⚠️ urllib 不接受含非 ASCII 的 URL（中文文件名会报
    #    'ascii' codec can't encode characters）。产物文件名里带中文是常态
    #    （"41176839128_模块勾选包.apk"），所以下载前必须百分号编码。
    safe_url = urllib.parse.quote(url, safe=":/?&=%@#+")

    # 重试 3 次：构建已经成功、链接已经拿到，此时因网络抖动丢掉产物最不值。
    # 实测踩过整包 6.6MB 下载到一半握手超时 —— 必须从头重试，不能放弃。
    last_err = None
    for attempt in range(1, 4):
        req = urllib.request.Request(safe_url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=180) as r, open(dest, "wb") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
            size = os.path.getsize(dest)
            print(f"  ✅ 已保存（{size} 字节）")
            return dest
        except Exception as e:  # noqa: BLE001
            last_err = e
            try:
                os.remove(dest)      # 半截文件必须删，否则下次误判"已下载"
            except OSError:
                pass
            if attempt < 3:
                wait = 3 * attempt
                print(f"  ⚠ 下载失败（{e}），{wait}s 后重试 {attempt}/2",
                      file=sys.stderr)
                time.sleep(wait)

    print(f"  ⚠ 下载失败（{last_err}），链接仍可手动访问")
    print(f"     手动下载: {url}")
    return ""


def upload_apk(base: str, token: str, apk_path: str, key: str, dry: bool) -> str:
    """调 /api/r2/presign 拿签名 URL，PUT 上传，返回 public_url。"""
    size = os.path.getsize(apk_path)
    print(f"  APK: {apk_path} ({size} 字节)")
    print(f"  R2 key: {key}")

    if dry:
        return f"<dry-run public_url for {key}>"

    status, resp = http("POST", f"{base}/api/r2/presign", token,
                        body={"key": key, "content_type": "application/vnd.android.package-archive"})
    if status != 200 or not isinstance(resp, dict):
        die(f"presign 失败 HTTP {status}: {resp}")

    url = resp.get("url")
    public_url = resp.get("public_url")
    headers = resp.get("headers") or {}
    if not url or not public_url:
        die(f"presign 响应缺 url/public_url: {resp}")

    print(f"  签名 URL 有效期: {resp.get('expires_at', 0) - int(time.time())} 秒")
    print(f"  上传中...", end="", flush=True)

    with open(apk_path, "rb") as f:
        data = f.read()
    # ⚠️ 同一把 UA：R2 侧虽不查 CF 的完整性检查，但保持一致避免将来踩坑
    up_headers = dict(headers or {})
    up_headers.setdefault("User-Agent", "relay-build-cli/1.0")
    req = urllib.request.Request(url, data=data, method="PUT", headers=up_headers)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            print(f" HTTP {r.status} ✅")
    except urllib.error.HTTPError as e:
        print(f" HTTP {e.code} ❌")
        die(f"上传失败: {e.read()[:300].decode('utf-8', 'replace')}")

    return public_url


def _echo_remote_modules(base: str, token: str, job_id: str) -> None:
    """触发后从服务端取回该任务【实际生效】的模块清单并打印。

    为什么需要（用户反馈"可视化缺失"）：
    本地 describe_plan 是从参数推的，服务端可能拒掉/改写某些项。
    以前要确认"到底勾了什么"，只能去翻 /api/log 的 6KB 构建日志 ——
    那不该是人做的事。EdgeRelay 的 /api/jobs 本来就有 modules 字段，
    直接读出来打印即可。

    失败不阻断（fatal=False 语义）：任务已经触发了，取不到清单只是
    少一行信息，不该让整个流程算失败。
    """
    status, resp = http("GET", f"{base}/api/jobs?limit=20", token, fatal=False)
    if status != 200 or resp is None:
        print("   （取云端模块清单失败，不影响构建）")
        return
    jobs = resp if isinstance(resp, list) else (resp.get("jobs") or resp.get("items") or [])
    job = next((j for j in jobs if j.get("job_id") == job_id), None)
    if not job:
        return
    mods = job.get("modules")
    if mods is None:
        return
    print("")
    print("── 服务端已受理的模块（权威）──")
    if not mods:
        print("  （无）")
    else:
        for m in mods:
            print("  ✅ %s" % m)
    print("")


def _report_nox_version() -> None:
    """打印本次构建会用到的 nox 版本，以及它是否真的带 VMP。

    为什么需要这个（2026-11-06 踩过）：两个仓库的版本号【没有任何自动
    校验】，nox 发了新版而本仓库 tools/nox.zip 没跟上时，构建照样成功、
    产物照样能用，只是里头是旧版加固 —— 而输出里一个字都不会提。
    实测就发生过：nox 已发 v0.9.7（VMP 升档到函数级），本仓库还停在
    v0.9.7 之前的版本，跑完构建才发现。

    判据不是版本号字符串（那个可以忘了改），而是【产物结构】：
    静态库形态下 nc_guard_crypto.o 的 VM 子段数直接反映 VMP 档位
    （module 共享 ~113，函数级隔离 ~152；0 = 完全没 VMP）。
    所以这里读版本号 + 尽力验一次结构，两者都打印。

    不阻断流程：验不出来只警告。挡路成本高于收益 —— 用户要的是出包。
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ver_file = os.path.join(root, "tools", "nox", "VERSION")
    zip_file = os.path.join(root, "tools", "nox.zip")

    ver = "?"
    try:
        with open(ver_file, encoding="utf-8") as f:
            ver = f.read().strip() or "?"
    except OSError:
        if os.path.isfile(zip_file):
            ver = "?（tools/nox/ 未解压，构建时按 nox.zip 现解）"
        else:
            print("   ⚠ 找不到 tools/nox.zip 与 tools/nox/ —— 构建可能缺加固设施")
            return

    print(f"nox 设施: {ver}")

    # 尽力验 VMP 档位：只在 .a 已就位时做（源码形态/未解压则跳过）
    lib = os.path.join(root, "tools", "nox", "so-guard", "lib",
                       "arm64-v8a", "libnox.a")
    if not os.path.isfile(lib):
        return
    ar = shutil.which("llvm-ar") or shutil.which("ar")
    readelf = shutil.which("llvm-readelf") or shutil.which("readelf")
    if not (ar and readelf):
        return
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            subprocess.run([ar, "x", lib], cwd=td, check=True,
                           capture_output=True)
            obj = os.path.join(td, "nc_guard_crypto.o")
            if not os.path.isfile(obj):
                return
            out = subprocess.run([readelf, "-SW", obj],
                                 capture_output=True, text=True).stdout
            subs = out.count("L.L__")
    except (OSError, subprocess.SubprocessError):
        return

    if subs == 0:
        print("   ⚠ nc_guard_crypto.o 无 VM 子段 —— 该 nox 未启用 VMP")
    else:
        # 113 ≈ module 共享一套；152 ≈ 函数级各一套（2026-11-06 实测）
        tier = "函数级隔离" if subs >= 140 else "module 共享"
        print(f"   VMP: {subs} 个 VM 子段（{tier}档）")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="命令行触发 EdgeRelay 构建",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("apk", nargs="?", default="",
                    help="本地 APK 路径。留空 = 用脚本同目录的 样本.apk"
                         "（最常用的默认值，省得每次打全路径）")
    ap.add_argument("--base", default=os.environ.get("RELAY_BASE", DEFAULT_BASE),
                    help=f"EdgeRelay 地址（默认 {DEFAULT_BASE}）")
    ap.add_argument("--token", default=os.environ.get("RELAY_TOKEN"),
                    help="Bearer 令牌（默认读 RELAY_TOKEN 环境变量）")
    ap.add_argument("--workflow", default=DEFAULT_WORKFLOW, help="workflow 文件名")
    ap.add_argument("--name", default="", help="任务显示名（面板可见）")
    ap.add_argument("--dpt-extra", default="", help="附加 dpt.jar 参数")

    g = ap.add_argument_group("模块勾选")
    g.add_argument("--sigcheck", action="store_true", help="签名校验")
    g.add_argument("--dex2c", action="store_true", help="Dex2C 转译")
    g.add_argument("--stringenc", action="store_true", help="字符串加密")
    g.add_argument("--antidiff", action="store_true", help="防对比混淆")
    g.add_argument("--envcheck", action="store_true", help="环境检测")
    g.add_argument("--packer", action="store_true", help="基础加壳")
    g.add_argument("--all", action="store_true", help="全选（含 packer，慢）")

    p = ap.add_argument_group("预设（互斥，优先于逐个开关）")
    p.add_argument("--fast", action="store_true",
                   help="快速档：只 sigcheck（默认，约 1-2 分钟）")
    p.add_argument("--std", action="store_true",
                   help="标准档：sigcheck + dex2c + stringenc（约 5-10 分钟）")

    r = ap.add_argument_group("规则文件（不给则用默认）")
    r.add_argument("--dex2c-rules", default="",
                   help="Dex2C 类名规则，一行一条。留空 = 自动抽 Manifest 主类"
                        "（需同时勾 sigcheck）。⚠️ 不要填 ** —— 整个 App 转译，上游不支持")
    r.add_argument("--stringenc-native", action="store_true",
                   help="解密桩用【纯 C 实现】：算法编进 libnc.so，dex 侧只有 "
                        "native 声明（不含任何密钥/算法）。需同时开字符串加密；"
                        "与 --dex2c-stub / --all 互斥。对应 schema 的 "
                        "stringenc.stub_impl=native。")
    r.add_argument("--dex2c-stub", action="store_true",
                   help="联动：把解密桩内核也抽进 libnc.so（需同时勾 dex2c + stringenc）。"
                        "勾选后走 LINK_STUB 路径 —— 桩先注入再转译，"
                        "解包/回编次数由 1 次变 2 次（+30~60s）")
    r.add_argument("--stringenc-rules", default="**",
                   help="字符串加密规则，默认 ** （全量）。")
    r.add_argument("--stringenc-rules-file", default="",
                   help="从文件读字符串加密规则（与 --stringenc-rules 二选一）")
    r.add_argument("--dex2c-rules-file", default="",
                   help="从文件读 Dex2C 规则（与 --dex2c-rules 二选一）")

    ap.add_argument("--dry-run", action="store_true", help="只打印，不真发请求")
    ap.add_argument("--allow-reprotect", action="store_true",
                    help="允许对【已加固】的 APK 二次加固（不推荐：产物会卡启动页，"
                         "仅供复现问题）")
    ap.add_argument("--no-wait", action="store_true", help="触发后立即返回，不等结果")
    ap.add_argument("--timeout", type=int, default=1800, help="等待上限（秒）")
    ap.add_argument("--download-dir", default=DEFAULT_DOWNLOAD_DIR,
                    help=f"产物下载目录（默认 {DEFAULT_DOWNLOAD_DIR}；"
                         "不可写时退回 ~/Download）")
    ap.add_argument("--no-download", action="store_true",
                    help="只打印链接，不下载产物")
    ap.add_argument("--no-sign", action="store_true",
                    help="即使 --all 也【不】请求签名（--all 默认带签名，本开关用于关掉）")
    ap.add_argument("--sign", action="store_true",
                    help="请求流水线用仓库 Secrets 里的 keystore 重签产物"
                         "（产出可直接安装）。需要 KEYSTORE_BASE64 / "
                         "KEYSTORE_PASSWORD / KEY_ALIAS / KEY_PASSWORD 四个 Secrets；"
                         "⚠️ keystore 必须与上传 APK 同源，否则证书绑定失败"
                         "（见 docs/AI接手文档.md）")
    args = ap.parse_args()

    # ── 默认样本 APK（2026-11-06）────────────────────────────────────
    # 最常用的场景是"改完 nox 打一版验证"，源包固定为仓库内的样本。
    # 每次手打全路径既烦又容易指错（实测踩过：把一次加固产物当源包，
    # 二次加固后卡启动页，排查半天才发现是输入错了）。
    if not args.apk:
        here = os.path.dirname(os.path.abspath(__file__))
        for cand in (os.path.join(here, "样本.apk"),
                     os.path.join(here, "sample.apk")):
            if os.path.isfile(cand):
                args.apk = cand
                break
        if not args.apk:
            die("未指定 APK，且脚本同目录下找不到 样本.apk\n"
                "  用法: %s [APK路径] [选项]\n"
                "  或把待测 APK 放到: %s/样本.apk" % (sys.argv[0], here))
        print(f"APK: {args.apk}（默认样本，可用位置参数覆盖）")

    if not os.path.isfile(args.apk):
        die(f"APK 不存在: {args.apk}")

    # ── 源包体检：拒绝二次加固 ───────────────────────────────────────
    # 二次加固不报错、不告警，只在手机上卡启动页 —— 属于本仓库
    # AGENTS.md 反复强调的"静默失效"，必须在入口挡住。
    if not args.allow_reprotect:
        _check_source_apk(args.apk)
    else:
        print("   ⚠ --allow-reprotect：跳过源包加固检测（产物可能卡启动页）")

    token = args.token
    if not token and not args.dry_run:
        token = getpass.getpass("RELAY_TOKEN: ")
    if not token and not args.dry_run:
        die("缺令牌：用 --token 或设 RELAY_TOKEN 环境变量")

    # R2 key 规则（见 EdgeRelay services/sigv4.py validatePresignKey）：
    #   必须以 apks/ 开头；不能含 . / .. 路径段；不能有 //；不能以 / 结尾。
    # 用内容哈希做 key，天然去重：同一份 APK 重复触发不会传两份。
    with open(args.apk, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()[:16]
    base_name = os.path.basename(args.apk)
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in base_name)
    key = f"apks/{digest}-{safe_name}"

    config = build_config(args)
    _report_nox_version()

    # ── 模块清单：触发【前】就让人看清勾了什么 ──────────────────────
    # 用户反馈的"可视化缺失"：原来只打一行「A + B + C」，看不出哪些没开，
    # 也看不出 obfuscate 根本不在这个 config 里。要确认得去翻 6KB 构建
    # 日志 —— 这不该是人做的事。
    print("")
    print("── 本次勾选的模块 ──")
    print(describe_plan(config))
    print("")

    print("=== 1. 上传 APK 到 R2 ===")
    public_url = upload_apk(args.base, token, args.apk, key, args.dry_run)
    print()
    print("=== 2. 触发构建 ===")
    payload = {
        "apk_url": public_url,
        "workflow_file": args.workflow,
        "protect_config": config,
        "dpt_extra_args": args.dpt_extra,
        "display_name": args.name or base_name,
    }
    # 签名：--all 默认带上（用户口径"默认签名"= 默认带 --sign 这个参数），
    # 其他预设仍需显式 --sign，--no-sign 可强制关掉。
    want_sign = (args.sign or args.all) and not args.no_sign
    if want_sign:
        payload["sign"] = True
    print(f"  workflow: {args.workflow}")
    if args.dry_run:
        print(f"  config:   {config}")
        print(f"  payload:  {json.dumps(payload, ensure_ascii=False)}")
        print()
        print("（dry-run：未发送任何请求）")
        return 0

    status, resp = http("POST", f"{args.base}/api/build", token, body=payload)
    if status != 200 or not isinstance(resp, dict) or not resp.get("success"):
        die(f"触发失败 HTTP {status}: {resp}")

    job_id = resp["job_id"]
    print(f"  ✅ 已触发，job_id = {job_id}")

    # ── 云端回显：确认【服务端实际收到】的模块 ──────────────────────
    # 本地打印的是"我以为勾了什么"，这里打印"服务端记下了什么"。
    # 两者不一致 = 参数被拒/被改写，早发现比等构建完再说好。
    _echo_remote_modules(args.base, token, job_id)

    if args.no_wait:
        print()
        print(f"任务页: {args.base}/jobs/{job_id}")
        return 0

    print()
    print("=== 3. 等待结果 ===")
    started = time.time()
    last_status = None
    net_fail_streak = 0          # 连续网络失败次数（拿到响应即清零）
    MAX_NET_FAIL_STREAK = 15     # 连续 15 次 × 20s ≈ 5 分钟全网络中断才放弃
    while time.time() - started < args.timeout:
        # fatal=False：轮询是高频重复请求，单次网络抖动不该终止等待。
        # 实测踩过：构建 122s 已成功，轮询撞一次握手超时 → die() → 用户拿不到
        # 产物，必须重新上传整包重跑。
        status, resp = http("GET", f"{args.base}/api/status/{job_id}", token,
                            fatal=False)
        if status is None:
            net_fail_streak += 1
            elapsed = int(time.time() - started)
            print(f"  [{elapsed:>4}s] 网络中断，重试中…"
                  f"（连续 {net_fail_streak}/{MAX_NET_FAIL_STREAK}）")
            if net_fail_streak >= MAX_NET_FAIL_STREAK:
                print(f"  ❌ 连续 {net_fail_streak} 次网络失败，放弃等待。")
                print(f"     构建可能仍在跑，稍后手动查：")
                print(f"     curl -H 'Authorization: Bearer <令牌>' "
                      f"{args.base}/api/status/{job_id}")
                print(f"     或打开任务页: {args.base}/jobs/{job_id}")
                return 1
            time.sleep(20)
            continue
        net_fail_streak = 0

        if status != 200 or not isinstance(resp, dict):
            print(f"  ⚠ 查询失败 HTTP {status}，重试...")
            time.sleep(5)
            continue

        st = resp.get("app_status") or resp.get("status") or "?"
        if st != last_status:
            elapsed = int(time.time() - started)
            print(f"  [{elapsed:>4}s] {st}")
            last_status = st

        if st in ("SUCCESS", "FAILED"):
            print()
            if st == "SUCCESS":
                print(f"✅ 构建成功（耗时 {int(time.time() - started)}s）")
                dl = resp.get("download_url")
                if dl:
                    print(f"   链接: {dl}")
                    if not args.no_download:
                        dest = resolve_download_dir(args.download_dir)
                        saved = download_file(dl, dest, token,
                                              save_as=artifact_filename(args.apk))
                        if saved:
                            print(f"   本地: {saved}")
                            _report_signature(saved, want_sign)
            else:
                print(f"❌ 构建失败")
                if resp.get("error"):
                    print(f"   原因: {resp['error']}")
            print(f"   任务页: {args.base}/jobs/{job_id}")
            return 0 if st == "SUCCESS" else 1

        # 20s 一次：构建通常 1-2 分钟，20s 内必然有状态变化，
        # 不必更密。EdgeRelay 限流 RATE_LIMIT_PER_MIN=120（次/分钟），
        # 3 次/分钟的轮询远低于阈值，但也没必要白花请求。
        time.sleep(20)

    print(f"⚠ 超时（{args.timeout}s），任务仍在跑: {args.base}/jobs/{job_id}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
