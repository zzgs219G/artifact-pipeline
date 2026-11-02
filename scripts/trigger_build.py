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
        if args.dex2c_stub or args.all:
            cfg["stringenc"]["dex2c_stub"] = True

    return json.dumps(cfg, ensure_ascii=False, separators=(",", ":"))


def describe_plan(cfg_json: str) -> str:
    """把 config JSON 翻成人类可读的模块列表，便于触发前确认。"""
    c = json.loads(cfg_json)
    mods = []
    if c.get("sigcheck"):
        mods.append("签名校验")
    if c.get("dex2c", {}).get("enabled"):
        mods.append("Dex2C")
    if c.get("stringenc", {}).get("enabled"):
        mods.append("字符串加密")
    if c.get("antidiff"):
        mods.append("防对比")
    if c.get("envcheck"):
        mods.append("环境检测")
    if c.get("packer", {}).get("enabled"):
        mods.append("加壳")
    return " + ".join(mods) if mods else "（无）"


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


def main() -> int:
    ap = argparse.ArgumentParser(
        description="命令行触发 EdgeRelay 构建",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("apk", help="本地 APK 路径")
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

    if not os.path.isfile(args.apk):
        die(f"APK 不存在: {args.apk}")

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
    print(f"  模块:     {describe_plan(config)}")
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
