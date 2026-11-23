#!/usr/bin/env python3
"""apply-mods.py —— 业务补丁（广告绕过 / 任务自动化 / 去开屏弹窗 / 反检测）

## 这个脚本做什么

输入官方 APK，输出**打好业务补丁、未签名**的 APK。
**不包含签名校验相关的改动**（那是 uncheck.sh 的职责）。

## 与 uncheck.sh 的顺序

```
官方 APK
  → apply-mods.py   （本文，业务补丁：广告/任务/弹窗/反检测）
  → uncheck.sh      （签名校验绕过：Java 三层 hook + native IO 重定向）
  → MT 管理器签名
```

⚠️ 全程**不签名**。不签名是必须的：
  ① uncheck.sh 要从输入包提原始证书（v2/v3 签名块 或 META-INF/*.RSA），
     一旦重签，提出来就是新证书，origin.apk 的证明力就没了
  ② 重签还会让 META-INF 的 v1 签名失效，而部分检测会读它

## 补丁清单

### A. 广告绕过（拿奖励不用真看）
| 目标 | 改法 |
|---|---|
| `SdkRenderBridgeKt.reduceAdEvent` | `Shown` → 直接 `Settle(Completed)`；`Closed` → 无条件 `Completed` |
| 渠道 `RewardAdAdapter.showAd` × 8 | 不渲染，直接 `callVideoAdShow → PlayComplete → Reward(true) → Closed` |
| 渠道 `InterstitialAdAdapter.showAd` × 8 | `callVideoAdShow → Closed` |
| `AdSdkReadyGate.isSupported` | 恒 true |
| `AdTaskRewardRunner.<clinit>` | `DEFINITE_REJECTION_HINTS` 清空 |
| `AdvertisingState.shouldShow` | 仅 `task_reward` 返回 true，其余 false |
| `AdRewardBus` + `WhenMappings` | `Recorded→结算`、`Unknown→继续轮询`、`POLL_TOTAL 30s→120s` |

### B. 任务自动化
| 目标 | 改法 |
|---|---|
| `WelfareViewModelKt.canSubmitSignIn` | 恒 true |
| `WelfareViewModel.autoCompleteRegisterTaskIfNeeded` | 重写为同步遍历 |
| `WelfareViewModel$loadData$3` | `shouldAutoCompleteRegisterTask` → `const/4 0x1` |

### C. 观看时长秒达标
| 目标 | 改法 |
|---|---|
| `WatchDurationTracker.takeHeartbeatIfReady` | 固定上报 90 秒 |
| `WatchDurationTracker.<init>` | 心跳间隔 1 秒 |
| `ReportWatchDurationUseCase.enqueue$shared_release` | 单次心跳入队 40 条 |
| `WelfareApiMapperKt.toDomain` | `watchedSeconds` 改读 `targetSeconds` |

### D. 去开屏 / 弹窗
| 目标 | 改法 |
|---|---|
| `HomeChromeSplashHoldKt.isHomeChromeHeldForSplash` | 恒 false |
| `SplashFadeGate.isCompleted` | 恒 true |
| `HomeViewModel.requestHomeInterstitial` | 豁免为 null 时返回 `left(AdError$NotEnabled)` |

### E. 反检测（注入 hook 框架的前提）
| 目标 | 改法 |
|---|---|
| `SupportGuard.checkHookXposed()Z` | 方法体清空，恒 return 0 |

为什么只改这一个、不改 `runAll`：`runAll` 是 14 项检测总出口，改它会把
调试器/root/模拟器/虚拟空间/抓包一起废掉；`checkHookXposed` 才是
「hook 框架类名静态扫描」的入口，而**0x4 位的类名名单是远程配置下发的**，
今天不在名单里的框架明天可能被加进去 —— 所以必须拆整个方法，不能逐条删。

### F. 硬件证明短路（动漫共和国业务层判决链）
| 目标 | 改法 |
|---|---|
| `AndroidHardwareAttestation.<init>` | `isSupported` 常量 0x1 → 0x0，恒 false |

`isSupported` 硬编码恒 true 时 App 每次启动都向系统 keystore2 发起
STRONGBOX 硬件证明；证书链由**系统进程**从【真实安装签名】组装，
App 进程内的任何 hook（SigFix/MT/第三方）都无法影响。恒 false 后
attemptOnce 跳过 challenge/attestCertChain/verify 全链。

### G. native 检测快照隐匿
| 目标 | 改法 |
|---|---|
| `AndroidIntegrityInspectorKt.nativeSnapshotDetail` | libcCrc 键永不放入 detail；nVa/nMagisk/nFrida/nXposed/nMagiskFile 强制 FALSE（"0"） |

`libcCrc` 是 native 对 libc .text 做 CRC 的结果——uncheck 的 shadowhook
inline hook 改写 libc open/fopen 函数体后必然触发，官方包此键【不存在】。
其余五项是设备真实状态（有 Magisk 的设备为 "1"），与官方"干净设备"形态
对齐归零。

### H. native 探针直证伪造（★ 业务 API 判"破解版"的根因修复）
| 目标 | 改法 |
|---|---|
| `NativeApkSignatureProbe$1$1`（quickjs 脚本常量） | collect 函数不再调 `q7.a()`，恒返回 `native_verified:true` + 官方证书 SHA-256 |

原脚本调 `q7.a()`（native secure 组件的自校验结论）。重打包环境下该
自校验**必然失败**（读的是真实重签 APK，判定逻辑在混淆 so 内无法干预）
→ `nativeSigStatus=unread` → **签到/任务/领奖等业务 API 全部被判"破解版"**
（注意：此时 security.attest verdict 是 observe —— 安全层放行、业务层
照拒，两层是独立判决）。官方包冷启动竞态（首开也弹、刷新数次后探针
就绪恢复）证实该字段就是业务判决依据。

⚠️ 依赖关系：H 组必须与 uncheck.sh（SigFix 三层 hook）**配套使用**——
H 只伪造 native 探针线，Java 层的 asig/acert（业务指纹）靠 SigFix 拦
PackageManager 才统一成官方值。只打 H 不跑 uncheck，两条线口径矛盾
（Java=重签指纹、native=官方指纹），服务器照样判破解。

### 诊断插桩（F2/F3，随包生效，日志 tag=AttestDump / VerdictDump）
| 目标 | 改法 |
|---|---|
| `SecurityAttestApi.report` 入口 | `request.toString()` 打 logcat |
| `OfficialGuideNotifierKt.toOfficialGuide` | `verdict.toString()` 打 logcat |

排查"被判破解"类问题的标准工具：一次装机看清上报全字段与服务器判决
原文，不用逆向猜测。

## ★ 跨 App 适配（2026-11-23 新增）

同一套 App 模板（囧次元 / 动漫共和国 …）的 **dex 布局不同**：
同一个类在不同 App 里可能落在不同的 classesN.dex。

所以本脚本改为 **按类名自动定位 dex**：
  1. baksmali 全部 dex 到临时目录
  2. 按 `SMALI_PATCHES` 里的**类路径**（不是 dex 号）查找实际所在目录
  3. 只重编命中的 dex

这样同一份补丁源可以套用到任意同构 App。

## 用法

```bash
python3 apply-mods.py <输入.apk> <输出_未签名.apk>
```
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

SIG_BLOCK_MAGIC = b'APK Sig Block 42'

# ── 补丁源：基于囧次元 1.0.17 打好的 smali 树
PATCH_SRC = os.environ.get('MODS_SRC',
                           os.path.expanduser('~/jk_reverse/refix/r3'))

# ── 需要打的补丁：**按类路径**列（不含 dex 号，运行时自动定位）
PATCH_CLASSES = [
    # 0. 签名防检测（★ 文档 §2.1：凌晨成功版的核心组成，此前一直漏打！）
    #    SigSpoof 类本体必须进包，否则 DeviceProvider/Hx/IntegrityInspector
    #    的插桩（也在源树里，随 0.2/0.3 条目进包）会 NoClassDefFoundError。
    #    DeviceProvider 的 11 处插桩喂 asig/acert（设备指纹），是 CREATOR
    #    hook 覆盖不了的那条线（文档 §4"CREATOR hook 已验证不够"）。
    'com/yy/myuko/crackfix/SigSpoof.smali',
    'com/yy/myuko/feature/deviceinfo/DeviceProvider_androidKt.smali',
    'com/yy/myuko/feature/riskcollector/binding/Hx.smali',
    'com/yy/myuko/shared/data/security/integrity/AndroidIntegrityInspector.smali',
    'com/yy/myuko/shared/data/behavior/risk/AndroidRiskEnvProbe.smali',
    # A. 广告绕过
    'com/yy/myuko/shared/presentation/ad/SdkRenderBridgeKt.smali',
    'com/yy/myuko/shared/domain/ad/AdSdkReadyGate.smali',
    'com/yy/myuko/shared/presentation/ad/AdTaskRewardRunner.smali',
    'com/yy/myuko/shared/domain/ad/AdvertisingState.smali',
    'com/yy/myuko/shared/domain/ad/AdRewardBus.smali',
    'com/yy/myuko/shared/domain/ad/AdRewardBus$WhenMappings.smali',
    # A2. 渠道适配器（glob，8 个渠道 × 2 类型）
    'com/windmill/*/RewardAdAdapter.smali',
    'com/windmill/*/InterstitialAdAdapter.smali',
    # B. 任务自动化
    'com/yy/myuko/shared/presentation/screen/welfare/WelfareViewModelKt.smali',
    'com/yy/myuko/shared/presentation/screen/welfare/WelfareViewModel.smali',
    'com/yy/myuko/shared/presentation/screen/welfare/WelfareViewModel$loadData$3.smali',
    # C. 时长
    'com/yy/myuko/shared/domain/playback/usecase/WatchDurationTracker.smali',
    'com/yy/myuko/shared/domain/welfare/usecase/ReportWatchDurationUseCase.smali',
    'com/yy/myuko/shared/data/welfare/mapper/WelfareApiMapperKt.smali',
    # D. 去开屏 / 弹窗
    'com/yy/myuko/shared/presentation/screen/main/home/HomeChromeSplashHoldKt.smali',
    'com/yy/myuko/shared/presentation/screen/main/home/HomeViewModel.smali',
    'com/yy/myuko/shared/presentation/screen/splash/SplashFadeGate.smali',
    # E. 反检测
    'com/android/support/runtime/SupportGuard.smali',
    # F. 硬件证明短路（2026-11-23，动漫共和国过不掉的根因方向）
    #    AndroidHardwareAttestation.isSupported 硬编码恒 true，导致 App
    #    每次启动都向系统 keystore2 发起 STRONGBOX 硬件证明：证书链由
    #    系统进程从【真实安装签名】组装，App 内任何 hook（SigFix/MT/
    #    第三方）都无法影响 → 重签包必然露馅（keystore2 日志实锤：
    #    ATTESTATION_KEYS_NOT_PROVISIONED ... AppUid=共和国）。
    #    恒 false 后 attemptOnce 直接跳过 challenge/attestCertChain/verify
    #    全链。若服务器兼容无硬件证明的旧客户端（降级路径）即可通过。
    #    ⚠️ 只改构造器常量，不改 suspend 方法体（改 suspend 返回值会崩）。
    # [已停用-回滚实验] 'com/yy/myuko/shared/data/security/attestation/AndroidHardwareAttestation.smali',
    # F2. 诊断插桩（2026-11-23）：打印 SecurityAttestRequest 全部字段
    #     （runtimeApkSignature / runtimeApkSignatureNative / repackaged /
    #      mapsSuspiciousLibs / hookFrameworks / nativeSigStatus ...）
    #     —— 服务器判破解的依据全在请求字段里，插桩后一次装机看清。
    # [已停用-回滚实验] 'com/yy/myuko/shared/data/security/integrity/SecurityAttestApi.smali',
    # G. libcCrc 隐匿（2026-11-23，"破解版"提示的直接暴露点）
    #    native secure 组件对 libc .text 做 CRC 校验，shadowhook inline hook
    #    改写 libc open/fopen 函数体 → CRC 异常 → SecureSignalSnapshot.libcCrc
    #    = true → detail 出现 "libcCrc":"1"。官方包此键【不存在】（put 辅助
    #    仅 true 才写）。让 areEqual 恒 false → 键消失，与官方形态一致。
    # [已停用-回滚实验] 'com/yy/myuko/shared/data/security/integrity/AndroidIntegrityInspectorKt.smali',
    # F3. 诊断插桩：打印服务器 verdict 原文（action/officialUrl/reasons/ttlSec）
    # [已停用-回滚实验] 'com/yy/myuko/shared/data/security/integrity/OfficialGuideNotifierKt.smali',
    # H. native 探针直证伪造（2026-11-23，业务 API 判"破解版"的根因）
    #    NativeApkSignatureProbe 的 quickjs 脚本调 q7.a()（native secure 组件
    #    自校验）。重打包环境 native_verified=false → nativeSigStatus=unread
    #    → 签到/任务/领奖等业务 API 全部被判"破解版"。官方包冷启动竞态
    #    （首开也弹、刷新数次后探针就绪恢复）证实该字段是业务判决依据。
    #    改脚本恒返回 native_verified=true + 官方证书 SHA-256。
    # [已停用-回滚实验] 'com/yy/myuko/shared/data/security/integrity/NativeApkSignatureProbe$1$1.smali',
]


def log(msg):
    print(f'[mods] {msg}')


def find_tools():
    apktool = os.path.expanduser('~/逆向工具/bin/apktool')
    if not os.path.isfile(apktool):
        apktool = shutil.which('apktool')
    if not apktool:
        raise SystemExit('❌ 找不到 apktool')

    libs = os.path.expanduser('~/jk_reverse/smalilibs')
    need = ['smali-2.5.2.jar', 'util-2.5.2.jar', 'dexlib2-2.5.2.jar',
            'jcommander.jar', 'guava.jar', 'commons-cli.jar', 'antlr-runtime.jar',
            'baksmali-2.5.2.jar']
    cp = ':'.join(os.path.join(libs, f) for f in need)
    missing = [f for f in need if not os.path.isfile(os.path.join(libs, f))]
    if missing:
        raise SystemExit('❌ 缺工具: ' + ', '.join(missing))
    return apktool, cp


def read_signing_block(data):
    eocd = data.rfind(b'PK\x05\x06')
    if eocd < 0:
        return None
    cd_off = struct.unpack_from('<I', data, eocd + 16)[0]
    if cd_off < 32 or cd_off > len(data):
        return None
    if data[cd_off - 16:cd_off] != SIG_BLOCK_MAGIC:
        return None
    size_total = struct.unpack_from('<Q', data, cd_off - 24)[0]
    if size_total + 8 > cd_off:
        return None
    return data[cd_off - 8 - size_total:cd_off]


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    in_apk = os.path.abspath(sys.argv[1])
    out_apk = os.path.abspath(sys.argv[2])

    apktool, cp = find_tools()
    if not os.path.isdir(PATCH_SRC):
        raise SystemExit(f'❌ 找不到补丁源: {PATCH_SRC}')

    work = tempfile.mkdtemp(prefix='mods-')
    try:
        # ── 1. 解包（只 smali）
        log('解包 ...')
        dec = os.path.join(work, 'dec')
        subprocess.run([apktool, 'd', in_apk, '-o', dec, '-f', '--no-res'],
                       check=True, capture_output=True)

        # ── 2. 按类路径定位实际所在 dex 目录
        #
        # 跨 App 适配的关键：同一模板的不同 App，同一个类可能落在不同
        # classesN.dex。所以先扫目标包的 smali 树，建 index：
        #   {类相对路径: dex目录名}
        log('定位类所在 dex ...')
        index = {}          # 'com/yy/.../Foo.smali' -> 'smali_classes8'
        for entry in sorted(os.listdir(dec)):
            if not re.match(r'^smali(_classes\d+)?$', entry):
                continue
            base = os.path.join(dec, entry)
            if not os.path.isdir(base):
                continue
            for root, _d, files in os.walk(base):
                for f in files:
                    if not f.endswith('.smali'):
                        continue
                    rel = os.path.relpath(os.path.join(root, f), base)
                    index.setdefault(rel, entry)
        log(f'  索引 {len(index)} 个类')

        # ── 3. 展开 glob，确定每个补丁文件的目标位置
        to_copy = []        # (dex_dir, 相对路径, 补丁源路径)
        missing = []
        for pat in PATCH_CLASSES:
            if '*' in pat:
                # 在目标包里按 glob 找匹配项（而不是在补丁源里找）
                #
                # ⚠️ pat 里可能有 '$'（如 AdRewardBus$WhenMappings）——
                # 直接塞进正则会被当成行尾锚点，必须 re.escape 后再把
                # 转义过的 \* 换回通配符。首版没处理，导致渠道 adapter
                # 一个都没匹配上（16/32）。
                rx_src = re.escape(pat).replace(r'\*', '[^/]+')
                rx = re.compile(rx_src)
                for rel, entry in index.items():
                    if not rx.fullmatch(rel):
                        continue
                    # 补丁源里可能在不同 dex 号下（囧次元 vs 动漫共和国
                    # 的类分布不同），所以先按目标 dex 号找，找不到再全扫
                    src = os.path.join(PATCH_SRC, entry, rel)
                    if not os.path.isfile(src):
                        src = None
                        for e2 in sorted(os.listdir(PATCH_SRC)):
                            p2 = os.path.join(PATCH_SRC, e2, rel)
                            if os.path.isfile(p2):
                                src = p2
                                break
                    if src:
                        to_copy.append((entry, rel, src))
                    else:
                        missing.append(rel)
            else:
                entry = index.get(pat)
                src = None
                if entry is None:
                    # 目标包没有这个类 —— 可能是补丁源独有的新增类
                    # （如 crackfix/SigSpoof）。按源树定位，作为新增类打进包。
                    for e2 in sorted(os.listdir(PATCH_SRC)):
                        p2 = os.path.join(PATCH_SRC, e2, pat)
                        if os.path.isfile(p2):
                            src = p2
                            entry = e2
                            break
                    if src is None:
                        missing.append(pat)
                        continue
                    log(f'  新增类（补丁源独有）: {pat} → {entry}')
                else:
                    src = os.path.join(PATCH_SRC, entry, pat)
                    if not os.path.isfile(src):
                        found = None
                        for e2 in sorted(os.listdir(PATCH_SRC)):
                            p2 = os.path.join(PATCH_SRC, e2, pat)
                            if os.path.isfile(p2):
                                found = p2
                                break
                        if found is None:
                            missing.append(pat)
                            continue
                        src = found
                to_copy.append((entry, pat, src))

        log(f'  待打补丁 {len(to_copy)} 个文件')
        if missing:
            log(f'  ⚠️ 目标包缺这些类（跳过）:')
            for m in missing:
                log(f'     {m}')

        # ── 4. 覆盖 smali
        affected = set()
        for entry, rel, src in to_copy:
            dst = os.path.join(dec, entry, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
            affected.add(entry)
        log(f'  已覆盖 {len(to_copy)} 个 smali，涉及 {len(affected)} 个 dex: '
            f'{", ".join(sorted(affected))}')

        # ── 5. 只重编受影响的 dex
        log('重编 dex ...')
        rebuilt = {}
        for entry in sorted(affected):
            smali_dir = os.path.join(dec, entry)
            dex_name = ('classes.dex' if entry == 'smali'
                        else entry.replace('smali_classes', 'classes') + '.dex')
            out_dex = os.path.join(work, dex_name)
            r = subprocess.run(
                ['java', '-Xmx2g', '-cp', cp, 'org.jf.smali.Main',
                 'assemble', '--api', '28', '-o', out_dex, smali_dir],
                capture_output=True, text=True)
            if r.returncode != 0:
                log(f'  ❌ 重编 {entry} 失败:')
                print((r.stdout or '')[-1500:])
                print((r.stderr or '')[-1500:])
                return 1
            rebuilt[dex_name] = out_dex
            log(f'  {dex_name}: {os.path.getsize(out_dex)} B')

        # ── 6. 组装（保留 Signing Block + 原压缩字节）
        #
        # 两个必须保留的东西（都踩过）：
        #   ① APK Signing Block —— Python zipfile 不写它；
        #      丢了之后 uncheck 提不到证书，整个流程失败
        #   ② 原始压缩字节 —— 用 zin.read() 拿到的是解压数据，
        #      按原 compress_size 写 header 会让文件从 127MB 涨到 256MB
        log('组装 APK（保留原 Signing Block，不签名）...')
        with open(in_apk, 'rb') as f:
            src_data = f.read()
        sig_block = read_signing_block(src_data)

        with zipfile.ZipFile(in_apk) as zin:
            infos = zin.infolist()
            entries = {}
            for item in infos:
                if item.filename in rebuilt:
                    raw = open(rebuilt[item.filename], 'rb').read()
                    if item.compress_type == 8:
                        co = zlib.compressobj(9, zlib.DEFLATED, -15)
                        payload = co.compress(raw) + co.flush()
                        method, csize = 8, len(payload)
                    else:
                        payload, method, csize = raw, 0, len(raw)
                    entries[item.filename] = {
                        'data': payload, 'method': method, 'csize': csize,
                        'fsize': len(raw), 'crc': zlib.crc32(raw) & 0xFFFFFFFF}
                else:
                    off = item.header_offset
                    if src_data[off:off + 4] != b'PK\x03\x04':
                        raise RuntimeError(f'{item.filename} local header 非法')
                    nl = struct.unpack_from('<H', src_data, off + 26)[0]
                    el = struct.unpack_from('<H', src_data, off + 28)[0]
                    dstart = off + 30 + nl + el
                    entries[item.filename] = {
                        'data': src_data[dstart:dstart + item.compress_size],
                        'method': item.compress_type,
                        'csize': item.compress_size,
                        'fsize': item.file_size,
                        'crc': item.CRC}

        out = bytearray()
        offsets = {}
        for item in infos:
            offsets[item.filename] = len(out)
            nb = item.filename.encode('utf-8')
            e = entries[item.filename]
            out += b'PK\x03\x04'
            out += struct.pack('<H', 20 if e['method'] == 8 else 10)
            out += struct.pack('<H', 0)
            out += struct.pack('<H', e['method'])
            out += struct.pack('<HH', item.date_time[3] & 0xFFFF,
                               ((item.date_time[0] - 1980) << 9) |
                               (item.date_time[1] << 5) | item.date_time[2])
            out += struct.pack('<I', e['crc'])
            out += struct.pack('<I', e['csize'])
            out += struct.pack('<I', e['fsize'])
            out += struct.pack('<H', len(nb))
            out += struct.pack('<H', 0)
            out += nb
            out += e['data']

        cd = bytearray()
        for item in infos:
            nb = item.filename.encode('utf-8')
            e = entries[item.filename]
            cd += b'PK\x01\x02'
            cd += struct.pack('<H', 20)
            cd += struct.pack('<H', 20 if e['method'] == 8 else 10)
            cd += struct.pack('<H', 0)
            cd += struct.pack('<H', e['method'])
            cd += struct.pack('<HH', item.date_time[3] & 0xFFFF,
                              ((item.date_time[0] - 1980) << 9) |
                              (item.date_time[1] << 5) | item.date_time[2])
            cd += struct.pack('<I', e['crc'])
            cd += struct.pack('<I', e['csize'])
            cd += struct.pack('<I', e['fsize'])
            cd += struct.pack('<H', len(nb))
            cd += struct.pack('<H', 0)
            cd += struct.pack('<H', 0)
            cd += struct.pack('<H', 0)
            cd += struct.pack('<H', item.internal_attr)
            cd += struct.pack('<I', item.external_attr)
            cd += struct.pack('<I', offsets[item.filename])
            cd += nb

        if sig_block:
            out += sig_block
        cd_off_in_out = len(out)
        out += cd
        n = len(infos)
        out += b'PK\x05\x06'
        out += struct.pack('<H', 0)
        out += struct.pack('<H', 0)
        out += struct.pack('<H', n)
        out += struct.pack('<H', n)
        out += struct.pack('<I', len(cd))
        out += struct.pack('<I', cd_off_in_out)
        out += struct.pack('<H', 0)

        with open(out_apk, 'wb') as f:
            f.write(out)

        log(f'✅ 完成: {out_apk} ({os.path.getsize(out_apk)} B)')
        log('   未签名 —— 接下来交给 uncheck.sh')
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
