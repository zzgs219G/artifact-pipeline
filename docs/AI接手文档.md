# AI 接手文档（2026-11-02）

> **给下一个接手这个项目的 AI。** 本文只写「不写下来你就一定会踩」的东西，
> 不写项目介绍（那看 `项目导览.md`）、不写机制细节（那看 `流程文档.md`）。
>
> ⚠️ **本文与源码冲突时，以源码为准。** 文档会过期，源码不会。

---

## 0. 三十秒定位

```
/data/data/com.termux/files/home/克隆仓库x/     ← 所有仓库都在这一层（平级）
├── artifact-pipeline/     ← 主流水线（你大概率从这开始）
├── nox/                   ← so 段加密设施的【唯一源码真相源】
├── Dex2C/                 ← dex2c 转译引擎（自研 fork）
├── d2c/                   ← 上游 d2c（只读参考，不要改）
├── dpt-shell/             ← 基础加壳
├── EdgeRelay/             ← 触发网关（Cloudflare Worker）
└── jian_box/              ← 被加固的目标 App（keystore 在这）
```

**改 so 层的东西去 `nox`，不要在 `artifact-pipeline` 里找 `nc_guard_*.c`**
——那已经在 2026-10-30 迁走上游了。

---

## 1. 三个仓库的角色（最容易搞混）

| 仓库 | 改什么 | 消费关系 |
|---|---|---|
| `nox` | `so-guard/*.c`、`so-section-lock.py`、`so_section_mark.py` | 打包成 `tools/nox.zip` 给下游 |
| `artifact-pipeline` | `protect.sh`、`sigcheck/src/*.c`、`string-enc/`、`lib-ndk.sh` | 消费 `tools/nox.zip`、`tools/dex2c.zip`、`tools/dpt-shell.zip` |
| `Dex2C` | `dcc.py`、`dex2c/writer.py`、`dex2c/compiler.py` | 打包成 `tools/dex2c.zip` |

**`artifact-pipeline` 里不保存 nox 的 `.c` 源码**，只有 `tools/nox.zip`。

---

## 2. 测试样本（**别自己造样本**）

```
artifact-pipeline/scripts/样本.apk        ← 就是它，直接 git 跟踪了
```

- **它会被人手动替换**：作者偶尔会把最新打包的 APP 覆盖到这里。
  所以**不要**假设它对应某个固定版本，也不要拿 md5 去比对「哪个才是真的」。
- `*.apk` 在 `.gitignore` 里，这个文件靠 `!scripts/样本.apk` 白名单入库。
- **不要在 `/storage/emulated/0/Download/` 里翻样本**。那里是构建产物的下载目录，
  有几十个同名不同版的 apk，翻到旧版会得出完全错误的结论。

### 为什么这条要单独写

2026-11-02 接手时因为找不到样本，自己拉了一个「看起来对」的包做测试，
结果和作者的样本不是同一份（大小/证书/dex 数全一样，但内容差 454 万字节）。
后续用错样本排查了十几轮，得出了一堆错误结论。

---

## 3. 测试构建（远程 CI）

```bash
cd /data/data/com.termux/files/home/克隆仓库x/artifact-pipeline

# 最常用：标准档 + 自动签名（签名用仓库 Secrets 里的 keystore）
RELAY_TOKEN='zzgs219' python3 scripts/trigger_build.py scripts/样本.apk --std --sign

# 全模块（含 packer/antidiff/envcheck，慢）
RELAY_TOKEN='zzgs219' python3 scripts/trigger_build.py scripts/样本.apk --all

# 本地直跑（不经过网关，不需要 token）
export ANDROID_NDK_HOME=/data/data/com.termux/files/home/android-ndk-r29-aarch64/android-ndk-r29
bash scripts/pipelines/protect.sh scripts/样本.apk /tmp/out.apk --sigcheck --dex2c
```

### 关键信息

| 项 | 值 |
|---|---|
| **RELAY_TOKEN** | `zzgs219`（网关令牌；**不在环境变量里，GitHub Secrets 也只有 CI 能读**） |
| 网关地址 | `https://relay.614118.xyz` |
| 产物下载目录 | `/storage/emulated/0/Download/` |
| 产物命名 | `[App名]_signed_[HH_mm_ss].apk`（由 `trigger_build.py:artifact_filename` 生成） |

### ⚠️ token 的三个坑

1. **`RELAY_TOKEN` 存在 `artifact-pipeline` 的 GitHub Secrets 里，但 CI 根本不用它**
   —— 它的使用方是 EdgeRelay（Cloudflare Worker）。
2. **GitHub Secrets 只写不读**，连管理员也拿不到明文。
3. 所以本地要跑 `trigger_build.py` 时，**必须显式传 `--token` 或设环境变量**，
   否则会卡在 `getpass` 交互提示（非终端下抛 `EOFError`）。

### 产物名为什么长这样

```
输入 scripts/样本.apk  →  下载时改名 样本_signed_14_36_22.apk
```

`_clean_app_name()` 会剥掉 `-v2`/`_v2`/`·v2` 这类版本后缀。
所以**输入文件名决定产物名**——用 `scripts/样本.apk` 就会得到 `样本_signed_*.apk`，
这是正常的，不是 bug。

---

## 4. 真机验证（**最容易假阴性的地方**）

```bash
export PATH=/data/data/com.termux/files/home/android-sdk-tools-static-aarch64/platform-tools:$PATH

# ⚠️⚠️ 必须先卸载 + 清缓存，否则会误判
adb uninstall com.xixin.box >/dev/null 2>&1
adb install -r -g -t <产物.apk>
adb logcat -c
adb shell "monkey -p com.xixin.box -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
sleep 12
adb logcat -d | grep -E " nc *:"          # 看加固链路日志
adb shell "ps -A | grep xixin.box"        # 进程存活？
adb logcat -d | grep -iE "SIGILL|FATAL"   # 崩溃？
```

### ⚠️⚠️ 同包名反复装卸会污染 ART 缓存 —— 这是最大的假阴性来源

**现象**：同一个包，前一次装能跑，后面装就 SIGILL；或者反过来。

**根因**：反复 `adb install/uninstall` 同一个包名，ART 的
`/data/dalvik-cache`、`/data/app/<pkg>/oat/` 会残留旧状态。签名一换就触发
缓存重建，于是「重签一下就好了」——**看起来像签名问题，其实是缓存问题**。

**判断方法**：如果「同一份 apk 有时能跑有时崩」或「重签就好」，先怀疑缓存。

**处理**：`adb uninstall` 后加 `adb shell pm clear <pkg>`，或者换个包名测。

> 2026-11-02 因为不知道这条，把缓存污染误判成「签名工具问题」，连续排查了
> 十几轮，先后错误怀疑过：zipalign、apksigner 版本、签名别名、zip 条目顺序、
> APK Signing Block 结构。每次都被实测推翻但没怀疑到验证环境本身。

---

## 5. 签名

### 远程 CI 自动签（推荐）

```bash
python3 scripts/trigger_build.py scripts/样本.apk --std --sign
```

流程（`.github/workflows/protect-modules.yml`）：
```
zipalign -f -p 4 → apksigner sign → 上传 R2
```
用仓库 Secrets：`KEYSTORE_BASE64` / `KEYSTORE_PASSWORD` / `KEY_ALIAS` / `KEY_PASSWORD`。

⚠️ **keystore 必须与上传 APK 同源**，否则证书绑定失败（`k_so` 由证书 DER 派生，
换了证书密文解不开 → `-12` fail-closed → SIGILL）。

### 本地签

```bash
# 可用 keystore（原包签名密钥）
/data/data/com.termux/files/home/克隆仓库x/jian_box/熠小夕.keystore
  别名: 熠小夕    storepass: z2458181028    keypass: 245818
  证书 SHA-256: D82E48DA E7CE6268 EBCEFD61 FEB8128F DF1A55F5 74CB BBC7 88DB7BE4 491B689E

# ⚠️ 必须照 CI 的顺序：先 zipalign 再 apksigner
ZA=/data/data/com.termux/files/home/android-sdk-tools-static-aarch64/build-tools/zipalign
$ZA -f -p 4 in.apk aligned.apk
apksigner sign --ks jian_box/熠小夕.keystore --ks-pass pass:z2458181028 \
    --key-pass pass:245818 --ks-key-alias 熠小夕 --out out.apk aligned.apk
```

**apksigner 的三个位置**（都验证过可用，行为一致）：
```
/data/data/com.termux/files/usr/bin/apksigner                        ← Termux 包管理器
/data/data/com.termux/files/home/android-sdk/build-tools/37.0.0/apksigner
/data/data/com.termux/files/home/android-sdk/build-tools/35.0.0/apksigner
```

---

## 6. 工具链位置

```
NDK r29 (aarch64 host):
  /data/data/com.termux/files/home/android-ndk-r29-aarch64/android-ndk-r29
  → 交叉编译器: toolchains/llvm/prebuilt/linux-aarch64/bin/aarch64-linux-android26-clang
  → llvm-readelf / llvm-objdump / llvm-objcopy / llvm-nm 都在同目录

Android SDK build-tools:
  /data/data/com.termux/files/home/android-sdk-tools-static-aarch64/build-tools/
  → aapt、aapt2、zipalign

其它 build-tools（含 apksigner / d8）:
  /data/data/com.termux/files/home/android-sdk/build-tools/{35,36,37}.0.0/

dex 工具:
  d8: /data/data/com.termux/files/home/android-sdk/build-tools/35.0.0/d8

adb:
  /data/data/com.termux/files/home/android-sdk-tools-static-aarch64/platform-tools/adb
```

⚠️ **`ANDROID_NDK_HOME` 默认未设置**，本地跑流水线必须自己 `export`。
⚠️ Termux 上 `/tmp` 不可写，**临时目录用 `mktemp -d`**，别写死 `/tmp/xxx`。

---

## 7. 真机

```
设备: Redmi 2602BRT18C
系统: Android 17 (SDK 37)
ABI:  arm64-v8a only（abilist32 为空 → **无法测 armeabi-v7a**）
包名: com.xixin.box
```

**32 位（v7a）只能靠离线验证**：用宿主机跑 ELF 解析逻辑去解真实 v7a 产物。
没有 qemu-arm，没有 32 位设备。

---

## 8. 这个项目的历史陷阱（每条都真实踩过）

### 8.1 「试过、崩过、回退过」的结论要核对崩在哪一行

`变更历史.md` 里 2026-10-21 记着「动态注册会崩」，挡了半年。实际崩的是
**`constructor(200)` 里调 `FindClass`**（动态链接器在 `dlopen` 内部执行，
classloader 未建立），而不是 `JNI_OnLoad` 里调（ART 主动回调，会切 classloader）。

**结论**：看历史结论时，去翻当时的 commit，确认失败的**具体形态**。

### 8.2 冻结模块不能随便改

`artifact-pipeline/AGENTS.md` 有清单。改之前必须在当次对话里**用户明确点名**，
并跑完全部回归 + 在 `变更历史.md` 留痕。

具体包括：`sigcheck/src/*.c`（`sig_check.c` / `env_check.c` / `nc_link.c` /
`sig_guard2.c`）、`nox/so-guard/nc_guard_layout.h`。

### 8.3 改 `.c` 必须双 ABI 验证

`APP_ABI := armeabi-v7a arm64-v8a`。只测 arm64 会漏掉 ELF32 相关的问题
（2026-11-02 的 v7a SIGILL 就是这么漏了几个月）。

### 8.4 「失败但继续」等于「从来没生效」

`protect.sh` 里删 `.comment` 那步在 CI 上失败了**三个月无人发现**，因为：
```bash
echo "[strip] ⚠️ .comment 移除失败（objcopy 异常）——继续但不阻塞"
```
根因是 GH Actions 没有 GNU `objcopy`（只有 `llvm-objcopy`）。

**推论**：不能阻塞出包的步骤，**必须在产物侧有断言**（写进 `test.sh`），
不能只看日志有没有报错。

### 8.5 加密了内容 ≠ 隐藏了结构

六段 RC4+HMAC 把字节变成密文，但 `.eh_frame` 里 709 个 FDE 把每个函数的
精确起止地址全列出来了。**评估加密效果时要问「还有什么没加密但能推出结构」**。

### 8.6 报告结论要用实测复核

外部报告里凡是「推测」「应该」的措辞都要当待验证项。已知错误：
- 「`--strip-all` 会一并去掉 libc++ 源码路径」→ 错，那在 `.rodata`，`--strip-all` 不碰
- 「推测只加了 `-fvisibility=hidden`/`-Oz`/strip，需要新增 `-fno-ident`」→ `-fno-ident` 早已在
- 「`getauxval` 我们完全没有」→ 有，但用于 CRC32 能力探测，不是反 hook 自检

---

## 9. 改完必做

```bash
# nox 改了什么
cd nox && ./test.sh          # 必须 18 通过 0 失败

# 分发包要更新（artifact-pipeline 消费的是 zip，不是你的工作区）
export ANDROID_NDK_HOME=/data/data/com.termux/files/home/android-ndk-r29-aarch64/android-ndk-r29
cd nox && bash scripts/make-zip-lib.sh <版本号>          # 静态库形态（生产用）
cd nox && bash scripts/make-zip-src.sh  <版本号>          # 源码形态（仅调试）
cp nox/dist/nox-<版本>.zip ../artifact-pipeline/tools/nox.zip
rm -rf ../artifact-pipeline/tools/nox                    # 强制重新解压

# 端到端
cd artifact-pipeline
RELAY_TOKEN='zzgs219' python3 scripts/trigger_build.py scripts/样本.apk --std --sign
# → 装真机验证（记得先 uninstall + pm clear）
```

⚠️ **`tools/nox.zip` 必须是静态库形态**（只有 `.h` + `.a`，没有 `.c`），
CI 的 `setup-toolchain` action 会校验，源码形态会直接失败：
```
❌ nox.zip 缺 arm64-v8a 静态库
❌ nox.zip 含 C 源码（应为静态库形态）
```

---

## 10. 一句话交接

**先看源码，再看文档。** 这个项目的文档写得很细（`流程文档.md` 2300 行、
`变更历史.md` 150+ 条报错），但它们**描述的是当时的代码**。改之前先
`grep` 一下源码，确认文档说的还在不在。

反过来，**踩坑经验一定要写回 `变更历史.md`** —— 这个项目靠它避免了大量重复劳动。
