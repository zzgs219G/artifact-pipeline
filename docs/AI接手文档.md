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

## 1. 周边仓库的角色（最容易搞混）

> 全部**平级并列**在同一父目录下。依赖方向**单向**：本仓库消费三个工具上游的
> 分发包（zip），工具上游都不认识本仓库。

| 仓库 | 改什么 | 与本文档的关系 |
|---|---|---|
| `nox` | `scripts/so-guard/*.c`、`so-section-lock.py`、`so_section_mark.py`、`nox` CLI、`test.sh` | 打包成 `tools/nox.zip` 给本仓库。**完整说明见 [`上游仓库-nox.md`](./上游仓库-nox.md)** |
| `artifact-pipeline` | `protect.sh`、`guard/src/*.c`、`string-enc/`、`lib-ndk.sh` | 本仓库。消费 `tools/nox.zip`、`tools/dex2c.zip`、`tools/dpt-shell.zip` |
| `Dex2C` | `dcc.py`、`dex2c/writer.py`、`dex2c/compiler.py` | 打包成 `tools/dex2c.zip`（唯一转译引擎） |
| `dpt-shell` | 加壳器（Java） | 打包成 `tools/dpt-shell.zip`（packer 模块） |
| `d2c` | 上游 d2c | **只读参考，不要改** |
| `EdgeRelay` | Cloudflare Worker | 触发本仓库 workflow 的网关 |
| `jian_box` | 被加固的目标 App | keystore 在这里 |

**`artifact-pipeline` 里不保存 nox 的 `.c` 源码**，只有 `tools/nox.zip`。
同理也不保存 Dex2C / dpt-shell 的源码。

### 1.1 nox 上游的四个关键事实（改 so 层前必读）

1. **没有 `nc_guard_*.c` 可改** —— 去 `../nox/scripts/so-guard/` 改。
   本仓库里连副本都没有（刻意：双源头必然漂移）。
2. **它有自己的 CLI 和自测**，本仓库文档此前完全没提：
   ```bash
   cd ../nox
   ./test.sh                                   # V1–V10，零参数即可跑（判据 0 失败）
   ./nox protect mycode.c --apk app.apk -o libmy.so   # 一条命令编译+加密+strip
   ```
3. **改完必须换 zip 并删解压产物**：
   ```bash
   cd ../nox && ./test.sh                     # 23 通过 0 失败（2026-11-09 实测）
   export ANDROID_NDK_HOME=/path/to/ndk-r27d
   bash scripts/make-zip-lib.sh <版本号>       # 静态库形态（生产用）
   cp dist/nox-<版本>.zip ../artifact-pipeline/tools/nox.zip
   rm -rf ../artifact-pipeline/tools/nox      # ← 不删会静默用旧版
   ```
4. **两个 tag 陷阱**：nox 现有 **22 个 tag，最新是 `v0.9.11-obf`**（`v0.4.2` 仍然不存在）；
   CI clone nox 用的是 `ref: main`，不是 tag。详见 `上游仓库-nox.md` §8。

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

### CI 签名（可选，`sign=true` 才跑）

默认**不签名** —— 本仓库契约是「产出未签名包，开发者自行重签」。
只有显式请求 `sign=true` 时才用仓库 Secrets 里的 keystore 重签。

| 场景 | 是否需要签名 |
|---|---|
| App 正常流程 | ❌ 不需要，开发者自己重签（既有契约） |
| CLI 调试（`trigger_build.py --sign`） | ✅ 需要，省掉手工重签 |

**四个 Secrets**（Settings → Secrets and variables → Actions）：

| Secret 名 | 内容 | 怎么生成 |
|---|---|---|
| `KEYSTORE_BASE64` | keystore 文件 base64 | `base64 -w0 release.keystore` |
| `KEYSTORE_PASSWORD` | **store 密码**（keystore 容器密码） | 你自己的 |
| `KEY_ALIAS` | key 别名 | 你自己的 |
| `KEY_PASSWORD` | **key 密码**（该别名对应的私钥密码） | 你自己的 |

> ⚠️ **store 密码与 key 密码不一定相同。** 实测踩过：两个填成同一个 →
> `java.security.UnrecoverableKeyException: Cannot recover key`。
>
> 陷阱在于 `keytool -list -storepass <store密码>` **能通过** —— 它只校验
> store 密码、不校验 key 密码。所以「keystore 载入成功」不等于「密码正确」，
> 真正的失败要等到 `apksigner sign` 才暴露。
>
> 本地先验一次：`keytool -list -keystore release.keystore`（会分别问两个密码）。

**keystore 必须与上传 APK 同源**（本仓库最重要的一条签名约束）：
`libnc.so` 里 `k_so = HKDF(master, SHA256(certDER), ...)`，换证书重签 →
运行期派生失败 → 包起不来（返回 `-12`）。所以 Secrets 里的 keystore
必须就是签那个 APK 的同一个证书。

**用 CLI 存 Secrets**：

```bash
REPO=zzgs219G/artifact-pipeline
base64 -w0 release.keystore | gh secret set KEYSTORE_BASE64 --repo "$REPO"
gh secret set KEYSTORE_PASSWORD --repo "$REPO"   # 交互式提示，值不回显
gh secret set KEY_ALIAS         --repo "$REPO"
gh secret set KEY_PASSWORD      --repo "$REPO"
```

⚠️ `gh secret set` **不带 `--body`** 才安全（交互输入、不进 shell history）。
带 `--body` 传值会进 history，别用。

**签名相关报错对照**：

| 现象 | 原因 |
|---|---|
| `❌ 请求了 sign=true 但缺少 Secrets: ...` | 四个 secret 没配齐 |
| `❌ keystore 解密失败` | base64 截断（`base64` 没加 `-w0`，带换行）或密码错 |
| `Cannot recover key` | `KEY_PASSWORD` 与 `KEYSTORE_PASSWORD` 填成了不同/相同的错值 |
| 装上去启动即退出 / SIGILL | keystore 与上传 APK 不同源 → 证书绑定 fail-closed(`-12`) |

### 远程构建产物名与耗时

| 配置 | 耗时 | 备注 |
|---|---|---|
| `--sigcheck`（默认档） | ~54s | so 约 78KB |
| `--std`（sigcheck+dex2c+stringenc） | ~90s | 本轮实测 89s |
| `--all`（6 模块） | ~115s | so 约 328KB |

**耗时分布**（`--all` 的 87s 模块编排内）：

```
dex2c 转译                 20.0s   23%
NDK 编译                   10.3s   12%
解包 + stringenc + anti-diff 31.4s  36%
apktool 回编                9.7s   11%
dpt 加壳                   11.2s   13%
```

**结论**：NDK 编译不是瓶颈，优化空间有限。别为省 6 秒动编译参数。

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

具体包括：`guard/src/*.c`（`sig_check.c` / `env_check.c` / `nc_link.c` /
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

### 8.4.1 本地 Termux 构建的 so 装机必崩 —— 验证只能走云端（2026-11-09 血泪）

```
本地 Termux (NDK r29, linux-aarch64) 编译 → 装机 SIGILL
  且：连纯 --sigcheck（完全不含 stringenc-native 代码）也崩
  且：关掉段标记也崩
云端 CI (r27d / r29 都试过) → 全部正常
```

逐字节对比两边 `.text`：**大小完全相同（166772），只差 22 字节，
全是 SIMD 栈访问偏移**（`ldr q1,[x9,#0x290]` vs `#0x280`）——
高度怀疑与 nox VMP 对栈布局的隐含依赖有关（未证实）。

**教训：本地装机的"能跑/不能跑"结论一律不可采信。**
这一条不懂，会像我一样连续误判"锁箱失败""clang 版本不兼容"，
每次都要重跑云端才发现方向错了。

**正确姿势**：
```bash
RELAY_TOKEN=... python3 scripts/trigger_build.py --sigcheck --stringenc \
    --stringenc-native --stringenc-rules '**' --sign
# → 下载 → adb install → 看 logcat
```

### 8.4.2 C 桩的五个必崩点（改这块前必读）

真机实测，每条都是硬崩溃：

| # | 症状 | 根因 | 修法 |
|---|---|---|---|
| 1 | `无法得知本次的随机桩名` | STEP3 编 so 早于 STEP5 注桩 | `emit-stub-decl` 只算名字不注入 |
| 2 | `library "libnc.so" not found` | STEP5 放 so 的条件漏了 `WANT_NATIVE_STUB` | 条件补上 |
| 3 | `JNI_ERR returned from JNI_OnLoad` | 桩 `<clinit>` 里 loadLibrary 时类正在初始化，`FindClass` 自己失败 | 删自建 OnLoad，改 JNI 短名绑定 |
| 4 | `NoSuchMethodError: ncSetKey([B)V` | ART 在**类链接阶段**解析 native 短名（早于 `<clinit>`） | 密钥编译进 so，不经 Java |
| 5 | App 起得来但功能全废（Room 报 `no table with name <密文>`） | `bootstrap` 只在 `JNI_OnLoad` 里调，纯 native 桩组合没有 OnLoad → **密钥永远没设** | `nc_ensure_key()` 惰性注入 |

**第 5 条最危险**：解密失败是静默的（返回原密文，不崩不报错）。
为此加了 `nc_strdec_fail_count()` —— **非 0 就说明加固在静默劣化**。

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
# nox 改了什么（在 nox 仓库）
cd ../nox && ./test.sh          # 必须 23 通过 0 失败（2026-11-09 实测 23/0）

# 分发包要更新（artifact-pipeline 消费的是 zip，不是你的工作区）
export ANDROID_NDK_HOME=/data/data/com.termux/files/home/android-ndk-r29-aarch64/android-ndk-r29
cd ../nox && bash scripts/make-zip-lib.sh <版本号>          # 静态库形态（生产用）
cd ../nox && bash scripts/make-zip-src.sh  <版本号>          # 源码形态（仅调试）
cp ../nox/dist/nox-<版本>.zip /path/to/artifact-pipeline/tools/nox.zip
rm -rf /path/to/artifact-pipeline/tools/nox                 # 强制重新解压

# 回到本仓库：先跑不依赖 NDK 的
cd artifact-pipeline
python3 scripts/actions/tests/test-docs-paths.py
bash scripts/lib/tests/test-so-lock.sh                      # 52 项，需 ../nox 源码

# 端到端
RELAY_TOKEN='zzgs219' python3 scripts/trigger_build.py scripts/样本.apk --std --sign
# → 装真机验证（记得先 uninstall + pm clear）
```

⚠️ **`tools/nox.zip` 必须是静态库形态**（只有 `.h` + `.a`，没有 `.c`），
CI 的 `setup-toolchain` action 会校验，源码形态会直接失败：
```
❌ nox.zip 缺 arm64-v8a 静态库
❌ nox.zip 含 C 源码（应为静态库形态）
```

⚠️ **不要凭 `tools/nox.zip` 里的 `VERSION` 去写 CI 的 `ref`**——
那是包版本（形如 `2026.11.02-final`），不是 git tag。nox 仓库的 tag
共 22 个（`v0.1.0` … `v0.9.11-obf`），当年凭 "v0.4.2" 猜 tag 导致 checkout 直接失败。
⚠️ 但"最新 tag 是 v0.4.0"这个说法 2026-11-09 已过期——现在最新是 `v0.9.11-obf`。

---

## 9.5 当前进度与下一步（2026-11-09 更新）

> **新接手的 AI 先读这一节。** 它回答"现在做到哪了、接下来该干什么"——
> 这是本文其他地方都不覆盖的信息。

### 已完成并真机验证

| 项 | 状态 |
|---|---|
| **纯 C 解密桩**（`--stringenc-native`） | ✅ 云端 r27d / r29 产物均真机跑通 |
| 算法与密钥离开 dex | ✅ dex 内 `GAMMA/keyByte/mix64/nc_strdec` 命中 **0 处** |
| 算法进 `.ncx` 锁箱段 | ✅ arm64 0x1e70，`objdump` 看到的是密文 |
| 密钥编译进 so | ✅ `nc_strdec_cfg.h` 的 `NC_STRDEC_KEY_BYTES`，dex 零密钥 |
| JNI 短名绑定（不进 `.dynsym`） | ✅ 只导出 `Java_<随机包名>_<随机方法名>` |
| 三套测试进 CI | ✅ 291 + 184 + 13 项 |

### 当前配置的实际形态

```
schema: stringenc.stub_impl  ← type=select, value_kind=choice（2026-11-09 起）
        default "java" → Java 桩
        选 "c"         → --stringenc-native（纯 C 桩）
```

**注意：`stub_impl`（下拉框）和 `dex2c_stub`（复选框）在 UI 上仍是两个独立控件，
可以同时选** —— 那是非法组合，靠 CLI / `protect.sh` / 云端 `resolve-config`
三层 fail-fast 拦。**UI 层没拦**（schema 没有表达"互斥"的能力，
`required.unless` 只能表达"必填豁免"）。

### 下一步（按优先级）

#### ① 把 Java/C 桩改成真单选 —— ✅ **已完成（2026-11-09）**

> **裁决：用「下拉框」，不用「单选框」。** 判据与反例见 `docs/配置schema.md` §4.2。
> 摘要：子项复选框被压到 20dp（行高 36dp 所迫），20dp 的圆（radio）与 20dp 的
> 圆角方框（checkbox）并排时形状差异基本不存在，用户无法区分"这个框是单选还是
> 多选"；下拉框用**折叠/展开的形态差异**把语义区分开。
> （例外：APP 顶层「加固方案」用 radio 是对的 —— 独立 SectionCard + 每项带 subtitle。）

**落地内容**（4 个文件，jian_box 零改动）：

```
configs/v1/config-schema.json         type=checkbox/flag → type=select/value_kind=choice
                                      options: java(arg_on="") / c(--stringenc-native)
scripts/actions/resolve-config.py     新增 value_kind=="choice" 分支 + 旧布尔快照兼容
                                      + _dump_plan 显示 option 的 label 而非裸 value
scripts/actions/check-schema.py       choice 结构断言 5 条（value 唯一 / 每项有 label 与
                                      arg_on / 带 arg_on 的最多 1 个 / default ∈ options）
scripts/actions/tests/                 T17a~T17g 七例（44 通过）
scripts/trigger_build.py              写入值 True → "c"；读点同步改判 == "c"
```

**为什么 jian_box 零改动**：`type=select` 的通路在 APP 侧早已完整 ——
`default` 走 `optString`、状态存 `String`、`buildProtectConfig` 走 else 分支写字符串、
`:143` 已分发 `"select"` → `ChildSelect()`。**schema 从未用过 select，但代码是通的。**

**旧快照兼容**（这条容易漏）：`stub_impl` 曾是 `value_kind=flag`，旧 App 会提交
`true`/`false`。`resolve-config.py` 遇到布尔值映射到"恰好一个带 `arg_on` 的选项"
（多于一个就 `die()`，不瞎猜），`check-schema.py` 用 `len(nd) <= 1` 静态保障这个前提。
不写这 10 行的话，旧 App 用户提交 `true` 会被判"值必须是字符串"直接报错 ——
**一个原本能跑的构建突然失败**。

**⚠️ 仍未解决**：UI 层不拦互斥。`stub_impl`（下拉）与 `dex2c_stub`（复选框）
在 UI 上仍是两个控件，**同时选仍然可选**。互斥靠 `trigger_build.py` /
`protect.sh` / `resolve-config` 三层 fail-fast 兜底。要真正在 UI 层拦住，
需要 `ProtectConfigSchema.validate()` 支持跨字段约束 —— schema 当前没有这个
表达力（`required.unless` 只能表达"必填豁免"，不能表达"互斥"）。
**这是"错了才发现"而非"不允许错"，如实记录为缺口。**

#### ② 算法可选框（splitmix64 / ChaCha20）—— ✅ **已完成（2026-11-09）**

**动机不是速度**，而是**可逆性**：

```
splitmix64：可逆 —— 猜中任意一条明文 → 反解种子 → 全包沦陷
ChaCha20  ：不可逆 —— 猜中一条只泄漏那一条
```

**落地形态**（与原计划的差异，都是实测后改的）：

| 原计划 | 实际做的 | 为什么改 |
|---|---|---|
| 每条多存 nonce，Base64 变长 | **0 增长**：offset 直接当 counter | offset 本来就是全包唯一的，满足 ChaCha20 的 counter 不重复前提 |
| 只影响 `key_byte()` 与 `nc_block_ks()` | 还改了**块粒度**（8→64 字节） | 硬套 8 字节契约会算了 64 字节只用 8 字节，浪费 8 倍 |
| 只影响 C 侧 | 还改了 `nc_strdec.c` 的 include 顺序 | `cfg.h` 曾被头文件的 `#ifndef` 挡住，注入的档位从未生效 |

**UI**：`stringenc.algo`，`type=radio`（横向单选）+ `visible_when{stub_impl,c}`。
选 Java 桩时整行不显示 —— Java 桩的算法在 dex 里，换算法要重做整条
d8→baksmali 链路与 384 项对拍，不在范围。

> **为什么用横向单选而不是下拉框**：同一模块里已有一个下拉框（解密桩实现），
> 两个长得一样会分不清。详见 `docs/配置schema.md` §4.2。

**性能：只写比值，不写绝对 MB/s。**

```
ChaCha20 块粒度 8 字节 → 64 字节：加速 7.6~8.3×（理论值精确 8.0×）
  · 旧版每 8 字节重跑一次 20 轮 = 算了 64 字节只用 8 字节，白算 7/8
  · 新版每 64 字节跑一次，用满整块
```

换算整包（5526 位点）：增量从 1.7~4.2 ms 降到 **0.15~0.77 ms**。

> ⚠️ **为什么不写绝对吞吐**：2026-11-09 曾报「63 → 311 MB/s（4.9×）」，
> 那是拿两个不同时刻的数字相除 —— 当时 `load average 21.5`（4 核）、
> CPU 降频到 1.0 GHz，之后用同一份代码重测得到 490~700 MB/s，
> **连自己的结论都复现不了**。正确做法是同进程交替测（两版内联进一个
> 程序、交替跑多轮取平均），比值才可信。测之前先看 `load average`
> 与 `/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq`。
>
> 复现命令：`bash scripts/string-enc/tests/bench-chacha20-blocksize.sh`
> （两版块粒度内联进同一程序交替跑 5 轮，输出比值并做区间判定）。

**真机（云端构建 + 装机）**：splitmix64 版与 ChaCha20 版均 TotalTime ≈300ms、
进程存活、零崩溃、Room 无密文表名报错。

**仍未做**：ChaCha20 真机耗时未单独测量（TotalTime 差异在噪声内，
只能说"没有可测的代价"，不能说"更快"）；SIMD 未做（v7a 的 NEON 是可选扩展，
且 §8.4.1 的 SIMD 栈布局问题未查清）。

#### ③ 其他待办（优先级低）

- `armeabi-v7a` 真机验证（本机只有 arm64）
- 本地 Termux 环境为何产出坏 so（22 字节 SIMD 栈偏移差异，原因未查清）
- `--stringenc-native` 纯桩（不带 `--sigcheck`）为何崩（`.ncx` 缺 `.ncxr`，
  锁箱链不完整）—— 目前靠"必须配 sigcheck"规避

### 千万别做的事

| 别做 | 原因 |
|---|---|
| **本地 Termux 构建后装机验证** | 产物必 SIGILL，连纯 sigcheck 也崩。见 §8.4.1 |
| 删 Java 桩 | `--dex2c-stub` 联动只能走它；且是所有现有用户的默认路径 |
| 给 `nc_strdec.c` 加计算量来"提升强度" | 加轮数不解决可逆性，白慢 |
| 在 `stub_impl` 上再加一个 flag | 那是单选语义，加 flag 只会更乱 |

## 10. 一句话交接

**先看源码，再看文档。** 这个项目的文档写得很细（`流程文档.md` 2300 行、
`变更历史.md` 150+ 条报错），但它们**描述的是当时的代码**。改之前先
`grep` 一下源码，确认文档说的还在不在。

反过来，**踩坑经验一定要写回 `变更历史.md`** —— 这个项目靠它避免了大量重复劳动。
