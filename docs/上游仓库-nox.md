# 上游仓库 nox（so 段加密设施的唯一源码真相源）

> **本文是 2026-11-05 按 `../nox` 实际内容重写的。** 此前本仓库的 4 份主文档
> （`项目导览.md` / `流程文档.md` / `AI接手文档.md` / `AGENTS.md`）都只把 nox
> 当成"`tools/nox.zip` 的来源"一笔带过，从没写清它是什么、里面有什么、怎么改、
> 怎么发版。结果是：改 so 层的人在本仓库里翻不到 `nc_guard_*.c`，也不知道
> `nox protect` 这个 CLI 存在。
>
> ⚠️ 与源码冲突时以源码为准。本文的每一条都能用 `ls` / `git ls-files` 复核。

> 📌 **2026-11-11 补充：Amice bundle 已改为自己的 fork。**
> 我们用的不是上游 `fuqiuluo/amice` 原版，而是 `zzgs219G/amice` 的
> **`v0.1.6-nox4`**（6 个补丁：保 section / 裁剪 CI / 跳过 JNI_OnLoad /
> `AMICE_VM_ONLY_ANNOTATED` / 豁免 `@llvm.used` / `--annotate-pattern`）。
> **完整记录见 [`so层防御/amice-fork改造记录.md`](./so层防御/amice-fork改造记录.md)** ——
> 包括 7 个真机事故的完整排查过程、防护矩阵、以及已知缺口。
> 改 amice 或换 bundle 版本前必读。
>
> ⚠️ **最容易踩的一条**：代码进 `.ncx`（可执行），数据进 `.ncxr`（可写）。
> 混放会生成 RWX 段，**Android 14+ 直接拒绝加载**（`UnsatisfiedLinkError`）。

---

## 0. 三十秒定位

```
克隆仓库x/
├── artifact-pipeline/    ← 主流水线（消费者）
└── nox/                  ← so 段加密设施（上游，本源码真相源）
```

| 项 | 值 |
|---|---|
| 仓库 | `zzgs219G/nox`（公开） |
| 本地路径 | 与本仓库**同级**：`../nox` |
| 作用 | 把标了 `__attribute__((section(".ncx")))` 的 C 函数加密进独立段，运行时自解密 |
| 依赖方向 | **单向**：`artifact-pipeline` 消费 nox；nox 不认识本仓库 |
| 现有 tag | 共 22 个，`v0.1.0` … **`v0.9.11-obf`**（最新）。没有 `v0.4.2` |

它不加密"已编好的成品 so"——没有 `.ncx` 段就没有可加密的单元；也不接受
无证书场景——密钥由 APK 证书派生，读不到就 fail-closed。

---

## 1. 上游仓库真实结构

`git ls-files` 的完整清单（2026-11-02 状态，24 个文件）：

```
nox/
├── nox                        ★ CLI：protect / build / test 三个子命令
├── test.sh                    ★ 自测：V1–V10，零参数即可跑（用包内 fixture；判据 0 失败）
├── AGENTS.md                  ★ 上游的硬约束（冻结契约、加密纪律、发版纪律）
├── README.md                    一句话介绍
├── VERSION                      当前 v0.9.11-obf（取数：cat tools/nox/VERSION）
├── .github/workflows/release.yml  两关：verify（自测+例子）→ build（打包+校验+冒烟）
├── docs/
│   └── SOURCE.txt               独立化时的来源与 sha256 校验清单
├── scripts/
│   ├── make-zip-lib.sh        ★ 打包【静态库形态】（生产用，要 ANDROID_NDK_HOME）
│   ├── make-zip-src.sh          打包【源码形态】（给要改代码/审查的人）
│   └── so-guard/              ★ 设施本体
│       ├── nc_guard_layout.h  ★★ 加密契约的唯一真相源（零 include / 零逻辑）
│       ├── nc_guard_boot.c      运行期自解谜引导（明文 stub + .ncxh 本体）
│       ├── nc_guard_probe.c     .ncx/.nck 段唯一定义处 + selftest 主体
│       ├── nc_guard_key.c(+.h)  SHA256 / HMAC / HKDF
│       ├── nc_guard_paths.c(+.h) /proc 路径密文表
│       ├── nc_guard_jni.c       JNI 自检入口 NcLink.selftest()
│       ├── so-section-lock.py ★ 构建期锁箱（lock / lock-head / strip-meta）
│       ├── so_section_mark.py   通用段标记器（--rule dex2c-jni）
│       └── gen-paths.py         一次性工具：生成路径密文表
├── fixtures/
│   ├── sample.c                 示例业务代码（标段写法的标准答案）
│   ├── sample.apk               专用测试证书的包，**与任何真实发布包无关**
│   └── make-fixture-apk.py      重新生成 sample.apk
└── example/
    ├── mycode.c                 完整可跑例子
    └── run.sh                   模拟"已安装环境"的端到端脚本
```

> **注意 nox 自己的目录约定**：根目录只留"产品 + 文档"（`nox` / `test.sh` /
> `AGENTS.md` / `README.md` / `VERSION`），开发脚本与其依赖集中到 `scripts/`。
> 但**打包时仍按包内布局摊平**回 `nox/so-guard/`，所以消费方的
> `ensure_nox` 拿到的路径永远是 `<解压根>/nox/so-guard`，与本仓库无关。

---

## 2. nox CLI：`nox` 三个子命令

这是本仓库文档此前**完全没提**的东西。它是"一条命令完成编译→加密→去符号"的封装，
存在的理由：直接手工用设施要记住 4 件事（拷哪些 `.c`、4 个编译参数、两次锁箱的
不同参数、最后 strip），任何一步记错都会得到"看起来成功但跑不起来"的产物。

```bash
./nox protect <你的代码.c> --apk <已签名APK> -o <输出.so>   # 编译+两级锁箱+strip
./nox build   <你的代码.c> -o <输出.so>                     # 只编译不加密（调试）
./nox test    [--apk <APK>]                                # 转发到 test.sh
```

`protect` 的内部四步（`nox` 里的 `do_protect()`）：

| 步 | 动作 | 关键点 |
|---|---|---|
| 1/4 | 编译出 raw.so | 自动探测有哪些加密段，**不能硬写 `.ncx`** |
| 2/4 | 一级锁箱（业务段） | `so-section-lock.py --section .ncx,.ncxr --from-apk` |
| 3/4 | 二级锁箱（unlock 本体） | `--lock-head` |
| 4/4 | strip | 交叉编译时**必须**用 NDK 的 `llvm-strip`，宿主 strip 不认识 ARM 产物 |

两个容易踩的细节（都已写进源码注释）：

- **段探测必须自动**：构建期 MAC 覆盖 `--section` 列出的段，运行期会自动探测
  `.ncxr` 等段并全部纳入；两边不一致 → MAC 不匹配 → 运行期返回 `-11`。
- **ABI 自动推导后必须回写** `args.abi`：否则 strip 段会退回宿主 `/usr/bin/strip`
  → `Unable to recognise the architecture of the input file`。

> ⚠️ **本仓库的流水线不用这个 CLI。** `protect.sh` 是直接调
> `so-section-lock.py` / `so_section_mark.py` 的。`nox` CLI 是给
> "自己写 C 代码、只想要一个加固 so" 的人用的。两者共享同一套 `.py` 与
> `.a`/`.c`，所以改设施时两条路都会受影响。

---

## 3. 上游自测：`test.sh` V1–V10（判据 0 失败，别写死总数）

```bash
cd ../nox && ./test.sh                    # 用 fixtures/sample.apk
cd ../nox && ./test.sh /path/to/真机.apk   # 用真实包
```

实测输出（2026-11-09 本机复跑）：**`=== 结果: 23 通过, 0 失败 ===`**

| 组 | 断言数 | 验的是什么 |
|---|---|---|
| V1 独立编译 | 1 | 零外部依赖能编出 so |
| V2 加密段结构 | 5 | `.ncx`/`.ncxh`/`.ncxhr`/`.nck`/`.ncks` 段齐全（`.ncxr` 无常量数据时跳过） |
| V3 锁箱 | 2 | 一级锁箱成功；`.ncx` 熵值确实变成密文 |
| V4 路径明文 | 1 | `/proc` 等路径明文零命中 |
| V5 篡改检测 | 2 | 二级锁箱成功；改密文中点 → 加密段不可执行（MAC 生效） |
| V6 完整解锁 | 2 | 未篡改 → 解锁成功且**加密段代码真的执行出正确结果** |
| V7 常量表 | 1 | `.ncxr` 与 `.bss` 同页时 mprotect 不踩坏邻居（2026-10-30 真 bug 回归） |
| V8 元数据清理 | 4 | `--strip-meta` 成功 / 三类元数据产物侧零命中 / 段地址不变 / 幂等 |

测试设计上有三条**假绿防线**（`AGENTS.md` §3.2），值得本仓库的人知道：

1. 判据必须是**真调用**，不能用 `dlsym` 拿到符号就算过（符号在 `.dynsym` 里
   与"段是否解密"无关）；
2. 测试壳必须放**独立编译单元**——同一 TU 内 `-Oz` 会把被测函数整个内联成
   明文副本，调壳永远成功；
3. 篡改要改段的**中点**，不能改段首（段首可能属于另一个函数）。

---

## 4. 两种分发形态（决定本仓库拿到的是什么）

| 形态 | 打包脚本（在上游仓库 `../nox/`） | 包内容 | 谁用 |
|---|---|---|---|
| **静态库** | `../nox/scripts/make-zip-lib.sh` | `*.h` + `*.py` + `lib/<abi>/libnox.a`，**无 `.c`** | 生产：本仓库的 `tools/nox.zip` |
| 源码 | `../nox/scripts/make-zip-src.sh` | `*.c` + `*.h` + `*.py` | 回归测试 / 要改代码的人 |

两者包内顶层目录都是 `nox/`（**不带版本号**，版本只出现在 zip 文件名上），
所以消费方可以硬编码 `<解压根>/nox/so-guard`，换版零改动。

### 4.1 静态库的真实内容（别再照抄旧注释）

```
$ ar t tools/nox/so-guard/lib/arm64-v8a/libnox.a
nc_guard_boot.o
nc_guard_jni.o      ← ⚠️ 在！
nc_guard_key.o
nc_guard_paths.o
nc_guard_probe.o
```

> ⚠️ **已知过期注释**：`scripts/pipelines/protect.sh` 的静态库分支里写着
> 「`.a` 只含 boot/probe/key/paths 四个固定源文件」—— **与实际情况不符**，
> 实测 `.a` 里五个成员，`nc_guard_jni.o` 在。上游 `make-zip-lib.sh` 的
> `LIB_SRCS` 也确实是五个。这段注释是早期版本留下的，`protect.sh` 的行为
> （只拷 `.h`、不拷 `.c`）本身没错，但读注释会误判 `selftest` 符号的来源。
> 以 `ar t` 结果为准。

### 4.2 静态库形态的两条硬约束

**① 链接必须加 `-Wl,--whole-archive`**

`ncg_boot_init` 是 `__attribute__((constructor(50)))`，无任何代码显式引用 →
静态库默认按需拉取 → 整个 `nc_guard_boot.o` 被丢弃 → `.ncxh`/`.ncxhr`/`.nck`/`.ncks`
四段连段一起消失。实测：不加时**加密段 5 个塌成 1 个，连 unlock 都找不到**。
`--no-whole-archive` 必须紧跟收尾，否则 libc/liblog 也会被全量拉入。

本仓库的实现位置：`scripts/lib/lib-ndk.sh` 的 `ndk_write_mk()`，条件触发
（`protect.sh` 传了 `guard_lib_dir` 才写这段）。

**② `.a` 与 NDK/编译器版本绑定**

`make-zip-lib.sh` 按 `APP_ABI` 编双 ABI（`arm64-v8a` + `armeabi-v7a`），
用 clang-XX 编的 `.o` 不能和 clang-YY 混链。

---

## 5. 本仓库与 nox 的两个接触面

### 5.1 生产链路（只认 zip）

```
protect.sh 入口
  └─ ensure_nox()            scripts/lib/common.sh
       解压 tools/nox.zip → tools/nox/so-guard
       ├─ 有 .c（nox_guard_has_src 为真）→ 拷 .c + .h 进 NDK 工程一起编
       └─ 无 .c（现行）        → 只拷 .h；lib/ 交给 ndk_write_mk 链接 .a
```

`ensure_nox` 的幂等判据是 `tools/nox/so-guard/nc_guard_layout.h` 存在
—— **两种形态都必有这个文件**，所以切换形态不会误用旧解压产物。
版本号从包内 `nox/VERSION` 读出并打进构建日志（0.4.1 起提供）。

### 5.2 回归测试（只认源码）

```
ensure_nox_src()            scripts/lib/common.sh
  └─ 唯一来源：$ROOT/../nox/scripts/so-guard
     找不到就 exit 1，并打印 clone 命令
```

为什么测试不能用 `.a`：`test-so-lock.sh` 的 T20 要 `grep` `nc_guard_boot.c`
里的 `NC_SEED_*_INIT` 做跨语言对拍，T22/T23/T27/T28/T32 要真编译那 5 个 `.c`。
机器码没有文本常量可 grep，也无法重编。

**2026-11 已删除 `tools/nox-src.zip` 兜底**（包在 `b655f0a` 删的）。
代价如实：**只克隆本仓库的人跑不了 `test-so-lock.sh`，必须先 clone nox。**

---

## 6. 加密契约：`nc_guard_layout.h`

消费方也 include 它（`nc_link.c` / `env_check.c` / `sig_check.c` 三处），
所以改它**必然波及本仓库**。当前值（与 `../nox/scripts/so-guard/nc_guard_layout.h` 逐字核对）：

| 常量 | 值 | 说明 |
|---|---|---|
| `NC_SEC_CODE` | `.ncx` | 加密代码段（AXR 可执行） |
| `NC_SEC_CONST` | `.ncxr` | 加密常量表段（AWR 不可执行） |
| `NC_SEC_HEAD` | `.ncxh` | unlock 本体（二级锁箱对象） |
| `NC_SEC_HEADRO` | `.ncxhr` | master 数据段（AWR 32B） |
| `NC_SEC_SLOT` | `.nck` | 一级密钥槽 |
| `NC_SEC_STUBSLOT` | `.ncks` | 二级 stub 密钥槽 |
| `NC_SLOT_SIZE` | **96** | `.nck` 字节数 |
| `NC_STUB_SIZE` | **112** | `.ncks` 字节数（含 `[104:112)` 碎片区） |
| 偏移 | 8 个 | `NC_OFF_EXPMAC` 48 / `NC_OFF_PKG_SHA` 80 / `NC_OFF_FRAGS` 104 / `NC_OFF_CODE_ADDR` 36 / `NC_OFF_CODE_LEN` 40 / `NC_OFF_K_MAC_HEAD` 48 / `NC_OFF_EXPMAC_HEAD` 64 / `NC_OFF_HEADRO_ADDR` 96 / `NC_OFF_HEADRO_SIZE` 100 |
| magic seed | 2 个 | `NC_SEED_SLOT_INIT` / `NC_SEED_STUB_INIT` |
| XOR 碎片表 | 1 张 | `NC_XOR_FRAG_INIT {1,0,2,3,0,1,3,2}` |

六条 `_Static_assert` 挡"偏移重叠/越界"——那是上一轮 88→104 扩容时最危险的
错误模式（新字段与既有 MAC 字段重叠会**静默**破坏校验，编译期完全不报）。

> ⚠️ **本仓库 `AGENTS.md` §1.2 曾把 slot 尺寸写成「96/104」，是旧值。**
> `.ncks` 现在是 **112**（`[104:112)` 是 XOR_KEY 的 4×uint16 碎片区）。
> 已按本文修正。

消费方（改契约前先看这张表会波及谁）：

```
C  : nc_guard_boot.c / nc_guard_probe.c / nc_guard_key.c / nc_guard_paths.c（均在上游）
     本仓库的 nc_link.c / env_check.c / sig_check.c 也 include 它
Py : so-section-lock.py（上游；_load_layout_contract() 抽取，抽不到即抛错）
Sh : make-sig-hash.sh（本仓库；sed 抽 NC_SEC_CONST，抽不到即 exit 1）
构建: protect.sh 三个分支都拷它；test-so-lock.sh / test-javacheck.sh /
     test-lsgs-strings.sh 的编译也都需要它
```

---

## 7. 改 nox 的完整流程（本仓库的人需要照做）

### 7.1 只改本仓库 → 不用碰 nox

绝大多数改动属于这类（`protect.sh`、`string-enc/`、`guard/src/*.c`、
workflow）。**设施的 `.c`/`.py` 与本仓库无关。**

### 7.2 真要改设施 → 去 nox 仓库改，然后换 zip

```bash
# ① 改 + 自测（判据 0 失败）
cd ../nox
./test.sh

# ② 打静态库形态的包（生产用；需要 NDK）
export ANDROID_NDK_HOME=/path/to/android-ndk-r27d
bash scripts/make-zip-lib.sh 2026.11.05-final

# ③ 换到本仓库（注意：必须先删解压产物）
cp dist/nox-2026.11.05-final.zip ../artifact-pipeline/tools/nox.zip
rm -rf ../artifact-pipeline/tools/nox        # ← 不删会静默用旧版
cd ../artifact-pipeline
python3 scripts/actions/tests/test-docs-paths.py
bash scripts/lib/tests/test-so-lock.sh       # 需 ../nox 源码形态
```

**纪律**：本仓库**不得**保存设施的 vendored 源码副本 —— 双源头必然漂移
（历史上布局常量曾在 4 种语言 7 个文件 24 处副本之间互相矛盾）。

### 7.3 包内容的正反向断言（CI 已自动化，人工核对时照这个查）

上游 `release.yml` 的 build job 会校验：

```
✔ 必需文件齐全：nox / test.sh / README.md / AGENTS.md / QUICKSTART.md /
   so-guard/{nc_guard_layout.h, nc_guard_key.h, nc_guard_paths.h,
            so-section-lock.py, so_section_mark.py} /
   so-guard/lib/{arm64-v8a,armeabi-v7a}/libnox.a /
   fixtures/{sample.c, sample.apk} / example/run.sh
✔ 未含 C 源码（静态库形态正确）
✔ 双 ABI 静态库架构正确（arm64-v8a→AArch64，armeabi-v7a→ARM）
```

本仓库 `.github/actions/setup-toolchain/action.yml` 也做了同样的三项断言
（契约头文件存在 / 双 ABI `.a` 存在 / 反向断言无 `.c`）——**两侧都查，互为兜底**。

---

## 8. 版本现状与已知不一致（如实记录）

⚠️ **本表只写取数命令，不抄具体值。** 这张表本身就是为"记录漂移"而存在的，
结果 2026-11-09 复核时发现表里的「实际值」已经过期了两轮（写成
`2026.11.02-final` / sha `432c3459…`，实际是 `v0.9.11-obf` / sha `adf7e739…`）——
**记录漂移的表自己漂移了**。凡可枚举事实，一律给命令。

| 项 | 取数命令 | 文档里曾写的（仅存档） |
|---|---|---|
| 包内 `nox/VERSION` | `cat tools/nox/VERSION` 或 `unzip -p tools/nox.zip nox/VERSION`（两者必须一致） | `v0.4.2`、`2026.11.02-final` |
| `tools/nox.zip` sha256 | `sha256sum tools/nox.zip` | `4ca8126c…`、`432c34593aae9c51…` |
| 最新 git tag | `cd ../nox && git tag --list --sort=-v:refname \| head -1`（当前共 22 个） | `v0.4.0` |
| CI 用的 nox ref | `grep -n 'nox-ref' .github/workflows/protect-modules.yml`（默认 `main`） | `v0.4.2`（`AGENTS.md` §3） |

**为什么 CI 不锁 tag**：`v0.4.2` 这个 tag **在 nox 仓库里根本不存在**
（当时最新是 `v0.4.0`，而 `v0.4.0` 早于修复 `nc_guard_jni` 缺失的那个提交
`1f1a732`，锁它等于测旧代码）。当初凭 `VERSION` 文件里的 "v0.4.2" 想当然
写成 `ref: v0.4.2`，导致 checkout 直接失败。现在 `setup-toolchain` 的
`nox-ref` 默认 `main`，注释里留了这条教训：**写 ref 前必须 `git tag -l` 核实**。

### 上游 `AGENTS.md` 自身待修正的两处（**不在本仓库职责内，仅提示**）

上游 `../nox/AGENTS.md` 内部有自相矛盾的说法，去 nox 改代码时别被带偏：

| 位置 | 说 | 冲突对象 |
|---|---|---|
| §1.1 / §3.2 / §5.1 | 「`./test.sh` 全绿（**14 项**）」 | §4「必须 **18** 通过 0 失败（2026-11-02 起；此前是 14 项）」 |
| §3.1 | 「分发形态是**源码**，没有预编译产物」 | §5.1「`make-zip-lib.sh` … **当前发版默认**」 |

**以 `./test.sh` 实跑结果为准（项数随环境变：`.ncxr` 缺失/`.a` 形态都会 skip）**；以 `tools/nox.zip` 实跑结果为准：
当前生产包是**静态库形态**（`ar t` 能列出 5 个 `.o`，包内无 `.c`）。

---

## 9. 一句话交接

> **改 so 层的东西 = 去 `../nox` 改，本仓库里没有 `nc_guard_*.c`。**
> 改完跑 `../nox/test.sh`（判据 0 失败）→ 打 `make-zip-lib.sh` → 换
> `tools/nox.zip` + **删 `tools/nox/`** → 回来跑 `test-so-lock.sh`（52 项）。
