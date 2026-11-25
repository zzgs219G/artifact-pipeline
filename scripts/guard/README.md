# scripts/guard — 签名校验 + 环境检测（C/NDK 层）

本模块产出的 `.c` 会**编进 `libnc.so`**，与 nox 的锁箱设施共用一个 so。
`string-enc` 的纯 C 桩（`--stringenc-native`）也落在这里编。

> ⚠️ **本模块的 `.c` 是冻结资产**（`AGENTS.md` §1）。改动必须在当次对话里
> 用户明确点名，且跑完全部回归。`sig_check.c` / `env_check.c` / `nc_link.c` /
> `sig_guard2.c` 尤其如此 —— 它们被真机验证过几十轮。

## 签名校验：多路取证书 + 交叉比对（2026-11-24）

### 为什么需要它

签名校验的**唯一**信息来源是 APK 里的 Signing Block。攻击者不需要改校验
逻辑，只要让"这次读取"返回另一份 APK 就行——「去签名校验」类工具正是用
inline hook 把 `open(base.apk)` 重定向到诱饵包（内含官方证书）。

真机日志铁证（修复前）：打印的路径是 `base.apk`，但 `fsize=5066408`
对应的是诱饵 `origin.apk`（真实 base.apk 是 10MB）。**校验逻辑没坏，
是它读到的数据被换了。**

### 机制

`sig_collect_fp()` 现在用 6 条**互不依赖**的路径各拿一次证书，交叉比对：

| # | 路线 | 调用方式 | 抗 hook 原理 |
|---|---|---|---|
| 0 | `open` | `open()` | ❌ 最易被 hook（**保留作诱饵探针**） |
| 1 | `openat` | `openat(AT_FDCWD,...)` | 独立符号 |
| 2 | `openat64` | `openat64(...)` | 又一个独立符号 |
| 3 | `syscall` | `sig_raw_syscall(__NR_openat)` | 内联 svc，不经 libc |
| 4 | `svc` | 内联 `svc #0`（本函数体内） | 连 `syscall()` 都不经 |
| 5 | `sysfd` | `/proc/self/fd/N` + `readlinkat` 直投 | **复用 ART 已开的 fd，不发起 open** |

判定：**成功 ≥2 路且指纹不一致 → fail-closed**（`return -2`）。
单路失败（seccomp / 平台不支持）只记日志跳过，不冤杀正常包。

**第二独立线（`sig_guard2.c`）同日已对齐多路化**（2026-11-24）：
`g2_collect_fp()` 同样 6 路交叉采集，但全部函数在第二线文件内**独立实现**
（`g2_raw_syscall` / `g2_open_route` / `g2_find_apk_fd`），与第一线零代码
共享——形态相似是平台约束（armv7 r7 / readlinkat 直投），不是复制。
不一致 → 走第二线自己的处置 `g2_fail()`。测试：`test-sig-guard2.sh`
第 4 项（宿主多路不误伤 + 指纹与 extract-cert-fp.py 对拍）。

### 日志（排障用）

每路一次简报 + 末尾一张对齐表，少数派标 `<== 不一致`：

```
【数据】多路证书采集表头
| open      size=5077060    fp=d82e48dae7ce6268  <== 不一致
| openat    size=10189766   fp=93622a733f598bf6
| openat64  size=10189766   fp=93622a733f598bf6
| syscall   size=10189766   fp=93622a733f598bf6
| svc       size=10189766   fp=93622a733f598bf6
| sysfd     size=10189766   fp=93622a733f598bf6
ok=6/6 mismatch=1
【失败】多路证书指纹不一致(疑似 APK 读取被劫持)
```

日志写到 `/storage/emulated/0/Android/data/<包名>/files/sigcheck_log.txt`
（哨兵 `touch /storage/emulated/0/xixin_debug` 开启）。

⚠️ **首次启动时目录可能还不存在**：`files/` 由第一次文件写入隐式创建，而
本 so 的 constructor 跑在那之前。`nc_log` 的处理是「存在就写，不存在就起
后台线程 2 秒后再写一次」；期间该条日志打到 logcat 并标 `[no-file]`。
实测通常 2 秒内就绪（干净安装 → 只启动一次 → 2 秒内出文件）。

⚠️ **`nc_log` 的任何函数都不许 sleep** —— 它由 constructor 里的 `sig_verify`
调用，而 constructor 跑在 App 主线程上；在那里 sleep 会把启动卡住
（2026-11-25 真机事故：App 点了图标进不去）。"等 2 秒"只在后台线程里。

⚠️ **"哪一路是诱饵"按多数派判定**，不能按"第一个成功的"
（被劫持的往往正是最先成功的 `open()`；以它为基准会把 5 路真货全标错，
实测踩过）。

### 能力边界（如实）

| 攻击手段 | 能否绕过 |
|---|---|
| 改 dex / 资源后重签 | ❌ 拦得住（证书指纹不符） |
| Hook `open`/`openat`/`fopen` 等 libc 文件函数 | ❌ 拦得住（其余路线不受影响） |
| Hook **所有** libc 文件函数 | ❌ 仍拦得住（`syscall`/`svc`/`sysfd` 三条不经过它们） |
| **改 `.ncx` 段里的内联 svc 指令** | ✅ 能绕过（但需逆向加密段，不再是"通用"手段） |
| 拥有官方私钥签出合法包 | ✅ 能绕过（密码学意义的攻破，非本层能防） |

---

## 目录

```
guard/
├── src/                  ★ 本体（编进 libnc.so）
│   ├── sig_check.c         签名校验主流程 + 中文日志
│   ├── sig_guard2.c        APK Sig Block 解析 / 证书提取
│   ├── sig_hash.h          证书指纹（make-sig-hash.sh 生成）
│   ├── nc_link.c           Java ↔ so 的 JNI 边界（ncVerify/heartbeat/selftest）
│   ├── nc_link_jni.c       JNI 注册（表驱动：槽位数由条目数派生）
│   ├── nc_link_jni.h
│   ├── nc_jni_selfcheck.c  注册前表项自检（拒重名/空表/NULL）
│   ├── nc_jni_selfcheck.h
│   ├── env_check.c         环境检测主体（13 探针 + 常驻复查）
│   ├── env_probes.c        探针实现（特征串在这里，LSGS 密文化）
│   ├── env_internal.h      探针声明
│   ├── nc_log.c            文件日志【唯一实现】（sig_check/env_check 共用）
│   ├── nc_log.h            日志契约：nc_log_open / nc_log_line / nc_log_ready
│   └── nc_demangle_stub.c  __cxa_demangle 的最小替代
├── hash/                 make-sig-hash.sh（提证书指纹 → sig_hash.h）
│                         extract-derive.py（从生成侧抽取派生公式，供测试用）
├── javalink/             Java 层判决式校验注入（inject-javacheck.py + 测试）
├── log/                  make-sig-log.py（LSGS 中文日志文案密文化）
├── docs/                 ★ 模块文档（不在 docs/ 下）
│   ├── 环境校验说明.md      13 个探针分别查什么、为什么这么设计
│   └── 反Frida方案调研.md   4 个参考项目对比 + 最值得补的三项
├── tests/                回归测试
└── archive/              历史存档（nc_guard_unlock.c 等，不进 NDK 工程）
```

## 谁调用它

```
scripts/pipelines/protect.sh
  ├─ STEP1  取证书指纹 ─► hash/make-sig-hash.sh
  ├─ STEP3  组装 NDK 工程 ─► 拷 src/*.c + log/make-sig-log.py 生成 sig_log_data.h
  ├─ STEP3  注入 Java 层 ─► javalink/inject-javacheck.py
  └─ STEP4  编译 ─► libnc.so（与 nox 的 libnox.a 一起链接）
```

只勾 `--envcheck` 不勾 `--sigcheck` 时，`sig_check.c` 仍要编（日志文案表依赖它），
但注入步骤跳过 —— 见 `protect.sh` 的 `WANT_ENVCHECK` 分支。

## 契约依赖

本模块 include 上游 nox 的 `nc_guard_layout.h`（段名/尺寸/偏移的唯一真相源）。
该头文件在 `tools/nox.zip` 里，`protect.sh` 从 `$GUARD_SRC` 拷过来。

**改契约先看** [`docs/上游仓库-nox.md`](../../docs/上游仓库-nox.md) §6 的常量表
—— 那里列了全部消费方，改一处会波及三处编译。

## 文档

| 你要做什么 | 读哪份 |
|---|---|
| 改环境检测（加探针 / 调频率） | [`scripts/guard/docs/环境校验说明.md`](docs/环境校验说明.md) |
| 想加强反 Frida / 反 Hook | [`scripts/guard/docs/反Frida方案调研.md`](docs/反Frida方案调研.md) |
| 改签名校验逻辑 | 本文 + 源码注释（`sig_check.c` 头注很详细） |
| 为什么某处这么写 | `grep -rn '关键词' ../../docs/变更历史/` |

## LSGS：中文日志为什么不能直接写字符串

`sig_check.c` / `env_check.c` 里的中文日志用 `LSGS("...")` 标记，
由 `log/make-sig-log.py` 在构建期扫出来做 XOR 密文化，生成 `sig_log_data.h`。

**为什么**：日志文案会说明"正在检查什么"，直接留在 `.rodata` 等于把
校验流程的伪代码印在产物里。密文化后 `strings` 扫不到语义。

⚠️ **加新探针时的坑**：标记分散在 `env_check.c` 与 `env_probes.c` 两个文件，
生成器必须两个都扫 —— 漏扫会让 `sig_log_data.h` 缺枚举，编译期直接
`undeclared identifier`（fail-fast，比运行期静默好）。
