# scripts/guard — 签名校验 + 环境检测（C/NDK 层）

本模块产出的 `.c` 会**编进 `libnc.so`**，与 nox 的锁箱设施共用一个 so。
`string-enc` 的纯 C 桩（`--stringenc-native`）也落在这里编。

> ⚠️ **本模块的 `.c` 是冻结资产**（`AGENTS.md` §1）。改动必须在当次对话里
> 用户明确点名，且跑完全部回归。`sig_check.c` / `env_check.c` / `nc_link.c` /
> `sig_guard2.c` 尤其如此 —— 它们被真机验证过几十轮。

## 目录

```
guard/
├── src/                  ★ 本体（编进 libnc.so）
│   ├── sig_check.c         签名校验主流程 + 中文日志
│   ├── sig_guard2.c        APK Sig Block 解析 / 证书提取
│   ├── sig_hash.h          证书指纹（make-sig-hash.sh 生成）
│   ├── nc_link.c           Java ↔ so 的 JNI 边界（ncVerify/heartbeat/selftest）
│   ├── nc_link_jni.c       JNI 注册
│   ├── nc_link_jni.h
│   ├── env_check.c         环境检测主体（13 探针 + 常驻复查）
│   ├── env_probes.c        探针实现（特征串在这里，LSGS 密文化）
│   ├── env_internal.h      探针声明
│   └── nc_demangle_stub.c  __cxa_demangle 的最小替代
├── hash/                 make-sig-hash.sh（提证书指纹 → sig_hash.h）
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
