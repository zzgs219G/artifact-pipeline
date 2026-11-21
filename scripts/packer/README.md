# scripts/packer — 基础加壳（dpt-shell）

`protect.sh` 的**最后一个执行模块**。契约：`<输入.apk> <输出.apk>`。

> ⛔ **必须最后执行。** 它改写 dex / so / Manifest —— 加壳后再动 smali 或再回编一次，
> 壳与保护层就对不上（见 `docs/流程文档.md` §3.10）。

## 文件

```
packer/
├── packer.sh                       唯一入口（吃对齐好的包，dpt -x 加壳）
└── tests/
    ├── test-packer.sh              产物提取链路 + schema→arg 端到端契约
    └── test-protect-packer-wiring.sh  与 protect.sh 的接线断言
```

## 依赖

真源是 `tools/dpt-shell.zip`（解压到 `tools/executable/`，`.gitignore` 忽略）。
上游仓库：`../dpt-shell/`（自研二改，**不是**上游原版）。

`dpt.jar` 必须在**自身目录**下运行 —— `shell-files/`、`build-key`、
`keyladder-seed.txt` 都要与 jar 同级。所以 `packer.sh` 全程走
`module_cd_run` 子 shell，主进程 cwd 不漂移。

## 与其他模块的关系

| 关系 | 说明 |
|---|---|
| 执行顺序 | **最后**。`protect.sh` 固定 `sigcheck → dex2c → stringenc → anti-diff → envcheck → packer` |
| 对齐 | `protect.sh` 负责 zipalign，`packer.sh` 只吃已对齐的包 |
| 签名 | 产物**不签名**（`-x`），沿用"未签名包、开发者自行重签"契约 |
| 产物 | **直接作为最终输出**。加壳已重写 dex/so/Manifest，二次 zipalign 属二次改写 → `protect.sh` 跳过 `finish_apk` |

## 参数进 dpt 的三个来源（别混）

`packer.sh` 把三类来源合并成一次 dpt 调用，**优先级无关、重复无害**
（dpt 的 `hasOption` 幂等）：

| 源 | 从哪来 | 例子 |
|---|---|---|
| ① 专线 | `protect.sh` 的 `PACKER_SMALLER` 环境变量（schema `packer.smaller`） | `--smaller` |
| ② schema 带值 | `protect.sh` 的 `EXCLUDE_ABI`（schema `packer.exclude_x86`） | `--exclude-abi x86,x86_64` |
| ③ 通用通道 | `protect.sh --dpt-extra-args` 自由文本 → `DPT_EXTRA_ARGS` 环境变量 | 任意 dpt 参数 |

> ⚠️ **`--exclude-abi` 走的是源②，不是源③。** 它是 schema 里的结构化子选项，
> 由 `resolve-config.py` 解析成 `EXCLUDE_ABI` 环境变量。`dpt_extra_args`
> 是给"schema 还没表达的新参数"留的逃生口 —— 新增参数应优先加进 schema，
> 只有临时/实验性参数才用通用通道。

## 改之前

1. 先看 `packer.sh` 头注 —— dpt CLI 契约是从源码 + `--help` 实测钉死的，别凭猜改。
   换版要逐项复核 `-f/-o/-x/-r`、产物命名、解压布局。
2. 换版同步 `tools/工具包版本.md` 并删 `tools/executable/`
   （`ensure_dpt` 的幂等判据是"某文件存在则跳过解压"，旧产物在会**静默用旧版**）。
3. 改完跑 `tests/test-packer.sh`（26 项）与 `tests/test-protect-packer-wiring.sh`。

历史坑见 `grep -rn 'dpt' docs/变更历史/02-so加固与加壳.md`。
