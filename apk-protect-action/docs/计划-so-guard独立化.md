# 计划：so 加密设施独立化（so-guard 自包含）

> **本文用途**：给监督者（另一个 AI 或人）审查本次改动的计划与验收标准。
> 执行者不得在未获批准前越过 §6 的红线。
>
> 编写日期：2026-10-30
> 基线提交：`d4d1869`
> 基线 tag：`so-guard-independent-baseline`（仅本地）
> 物理备份：`~/so-guard-backup-20261030-142530`（含 `SHA256SUMS`）

---

## 1. 目标与范围

### 1.1 唯一目标

让 `scripts/so-guard/` **零外部源码依赖**，可单独编译成一个可用的 so。

### 1.2 明确不做（本次范围外）

| 不做的事 | 原因 |
|---|---|
| 改成"密钥模式"（无 APK 解锁） | 已与用户确认**放弃**。要求使用方必须提供 APK |
| 支持加密"已编译好的成品 so" | 机制决定不可能：必须有 `.ncx` 段才可加密 |
| 打包成 zip 分发包 | 前置条件是先能独立编译，顺序不可颠倒 |
| 段伪装 / 匿名内存展开 | 独立工程之外的另一个议题 |
| 动 `ncg_head_unlock` 的开锁链路 | 见 §6 红线 |

---

## 2. 当前事实（已实测，供监督者复核）

### 2.1 目录结构

```
scripts/so-guard/            4277 行
  nc_guard_layout.h    196   契约唯一真相源
  nc_guard_boot.c     1662   自解谜引导
  nc_guard_key.c       508   SHA256/HMAC/HKDF/证书DER
  nc_guard_key.h       110
  nc_guard_probe.c      64   .ncx/.nck 唯一定义处
  nc_guard_jni.c        63   selftest 入口
  so-section-lock.py  1336   构建期锁箱
  so_section_mark.py   338   通用段标记器

scripts/sigcheck/src/        只剩签名校验模块自身
  sig_check.c  sig_guard2.c  nc_link.c  env_check.c  sig_hash.h
```

### 2.2 唯一的外部依赖

`nc_guard_boot.c` 的 `#include` 全集（已 grep 验证）：

```
nc_guard_key.h       ← 目录内，OK
nc_guard_layout.h    ← 目录内，OK
sig_log_data.h       ← ★ 唯一外部依赖，由 sigcheck 模块生成
```

### 2.3 该依赖的具体用量（极小）

`nc_guard_boot.c` 只用了 **2 条路径**和 1 个函数：

```
第 546 行   lsg_s(LSGS_PATH_CMDLINE, _cb, sizeof(_cb))   → "/proc/self/cmdline"
第 602 行   lsg_s(LSGS_PATH_MAPS,    _mb, sizeof(_mb))   → "/proc/self/maps"
```

### 2.4 实测证据：不切依赖则编译失败

用一个只有业务函数的 `biz.c` 配设施，只配业务代码，不加任何 sigcheck 模块：

```
$ clang -DNC_GUARD_SECTIONED -I. nc_guard_boot.c nc_guard_probe.c nc_guard_key.c biz.c
nc_guard_boot.c:56:10: fatal error: 'sig_log_data.h' file not found
```

### 2.5 实测证据：补一个最小替身后可编译、可锁箱

已用临时 `sig_log_data.h`（明文字符串版）验证：

```
编译 → 成功（27384 字节）
段表 → .ncks / .nck / .ncxh / .ncx / .ncxhr 五段齐全
一级锁箱 → 成功（.ncx 188 字节已加密）
二级锁箱 → 成功（.ncks 112 字节）
```

**结论：技术路径可行，只差"把临时替身换成正式实现"。**

---

## 3. 方案

### 3.1 采用做法：设施自带密文表（方案①）

新增两个文件：

```
scripts/so-guard/nc_guard_paths.h   — 接口 + 常量声明
scripts/so-guard/nc_guard_paths.c   — 两条路径的密文 + 解密函数
```

### 3.2 为什么不选另外两个做法

| 备选 | 否决理由 |
|---|---|
| 运行时字符拼接（`{'/','p','r'...}`） | `strings` 对单字符数组无效，但编译器可能把连续常量折叠回完整字符串（本项目已踩过同类坑：LLVM 函数间常量传播把密钥折回 `.rodata`）。不可靠 |
| 直接写明文 | **防护退步**。当前这两条路径是密文，改明文等于削弱既有强度 |

### 3.3 密钥流算法（与既有实现保持同族）

复用设施自带的 `ksha256`（`nc_guard_key.c` 内，已被 NIST 向量钉死），不引入新原语：

```
keystream_i = SHA256(key[16] || msg_id_be32 || counter_be64)
cipher      = plain XOR keystream
```

- `key`：16 字节，写死在 `nc_guard_paths.c`（见 §3.4 的强度说明）
- `msg_id`：0 = cmdline，1 = maps（域分离，避免两条消息共用密钥流）
- `counter`：从 0 起，每块 32 字节

**与 `make-sig-log.py` 的算法差异（必须写明，避免误认为不一致）**：
生成器用 32 字节 key + `msg_id` 大端 4 字节 + 计数大端 8 字节。
本方案**沿用同一结构**，仅 key 改为 16 字节。两者是**并存的两套**，不是同一套的副本——
监督者不应要求二者逐字节对拍，它们是不同用途（前者给日志文案，后者给路径）。

### 3.4 强度说明（如实，不夸大）

这是**混淆**，不是**加密**。攻击者若愿意反汇编 `ncg_path_ctr_xor` 并读常量，可以还原这两条路径。

**为什么仍然值得做**：
- 现状（路径在 `.rodata` 明文）连反汇编都不用，`strings` 一行命令即可
- 目标只是"提高发现成本"，与项目既有定位一致（见 `nc_guard_layout.h` 顶部关于 magic seed 的诚实说明）
- **不声称**能挡住愿意逆向的人

监督者请按这个标准判定，不要按"能否被破解"判定。

---

## 4. 改动清单

### 4.1 新增文件

| 文件 | 内容 | 预估行数 |
|---|---|---|
| `so-guard/nc_guard_paths.h` | 枚举 ID + 接口声明 | ~40 |
| `so-guard/nc_guard_paths.c` | 2 条密文常量 + `ncg_path_s()` 解密 | ~110 |

### 4.2 修改文件

| 文件 | 改动 | 风险 |
|---|---|---|
| `so-guard/nc_guard_boot.c` | 删 `#include "sig_log_data.h"`；改 `#include "nc_guard_paths.h"`；两处 `lsg_s(...)` → `ncg_path_s(...)` | 中（改调用点，不动流程） |
| `scripts/pipelines/protect.sh` | 拷贝清单加两个新文件（3 个分支，共 6 行） | 低 |
| `scripts/lib/tests/test-so-lock.sh` | 拷贝段加两个新文件 | 低 |

### 4.3 不改动

- `nc_guard_layout.h`（契约不变 → T20/T21/T22 契约对拍不受影响）
- `ncg_head_unlock` / 解锁流程 / 密钥派生（**零改动**）
- 任何段名、slot 布局、密钥槽格式

---

## 5. 验收标准（监督者按此判定）

### 5.1 必须全部通过，缺一即失败

| # | 验收项 | 判定命令 | 通过条件 |
|---|---|---|---|
| V1 | **产物二进制等价** | `bash scripts/lib/tests/build-baseline.sh /tmp/after.so scripts/so-guard scripts/sigcheck/src` 然后 `cmp -s ~/baseline_before.so /tmp/after.so` | **完全一致**（基线 sha256 `65b2e2c900b5ae423b31f32d0cfd5d17b1831019b19136730fdd1c8b773ea591`） |
| V2 | **全量回归** | `bash scripts/lib/tests/test-so-lock.sh` | **52 通过 0 失败** |
| V3 | **设施可单独编译** | 见 §5.2 的命令 | 编译成功，且无 `sig_log_data.h` |
| V4 | **独立编译后能锁能解** | 同上，锁箱 + `ncguard_unlock()` 返回 0 | 返回 0（不是 -12 / -999） |
| V5 | **零外部 include** | `grep -rn '#include "' scripts/so-guard/*.c scripts/so-guard/*.h` | 只出现 `nc_guard_*.h` |
| V6 | **设施自身路径明文零命中** | `strings -n 6 <产物> \| grep -c "/proc/self/cmdline\|/proc/self/maps"` | 结果为 **0** |

### 5.2 V3/V4 的具体验证方法与预期

```bash
# 造一个「只有业务代码 + 设施」的工程，不拷任何 sigcheck 模块文件
mkdir -p /tmp/indep && cd /tmp/indep
cp $REPO/scripts/so-guard/*.c $REPO/scripts/so-guard/*.h .
printf '#include <stdint.h>\n__attribute__((section(".ncx"),used,retain,visibility("default")))\nint biz_calc(int a){ return (a^0x5A)*3; }\n' > biz.c
clang -fPIC -shared -Oz -fvisibility=hidden -DNC_GUARD_SECTIONED -I. \
      nc_guard_boot.c nc_guard_probe.c nc_guard_key.c nc_guard_paths.c biz.c -o indep.so
```

**预期**：编译成功，`.ncx/.nck/.ncks/.ncxh/.ncxhr` 五段齐全。

**V4 的已知限制（必须提前说明，不要当成失败）**：

`ncguard_unlock()` 在纯 so 环境下会返回 **-12**，因为证书绑定要求有 APK。
这是**设计行为，不是 bug**。V4 若在纯 so 下跑，判据不是"返回 0"，而是：

- 能走到 `-12`（说明 `.ncks` 解密、`.ncxh` 解密、`.ncxhr` 解密、证书读取全部正常执行，只是最后缺 APK）
- **不能**是 `-2/-3`（段找不到）、`-6/-7`（读槽失败）、`-11`（MAC 不符）

真正端到端 `selftest=59` 由 V2 的 T4 覆盖（那里有真实 APK）。

### 5.3 V6 的额外说明与实测基线值

**实测基线（改造前，`baseline_before.so`）**：

```
$ strings -n 6 baseline_before.so | grep -c "/proc/self/"
2

命中的两条是：
  /proc/self/root%s/base.apk     ← 来自 sig_check.c:572（签名校验模块，不属设施）
  /proc/self/task/%s/comm        ← 来自 env_check.c:1170（环境检测模块，不属设施）

设施自己的两条（cmdline / maps）：
$ strings -n 6 baseline_before.so | grep -c "cmdline\|maps"
0    ← 已被 sig_log_data.h 加密，零明文
```

**这带来两个必须注意的点**：

1. **判定口径要精确**：V6 只能查设施自己的两条路径（`cmdline` / `maps`），
   **不能用 `/proc/self/` 通配**——那会命中 sigcheck 模块的两条明文，
   造成改造后仍"红"的假失败。sigcheck 模块自己的两条明文是该模块的既有状态，
   不在本次范围内，不得借此要求一并整改。

2. **V6 在改造前后都应为 0**：改造前由 `sig_log_data.h` 加密，
   改造后由 `nc_guard_paths.c` 加密。这条断言防的是**退步成明文**，
   不是"从有到无"的改进。

### 5.4 ksha256 的段归属（V4 前提，已核实）

`nc_guard_key.c` 中 `grep -c section` 返回 6，但**全部在注释里**（引用
`so-section-lock.py` 等文件名），实际**零 `__attribute__((section))`**。
故 `ksha256` 落在 `.text`（明文段），stub 可安全调用——
这与既有事实一致：`ncg_stub_recover` 已在调 `khmac_sha256`（`nc_guard_boot.c:1321`）。

新增的 `nc_guard_paths.c` 同样**不加段标记**，自然落 `.text`，
因此 `ncg_boot_key` 的 CRC 区间（覆盖整个 `.text`）会包含它——
这是正确的：路径解密代码被改 → CRC 变 → k_stub 变 → head 解不开。

---

## 6. 红线（违反即视为方案失败）

1. **不得修改 `nc_guard_layout.h` 的任何常量**。改了会触发 T20/T21/T22 全部重对拍，且历史产物全部失效。
2. **不得修改 `ncg_head_unlock` 的任何逻辑**。它是全项目最敏感的代码，改错 = 所有包起不来。
3. **不得修改 `so-section-lock.py` 的锁箱算法**（含 slot 布局、密钥派生、RC4/CTR 用法）。
4. **不得改变 `protect.sh` 的步骤顺序**。
5. **不得引入新第三方依赖**（Python 侧只用 stdlib；C 侧只用现有头文件）。
6. **V1 二进制等价不通过 = 立即停止**，不得"先提交再修"。
7. **不得提交/推送**，除非用户明确指令。

---

## 7. 风险与回退

| 风险 | 概率 | 处置 |
|---|---|---|
| V1 二进制不等价 | 中 | 立即 `git reset --hard so-guard-independent-baseline`，然后报告差异位置 |
| 新增文件漏拷（protect.sh 分支） | 中 | V2 会红，按报错补 |
| `ksha256` 在 `.text` 而非 `.text` 之外导致 stub 调用违规 | 低 | 已知 `ksha256` 在 `.text`（已验证），且 stub 已在调 `khmac_sha256` |
| 新文件进错段（应默认 `.text`） | 低 | 新文件不加 `__attribute__((section))`，自然落 `.text` |

**回退命令**：
```bash
git reset --hard so-guard-independent-baseline
# 或从物理备份恢复
cp -a ~/so-guard-backup-20261030-142530/so-guard/. $REPO/scripts/so-guard/
```

### 7.1 环境坑（Termux 专有，监督者会踩）

**`/tmp` 在 Termux 下不可写**（`/data/data/com.termux/files/usr/tmp` 才是 TMPDIR）。

- `build-baseline.sh` 内部用 `mktemp -d` 生成中间目录，它尊重 `TMPDIR`，没问题
- 但**输出路径不能给 `/tmp/xxx.so`**：脚本会"成功"打印 `构建完成: /tmp/after.so ( 字节)`，
  而文件实际不存在，`cmp` 随即失败，看起来像"二进制不等价"——**这是假失败，不是真问题**

正确用法：
```bash
bash scripts/lib/tests/build-baseline.sh ~/after.so scripts/so-guard scripts/sigcheck/src
cmp -s ~/baseline_before.so ~/after.so
```

**已实测**：用 `~/after.so` 这种可写路径时，基线可复现，与 §5.1 声明的 sha256 一致。

---

## 8. 执行顺序（每步可独立验证）

```
Step 1  写 nc_guard_paths.h / .c（含密文常量生成脚本，一次性）
Step 2  改 nc_guard_boot.c 的 include + 两处调用
Step 3  V3：单独编译验证（此时还没改 protect.sh，只验证编译）
Step 4  V5 + V6：依赖与明文检查
Step 5  改 protect.sh + test-so-lock.sh 的拷贝清单
Step 6  V2：全量回归 52 项
Step 7  V1：二进制等价比对
Step 8  报告结果，等用户决定是否提交
```

**Step 3 与 Step 7 是两道关卡**：Step 3 不过就地停，不要继续往下改。

---

## 9. 需要监督者特别关注的三点

1. **不要在 V4 上误判失败**。纯 so 环境返回 -12 是设计行为（§5.2 已说明）。判定看"失败码是哪一类"，不是"是否为 0"。

2. **不要把"路径可被还原"当成失败**。这是混淆不是加密，§3.4 已如实声明强度边界。判定标准是"是否比改造前更弱"，不是"是否绝对安全"。

3. **V1 是本次的核心证据**。源码结构、include、调用点全都变了，**只有二进制能证明加密机制没被改动**。若 V1 不过而其他全过，仍然判定失败。
