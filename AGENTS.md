# AGENTS.md — AI 改动本仓库前的必读契约

Agent 编程任务执行规范（架构师增强版）

---

本指南适用于Agent编程任务：

1. 角色定位：你不仅是编码员，更是该任务的技术负责人。你的核心职责是交付正确且可靠的方案，而非仅仅交付代码。若需求本身存在问题（业务逻辑矛盾、技术不可行、隐患未处理），你有权质疑并拒绝执行，但需给出明确理由和替代建议。
2. 工具调用原则：
   · 优先并行调用（同一轮同时发起多个工具），其次批量合并（多个bash命令用 && 或分号连接）。
   · 禁止无依赖关系的串行多轮；仅当后续工具输入依赖前面输出，才允许拆分为多轮。
   · 单轮工具调用数量上限为20个，超出时拆分为多轮。
3. 资源消耗通用约束（无论后端计费模式，必须遵守，不得降低推理思考质量）：
   · 禁止无差别读取全部完整源码；未变更文件只读取结构摘要（函数名、接口），仅改动目标文件读取完整内容。
   · 工具返回自动裁剪冗余噪声：过滤无关日志、stderr垃圾输出、无关元信息，仅保留决策必需内容。
   · 输出优先使用diff/片段补丁，禁止输出完整大文件，除非用户明确要求完整文件。
   · 上下文膨胀时，允许压缩执行过程描述（如"已读A文件"），但绝对禁止压缩三类核心信息：用户原始需求原文、所有显式约束条件、已确认的技术结论。这三类必须原样保留。
   · 严禁截断、删减模型内部思考推理链，不得为节约资源降低解决问题能力。
4. 核心工作法（拿到需求后的强制思维路径）：
   · 第一步——挑战需求：先推演该需求的真实业务场景。如果需求本身缺乏合理性（如"将所有日志改成Debug级别"），必须质疑并追问原因，拒绝盲目执行。
   · 第二步——多路径对比：至少构想两种实现方案，对比其复杂度、维护成本、风险差异，选定最优方案并说明理由。禁止只给一种方案就开写。
   · 第三步——逆向审查：分析你的方案在以下4个压力场景下的表现——① 变更后能否快速回滚？② 新增外部依赖如果超时/下线，系统如何降级？③ 多步写入操作中途失败，是否会留下脏数据？④ API或数据库Schema变更，老版本客户端能否无感兼容？
   · 第四步——交付代码：代码只是上述思考过程的落地产物。确认前3步无阻塞问题后，再输出diff/补丁。

---

无需构建编译

> 给 AI(以及人类)的硬约束。**改任何代码前先读完本文。**
> 违反下列任何一条,改动视为无效,必须回滚。
> 配套强制手段:冻结模块的回归测试(若 `tests/` 目录存在则执行,冻结模块被改红即失败)。

---

## 1. 冻结模块清单(⛔ 禁止修改,除非用户在当次对话中明确点名)

以下模块经过真机/宿主端反复验证,是**已收敛的稳定资产**。
AI 不得"顺手优化"、"重构"、"重命名"、"整理格式"。它们的正确性靠
回归测试钉死(若 `tests/` 目录存在)——**测试红了 = 你改坏了,立即回滚**。

> ⚠️ **2026-11 更正**：so 段加密设施的 C 源码已整体迁到上游仓库
> `zzgs219G/nox`（2026-10-30 独立化），本仓库**不再保存副本**。
> 本表此前列的一批本仓库内路径（原来在 `scripts/so-guard/`、`scripts/lib/`
> 与 `scripts/guard/src/` 下的 nc_guard_* 与 so-section 脚本）
> 均已不存在。跨仓库边界见 §1.1，冻结契约随源码一起搬到 nox 的 `AGENTS.md`。
>
> 📖 **上游仓库 nox 的完整说明（结构 / CLI / 23 项自测 / 两种分发形态 /
> 加密契约 / 改法与发版流程）见 `docs/上游仓库-nox.md`**。

### 1.0 本仓库内的冻结清单

| 冻结模块 | 职责 | 钉死的回归测试 |
|---|---|---|
| `scripts/guard/src/sig_check.c` | 签名校验 native 实现(maps 定位截断、Signing Block 解析、SHA-256) | `scripts/guard/tests/test-sig-verify.sh`(完整校验链路,真实 APK) + `scripts/guard/javalink/tests/test-javacheck.sh`(9 阶段/11 断言,host 编译+对拍) + `scripts/guard/tests/test-lsgs-strings.sh`(密文零泄漏)。**2026-11-17**: 段标记拆成两个宏 —— `SIG_SEC_MARKED`（段 + `annotate("+vm_virtualize")`，只给**判定点** `derive_expected`/`sig_compare_fp`）+ `SIG_SEC_MARKED_NOVMP`（只有段，给解析函数，让它们吃混淆）。理由：链式依赖里改解析函数只会失败不会绕过；而"标了 VMP 但被跳过"的函数连混淆也吃不到（`TMP_VMP_ONLY` 分流语义），主动去掉 VMP 反而更强 |
| `scripts/guard/src/env_check.c` | 环境检测(10 探针/反调试抢占/so 自校验/心跳检查端) | `test-lsgs-strings.sh`(特征串密文化) + `test-mem-readable.sh`(跨映射判定) + `test-javacheck.sh`(心跳语义)。**2026-10-19**:`env_delayed_kill` 进加密段(段名已中性化,见 §1.2);`safe_syscall` 改内联 `svc`(arm64 `x8`/armv7 `r7`)、新增 `env_raw_die`——**`syscall()` 本身也是 PLT 表项**,验收必查 `nm -D -u \| grep -wE "abort\|syscall\|_exit\|raise"` 为空。**kill 函数标段、调用方(`env_fail`)不标段**(后者是 unlock 使用者,标了即死锁) |
| `scripts/guard/src/nc_link.c` | Java↔Native 判决核心 `nc_verify_t1` + 心跳记录侧 + `ncVerify`/`heartbeat` 两个 JNI 入口 | `test-javacheck.sh`(判决对拍/心跳语义)。**2026-10-19**:`nc_verify_t1` 进 `.ncx` 段,两张签名表进 `.ncxr`——**`ncVerify`/`heartbeat` 两个 JNI 入口绝不能标段**(它们是 unlock 调用方,标了即死锁);段标记必须条件化 `NC_GUARD_SECTIONED && !NCLINK_HOST_TEST`(否则宿主测试读到密文假红) |
| `scripts/guard/src/sig_guard2.c` | 签名校验**第二独立线**:独立派生(`sig_guard2.h`)/独立处置路径(`syscall(tgkill)` + watchdog),与 `sig_check.c` 零代码共享 | `scripts/guard/tests/test-sig-guard2.sh`(`g2_derive()` 与 `make-sig-hash.sh` 的 python 生成侧逐字节对拍)。**2026-11-17~18**: ① `G2_SEC_MARKED` 拆成两个宏（判定点 `g2_derive`/`g2_verify` 带 `+vm_virtualize`，支撑函数走 `G2_SEC_MARKED_NOVMP`）；② `g2_verify` 里 `open()` 改成 `g2_open_ro()` 隔离层（bionic 的 `__open_2` 被 amice 误判为 intrinsic → VMP 跳过）；③ 抽出 `g2_collect_fp()` 降寄存器压力（13+6 → 通过）。**⚠️ `g2_entry` 是 constructor，绝不能标段**（unlock 调用方）|
| `scripts/guard/hash/extract-cert-fp.py` | 证书指纹提取(纯 stdlib 解析 APK Signing Block,v3 优先退 v2) | 无独立测试;由 `test-sig-verify.sh` + `test-so-lock.sh` 间接覆盖(**已知缺口,见本节末尾「冻结资产的能力边界」**) |
| `scripts/inject/inject-loadlib.py` | loadLibrary 插桩(幂等、多 dex、AXMPrinter 解析二进制 Manifest) | `scripts/inject/tests/test_inject_loadlib.py`（**73 断言**，纯 stdlib；覆盖 SMALI_DIR_RE 多 dex/双重转义、寄存器策略、双保险互不连累、幂等、Manifest LAUNCHER 解析、CLI 参数） ✅CI。`SMALI_DIR_RE` 与 `inject-javacheck.py` / `encrypt-strings.py` 同源,改一处必须 grep 另外两处(报错七)——测试里已断言两份副本一致。**2026-11-05 实测更正：此前文档写 69，实跑 73** |
| `scripts/repack/mark-native.py` | native 壳替换 + loadLibrary 插桩 | `scripts/repack/tests/test_mark_native.py`（42 断言，纯 stdlib；覆盖 full_name 解析与 `->` 误写纠正、方法名非贪婪解析(报错十)、保留 `.end method`(报错十三)、构造器不 native 化、幂等、多 dex、exit 3 语义） ✅CI |
| `scripts/repack/dex-capacity.py` | dex 方法数容量检测 + 注入落点选择（读 header 的 method_ids_size，不反汇编） | `scripts/repack/tests/test_dex_capacity.py`（33 断言，纯 stdlib；覆盖 header 解析边界、目录名→dex 名映射(对齐 apktool 字节码)、n+1 命名(含不连续序号)、落点决策三分支、不捡现成空 dex、扫描路径 ×1.25 保守上浮、SMALI_DIR_RE 单一真相） ✅CI。**报错五十九**：注入类曾固定写 `smali/`，大型包 classes.dex 贴顶(65519/65536)导致回编 `Unsigned short value out of range: 65536`，且报错类名随机无诊断价值 |
| `tools/apktool.jar` | 解包/重打包工具(apktool 3.0.3,git 跟踪独立文件) | 严禁替换版本(历史: 报错四/五)。升级必须回归「解包后 manifest 头 4 字节仍是 `03 00 08 00`」 |
| `scripts/guard/archive/nc_guard_unlock.c` | `.ncx` 段运行期自解密的**旧实现**(历史存档) | **不进 NDK 工程、不参与任何构建**。契约逐条过期(slot 80 字节/旧 XOR_KEY/`slot^XOR_KEY` 取钥),刻意保留旧段名——读到 `.ncguard` 说明那是旧版,不要照着改。现行实现见 §1.1 |

### 1.1 so 段加密设施的上游边界(2026-10-30 独立化后)

设施的**唯一真相源**是上游仓库 `zzgs219G/nox`，本仓库只是消费者：

```
../nox/scripts/so-guard/                 ← 源码真相源（开发机常态，两仓库并列）
  nc_guard_boot.c / nc_guard_probe.c / nc_guard_key.c(+.h)
  nc_guard_paths.c(+.h) / nc_guard_layout.h / nc_guard_jni.c
  so-section-lock.py / so_section_mark.py / gen-paths.py

tools/nox.zip → tools/nox/so-guard/      ← 生产分发形态（静态库）
  只有 *.h + *.py + lib/<abi>/libnox.a，【无 .c】
```

> 📖 **上游仓库的完整说明见 `docs/上游仓库-nox.md`**（结构 / CLI / 23 项自测 /
> 两种分发形态 / 加密契约 / 改法与发版流程）。本节只讲跨仓库边界。

- **改设施 = 去 nox 仓库改**，冻结契约见该仓库的 `AGENTS.md`。本仓库对它的
  改动方式只有一种：换 `tools/nox.zip`（换版纪律见 `docs/流程文档.md` §3.13.5）。
- **本仓库不得复制 vendored 源码副本**——双源头必然漂移。
- `nc_guard_layout.h` 仍是**加密契约的唯一真相源**（段名/slot 尺寸/偏移/magic
  seed/XOR 碎片表），但它现在位于 `tools/nox/so-guard/`（解压产物）与
  `../nox/scripts/so-guard/`（源码）。`protect.sh` 从 `GUARD_SRC` 拷它，
  `so-section-lock.py` 用 `_load_layout_contract()` 抽取，抽不到即抛错。
- 改布局常量的验收在 nox 侧：`test-so-lock.sh` 的 T20(跨语言对拍)/T21(段名登记)/
  T22(二进制等价)。该测试通过 `ensure_nox_src` 读源码形态，**必须 clone nox 仓库**。

### 1.2 段名中性化对照表(2026-10-19 改名,2026-10-20 补表)

| 旧名(2026-12 ~ 2026-10-18) | 现行名 | 用途 |
|---|---|---|
| `.ncguard` | `.ncx` | 加密代码段(AXR,可执行) |
| `.ncguard_ro` | `.ncxr` | 加密常量表段(AWR,不可执行) |
| `.ncguard_head` | `.ncxh` | unlock 本体(二级锁箱对象) |
| `.ncguard_head_ro` | `.ncxhr` | master 数据段(AWR,32B) |
| `.nckey` | `.nck` | 一级密钥槽 |
| `.nckey_stub` | `.ncks` | 二级 stub 密钥槽 |

改名的理由:旧名自解释(`ncguard`/`nckey` 一眼看出机制),`readelf -S`
即可列举出全部加固结构。现行名无语义,仅缩短。

⚠️ 例外:`scripts/guard/archive/nc_guard_unlock.c` 是历史存档(2026-10-20
已移出 src/),**刻意保留旧段名**——读到 `.ncguard` 说明那是旧版实现,不要照着改。
现行实现在上游 nox 仓库的 `nc_guard_boot.c`(用 `.ncxh`/`.ncxhr`),见 §1.1。

**契约常数的单一真相源是 `nc_guard_layout.h`**(2026-10-30 起位于上游 nox 仓库;
本仓库解压态在 `tools/nox/so-guard/`):
段名(6)、slot 尺寸(96/112)、偏移(8)、magic seed(2)、XOR 碎片表(1)全在那里,
带 `_Static_assert` 挡"偏移重叠/越界"类手误(上一轮 88→104 扩容最危险的错误模式)。

> ⚠️ 2026-11-05 更正：本文原写"slot 尺寸 96/104"，是**旧值**。
> 实测 `nc_guard_layout.h`：`NC_SLOT_SIZE=96`、`NC_STUB_SIZE=112`
> （`[104:112)` 是 XOR_KEY 的 4×uint16 碎片区）。以源码为准。

消费方(改契约前先看这张表会波及谁)：
  C:    nc_guard_boot.c / nc_guard_probe.c / nc_guard_key.c / nc_guard_paths.c
        (以上均在上游 nox) ; 本仓库的 nc_link.c / env_check.c / sig_check.c 也 include 它
  Py:   so-section-lock.py（上游 nox；`_load_layout_contract()` 抽取,抽不到即抛错）
  Sh:   make-sig-hash.sh（本仓库；sed 抽 NC_SEC_CONST,抽不到即 exit 1）
  构建: protect.sh 三个分支都拷它;test-so-lock.sh / test-javacheck.sh /
        test-lsgs-strings.sh 的编译也都需要它

⚠️ C 侧数组【符号名】刻意不跟着改(`NCG_MAGIC_SEED_SLOT` 等保持原样,
只把值换成 `NC_SEED_*_INIT`)：改名会改变 `.rodata` 布局,使 T22 的
二进制等价性验证失效。跨语言契约是"值",不是"C 变量叫什么"。

三项反向保险(`test-so-lock.sh`)：
  T20 C↔Python 跨语言对拍(双路抽取,防"抽取器本身写错也自洽通过")
  T21 全仓段名字面量登记检测(防手打错一个字母——那种编译链接全过,
      直到锁箱期才报"段不存在",且不告诉你是拼错了)
  T22 二进制等价性(需调用方传 NC_BASELINE_SO；不固定 sig_hash.h 时
      随机 salt 会让 cmp 永远不一致,见 make-sig-hash.sh 的 os.urandom)

### LSGS 密文机制约束(2026-10 新增,改 sig_check.c/env_check.c 前必读)

- 上述两个 C 文件里的**所有功能语义字符串**(中文文案/检测特征串/外围串)
  一律走 `/*LSG:NAME|...*/` 或 `/*LSGS:NAME|...*/` 标记 → 构建期
  `scripts/guard/log/make-sig-log.py` 扫描加密 → so 里只有密文。
- **新增/修改标记必须重新生成** `sig_log_data.h`(protect.sh 自动做);
  直接写明文字符串 = 改坏了(strings 零泄漏断言会红)。
- 注释里**禁止书写 LSGS 标记的字面形态**(嵌套注释提前终结,编译炸,
  报错速查已留档)。
- `sig_log_data.h` 是构建中间产物,不进 git,不存在"改坏"一说。

### 冻结资产的能力边界（审查时知悉，不算 bug）

| 缺口 | 说明 |
|---|---|
| `extract-cert-fp.py` 无独立测试 | 只被 `test-so-lock.sh` / `test-sig-verify.sh` 间接覆盖。历史报错五十八（签名块解析差 1 字节 → 全量闪退）出在这个文件上，补独立测试是待办。（`inject-loadlib.py` / `mark-native.py` 已于 2026-11-01 补齐，见冻结表） |
| `test-javacheck.sh` / `test-protect-packer-wiring.sh` / `test-sig-verify.sh` **只在本地跑** | 前两套需真实 `ndk-build` / `zipalign`，CI 未接；`test-sig-verify.sh` 需一份已签名的真实 APK 作夹具，接进 CI 只剩 `skip + exit 0` = 假绿。其余套件（含 so-lock 52 项、stringenc 五套）已于 2026-11-01 接入 CI |

### 为什么"100% 正确"也必须冻结

历史事故(详见 `docs/变更历史.md` 与 `docs/报错速查.md`)中,正确模块被改坏的原因**从来不是
逻辑错,而是 AI 在改别处时顺手重写了它们**:

- 报错三: 移动脚本目录时 `__file__` 路径少算一级 → `ModuleNotFoundError`
- 报错七: 改写文件时 `r'\d'` → `r'\\d'` 双重转义 → 静默收窄匹配
- 报错十一: 抽公共 mk 模板时丢了 dcc 原版 `nc/*.cpp` 子目录布局 → 空壳 so
- 报错十二: maps 定位分支被重写时截掉 `base.apk` 文件名 → 必闪退

**教训: 文字警告防不住文本级重写,只有回归测试能。**

## 2. 允许的改动方式

1. **新增模块**: 新建文件/目录,实现新功能(如 `packer` 模块),不动冻结区。
2. **改非冻结脚本**: `scripts/pipelines/*.sh`、`scripts/lib/*.sh`、workflow yml。
3. **修复冻结模块的真实 bug**: 必须满足——
   - 用户在当次对话明确报告了该模块的错误行为(附日志/复现);
   - 改动后回归测试全绿(若 `tests/` 目录存在);
   - 在 `docs/变更历史/` 对应分卷追加一行(报错 N)记录根因。
4. **扩展冻结模块**(加日志、加防御): 只允许**追加**,不允许改写已有逻辑行。

## 2.5 混淆 pass 选型：按「改哪一类信息」分类，不按数量堆

**别再"多开几个 pass 就更安全"** —— 2026-11-19 实测结论。

### 已实测的三类效果

| pass | 改什么 | 体积代价 | 对仿真的效果 | 结论 |
|---|---|---|---|---|
| `vm_virtualize` | 逻辑→VM 字节码 | +470 KB | ✅ 挡住（需逆 VM，天~周）| **必开** |
| `vm_flatten` | 状态机 + 运行期状态码 | 中等 | ⚠️ 干扰但可 trace | 开 |
| `mba` | 表达式重写（含浮点）| 小 | ❌ 可自动化简 | 开（便宜）|
| `bcf` | 永假分支 | **+164 KB `.text`/+127 KB APK** | ❌ **完全没被识别，一句"仿真跑一遍"绕过** | **不开** |
| `param_aggregate` | 参数打包成结构体 | **+12 KB** | ⚠️ 改签名，AI 要逆结构体布局 | 开（性价比最高）|
| `flatten` | 静态状态机 | 中等 | ❌ 与 `vm_flatten` 同类，重复 | 不开 |
| `shuffle_blocks`/`split_basic_block` | 块顺序/拆分 | 小 | ❌ 画个 CFG 就还原 | 不开 |

### 当前配置（4 个子项，默认开 3 个）

```
默认开 ：vm + mba + param_aggregate
需显式开：vm_flatten（体积与编译开销大，见 schema default=false）
```

> ⚠️ **本节此前写「当前配置 4 个子项：vm + mba + param_aggregate + vm_flatten」，
> 与 schema 不符**（2026-11-22 校正）。`configs/v1/config-schema.json` 里
> `vm_flatten` 的 `default` 是 **false**，且 `scripts/actions/tests/test_obfuscate_args.py`
> 有断言钉住这一点（"vm_flatten 默认关闭（体积与编译开销大，需显式开）"）。
> 上表"结论"列的「开」指的是**值得开**，不是**默认开**——两回事，别混。

### 选型判据

1. **跨类互补 > 同层叠加**：`flatten` 和 `vm_flatten` 都是"状态机"，
   叠加收益低；`param_aggregate` 改签名，是**正交维度**。
2. **看体积代价**：`bcf` 的 +127 KB 换不到等效保护，砍掉。
3. **与 VMP 的 ABI 冲突**：改 ABI 的 pass（`param_aggregate`）
   必须跳过 VMP 目标函数（见 `amice/src/aotu/obf_skip.rs`）。

### 加新 pass 前必做

```bash
# 1. 单独开它，跑一次构建，看：
#    · .text 体积涨多少
#    · VMP 成功率是否下降
#    · 真机是否闪退
# 2. 对比基线（只开 vm+mba+vm_flatten）的同一指标
# 3. 只有「体积涨幅 < 20% 且 VMP 不降」才考虑加
```

---

## 2.6 调试开关一律编译期，不用运行期字符串

外部 0 信息逆向 **5 秒**就通过 `strings libnc.so | grep -i xixin`
找到 `/storage/emulated/0/xixin_debug` 和 `NCG_REPORT_PATH`，
`touch` 一下就让壳吐出 12 步解密流水线。

**因为 C 的字符串字面量永远进 `.rodata`，而 `.rodata` 不在锁箱范围。**

| 不要做 | 要做什么 |
|---|---|
| ❌ `getenv("XXX_DEBUG")` / `access("/sdcard/xxx")` | ✅ 编译期 `#ifdef`，release 里代码不存在 |
| ❌ 给开关改名（"不显眼的名字"）| ❌ 没用 —— `strings` 看的是 ASCII，改名不改变可见性 |
| ❌ 用 Android 的 `debuggable` | ❌ `protect.sh` 已强制 `false`（安全要求，不能为调试改回去）|

**当前实现**：`nc_guard_report.c` 的 `ncg_debug_log_path()` 整体包在
`#ifdef NCGUARD_DEBUG_REPORT` 里；`lib-ndk.sh` 读 `DEBUG_REPORT` 环境变量
决定是否加宏。出调试包：

```bash
python3 scripts/trigger_build.py app.apk --sigcheck --vmp --debug-report
```

详见 `docs/调试包怎么出.md`。

---

## 3. 改动后的必做动作(任何改动,不论大小)

```bash
git diff                          # 自查: 只含预期改动
```

(原 `tests/run-tests.sh` 与 module-guard.yml CI 守卫已移除;改动冻结模块
仍需自查 diff,并在 docs/变更历史/ 留痕。)

> ⚠️ **CI 的测试覆盖是分层的（按 `.github/workflows/protect-modules.yml` 实际 step 核对，2026-11-05）**：
>
> **触发方式**：`push`/`pull_request` 到 `main` → **只跑 test job**（自动，无需手动点）；
> 出包（protect job）仍是 `workflow_dispatch` 手动触发，且用 job 级 `if` 隔离。
>
> | 层 | 内容（与 workflow 的 step 一一对应） | 触发 |
> |---|---|---|
> | `test` job 第一批（<10s） | 文档路径校验 / schema 结构 / resolve-config（用例数跑一遍看，勿抄） / workflow yml / smali 参数槽 / dex 版本头 / **inject-loadlib 73 断言** / **mark-native 42 断言** | 按改动范围过滤，与构建**并行** |
> | `test` job 第二批（~4min） | anti-diff 冒烟 / **dex 容量 33 断言** / packer 冒烟 / **stringenc 五套**（含 apktool 真汇编、密钥流 468 例、联动端到端） | 仅改代码时跑 |
> | `test` job 第三批（~5min） | **so-lock 52 项** / sig-guard2 / mem-readable / lsgs-strings（需 `../nox` 源码；CI 用 `setup-toolchain` 的 `nox-source: true`，**ref 为 `main` 而非 tag**） | 仅改代码时跑 |
> | 本地手工 | `javacheck`（需 `ndk-build`）/ `packer-wiring`（需 `zipalign`）/ **`sig-verify`（需真实已签名 APK 夹具）** | **CI 不跑**，改动后必须本地跑 |
>
> ### 🔴 被 `if` 跳过的测试 = 没有测试（2026-11-22 血的教训）
>
> 第三批 step 都带 `if: steps.scope.outputs.code == 'true'`，只在**改代码**时跑。
> 历史上多次推送只改文档（`code=false`）→ 整批被跳过 → GitHub 显示 **success**。
> 于是这批测试**从来没真正执行过**，而"success"让它看起来是健康的。
>
> 直到 2026-11-22 一次真改代码才第一次触发，一次性炸出一串：
> CI 从未把 NDK 加进 PATH（`jni.h not found`）、测试与 nox 演进脱节 6 处、
> NDK clang 编 ARM 在 x86_64 runner 上跑不了（波及 8 个文件）、
> 以及一个断言永远查错流的 `run()`。
>
> **判别方法**：看 step 是 `success` 还是 `skipped`。GitHub UI 上两者都显示绿色，
> 但 `gh api .../jobs -q '.steps[]|.name+" "+.conclusion'` 能看出区别。
> 改了第三批相关代码后，**必须确认那些 step 真的 `success` 而不是 `skipped`**。
>
> **连带纪律**：
> - 测试要跑产物（执行 ELF / 反汇编 / dlopen）时，必须用
>   [`scripts/lib/host-cc.sh`](scripts/lib/host-cc.sh) 的 `nc_pick_host_cc` 选编译器。
>   CI 的裸 `clang` 被转发到 NDK aarch64 包装器（为了让 `jni.h` 可达），
>   `command -v clang` 找得到但它编出的是 **ARM**，在 x86_64 runner 上
>   "cannot execute binary file"。症状是"期望 X 实得 （空）"，极易误判成被测代码有 bug。
> - 判据用**可执行性**，不是编译器名字（CI 的转发器就叫 `clang`）。
> - 确实无法在本机执行的项目（如 T4 跑 ARM so）要**明确 skip 并打印原因**，
>   不能让它假红 —— 假红会让人逐渐无视红色。

> **两条容易搞错的**（2026-11-05 核对）：
> - **`sig-verify` 不在 CI**。workflow 里有显式注释：该脚本没有 APK 时是
>   "skip + exit 0"，接进来等于"0 通过 0 失败"的**假绿**，比不接更糟。
>   本文此前把它列在第三批，是错的。
> - **CI 不锁 nox tag**。当时的 `v0.4.0`（现在最新是 `v0.9.47-noreport-obf`）早于修复 `nc_guard_jni`
>   缺失的提交（`1f1a732`），锁它等于测旧代码；且 `v0.4.2` 这个 tag
>   **在 nox 仓库里根本不存在**（当初凭 `tools/nox/VERSION` 猜的，
>   checkout 直接失败）。现用 `ref: main`。
>
> **环境与 protect job 保持一致**（同样的 NDK / dex2c / nox / pip 步骤，
> 两边都 `uses: ./.github/actions/setup-toolchain` 一份真相）：
> 测试因"环境少东西"而红是噪音，会让人逐渐无视红色 CI。
> 仅剩两套需真实 NDK 编译的 + 一套需真实 APK 的没接；**"CI 绿"仍不等于"全绿"**。
> 全套清单见 `docs/流程文档.md` §6.0。

## 4. 模块化契约(新增模块时遵守)

- 模块 = 独立脚本 + 明确 CLI 契约 `<输入> <输出> [参数]`,不 import 仓库内
  其他模块的内部函数(公共能力放 `scripts/lib/`)。
- so 名统一 `nc`;`ndk_write_mk` 是唯一 mk 模板来源(报错十一)。
- 每个新模块必须带最小回归测试(若仓库恢复 `tests/` 目录则挂进运行入口)。
- 文档 `docs/流程文档.md` 与代码同步更新；变更留痕写进 `docs/变更历史/`
  （按时间倒序追加一行，格式同 §3）。
