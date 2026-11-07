# 反 Frida / 反 Hook 方案调研（2026-11-07 初稿 · 2026-11-08 按源码全面校正）

> 起因：`env_check.c` 的检测项是否够用？四个参考项目对比后的结论。
>
> **本文只记录调研结果与建议，不包含代码改动。**
> `env_check.c` 是冻结模块（`AGENTS.md` §1.0），改它需要用户明确点名。

---

## ⚠️ 读本文前必读：2026-11-08 校正说明

**初稿（2026-11-07）有多处与源码不符，已逐条实测更正。** 保留这份说明是因为
初稿的错误本身就是教训：

| 初稿写的 | 实测（`env_check.c` @ 2026-10-29 22:30） |
|---|---|
| 「10 个探针」 | **11 个探针**（`env_check_run` 调 10 个，watchdog 调 11 个） |
| 「❌ 缺 `/proc/self/stat`」 | **不成立** —— 5 处命中全是 `/proc/self/status`，真正的 `stat`（state 字段）确实没有，但初稿把两者混为一谈了，读起来像"什么都没有" |
| 「缺 Frida fd 扫描」 | **不成立** —— `frida_unix_probe` 扫 `/proc/net/unix`（frida / linjector / gum-js），是同类能力 |
| 「sentry 8600 行」 | **实测 native 5293 行**（.cpp 4885 + .h 408）+ Java 4790 行 + 规格文档 612 行 |
| 「XopProtector 1360 行」 | **实测 risk + so_guard = 1223 行**（另有 hooks.cpp 691 / business_so.cpp 6052） |
| 「NativeShield 2265 行」 | **实测 .cpp = 1045 行**（含头文件 2265） |
| 「`libc_hook_probe` 在明文」 | **不成立** —— 它的 `section(NC_SEC_CODE)` 属性被 `#define` 隔开了（见 §1.2），需预处理后确认 |

**教训**：`AGENTS.md` §3.3 写「日志里有输出 ≠ 防护生效」，它的镜像同样成立 ——
**文档里没写 ≠ 没做**。本文件初稿是照着更早的源码状态写的，写完没有回头核对，
于是把一个"只差 4 项"的现状描述成了"差一大片"。这会让下一个人（或 AI）
重复做已经做完的工作，正是仓库反复强调的"错误前提导致错误加固判断"。

---

## 0. 一句话结论

**我们现有的检测覆盖了主流手段，只差 4 项，且这 4 项都不涉及架构改动。**
四个参考项目里 `sentry` 的检测面最广（native 5293 行 / 24 项 / 有 612 行规格文档 /
自带绕过脚本），但它定位是**风控引擎**（输出画像），不是**加固壳**（阻止逆向）。

⚠️ **没有任何检测能保证不被绕。** 攻击者永远可以先 hook 掉检测本身。
这是永恒的猫鼠游戏，检测的收益是"抬高成本"，不是"防住"。

---

## 1. 四个项目对比

| 项目 | 体量（实测） | 定位 | 评价 |
|---|---|---|---|
| `AntiDebugandMemoryDump` | 1023 行 | 教学 demo | 思路对但过时，不覆盖 gadget 注入 |
| `NativeShield` | .cpp 1045 行（含头 2265） | 功能演示 | 结构漂亮，但**端口全扫不可用**（见 §2.1）；`SecureAPI` 封装层值得借鉴 |
| `XopProtector` | risk+so_guard 1223 行 | 商业壳雏形 | 实战经验足，**5 种处置方式** + **复合打分**值得学 |
| **`sentry`** | native 5293 行 + java 4790 行 + 规格 612 行 | **风控检测引擎** | **检测面最广**，24 项 + 逐项实测数据 |

### 1.1 我们（`env_check.c`）在哪

**11 个探针 + `anti_debug_preempt` + Java 心跳，1421 行。**

| 探针 | 位置 | 抓什么 |
|---|---|---|
| `frida_port_probe` | `.ncx` | 27042/27043 直连 |
| `frida_maps_probe` | `.ncx` | maps 特征串 |
| `frida_tcp_table_probe` | `.ncx` | `/proc/net/tcp` LISTEN 解析 |
| `frida_thread_probe` | `.ncx` | `/proc/self/task/*/comm` 线程名 |
| `frida_unix_probe` | `.ncx` | `/proc/net/unix` 扫 frida/linjector/gum-js |
| `xposed_maps_probe` | `.ncx` | maps 里的 Xposed/LSPosed/Riru |
| `xposed_file_probe` | `.ncx` | LSPosed/zygisk/riru/XBridge 文件路径 |
| `tracer_probe` | `.ncx` | `/proc/self/status` 的 `TracerPid` |
| `libc_hook_probe` | `.ncx`（见 §1.2） | 8 个 libc 符号序言打分，**≥2 才判** |
| `libc_text_crc_probe` | `.ncx` | libc `.text` 内存 vs 磁盘 CRC |
| `self_text_crc_probe` | `.ncx` | 本 so `.text` 内存 vs 磁盘 CRC |

外加（非探针，但同属防御）：

| 机制 | 位置 | 说明 |
|---|---|---|
| `env_delayed_kill` | `.ncx` | 处置：延时 1~3s + 延时堆破坏 8~23 轮 + `svc` 直投 SIGABRT |
| `delayed_kill_0/1/2`（`sig_check.c`） | `.ncx` | 三个**独立函数体**（地址互不相同，防参数化退化） |
| `ncg_code_check_impl`（nox） | `.ncx` | 解密后代码页 CRC，25s 一轮 |
| `env_hw_crc_ok` | `.ncx` | 硬件 CRC32 探测（`getauxval(AT_HWCAP)` + `arm_acle.h`） |
| `env_pvm_read_u32` | `.text` | `process_vm_readv` 读 XOM 页（读不可读的 `.text`） |
| `anti_debug_preempt` | `.text` | `PTRACE_TRACEME` + `prctl(PR_SET_DUMPABLE, 0)` |

#### ✅ 我们已有、且四家参考项目里只有我们有

| 机制 | 为什么重要 |
|---|---|
| **探针进 `.ncx` 密文段**（10/11，`libc_hook_probe` 见 §1.2） | 静态视角是密文，`strings`/`objdump` 扫不到；sentry/Xop/NativeShield 的检测代码**全在明文** `.text` |
| **探针被 `ncg_code_check` 覆盖** | 探针进 `.ncx` 后，25s 一轮的代码页 CRC 会自动覆盖它们 —— 攻击者 patch 探针 → CRC 发现。**三家参考项目都没有这层** |
| **内联 `svc` 绕 `syscall@plt`** | 源码 4 处内联 `svc #0`（arm64/armv7 各两条路径）；`变更历史.md` 记录**产物侧实测 17 处**。`syscall()` 本身也是 PLT 表项，改 4 字节即废 |
| **延时堆破坏** | 死之前先破坏堆，让 dump 拿到的内存不可用 |
| **硬件 CRC32** | `arm_acle.h` 的 `__crc32*`，带 `AT_HWCAP` 运行期探测回退 |
| **LSGS 字符串密文化** | 59 个 `/*LSG(S):` 标记，构建期加密，`strings` 零命中 |
| **kill 链三变体独立函数体** | 参数化/表驱动仍是控制流单点，改一处比较即全废 |

#### ❌ 真正缺的 4 项

| 项 | 来源 | 成本 | 为什么值得补 |
|---|---|---|---|
| **LR 返回地址检测** | sentry `hook_detector.cpp:92` | ~60 行 | 唯一**不依赖读字节**的 hook 检测，XOM 机型也能用 |
| **全线程 TracerPid** | NativeShield `AntiDebug.cpp:52` | ~40 行 | 我们只读 `/proc/self/status`（主线程） |
| **`/proc/self/stat` 的 state 字段** | XopProtector `risk.cpp:345` | ~15 行 | `state == 't'/'T'` = traced/stopped，比 `TracerPid` 难伪造 |
| **SIGTRAP 陷阱** | sentry `trap_detector.cpp` | ~70 行 | 零误报风险，抓 signal chaining 被劫持 |

#### ⚠️ 已有但可加强的 3 项

| 项 | 现状 | 可加强处 |
|---|---|---|
| **复合打分** | 只有 `libc_hook_probe` 内部用（≥2/8 才判） | XopProtector 的 `risk.cpp:534-572` 是**全局**累加（unix socket +2 / tmp 文件 +1 / 线程 +N / fd +2，≥3 才处置）。我们各探针独立判定，弱信号不参与 |
| **`PTRACE_TRACEME`** | 仍在用（`anti_debug_preempt`） | 见 §2.3 —— 现代 Android 上大概率空转，但因"失败不判"所以不误报 |
| **线程名白名单含 `gmain`/`gdbus`** | `env_check.c:701-702` 把 `gmain`/`gdbus` 也当 Frida 特征 | **sentry 和 XopProtector 都明确移除过这两个词**，理由一致：GLib 标准线程名，正常使用 GLib 的合法库会误报。见 §2.4 |

#### 明确不做（不是缺口）

| 项 | 为什么 |
|---|---|
| ClassLinker `class_loaders_` 计数 | 强依赖 ART 堆布局。sentry 自己在 `DETECTION_SPEC.md:207` 写明"移植到多 ClassLoader 宿主必须重新测 baseline" |
| ArtMethod entry | 偏移 48/56/64 随 ART 版本漂移，需长期维护 |
| root / 模拟器 / Key Attestation | 我们是影视 App，误报率高 |
| 时序异常 | 低端机误杀（sentry 自己也标 `warnOnly`） |
| smaps Private_Dirty / pagemap | sentry `DETECTION_SPEC.md:267-268` 自认"多数设备返回全 0，实际命中率较低" |

### 1.2 `libc_hook_probe` 的段归属（需预处理后确认）
源码里这个属性被 `#define` 隔开了，肉眼容易读错：

```c
/* env_check.c:993-995 */
__attribute__((section(NC_SEC_CODE), retain))
#define NC_HOOK_PROBE_N 8
static int libc_hook_probe(void) {
```

`#define` 不是声明，属性会**落到下一个声明**上。预处理后确认：

```c
__attribute__((section(".ncx"), retain))
static int libc_hook_probe(void) { ... }      ← 属性生效，在 .ncx
```

**结论：11 个探针全部在 `.ncx`。** 但这个写法有风险（宏在中间，人和工具都容易误读），
建议后续把 `#define` 挪到属性之上，或在注释里显式写明。

---

## 2. 四个必须知道的坑（别照抄）

### 2.1 NativeShield 的端口全扫 —— 绝不可用

```cpp
bool FridaDetect::detectFridaListener() {
    for (int i = 1; i < 65535; i++) {      // ← 扫全部端口
        if (i == 39963) { // YouTube port (WTF???)
            continue;
        }
        socket(); connect(); write(); read(); close();
    }
}
```

**65535 次 connect，每次可能阻塞 → 启动卡死几十秒。**
作者自己写了 `(WTF???)`，说明他也不理解这段。

### 2.2 NativeShield 的错误处理反了

```cpp
int fd = SecureAPI::openat(...);
if (fd == -1) {
    return true;      // ← 打开失败 = 检测到威胁 → 误报
}
```

我们的实现是 `return 0`（放弃检测，宁漏勿误伤）。**这条纪律是对的，别改。**

### 2.3 `PTRACE_TRACEME` 在现代 Android 上不可靠

XopProtector 的 `detect_ptrace_self()` 是**空函数**，注释写明：

```c
// PTRACE_TRACEME is unreliable on modern Android (SELinux / YAMA often
// return EPERM with no debugger attached, and some OEMs leave a
// non-parent TracerPid). Rely on TracerPid + /proc/self/stat instead.
(void)0;
```

我们 `env_check.c` 的 `anti_debug_preempt()` 仍在用它：

```c
static void anti_debug_preempt(void) {
    (void)ptrace(PTRACE_TRACEME, 0, 0, 0);
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}
```

我们的注释写了"失败不判、宁漏勿误伤"，所以不会误报——但**这条防线在现代 Android 上大概率一直是空的**。
（`prctl(PR_SET_DUMPABLE, 0)` 那条仍然有效。）

### 2.4 我们的 `frida_thread_probe` 含误报源（sentry / Xop 都已移除）

```c
/* env_check.c:701-702 —— 这两条是 LSGS 标记 */
/*LSGS:THR_GMAIN|gmain*/
/*LSGS:THR_GDBUS|gdbus*/

/* env_check.c:1157-1158 —— 被实际参与比对 */
names[1] = lsg_s(LSGS_THR_GMAIN,  n2, sizeof(n2));
names[2] = lsg_s(LSGS_THR_GDBUS,  n3, sizeof(n3));
```

判定逻辑（`env_check.c:1187`）：

```c
/* gum-js-loop 为 Frida 最特征线程名,单命中即判;其余要求 ≥2 个,压低误报 */
return (gum || hits >= 2) ? 1 : 0;
```

**问题**：`gmain` + `gdbus` 同时存在 → `hits == 2` → 直接判定命中 → 走 `env_fail`。
而这两个恰好是 GLib 主循环和 D-Bus 线程的标准名字，**任何用 GLib 的库在正常设备上
都会同时起这两个线程**。

两份独立参考实现的结论一致：

> **sentry** `DETECTION_SPEC.md:88`：
> 「历史版本曾包含 `gmain`/`gdbus`/`gthread`/`gpool`/`gjs-context`，但这些是 GLib
> 标准线程名，**正常使用 GLib 的合法库会触发误报**——已在本版本移除。」

> **XopProtector** `risk.cpp:520`：
> 「Do NOT match generic GLib names (gmain/gdbus) — common on MIUI/OEM processes
> and cause false positives. Keep Frida-specific markers only.」

**严重度：中高。** 这不是理论风险 —— 我们的下游是**任意 APK**（影视 App 常带
ExoPlayer / FFmpeg / 各种媒体 SDK，其中用 GLib 的不在少数），误判即杀用户。
`§4` 已经记录过一次同类事故：「囧次元那次已经踩过：`libc_hook_probe` 误杀了广告 SDK」。

**修法**（成本极低，删两行 + 调整 `hits` 阈值）：
1. 移除 `names[1]` / `names[2]`（`gmain` / `gdbus`），保留 Frida 专属词
2. `gum-js-loop` 仍保持"单命中即判"（它是 Frida 最特征的名字）
3. 其余词维持 ≥2 才判

**注意**：`THR_GMAIN` / `THR_GDBUS` 两个 LSGS 标记若删掉调用点，标记本身也要删，
否则 `make-sig-log.py` 生成的 `sig_log_data.h` 会留下未被引用的枚举
（`-Wall` 报 unused，且密文表里多两个无意义条目）。

---

## 3. 最值得补的四项（按收益排序）

### 3.1 LR 检测（sentry，技术含量最高）

**原理**：不看函数体有没有被改，看**调用者的返回地址**在哪。

```cpp
// sentry/app/src/main/cpp/detector/hook_detector.cpp:92
static bool is_lr_suspicious(uint64_t lr) {
    if (lr == 0) return false;
    uint64_t start, end;
    if (!get_module_bounds((void *)is_lr_suspicious, &start, &end)) return false;
    if (lr < start || lr >= end) {
        // LR 指向模块外 → Frida Interceptor 的跳板
        return true;
    }
    return false;
}
```

**为什么改不掉**：Frida 的 `Interceptor` 必然在模块外的匿名内存建跳板。
攻击者可以 `Memory.patchCode` 改完再还原，但改不了"我调你时 LR 在哪"。

**成本**：约 60 行（`get_module_bounds` 读 maps + 比较）。

⚠️ **移植注意**：sentry 的 `get_module_bounds` 有 `static` 缓存
（`hook_detector.cpp:52` 的 `cached_start/cached_end/cached`）。缓存变量放
`.bss`/`.data` 没问题，但**函数体进 `.ncx` 后，首次调用必须在解锁之后** ——
和 `ncguard_code_check`（`.text` 调用方）/ `ncg_code_check_impl`（`.ncx` 实现）
的拆分方式一致。

### 3.2 全线程 TracerPid（NativeShield）

**我们只读 `/proc/self/status`（主线程）。**
Frida 挂在独立线程上时，`task/<tid>/status` 里才看得到 `TracerPid`。

```cpp
// NativeShield/app/src/main/cpp/Modules/AntiDebug/AntiDebug.cpp:52
// 遍历 /proc/self/task/*/status，每个都查 TracerPid
```

**成本**：约 40 行（`getdents64` 遍历 + 逐线程读 status）。

⚠️ 我们已有 `LSGS_PATH_TASK`（`/proc/self/task`，`frida_thread_probe` 在用），
且 `env_check.c:199` 已登记 `LSGS_PATH_TASK_COMM`（`/proc/self/task/%s/comm`）。

**但该标记目前只有定义、没有调用点** —— `frida_thread_probe` 实际是硬编码的：

```c
/* env_check.c:1170 */
snprintf(p, sizeof(p), "/proc/self/task/%s/comm", de->d_name);
```

这是全文件**唯一一处硬编码 `/proc` 明文串**（实测 `grep -nE '"/proc/[^"]*"'`
只命中这一行），属于 LSGS 纪律的漏网之鱼。实现全线程 TracerPid 时正好把它一并收编。

**严重度：低。** `/proc/self/task/` 这个前缀在几乎任何 so 里都不奇怪，泄露的信息量
近似为零（不像 `/proc/net/unix`、`/proc/self/cmdline` 那种能推出检测意图的）。
但它违反了「功能语义字符串一律走 LSGS」这条纪律，而修它只是把标记接上，成本为零。

### 3.3 `/proc/self/stat` 的 state 字段（XopProtector）

`state == 't' || state == 'T'` = traced/stopped，比 `TracerPid` 难伪造。

```c
// XopProtector/native/src/main/cpp/risk/risk.cpp:345 detect_stat_trace()
```

**成本**：约 15 行。

⚠️ **注意别和 `/proc/self/status` 混淆**：`status` 是 `TracerPid:` 那种键值文本
（我们已有）；`stat` 是单行、空格分隔、第 3 个字段是 state。两者格式完全不同。

### 3.4 SIGTRAP 陷阱（sentry）

```cpp
// sentry/app/src/main/cpp/detector/trap_detector.cpp
// 专用 pthread 装 SIGTRAP handler → tgkill(pid, tid, SIGTRAP) 只发给自己
// → handler 内 siglongjmp 跳回。handler 没运行 = 被外部 signal chaining 吞掉
```

**成本**：约 70 行。**零误报风险**（只影响自己的专用线程）。

---

## 4. 明确不建议做的

| 项 | 为什么不做 |
|---|---|
| **端口全扫** | 启动卡死（见 §2.1）|
| **root / 模拟器检测** | 我们是影视 App，误报率高（用户可能用云手机、开发者模式）|
| **时序异常检测** | 低端机上会误杀正常用户（Sentry 也标了 `warnOnly`）|
| **Key Attestation** | 同上，且我们不改系统分区，用不上 |
| **ClassLinker 计数 / ArtMethod entry** | 强依赖 ART 内部布局，需长期跟版本 |
| **24 项全上** | 囧次元那次已经踩过：`libc_hook_probe` 误杀了广告 SDK |

---

## 5. 一个更根本的判断

**检测项再多，都改变不了这个事实**：

```
攻击者永远可以先 hook 掉检测函数本身
  → 检测返回"正常"
  → 后续所有检测失效
```

Sentry 自己的 `frida-script/bypass.js`（31 行）就演示了这个：

```js
Interceptor.replace(dlsymPtr, function(handle, symbol) {
    // 被检测的函数返回原始 libc 地址
    return originalAddrs[symbol.readCString()];
});
console.log("[✓] dlsym bypass loaded - GOT detection should fail");
```

**所以别把资源全投在"加检测项"上。** 我们真正的强度来自：

| 机制 | 为什么是根 |
|---|---|
| **代码自绑定 CRC**（折进密钥）| 改一位 → 密钥错 → 解出乱码 → SIGILL。没有单点可 patch |
| **证书绑定**（HKDF + APK 证书）| 换签名重打包 → 密钥变 → 解不开 |
| **判定点改数据依赖**（`ncg_pkg_fault` / `ncg_apk_path_fault`）| 包名/路径不符 → 污染密钥 → 解出乱码，**没有 `if` 可 patch** |
| **六段加密** | 磁盘上是密文 |
| **探针进 `.ncx`** | 静态不可见 + 被 25s 代码页 CRC 覆盖 |

这些是**链式依赖**，不是"检测后返回"。攻击者要绕过必须**同时**满足多个条件。

检测是"多一层噪音"，不是"防线"。这个认知比加检测项重要。

### 5.1 但"检测在密文段"这件事改变了天平

初稿写这段时还没核实段归属。**核实后结论要更强一点**：

sentry / XopProtector / NativeShield 的检测代码全在明文 `.text`，攻击者
`strings` 定位后 patch 掉即可，**patch 完没有任何后果**。

我们的 11 个探针在 `.ncx`，而且被 `ncg_code_check` 的 25s 代码页 CRC 覆盖：

```
攻击者 patch 探针
  → 代码页 CRC 变化
  → ncg_code_check_impl 返回 0
  → ncg_self_kill() → __builtin_trap() 死循环
```

**"检测可被 patch"这个天花板，我们比三家都高一层。** 这不是说检测变强了，
而是说"绕过检测"本身的成本变高了 —— 从"改 4 字节"变成"改 4 字节 + 重算 CRC +
重新加密整个 `.ncx`（需要 k_so，而 k_so 绑定 APK 证书）"。

---

## 6. 如果要动手

`env_check.c` 是冻结模块（`AGENTS.md` §1.0），改它需要：

1. 用户明确点名
2. 改动后回归测试全绿：
   - `test-lsgs-strings.sh`（特征串密文化）
   - `test-mem-readable.sh`（跨映射判定）
   - `test-javacheck.sh`（心跳语义）
3. 新增检测项必须做**反向验证**：故意让检测命中，确认真的会处置
4. 新增的字符串必须走 `/*LSGS:NAME|...*/` 标记 → 构建期加密（否则 `strings` 能扫到）
5. **新增探针必须标 `__attribute__((section(NC_SEC_CODE), retain))`**，
   且**属性与函数之间不能夹 `#define`**（见 §1.2）
6. **调用点留在 `.text`**，只有实现进 `.ncx` —— 解锁前要能跑，
   且 `env_fail` 若进 `.ncx` = 开锁器锁进箱子（死锁）

**参考实现的位置**（都在 `~/克隆仓库x/` 下）：

```
sentry/app/src/main/cpp/detector/hook_detector.cpp:92    LR 检测 / GOT / PLT
sentry/app/src/main/cpp/detector/trap_detector.cpp       SIGTRAP 陷阱
sentry/app/src/main/cpp/detector/thread_detector.cpp     线程名检测
XopProtector/native/src/main/cpp/risk/risk.cpp:345       stat 的 state 字段
XopProtector/native/src/main/cpp/risk/risk.cpp:534       复合打分（弱信号累加）
XopProtector/native/src/main/cpp/risk/risk.cpp:456       process_vm_readv 读 XOM（我们已有）
NativeShield/app/src/main/cpp/Modules/AntiDebug/AntiDebug.cpp:52   全线程 TracerPid
NativeShield/app/src/main/cpp/Modules/FridaDetect/FridaDetect.cpp:49  dl_iterate_phdr
```

---

## 7. 本文的维护纪律

本文初稿的过期，根因是「写完没回头核对源码」。为避免复发：

1. **任何数字（行数/探针数/覆盖率）必须来自当场实测命令**，不引用旧文档
2. **改动 `env_check.c` / `sig_check.c` / `nc_link.c` 后，必须同步更新本文 §1.1**
3. 无法当场核实的项，标注「未核实」而不是写成结论
4. 本文与源码冲突时，**以源码为准**，并回改本文
