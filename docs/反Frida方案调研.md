# 反 Frida / 反 Hook 方案调研（2026-11-07）

> 起因：`env_check.c` 的检测项是否够用？四个参考项目对比后的结论。
>
> **本文只记录调研结果与建议，不包含代码改动。**
> `env_check.c` 是冻结模块（`AGENTS.md` §1.0），改它需要用户明确点名。

---

## 0. 一句话结论

**我们现有的检测覆盖了主流手段，但缺 3 项技术含量最高的。**
四个参考项目里 `sentry` 最强（8600 行 / 24 项检测 / 有规格文档 / 自带绕过脚本），
但它定位是**风控引擎**（输出画像），不是**加固壳**（阻止逆向）。

⚠️ **没有任何检测能保证不被绕。** 攻击者永远可以先 hook 掉检测本身。
这是永恒的猫鼠游戏，检测的收益是"抬高成本"，不是"防住"。

---

## 1. 四个项目对比

| 项目 | 年份 | 体量 | 定位 | 评价 |
|---|---|---|---|---|
| `AntiDebugandMemoryDump` | 2021 | 1023 行 | 教学 demo | 思路对但过时，不覆盖 gadget 注入 |
| `NativeShield` | 2025 | 2265 行 | 功能演示 | 结构漂亮，但**端口全扫不可用**（见 §2.1）|
| `XopProtector` | — | 1360 行 | 商业壳雏形 | 实战经验足，**5 种处置方式**值得学 |
| **`sentry`** | 2026-09 | **8600 行** | **风控检测引擎** | **最强**，24 项检测 + 规格文档 |

### 1.1 我们（`env_check.c`）在哪

10 个探针 + `anti_debug_preempt` + 心跳，约 1400 行。

```
✅ 有的：Frida 端口 / maps / 线程名 / unix socket / libc hook 打分
         libc text CRC / Xposed maps / TracerPid / 自身代码页 CRC / 心跳
❌ 缺的：LR 检测 / 全线程 TracerPid / dl_iterate_phdr / /proc/self/stat
         Frida fd 扫描 / Xposed Class.forName / 时序异常
```

---

## 2. 三个必须知道的坑（别照抄）

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

---

## 3. 最值得补的三项（按收益排序）

### 3.1 LR 检测（Sentry，技术含量最高）

**原理**：不看函数体有没有被改，看**调用者的返回地址**在哪。

```cpp
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

### 3.2 全线程 TracerPid（Sentry / NativeShield）

**我们只读 `/proc/self/status`（主线程）。**
Frida 挂在独立线程上时，`task/<tid>/status` 里才看得到 `TracerPid`。

```cpp
// 遍历 /proc/self/task/*/status，每个都查 TracerPid
```

**成本**：约 40 行（`getdents64` 遍历 + 逐线程读 status）。

### 3.3 `/proc/self/stat` 的 state 字段（XopProtector）

`state == 't' || state == 'T'` = traced/stopped，比 `TracerPid` 难伪造。

**成本**：约 15 行。

---

## 4. 明确不建议做的

| 项 | 为什么不做 |
|---|---|
| **端口全扫** | 启动卡死（见 §2.1）|
| **root / 模拟器检测** | 我们是影视 App，误报率高（用户可能用云手机、开发者模式）|
| **时序异常检测** | 低端机上会误杀正常用户（Sentry 也标了 `warnOnly`）|
| **Key Attestation** | 同上，且我们不改系统分区，用不上 |
| **24 项全上** | 囧次元那次已经踩过：`libc_hook_probe` 误杀了广告 SDK |

---

## 5. 一个更根本的判断

**检测项再多，都改变不了这个事实**：

```
攻击者永远可以先 hook 掉检测函数本身
  → 检测返回"正常"
  → 后续所有检测失效
```

Sentry 自己的 `frida-script/bypass.js` 就演示了这个：

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
| **六段加密** | 磁盘上是密文 |

这些是**链式依赖**，不是"检测后返回"。攻击者要绕过必须**同时**满足多个条件。

检测是"多一层噪音"，不是"防线"。这个认知比加检测项重要。

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

**参考实现的位置**（都在 `~/克隆仓库x/` 下）：

```
sentry/app/src/main/cpp/detector/hook_detector.cpp       LR 检测 / GOT / PLT
sentry/app/src/main/cpp/detector/trap_detector.cpp       SIGTRAP 陷阱
sentry/app/src/main/cpp/detector/thread_detector.cpp     线程检测
XopProtector/native/src/main/cpp/risk/risk.cpp           5 种处置 + stat 检测
NativeShield/app/src/main/cpp/Modules/                  SecureAPI 全套 syscall
```
