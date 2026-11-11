# amice fork 改造记录（v0.1.6-nox1 / nox2 / nox3）

> 我们用的不是上游 `fuqiuluo/amice` 的原版 bundle，而是自己 fork 的
> `zzgs219G/amice`。本文记录**为什么 fork、改了什么、怎么验证的**。
>
> 换版时先读本文再动手，否则会重新踩一遍下面这些坑。

---

## 0. 三十秒定位

```
zzgs219G/amice  master = 上游 62a8348 + 4 个补丁
                tag    = v0.1.6-nox3（当前生产使用）

消费方引用位置（两处 × 2 个 URL + 2 个 cache key）：
  artifact-pipeline/.github/workflows/protect-modules.yml
  nox/.github/workflows/release.yml
```

---

## 1. 四个补丁（按加入顺序）

| # | 提交 | 作用 | 不加会怎样 |
|---|---|---|---|
| ① | `8147ac5` | wrapper 继承原函数的 section | 自定义段（`.ncx`）里的函数被 VMP 后落到 `.text`，锁箱白做 |
| ② | `9162cca` | CI 只构建 android-ndk r29 linux | 一次 release 跑 8 个组合，约 1 小时；我们只要 1 个 |
| ③ | `37ede21` | 跳过 `JNI_OnLoad` / `JNI_OnUnload` | 应用启动即 SIGSEGV（见 §3.2） |
| ④ | `7c9c7e7` | 新增 `AMICE_VM_ONLY_ANNOTATED` | 全局开关把所有函数都当候选，`.text` 白涨 467KB + 栈溢出（见 §3.3） |

---

## 2. 每个补丁的细节

### ① `set_section`：保自定义段

`crates/amice/src/aotu/vm_virtualize/mod.rs` 的 `rewrite_as_wrapper()`：

```rust
let wrapper = module.add_function(&original_name, fn_type, Some(original_linkage));
copy_function_attributes(wrapper, original);
// ↓ 新增
if let Some(section) = original.get_section() {
    if let Some(name) = section.to_str().ok() {
        wrapper.set_section(Some(name));
    }
}
```

**为什么上游漏了**：VMP 的改写是「原函数改名 + 新建同名 wrapper + 删原函数」。
`copy_function_attributes` 只复制 `AttributeLoc::Function` 层面的属性，
而 **section 在 LLVM 里不是 function attribute**，是 GlobalObject 的独立字段。

**实测证据**（v0.1.6-beta.1，未打此补丁）：

```
VMP 前：nc_mix64 在 .ncx  → 磁盘密文 + 运行时明文
VMP 后：nc_mix64 在 .text → 磁盘明文 + 运行时字节码
.ncx 从 40,188 降到 39,444，.text 涨 22KB
```

等于拿「防静态分析」换「抗内存 dump」，不是净增益。

`FunctionValue` 是 `Copy`，所以 `set_section(self, ...)` 的 consuming self 不影响后续使用。

### ② CI 矩阵裁剪

`.github/workflows/release.yml`：

- `android-ndk` job 的矩阵从 4 NDK 版本 × 2 OS 裁到 `r29 × ubuntu-latest`
- `linux` / `linux-arm64` / `macos` 三个 job 加 `if: false`

我们只消费 `amice-android-ndk-r29-linux-x86_64.tar.gz`，其余产物用不到。
CI 时间从约 1 小时降到约 15 分钟。

要恢复完整构建：删掉各 job 的 `if: false` 与矩阵里的注释即可。

### ③ 跳过 `JNI_OnLoad`

`AMICE_VM_VIRTUALIZE=true` 是全局开关，`default_config.enable` 会传给每个
**没有注解**的函数（见 `crates/amice-macro/src/lib.rs:151-155`）。于是
`JNI_OnLoad` 也被 VMP。

**真机证据**（REDMI Turbo 5 Max / Android 17 / arm64）：

```
Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR)
tid DefaultDispatch, pid com.xixin.box
```

`.ncx` 里出现 3,076 字节的 `JNI_OnLoad`（未 VMP 时 388 字节，约 8 倍膨胀）。

**修复前后对比**：

| | 修复前 | 修复后 |
|---|---|---|
| 我们的日志 | **0 条**（没到打日志就崩） | 签名校验全部跑完、放行 |

`has_unsupported_function_uses` 没拦住它，是因为 **ART 运行期 `dlsym` 按名字查找
`JNI_OnLoad`**，编译单元内没有显式地址取用，静态分析看不到那个 use。

> ⚠️ 刻意**不排除 `Java_*`**：那是 JNI 短名绑定的业务入口，也是我们想 VMP 的目标。

### ④ `AMICE_VM_ONLY_ANNOTATED`

**这是最重要的一条。**

问题：全局开关让**所有函数**成为候选，包括 dex2c 引擎引入的 87 个辅助函数。

实测（arm64，同一份样本）：

| 配置 | `.text` | 函数数 | so 大小 |
|---|---|---|---|
| sigcheck + vmp | 180,836 | 43 | 466,064 |
| sigcheck + stringenc + vmp | — | — | 515,280 |
| sigcheck + dex2c + stringenc + vmp | **648,176** | **130** | **1,397,320** |

**`.text` 白涨 467KB**，且应用启动页栈溢出（xCrash 证实 `sp` 跌进 guard page）：

```
guard page: 0x74252d0000-0x74252d1000  ---   [anon:stack_and_tls]
栈本体:     0x74252d1000-...           rw-   0x107000 ≈ 1.03MB
sp    = 0x74252d1000   ← 正好在 guard 上边界
fault = 0x74252d0ff0   = sp - 0x10
失败指令: stp xzr, xzr, [sp, -0x10]!   ← 再压 16B 即越界
x29   = 0x74253d2670   → 与 sp 相差 0x101670 = 1.01MB
```

5 次崩溃 `fault addr` 低位恒为 `0xff0`/`0xff8`（页尾），同一模式。
崩溃线程均为 `DefaultDispatch`（ART 线程池，栈约 1MB，主线程是 8MB）。

修法：新增环境变量 `AMICE_VM_ONLY_ANNOTATED`，设 `1/true/on/yes` 时
只有函数自身带 `annotate("+vm_virtualize")`（或 `+vmp` / `vm_virtualize=1`）
才 virtualize。

未设时行为与上游一致，不影响其他使用者。

**效果**：

| | 修复前 | 修复后 |
|---|---|---|
| arm64 so | 1,397,320 | **560,584**（−60%） |
| v7a so | 1,678,252 | **616,780**（−63%） |
| 应用启动 | ❌ 栈溢出 | ✅ 进程存活、签名校验通过 |

---

## 3. 消费方怎么用

`protect.sh` 在 `--vmp` 时：

```bash
export AMICE_VM_VIRTUALIZE=true          # 让 pass 装上
export AMICE_VM_ONLY_ANNOTATED=1         # 但只处理带注解的函数
export AMICE_VM_PROFILE_PATH="$GUARD_SRC/vmp-profile-func"
export RUST_LOG="${RUST_LOG:-amice=debug}"   # 捕获 skip 日志
```

**`AMICE_VM_VIRTUALIZE` 和 `AMICE_VM_ONLY_ANNOTATED` 必须成对**：
前者让 pass 运行，后者决定处理范围。

> ⚠️ 少了 `AMICE_VM_VIRTUALIZE=true` = pass 根本没装，annotate 写了也没人读。
> 这个坑 2026-11-11 实测踩过：`.ncx` 只涨 36 字节（多了一张
> `llvm.global.annotations` 表），函数体一条指令都没虚拟化。
> `test-vmp-preconditions.sh` 的 T11c 钉住这一点。

---

## 4. 为什么 VMP 的覆盖率不高（如实）

即使 `AMICE_VM_ONLY_ANNOTATED=1`，实测 9 个目标函数里只有 5 个 VMP 成功：

| 函数 | 结果 | 原因 |
|---|---|---|
| `derive_expected` | ✅ | — |
| `nc_strdec_decrypt` | ✅ | — |
| `nc_block_ks` | ✅ | — |
| `nc_mix64` | ✅ | — |
| `nc_strdec_utf8_to_utf16` | ✅ | — |
| `sig_verify` | ❌ | 寄存器预算超限 `values=21` |
| `extract_cert_der` | ❌ | 寄存器预算超限 `values=17` |
| `nc_strdec_b64_decode` | ❌ | 寄存器预算超限 `values=26` |
| `find_apk_path` | ❌ | 取自身地址（`dladdr`） |

**寄存器预算上限是 32**（`x0..x31`），Amice 的 VM 直接映射到物理寄存器，
不是可扩展的软件限制。

上游 `0aea479`（PR #111）加了 translator-level spill frame 缓解，但提交说明里写明：
> Functions whose pinned (cross-block) live set alone exceeds the budget are still
> skipped; lifting that wall needs dominance-aware spilling and is left as follow-up work.

我们这三个函数正是「跨块活跃值超预算」，属于上游还没做的那部分。

`dex2c` 的业务方法（`onCreate` 等）**100% 被跳过**：dex2c 把 Dalvik 每个局部变量
映射成一个 C 变量（Dalvik 最多 255 个），寄存器需求天生超限。

---

## 5. 已知未解

### 5.1 v7a 上 VMP 不完整

实测（同一份样本，全开配置）：

| 特征 | arm64 | v7a |
|---|---|---|
| `0x7F4A7C15`（GAMMA 低 32 位）明文 | **0 处** | **18 处** |
| 64 位 GAMMA 明文 | **0 处** | **7 处** |
| `.text` | 648,176 | 1,325,220 |

arm64 上 GAMMA 完全消失（进了字节码），v7a 上还有明文 —— 说明 **VMP 在 ARM32
上只做了一半：代码被膨胀了，但原始常量没被虚拟化**。v7a 的 `.text` 也大得多。

### 5.2 VMP 的栈开销与 ART 线程池不兼容

Amice 的 spill frame 是**栈分配**（实测 `sub sp, sp, 0x560` = 1376 字节）。
`DefaultDispatch` 这类 ART 线程池线程栈只有约 1MB，深调用链 + 多次 VMP 调用
就会溢出。

当前靠「只对少量函数开 VMP」规避，没有根治。

---

## 6. 验证清单（改 amice 后照做）

```bash
# ① 本地加补丁并编译（需要 Rust + LLVM 21；没有就靠 CI）
cd ../防御仓库/amice
git commit -am "..." && git tag -a v0.1.6-noxN -m "..." && git push origin master --tags

# ② 触发 bundle 编译（会自动跑 smoke test）
gh workflow run release.yml -R zzgs219G/amice -f tag_name=v0.1.6-noxN

# ③ 换消费方 URL + cache key（两处 × 2）
#   ⚠️ cache key 必须改，否则命中旧 bundle 缓存，静默用旧版

# ④ 构建验证并检查 .text 规模
#   预期：--vmp 时 .text 接近「只有注解函数」的规模，
#        不应超过无 VMP 版本的 1.5 倍

# ⑤ 真机验证（CI 绿说明不了任何事）
adb logcat | grep -E 'I nc *:|Fatal signal'
#   期望：签名校验通过、无 Fatal signal、进程存活
```

---

## 7. 一句话交接

> **改 amice = 改 `zzgs219G/amice`，打 tag 走 CI 编译，换 bundle URL + cache key。**
> **每次换版必须真机验证** —— 上面每个补丁对应一次真机崩溃，
> CI 全绿也挡不住 `JNI_OnLoad` 被 VMP 或 87 个辅助函数各生成一份 runtime。
