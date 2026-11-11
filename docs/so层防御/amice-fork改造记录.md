# amice fork 改造记录 + VMP 接入全过程

> 我们用的不是上游 `fuqiuluo/amice` 原版 bundle，而是自己 fork 的
> `zzgs219G/amice`。本文记录**为什么 fork、改了什么、踩了哪些坑、怎么验证的**。
>
> **这是 2026-11-11 一整天的血泪记录。** 7 个坑全部来自真机实测，
> 其中 3 个是我自己改出来的（`used` 删错、`.ncx` 放数据、`inline` 栈溢出）。
> 换版或改 VMP 相关代码前必读，否则会重走一遍。

---

## 0. 三十秒定位

```
zzgs219G/amice  master = 上游 62a8348 + 6 个补丁
                tag    = v0.1.6-nox4（当前生产使用）

消费方引用位置（两处 × 2 个 URL + 2 个 cache key）：
  artifact-pipeline/.github/workflows/protect-modules.yml
  nox/.github/workflows/release.yml
```

---

## 1. 六个补丁（按加入顺序）

| # | 提交 | 位置 | 作用 | 不加会怎样 |
|---|---|---|---|---|
| ① | `8147ac5` | amice | wrapper 继承原函数的 section | 自定义段里的函数被 VMP 后落到 `.text` |
| ② | `9162cca` | amice | CI 只构建 android-ndk r29 linux | 一次 release 跑 8 组合约 1 小时 |
| ③ | `37ede21` | amice | 跳过 `JNI_OnLoad` / `JNI_OnUnload` | **应用启动即 SIGSEGV** |
| ④ | `7c9c7e7` | amice | 新增 `AMICE_VM_ONLY_ANNOTATED` | 全局开关把所有函数当候选，`.text` 白涨 467KB + 栈溢出 |
| ⑤ | `040ce6c` | amice | 豁免 `@llvm.used` | 想用 VMP 就得删 `used` → 函数被 gc → 加密段留死代码副本 |
| ⑥ | `fee11ca` | **nox** | `so_section_mark` 新增 `--annotate-pattern` | 无法"全部进 .ncx + 只有部分 VMP" |

消费方侧还有两处配套改动（见 §4）：
- `sig_check.c` 的 `SIG_SEC_MARKED` 保留 `used, retain`
- `nc_strdec_jni.c` 的密钥数组放 `.ncxr`（**不是 `.ncx`**，见坑 ⑦）

---

## 2. 七个坑（每个都是一次真机事故）

### 坑 ① VMP 后函数被搬到 `.text`，锁箱白做

**现象**：VMP 报成功，但 `.ncx` 从 40,188 降到 39,444，`.text` 涨 22KB。

**根因**：VMP 的改写是「原函数改名 + 新建同名 wrapper + 删原函数」。
`copy_function_attributes` 只复制 `AttributeLoc::Function` 层面的属性，
而 **section 在 LLVM 里不是 function attribute**，是 GlobalObject 的独立字段。

**修法**：`rewrite_as_wrapper` 里补 `set_section`（补丁 ①）。

### 坑 ② 漏了 `AMICE_VM_VIRTUALIZE=true`

**现象**：勾了 `--vmp`，构建全绿，`.ncx` 只涨 36 字节。

**根因**：函数注解只是【函数级覆盖】，**不能把没启用的 pass 拉起来**。
文档原文：「`AMICE_PASS_ORDER` 是更外层的 Pass 允许列表：没有列入的 Pass
不会因为函数注解而重新运行。」

**修法**：`protect.sh` 里 export `AMICE_VM_VIRTUALIZE=true`。
`test-vmp-preconditions.sh` 的 T11c 钉住这一点。

### 坑 ③ `runtime.entry=inline` 导致启动页栈溢出

**现象**：
```
Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), tid DefaultDispatch
guard page 0x74252d0000-0x74252d1000  ---   [anon:stack_and_tls]
sp = 0x74252d1000   ← 正好在 guard 上边界
fault = 0x74252d0ff0 = sp - 0x10
失败指令: stp xzr, xzr, [sp, -0x10]!
x29 与 sp 相差 1.01MB
```

**根因**：`inline` 把整个解释器内联进每个被保护函数，栈帧叠加。
`DefaultDispatch` 是 ART 线程池线程，**栈只有约 1MB**（主线程 8MB）。

**修法**：`vmp-profile-func/runtime.vm` 回退 `runtime.entry = call`。
代价是 `bl <dispatcher>` 路标回来了 —— 用可运行性换可发现性。

### 坑 ④ `JNI_OnLoad` 被 VMP，启动即崩

**现象**：应用启动后**一条 `nc:` 日志都没有**，直接 SIGSEGV。

**根因**：`AMICE_VM_VIRTUALIZE=true` 是全局开关，`default_config.enable`
传给每个无注解函数（`amice-macro/src/lib.rs:151`），`JNI_OnLoad` 也被 VMP。
`.ncx` 里出现 3,076 字节的 `JNI_OnLoad`（未 VMP 时 388 字节）。

`has_unsupported_function_uses` 没拦住它，是因为 **ART 运行期 `dlsym`
按名字查找**，编译单元内没有显式地址取用。

**修法**：候选筛选阶段跳过 `JNI_OnLoad` / `JNI_OnUnload`（补丁 ③）。
⚠️ 刻意**不排除 `Java_*`** —— 那是 JNI 短名绑定的业务入口，也是想 VMP 的目标。

### 坑 ⑤ 全局开关让 87 个辅助函数各生成一份 runtime

**现象**：`.text` 从 180,836 涨到 648,176（130 个函数），so 从 466KB 涨到 1,397KB。

**根因**：`AMICE_VM_VIRTUALIZE=true` 让**所有函数**成为候选。
dex2c 引入 87 个引擎辅助函数，每个都生成 runtime 副本。

**修法**：新增 `AMICE_VM_ONLY_ANNOTATED`（补丁 ④），
只有带 `annotate("+vm_virtualize")` 的函数才处理。

**效果**：arm64 so 1,397,320 → 560,584（−60%）。

### 坑 ⑥ 删掉 `used` 导致加密段变成死代码副本

**这是最隐蔽的一个，我花了几轮才找到。**

**现象**：VMP 报成功、`.ncx` 有东西，但 `.ncx` 里的函数**没有任何 VMP wrapper**。

**错误链条**：
```
带 used/retain → 生成 @llvm.used → Amice 判 non-call address use → 跳过 VMP
   ↓ 为了绕开
删掉 used/retain
   ↓ 副作用
--gc-sections 把它们当死代码 → .ncx 里留下【没人调用的副本】
   → 真正执行的是 .text 里另一份
   → 现象：「VMP 报成功但加密段毫无变化」，so 白涨 92KB
```

**关键认知**：`--gc-sections` 的判据是「**有没有被引用**」，
不是「有没有 section 属性」。

**修法**：两条合起来（缺一不可）
- ① 恢复 `used, retain`（函数一定被保留）
- ② Amice 豁免 `@llvm.used`（补丁 ⑤）—— 它的语义是「别删这个符号」，
  不是「取地址去用」，与 VMP 不冲突

只做 ① → VMP 跳过；只做 ② → 函数被 gc。

### 坑 ⑦ 可写数据放进 `.ncx` → RWX → Android 拒绝加载

**现象**：启动即崩，连 `constructor` 都没跑到，无 tombstone：

```
java.lang.UnsatisfiedLinkError: dlopen failed:
"libnc.so" has load segments that are both writable and executable
```

**根因**：`.ncx` 是 AXR（可执行）段。把**可写**数据（去掉 `const` 的数组）
塞进去，链接器为容纳它把整个 LOAD 段标成 `RWE`：

```
LOAD R-X  va=0x0      size=0x7b160
LOAD RWE  va=0x7f160  size=0xad98    ← .ncx 区域变成 RWX
```

Android 14+ 直接拒绝加载含 RWX 段的 so。

**这本来是 `nox/AGENTS.md` §2.2 写明的硬约束**（「数据段不能用 `.ncx`」），
但那条只写在「改 nox 的人」看的文档里，**消费方不知道**。

**修法**：数据用 `.ncxr`（AWR，可写不可执行）。
`.ncxr` 同样会被锁箱器加密（`--section .ncx,.ncxr`），所以密钥仍是磁盘密文。

**段的正确用法**（务必记住）：

| 段 | 权限 | 放什么 |
|---|---|---|
| `.ncx` | **AXR** = `R-X` | **代码**（函数） |
| `.ncxr` | **AWR** = `RW-` | **数据**（常量表、密钥） |

混放 → `RWE` → Android 14+ 拒绝加载。

---

## 3. `AMICE_VM_ONLY_ANNOTATED` 的用法

`protect.sh` 在 `--vmp` 时：

```bash
export AMICE_VM_VIRTUALIZE=true          # 让 pass 装上
export AMICE_VM_ONLY_ANNOTATED=1         # 但只处理带注解的函数
export AMICE_VM_PROFILE_PATH="$GUARD_SRC/vmp-profile-func"
export RUST_LOG="${RUST_LOG:-amice=debug}"   # 捕获 skip 日志
```

**前两个必须成对**：少了 `AMICE_VM_VIRTUALIZE` = pass 不装（坑 ②）；
少了 `AMICE_VM_ONLY_ANNOTATED` = 全部函数当候选（坑 ⑤）。

---

## 4. 消费方侧的两处必改（不是 amice 的锅）

### 4.1 `sig_check.c` 的 `SIG_SEC_MARKED`

```c
#  if defined(NC_AMICE_VMP)
#    define SIG_SEC_MARKED \
       __attribute__((section(NC_SEC_CODE), used, retain, noinline, \
                      annotate("+vm_virtualize")))
#  else
#    define SIG_SEC_MARKED \
       __attribute__((section(NC_SEC_CODE), used, retain, noinline))
#  endif
```

**`used, retain` 不能省**（坑 ⑥）。它们和 annotate 可以共存，
前提是 amice 豁免了 `@llvm.used`（补丁 ⑤）。

### 4.2 `nc_strdec_jni.c` 的密钥数组

```c
/* 必须在 .ncxr（AWR），不能放 .ncx（AXR）—— 否则 RWX，Android 拒绝加载 */
static uint8_t nc_strdec_key_cipher[NC_STRDEC_KEYLEN]
    __attribute__((section(".ncxr"), used, retain)) = NC_STRDEC_KEY_BYTES;

/* 读取时加一句 volatile，阻止 -Oz 把内容当常量传播到 .text */
*(volatile uint8_t *)nc_strdec_key_cipher;
nc_strdec_set_key(nc_strdec_key_cipher);
```

**为什么去掉 `const`**：`const` 数据不能进可执行段（clang 报 section type
conflict）。但去掉后就是可写数据，**必须放 `.ncxr`**。

**时序安全**：只在 `nc_ensure_key()` 读，而它由**首次解密调用**惰性触发，
晚于 `constructor(50)` 解锁。不在 `JNI_OnLoad` 期读。

---

## 5. 当前的防护矩阵（2026-11-11 最终状态）

### 5.1 哪些函数有什么保护

| 函数 | 做什么 | 锁箱 | VMP |
|---|---|---|---|
| **`nc_strdec_key_cipher`**（8 字节密钥） | **解密全部字符串的种子** | ✅ `.ncxr` | — 数据不能 VMP |
| `derive_expected` | **签名标准答案的派生** | ✅ `.ncx` | ✅ |
| `nc_block_ks` | splitmix64 密钥流 | ✅ `.ncx` | ✅ |
| `nc_mix64` | splitmix64 终混合 | ✅ `.ncx` | ✅ |
| `nc_chacha20_keystream64` | ChaCha20 密钥流 | ✅ `.ncx` | ❌ 寄存器超限 |
| `sig_verify` | 签名校验主流程 | ✅ `.ncx` | ❌ 寄存器超限 `values=21` |
| `extract_cert_der` | 解析 APK 签名块 | ✅ `.ncx` | ❌ 寄存器超限 `values=17` |
| `find_apk_path` | 从 maps 定位 APK | ✅ `.ncx` | ❌ 取自身地址 |
| `nc_strdec_decrypt` / `b64_decode` / `utf8_to_utf16` | 公开编码算法 | ✅ `.ncx` | 不需要（公开算法） |

**VMP 覆盖率 3/10，但覆盖的是最值钱的三样**：
密钥（锁箱）+ 签名答案派生（VMP）+ splitmix64 密钥流（VMP）。

### 5.2 产物指标

| 项 | 无 VMP | 崩溃版（全局开关） | 当前 |
|---|---|---|---|
| arm64 so | 527,000 | 1,397,320 | **577,080** |
| `.ncx` | 40,152 | 40,304 | **44,432** |
| `.ncxr` | 96 | 96 | **104**（+8 字节密钥） |
| LOAD 段权限 | R-X/RW-/RW- | **含 RWE** | R-X/RW-/RW- ✅ |
| 真机启动 | ✅ | ❌ 栈溢出 | ✅ |

---

## 6. 为什么要保护密钥（比 VMP 算法重要得多）

**这是本轮最重要的认知修正。**

最初的思路是「VMP 算法」，但 splitmix64 / ChaCha20 都是**公开规范**
（RFC 8439 写着），逆出来没有任何价值。

**真正的秘密是那 8 字节种子**：
- 原来写成函数内 `static const` → 编译进 `.rodata` 【明文】
- 攻击者不需要逆任何东西，直接十六进制读出种子
- 配公开算法 → 解开全部字符串

「给公开算法上 VMP、把密钥留在明文」是本末倒置。

---

## 7. 已知未解（如实）

### 7.1 VMP 的字节码和解释器都在明文段

```
.ncxa 里的 wrapper（密文，解锁后可见）
  → bl .text 的 dispatcher（明文，随时可读）
      → 读 .rodata 的字节码（明文，随时可读）
```

`emit_runtime_bytecode_global` / `emit_descriptor_table` 是**模块级 global，
没有 section 属性**，落在 `.rodata`；dispatcher 是独立函数，落在 `.text`。

**攻击者不需要解 `.ncx`**，直接读 `.text` / `.rodata` 就知道函数被虚拟化成了什么。
虽然还得逆 VM 语义，但比解 `.ncx` 简单。

**下一阶段课题**：给 `emit_runtime_bytecode_global` 加 section 参数，
把字节码搬进 `.ncxr`。**注意**：搬进去之后，需要确认 dispatcher 能读到
（`.ncxr` 是 RW-，可读，所以理论可行）。

### 7.2 覆盖率只有 3/10

| 函数 | 差距 | 怎么办 |
|---|---|---|
| `nc_chacha20_keystream64` | `values=6 spilled=2` | 差一点，拆函数有希望 |
| `extract_cert_der` | `values=17` | 拆成 2-3 个小函数 |
| `sig_verify` | `values=21` | 同上，但改动风险高（冻结模块） |
| `find_apk_path` | 取自身地址（`dladdr`） | 把取地址移到调用方 |

**但收益评估**：这几个是「公开规范的解析」+「装配流程」，
真正有秘密的 `derive_expected` 已经 VMP 了。
**拆 `sig_check.c` 要改冻结模块，风险大于收益**。

### 7.3 v7a 上 VMP 不完整

| 特征 | arm64 | v7a |
|---|---|---|
| `0x7F4A7C15`（GAMMA 低 32 位）明文 | 0 处 | **18 处** |
| 64 位 GAMMA 明文 | 0 处 | **7 处** |
| `.text` | 648,176 | 1,325,220 |

arm64 上 GAMMA 完全消失（进了字节码），v7a 上还有明文 ——
**VMP 在 ARM32 上只做了一半：代码被膨胀了，但原始常量没被虚拟化**。

### 7.4 密钥在运行时内存是明文

锁箱只能保证「磁盘上是密文」。`.ncxr` 解锁后是 `RW-`，
Frida 能读到密钥。这是锁箱的本质限制（代码要执行，必然有明文的一刻）。

真要解决只有三条路：服务端取密钥 / 用 `--packer` 让密钥在另一个 so /
密钥用后即毁（stringenc 需要反复用，做不到）。

---

## 8. 验证清单（改 amice 或改 VMP 相关代码后照做）

```bash
# ① 本地加补丁并编译（需要 Rust + LLVM 21；没有就靠 CI）
cd ../防御仓库/amice
git commit -am "..." && git tag -a v0.1.6-noxN -m "..." && git push origin master --tags

# ② 触发 bundle 编译（会自动跑 smoke test）
gh workflow run release.yml -R zzgs219G/amice -f tag_name=v0.1.6-noxN

# ③ 换消费方 URL + cache key（两处 × 2）
#   ⚠️ cache key 必须改，否则命中旧 bundle 缓存，静默用旧版

# ④ 构建后查【产物】，不看日志
readelf -lW libnc.so | grep LOAD      # 不能有 RWE
readelf -SW libnc.so | grep -E 'ncx'  # .ncx 是 AX，.ncxr 是 WA
#   .ncx 里应有 180 字节级的 wrapper（算 token + bl dispatcher）
#   .ncxr 应比 96 字节多 8（密钥）

# ⑤ 真机验证（CI 绿说明不了任何事）
adb logcat | grep -E 'I nc *:|Fatal signal|UnsatisfiedLinkError'
#   期望：签名校验通过 / 无 Fatal signal / 无 UnsatisfiedLinkError / 进程存活
```

**判断 VMP 是否生效，不要看 `.ncx` 大小**（dex2c 产物混在里面会误导）：

| 可靠判据 | 方法 |
|---|---|
| `.ncx` 里有 wrapper | 小函数（180B 级）+ `bl` 到 `.text` 的 VMP 区 |
| 目标常量消失 | `0xBF58476D1CE4E5B9` 等在 so 里 0 处 |
| skip 日志 | `RUST_LOG=amice=debug` 里没有该函数名 |

---

## 9. 一句话交接

> **改 amice = 改 `zzgs219G/amice`，打 tag 走 CI，换 bundle URL + cache key。**
> **代码进 `.ncx`（可执行），数据进 `.ncxr`（可写）。混放 → RWX → Android 14+ 拒绝加载。**
> **每次换版必须真机验证** —— 上面 7 个坑里，CI 全绿也挡不住其中 5 个。
