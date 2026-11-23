# scripts/uncheck — 去签名校验

把任意 APK 改成「签名校验必然通过」的包。**产物未签名**，由使用者自行 `apksigner`。

这是 `artifact-pipeline` 里唯一一个**方向相反**的模块：
`scripts/guard/` 加防御，这里拆防御。两者刻意不共用代码，也不共用一个 workflow。

---

## 现在的主入口在 ApkForge，不在这里

**同一套逻辑已经移植到本地 App（`ApkForge`）**，那才是日常使用的形态：

```
ApkForge → 选 APK → 开始处理（约 3 秒，纯本地）→ 自己签名 → 装机
```

| | ApkForge（推荐） | 本目录（Python） |
|---|---|---|
| 形态 | 手机 App，点按钮 | shell / Python 脚本 |
| 运行环境 | 任意 Android | Termux（需 java + apktool） |
| 速度 | 约 3 秒 | 约 10~15 秒（apktool 解包占大头） |
| 载荷 | 从 json 仓库下载 | 本地 `payload/` 目录 |

**本目录的定位**：上游参考实现 + 云端 workflow 的执行端。
改逻辑时两边都要同步（`scripts/uncheck/payload/src/` 是唯一真相源，
ApkForge 用 `payload/build.sh` 的产物）。
ApkForge 侧的完整说明见它的 `../ApkForge/docs/去签名校验.md`。

---

## 用法

### 云端（App / CLI 触发）

```bash
RELAY_TOKEN=<token> python3 scripts/trigger_build.py app.apk \
    --workflow uncheck.yml \
    --config '{"schema_version":2,"uncheck":true}'
```

对应 `.github/workflows/uncheck.yml`。卡片定义在 `configs/v2/config-schema.json`
（v1 是加固，互不影响）。

### 本地（Termux / Linux）—— 完全离线，不需要云端

```bash
# 一条命令（纯本地：apktool + d8，不需要 NDK、不需要网络）
bash scripts/uncheck/uncheck.sh in.apk out-unsigned.apk --uncheck

# 然后自己签
apksigner sign --ks my.jks --out final.apk out-unsigned.apk
```

本地能跑全套的原因：本模块只改 dex + Manifest，**不需要 NDK 编译**
（`payload.dex` 是预先编好入 git 的，见 `payload/build.sh`）。
这与加固流水线不同 —— 那边要编 so，必须云端。

依赖：`java`（JDK 17+）、`tools/apktool.jar`（仓库自带）、
`scripts/string-enc/tools/d8.jar`（仓库自带）、`android.jar`（`SIGFIX_ANDROID_JAR`
可选指定，默认去 `~/android-sdk/platforms/android-*/android.jar` 找）、
`zipalign`（可选，找不到会明确警告而非静默）。

---

## 挂载点：Application（最早）

改了 `AndroidManifest.xml` 的 `android:name` 指向 `SigFixApp`，理由与时序有关：

```
ContentProvider.onCreate      ← 最早
Application.attachBaseContext ← 我们挂在这里（SigFixApp）
Application.onCreate
Activity.onCreate             ← 只挂这里会漏掉上面三种
```

`SigFixApp` 不是"替换"原 Application，而是**代理**：

1. `attachBaseContext` 里先装 hook（早于原 Application 初始化）
2. 反射创建**原来的** Application 实例（无参构造 + `Application.attach`）
3. 清零它的 `mBase`，再调它自己的 `attachBaseContext`（原初始化逻辑完整执行）
4. 替换 `ActivityThread.mInitialApplication`，之后回调都落到原实例
5. `onCreate` 转发给原实例

**为什么不学 MT 改父类**：MT 把原类的 `extends Application` 改成
`extends KillerApplication`，Manifest 不动。缺点是原类若继承
`TinkerApplication` / `MultiDexApplication`，换父类等于删掉那些逻辑，
App 起不来。代理链保住了原继承关系与全部初始化逻辑。

## 原理：改「系统返回值」，不改 App 代码

App 无论怎么写校验，最终必须从某个信息源取签名。本模块**只碰信息源**：

```
目标 App:  "PMS，我的签名是啥？"
              ↓
我们的代理:  "是 <原版证书>"        ← 这里撒谎
              ↓
目标 App:  算 hash → 与原版一致 → 判定通过
```

因为不改 App 的任何代码，**它用什么方式写校验、混淆成什么样都不影响本模块**。
这也是它「通用」的来源 —— 一旦要去找校验点在哪，就退回逐包手工分析了。

### 拦截点：`IPackageManager` 接口层

`SigFix.java` 把 `ActivityThread` 里持有 `IPackageManager` 的那个字段换成
`java.lang.reflect.Proxy`。选这层而不是 `IBinder.transact` 的字节层，是因为：

| | 接口层（本模块） | 字节层（SRPatch 等） |
|---|---|---|
| 拿到的对象 | 已反序列化的 `PackageInfo` | 原始 `Parcel` |
| 要做什么 | 改字段 | 重写 Parcel + 知道每个 transaction code 的布局 |
| 跨版本风险 | 低（AIDL 接口稳定） | 高（Parcel 布局随版本变） |

---

## 兼容性：这是本模块最花功夫的地方

「我这部手机能开、别人那部打不开」的每一类成因，都在代码里对应处理：

| 风险 | 处理 |
|---|---|
| 载荷抛异常导致闪退 | **每个步骤独立 try/catch**，任何失败静默降级，App 照常启动 |
| 字段改名（`sPackageManager` → `mPackageManager`） | **按字段类型查找**，不按名字 |
| `SigningDetails` 内部字段名变化 | 遍历所有 `Signature[]` 字段全部替换 |
| 只换 `signatures`、漏换 `pastSigningCertificates` | 两者都换（`getSigningCertificateHistory()` 会走后者） |
| 改到别的包的 `PackageInfo`（emoji Provider 等） | 按 `packageName` 过滤，只改目标包 |
| 与其它 hook 框架叠加 | `Proxy.isProxyClass` 检测，已代理就跳过 |
| 注入点寄存器越界（35c 上限 v15） | 插桩前校验物理编号，越界放弃该点 |
| dex 版本头被汇编器改成 040 | 按原包版本还原并重算 checksum/SHA-1 |
| 一个可用注入点都没有 | **fail-fast**，不产出「装进去却不生效」的包 |

### 时序

载荷挂在生命周期方法最前面。优先级：

```
Application.attachBaseContext  ← 最早（目标包有自定义 Application 时）
Application.onCreate
LAUNCHER.attachBaseContext     ← 常见情况（不 override 时自动新建覆写）
LAUNCHER.onCreate              ← 最晚，兜底
```

`install()` **幂等**，所以多个点会全部注入，哪个先跑都行。

---

## 覆盖边界（必须如实告知）

| 校验读取途径 | 覆盖 | 说明 |
|---|---|---|
| `getPackageInfo().signatures` | ✅ | |
| `getPackageInfo(GET_SIGNING_CERTIFICATES).signingInfo` | ✅ | |
| `getApkContentsSigners()` / `getSigningCertificateHistory()` | ✅ | |
| `hasMultipleSigners()` | ✅ | 我们只放 1 个签名，返回 false |
| `checkSignatures()` | ✅ | 同一个 `IPackageManager` |
| `getPackageArchiveInfo(自身路径)` | ✅ | 走同一接口 |
| 自读 APK 文件（`sourceDir` + ZipFile / 解析 Signing Block / `stat` 大小） | ✅ | native 层 IO 重定向（见 §native） |
| native so 读 APK（`open`/`fopen`/`__open_2`/`access`/`stat`） | ✅ | 同上，shadowhook inline hook |
| 硬编码 `/data/app/<pkg>/base.apk` 直呼 `svc #0` | ❌ | 绕过 libc，需 seccomp / SVC patch |
| native 硬编码证书哈希（`memcmp` 常量） | ❌ | 需逆向该 so 逐个 patch |
| 硬件证明（STRONGBOX Key Attestation） | ❌ | 证书链由系统 keystore2 进程从真实安装签名组装，App 内 hook 结构性无法伪造 |
| 上报服务端裁决 / Play Integrity / SafetyNet | ❌ | 安全层与硬件级证明，本地无法胜出 |

> **本模块只做「去签名校验」**，不含任何业务补丁（广告绕过 / 任务自动化 /
> 弹窗去除 / 反检测 / 探针伪造等）。那些是针对具体 App 的定制工作，
> 不属于通用能力，需要时由使用者自行按目标包处理。

### native 层（2026-11-23 新增，2026-11-24 补全）

`payload/c/usign_hook.c` 用字节跳动 shadowhook（inline hook）把目标进程里
**所有指向 base.apk 的文件操作**重定向到 `origin.apk`（原签名 APK 全量副本，
注入时放进 `assets/nc_sigfix/origin.apk`，运行时释放到 `codeCacheDir`）。

覆盖 **17 个**路径类 libc 函数：

```
open      open64    __open_2    openat    openat64   __openat_2  openat2
fopen     fopen64   access      faccessat  stat       lstat      statx
readlink  readlinkat opendir
```

- **为什么 `__openat_2` 必须挂**（2026-11-24 实测）：C 里写
  `openat(AT_FDCWD, path, O_RDONLY)`，`_FORTIFY_SOURCE` 会把它编成
  **`__openat_2`**，不是 `openat`。只挂 `openat` 等于没挂。
  同理 `readlinkat` 是 `readlink` 的 at 版本，各挂各的。
- 为什么覆盖全集而非按包裁剪：不同目标 so 的导入表（`readelf -r | grep JUMP_SLOT`）
  各不相同。挂全集靠 `is_target_apk` 精确匹配路径，不匹配立即透传，开销可忽略。
- 为什么只 hook 路径类不 hook fd 类：`open` 返回的 fd 指向 origin.apk 后，
  后续 `fstat`/`mmap`/`read` 自然正确；反向 hook 需维护 fd→path 映射，易错。
- 编译：`bash payload/c/build-native.sh`（需 NDK；无 NDK 时 `build.sh` 自动跳过）

#### ⚠️ 通用 hook 的硬边界（如实，别高估）

加固侧（`scripts/guard`）已升级为**多路取证书 + 交叉比对**。本模块补全 hook
后实测：6 条路线中能拦住 3 条，另外 3 条属于技术边界，**不是没做**：

| 路线 | 为什么拦不住 |
|---|---|
| 内联 `svc #0` | 指令长在调用方函数体里，没有符号、没有独立函数可供 inline hook |
| `syscall()` 的 inline 展开 | 同上 |
| `/proc/self/fd/N` 复用系统已开 fd | 压根不发起 `open` |

要破这 3 条只能去改加密段 `.ncx` 里的指令 —— 那是针对性逆向，不再是
"通用去校验"。详见 [`scripts/guard/README.md`](../guard/README.md) 的
「签名校验：多路取证书」一节。

- 详细踩坑（含 Android 16 必需的 shadowhook 补丁）见
  [`../../docs/签名校验接手文档.md`](../../docs/签名校验接手文档.md)

后两类是**结构性无解**，不是「还没做」。工具不会假装能处理它们，
也不会在这种包上产出一个「装上去才发现没用」的结果。

---

## 目录

```
scripts/uncheck/
├── uncheck.sh                 总控（参数 → run.py → 产物自检）
├── run.py                     端到端：解包 → 注入 → 汇编 → 组装 → 对齐
├── inject.py                  在解包目录上注入（提证书 → 烘焙 → 选落点 → 插桩）
├── resolve.py                 configs/v2 卡片 → uncheck.sh 参数
├── payload/
│   ├── src/com/nc/uncheck/SigFix.java   载荷唯一源码真相（人读）
│   ├── build.sh               javac → d8 → baksmali（照 build-stub.sh 先例）
│   └── SigFix*.smali          build.sh 产物，入 git，**永不手改**
└── tools/
    └── VerifySmali.java       用 apktool 内的 dexlib2 汇编 smali（绕过 aapt2）
```

`VerifySmali.java` 存在的原因：`apktool b` 会重编资源（aapt2），
在非 x86 环境经常跑不起来，而本模块**只改 dex，资源一个字节都不动**，
没必要重编。dexlib2 的 `SmaliBuilder` 就是 apktool 内部用的那个。

---

## 已知未实现

| 项 | 状态 |
|---|---|
| `--file-redirect`（自读 APK 覆盖） | 勾选后 **fail-fast**，不静默降级 |
| 出包前体检（扫描 App 用了哪类取签名途径） | 未实现 |
| 贴顶大包新建 `classesN.dex` | 原包 `classes.dex` 方法数贴顶时 `run.py` 会报错退出 |

---

## AXML 改写的两个致命细节（真机实测）

挂载 `android:name` 需要写二进制 AXML。这两点写错时的症状**完全一样**
（系统读不到该属性、App 照旧跑原类、没有任何报错），但原因不同：

### ① 属性必须插在 resourceId 升序位置，不能追加末尾

`PackageParser` 解析 `<application>` 时按 framework 资源 ID 升序读，
**遇到乱序会提前停止扫描**，后面的属性全部丢弃。

`android:name` 的 ID 是 `0x01010003`，在这批属性里最小 → 必须插最前。
对照 MT 生成的包（`JMComic3v2.1.14_kill.apk`）逐字节验证：

```
MT  : [3]  41000000 03000000 4d000000 0800 00 03 4d000000   ← 插在第 4 位
错误: [11] ...                                              ← 追加到末尾，系统读不到
```

### ② rawValue 必须是字符串池索引，不是 NO_INDEX

属性 20 字节布局：

```
ns(4) name(4) rawValue(4) size(2) res0(1) dataType(1) data(4)
```

`rawValue` 与 `typedValue.data` **都要填字符串池索引**（两者相同）。
写成 `NO_INDEX(0xFFFFFFFF)` 时 androguard 和系统都读不出值。

原包自带的 `appComponentFactory` 就是这个形态（`raw=0x2e data=0x2e`），
可以直接拿来对照。

### 验证方法

```bash
# 1) 自己的解析器能读回
python3 scripts/uncheck/axml_edit.py get-app-name <manifest>

# 2) androguard 也能读回（独立实现，能发现自洽性错误）
repy -c "
import logging; logging.disable(logging.CRITICAL)
from androguard.core.axml import AXMLPrinter
import re
p=AXMLPrinter(open('<manifest>','rb').read())
xml=p.get_xml().decode()
print(re.search(r'android:name="([^"]*)"', re.search(r'<application[^>]*', xml).group(0)).group(1))
"

# 3) 装机后看系统是否识别（唯一权威判据）
adb shell "dumpsys package <pkg> | grep -oE 'ApplicationInfo\{[^}]*\}'"
#   能看到 className=<我们的类> 才算真的生效

# 4) 回归测试（用真实 Manifest 做夹具）
python3 scripts/uncheck/tests/test-axml.py <manifest>
```

## 改代码前必读（清单）

1. `SigFix.smali` 是**生成物**。改载荷请改 `payload/src/SigFix.java`，
   然后 `bash payload/build.sh`。直接改 smali 会在下次构建被覆盖。
2. `inject.py` 的 `SENTINEL` 必须与 `payload/build.sh` 的逐字一致，
   否则证书烘焙会静默失败（有自检拦截）。
3. 载荷里**不得新增 `catch` 之外的抛出路径**。`install()` 是「宁可没生效，
   更不能让宿主闪退」的语义，任何新增代码都要满足这条。
4. 改完跑 `tests/`，并在真机上验证一次 —— 静态合法不等于运行正常。

## 实现要点（为什么这么设计）

### 载荷分两个 dex，不能合并

```
boot.dex      SigFix + SigFixApp  → 进目标 App 的 classes{N+1}.dex
payload.dex   SigFixImpl           → 进 assets，运行时 new DexFile(path) 加载
```

`SigFixImpl` 必须由 **BootClassLoader** 加载才能反射访问 hidden API。
编进 App 自己的 dex → 应用域 → 反射被拦（实测 Android 17：
`setHiddenApiExemptions` 直接 `blocked`，报 `NoSuchMethodException`）。

### 载荷类是静态的，配置在 JSON 里

```
payload/*.dex              不含任何目标相关数据（可入 git / 可下载 / 可缓存）
assets/nc_sigfix/sigfix.json  唯一的目标相关数据：
                              {"cert": "<原证书 DER 的 Base64>", "originalApp": "com.x.Y"}
```

为什么不做「烘焙进 dex」：证书长度随 keystore 变（888~1152 字符），
改 dex 字符串池要重建；且每换一个目标 App 就要重编 dex。

### 每一步都必须兜住异常

`install()` / `attachBaseContext()` 里**严禁往上抛**。
目标 App 千奇百怪，我们的假设随时会错；崩了就等于这个模块不可用。

MT 的实现在简盒 v2.1.2 上就是栽在这：`IllegalAccessException`（改 static final
被拒）→ 抛 `RuntimeException` → `ExceptionInInitializerError` → App 在
`makeApplicationInner` 阶段崩。我们遇到同一条异常只记日志。

### 载荷类禁止读静态字段

handler 会被 `handlerLoader` 重新加载成另一个 Class 副本，静态字段不共享。
数据一律经构造器传入。

---


## 两边同步纪律与回归测试


| 改什么 | 同步到 |
|---|---|
| `scripts/uncheck/payload/src/*.java` | 跑 `payload/build.sh` → 产物 `boot.dex` / `payload.dex` 发布到 json 仓库 |
| `scripts/uncheck/axml_edit.py` 的逻辑 | `ApkForge/core/axml/AxmlEditor.kt` 必须同步改（两份实现，同样两条红线） |
| 载荷版本 | json 仓库 `backend/uncheck/index.json` 的 version + sha256 |

**唯一真相源是 `payload/src/`**，ApkForge 只消费编译产物。

---

## 回归测试

```bash
# AXML 改写（8 组断言，用真实 Manifest 做夹具）
python3 scripts/uncheck/tests/test-axml.py <path-to-AndroidManifest.xml>

# 夹具从任意 APK 取：
unzip -p app.apk AndroidManifest.xml > /tmp/m.xml
```

T4（插在升序位）/ T5（`raw == data` 且为字符串类型）钉死的正是坑 39 的两个根因。
