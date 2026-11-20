# scripts/uncheck — 去签名校验

把任意 APK 改成「签名校验必然通过」的包。**产物未签名**，由使用者自行 `apksigner`。

这是 `artifact-pipeline` 里唯一一个**方向相反**的模块：
`scripts/guard/` 加防御，这里拆防御。两者刻意不共用代码，也不共用一个 workflow。

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
| 自读 APK 文件（`sourceDir` + ZipFile / 解析 Signing Block / `stat` 大小） | ❌ | 需文件系统层重定向 + 原包副本，见下 |
| 硬编码 `/data/app/<pkg>/base.apk` | ❌ | 路径含随机后缀，只能 syscall 级 hook |
| 解析 `/proc/self/maps` | ❌ | 同上 |
| 上报服务端裁决 | ❌ **无解** | 本地无法胜出 |
| Play Integrity / SafetyNet / Key Attestation | ❌ **无解** | 硬件级证明 |

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

## 改代码前必读

1. `SigFix.smali` 是**生成物**。改载荷请改 `payload/src/SigFix.java`，
   然后 `bash payload/build.sh`。直接改 smali 会在下次构建被覆盖。
2. `inject.py` 的 `SENTINEL` 必须与 `payload/build.sh` 的逐字一致，
   否则证书烘焙会静默失败（有自检拦截）。
3. 载荷里**不得新增 `catch` 之外的抛出路径**。`install()` 是「宁可没生效，
   也不能让宿主闪退」的语义，任何新增代码都要满足这条。
4. 改完跑 `tests/`，并在真机上验证一次 —— 静态合法不等于运行正常。
