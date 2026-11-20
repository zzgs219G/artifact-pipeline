# scripts/uncheck — 去签名校验

把任意 APK 改成「签名校验必然通过」的包。**产物未签名**，由使用者自行 `apksigner`。

这是 `artifact-pipeline` 里唯一一个**方向相反**的模块：
`scripts/guard/` 加防御，这里拆防御。两者刻意不共用代码，也不共用一个 workflow。

---

## 用法

### 云端（App / CLI 触发）

```bash
RELAY_TOKEN=<token> python3 scripts/trigger_build.py app.apk \
    --workflow protect-uncheck.yml \
    --config '{"schema_version":2,"uncheck":{"enabled":true,"pms":true,"report":true}}'
```

对应 `.github/workflows/protect-uncheck.yml`。卡片定义在 `configs/v2/config-schema.json`
（v1 是加固，互不影响）。

### 本地（Termux / Linux）

```bash
# 一条命令
bash scripts/uncheck/uncheck.sh in.apk out-unsigned.apk --pms --report

# 然后自己签
apksigner sign --ks my.jks --out final.apk out-unsigned.apk
```

依赖：`java`（JDK 17+）、`tools/apktool.jar`（仓库自带）、
`scripts/string-enc/tools/d8.jar`（仓库自带）、`android.jar`（`SIGFIX_ANDROID_JAR`
可选指定，默认去 `~/android-sdk/platforms/android-*/android.jar` 找）、
`zipalign`（可选，找不到会明确警告而非静默）。

---

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

后两类是**结构性无解**，不是「还没做」。`--report` 检出时应明确报 UNBYPASSABLE，
而不是产出一个装上去才发现没用的包。

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
| `scan.py`（体检报告） | 未实现，`--report` 会明确告警后继续 |
| 贴顶大包新建 `classesN.dex` | 原包 `classes.dex` 方法数贴顶时 `run.py` 会报错退出 |

---

## 改代码前必读

1. `SigFix.smali` 是**生成物**。改载荷请改 `payload/src/SigFix.java`，
   然后 `bash payload/build.sh`。直接改 smali 会在下次构建被覆盖。
2. `inject.py` 的 `SENTINEL` 必须与 `payload/build.sh` 的逐字一致，
   否则证书烘焙会静默失败（有自检拦截）。
3. 载荷里**不得新增 `catch` 之外的抛出路径**。`install()` 是「宁可没生效，
   也不能让宿主闪退」的语义，任何新增代码都要满足这条。
4. 改完跑 `tests/`，并在真机上验证一次 —— 静态合法不等于运行正常。
