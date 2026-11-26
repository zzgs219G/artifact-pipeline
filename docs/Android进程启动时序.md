# Android 进程启动时序 — 注入点怎么选

> **本文回答一个问题：想在「目标 App 的任何代码执行之前」注入一段逻辑，
> 有哪些位置、各自的时机和代价是什么。**
>
> 写于 2026-11-27。起因：讨论「用 AXML 注册替代改 Application 类名」时，
> 发现仓库里一处文档把 `ContentProvider` 与 `Application` 的先后写反了，
> 而每次讨论都要重新推一遍时序 —— 这份表就是那个推演过程的结果。
>
> ⚠️ 以 AOSP `ActivityThread.handleBindApplication()` 为准。
> 厂商 ROM 可能有差异，但下面这些是 Android 框架层的契约，不是实现细节。

---

## 0. 一句话结论

**`Application.attachBaseContext()` 是「能改的地方里最早的一个」。**
比它更早的只有 `ActivityThread` 内部（系统类，改不了）。

想要更隐蔽，只能换**同一时机或更早**的挂载点 —— 换到更晚的点是净损失。

---

## 1. 完整时序（进程启动 → 首页可见）

```
zygote fork 出新进程
  │
  ├─ ActivityThread.main()                        ⛔ 系统类，不可改
  │
  └─ handleBindApplication()
       │
       ├─ ① LoadedApk.makeApplication()
       │     │
       │     ├─ appComponentFactory.instantiateApplication()   ← AXML 属性
       │     │     （Android 9+；默认是 androidx 的 CoreComponentFactory）
       │     │
       │     ├─ new Application()                    ← 可改构造器
       │     │
       │     ├─ attachBaseContext(base)              ← ★ 最早的可改点
       │     │     现在 SigFix / Guard 就挂在这里
       │     │
       │     └─ Application.onCreate()               ← 可改
       │
       ├─ ② installContentProviders()
       │     └─ 每个 Provider 的 onCreate()          ← 可改（比 ★ 晚）
       │
       └─ ③ Instrumentation.callApplicationOnCreate() 之后
             └─ Activity.onCreate()                  ← 最晚
```

**关键：③ 里的 Activity.onCreate 之前，② Provider 已经在跑；
② 之前，① 里的 attachBaseContext 已经跑完。**

---

## 2. 五个可选挂载点逐一对比

| # | 挂载点 | 时机 | 怎么改 | 隐蔽性 | 删除难度 |
|---|---|---|---|---|---|
| 1 | `appComponentFactory` | **最早**（比 attachBaseContext 还早） | AXML 改一个属性 | **高**（属性名很常见，AndroidX 本来就用它） | 中 |
| 2 | `new Application()` 构造器 | 早 | 改 dex 字节码 | 低 | 中 |
| 3 | **`attachBaseContext`** | **★ 现用** | 改 Application 类（换成我们的代理类） | **低**（类名 `com.nc.uncheck.SigFixApp` 一眼可见） | 中（双保险） |
| 4 | `Application.onCreate` | 中 | 改 dex | 低 | 中 |
| 5 | `ContentProvider.onCreate` | **最晚** | AXML 加子元素 | **高**（可混在系统 Provider 里） | **易**（删掉即可绕过） |

### 为什么 Provider 看起来最隐蔽却最不推荐

| 劣势 | 说明 |
|---|---|
| 时机最晚 | 目标 App 若在 `Application.onCreate` 里读 APK，Provider 来不及 |
| 最易被删 | 删掉 `<provider>` 元素 = 完全绕过，没有任何兜底 |
| 插入成本最高 | 要扩字符串池 + 插 START/END 元素 + 补 resource map（`axml-add-profileable.py` 在这上面失败过 6 轮） |

**隐蔽性换来的代价是「更晚 + 更脆」，不划算。**

---

## 3. 时序与「能拦住什么」的关系

时序早，只意味着「跑在别人的代码前面」。能拦住什么，取决于**挂上去之后 hook 了哪些接口**。

| 目标的校验代码在哪 | 需要的最晚时机 |
|---|---|
| `Application.onCreate` | `attachBaseContext` 或更早 |
| `ContentProvider.onCreate` | `attachBaseContext`（因为 Provider 更晚） |
| `Activity.onCreate` | `attachBaseContext` |
| **`Application` 的 `static {}`（`<clinit>`）** | **比 `new Application()` 还早 —— 只能靠双保险的另一处（`<clinit>` 自己）** |

最后一行是关键：**`<clinit>` 在类第一次被用到时执行，可能早于 `attachBaseContext`**
（`LoadedApk.makeApplication` 加载 Application 类时就会触发它的 `<clinit>`）。
所以双保险里 `<clinit>` 那份不是冗余，是覆盖「Application 自己的静态初始化」这个
最早的时机。

---

## 4. 现在实际用的是什么

```
sigcheck 单独方案（--sigcheck 不配 dex2c）
  ├─ inject-loadlib.py --entrypoints
  │    → <clinit> 插 System.loadLibrary   （覆盖 Application 静态初始化）
  │    → onCreate 插 System.loadLibrary   （覆盖 <clinit> 被删的情况）
  └─ Guard.java 的 catch(UnsatisfiedLinkError) → kill()   （so 缺失兜底）

去校验（scripts/uncheck/）
  └─ 改 android:name="com.nc.uncheck.SigFixApp"
       → SigFixApp.attachBaseContext 里调 SigFix.install()
```

两套都挂在**最早可用的位置**，区别只在于「改 dex 还是改 manifest」。

---

## 5. 如果将来要换挂载点

**能不能换，先看这条**：

| 想解决的问题 | 该换到哪 |
|---|---|
| 类名太显眼（`com.nc.uncheck.SigFixApp`） | `appComponentFactory`（更早 + 属性常见） |
| 想尽量少改 dex | `appComponentFactory` 或 Provider |
| 想覆盖 `<clinit>` 级别的初始化 | 只能继续用 `<clinit>` 注入，没有替代 |

**`appComponentFactory` 的注意点**：

```xml
<!-- 原包可能已经有这个属性 -->
android:appComponentFactory="androidx.core.app.CoreComponentFactory"
```

不能直接覆盖（会破坏 AndroidX 的组件实例化），必须**继承**：

```java
public class X extends androidx.core.app.CoreComponentFactory {
    @Override public Application instantiateApplication(ClassLoader cl, String name) {
        Application app = super.instantiateApplication(cl, name);
        /* 这里注入 —— 比 attachBaseContext 更早 */
        return app;
    }
}
```

`instantiateApplication` 里拿到的是 `Application` 实例但**尚未 `attach`**，
所以 `getBaseContext()` 还是 null —— 能做的是纯 native 侧的初始化（如 `System.load`），
依赖 Context 的动作要留到 `attachBaseContext`。

---

## 6. 常见误解（本文存在的原因）

| 误解 | 事实 |
|---|---|
| ❌ `ContentProvider.onCreate` 早于 `Application.attachBaseContext` | **反了**。Provider 在 `installContentProviders()` 里跑，那是 `makeApplication()` 之后 |
| ❌ 挂在 `Activity.onCreate` 足够早 | 太晚。`Application.onCreate` 和 Provider 都已经跑完了 |
| ❌ `<clinit>` 和 `onCreate` 双保险，`<clinit>` 是冗余 | 不冗余。`<clinit>` 覆盖「Application 类自己的静态初始化」，比任何 Application 方法都早 |
| ❌ 注入点越早，能拦的越多 | 时序只是前提。能拦什么取决于 hook 了哪些接口（见 §3） |
