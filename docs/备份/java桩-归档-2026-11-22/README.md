# Java 解密桩 — 归档（2026-11-22）

> **这里的东西不再参与构建。** 保留是为了「万一以后有用」。
> 现行唯一路径是**纯 C 桩**（`scripts/string-enc/csrc/`，算法在 `libnc.so`）。

## 为什么归档

`stringenc` 原本有两条解密桩路线，靠 schema 的 `stringenc.stub_impl`
（`java` / `c`）二选一：

| | Java 桩（已归档） | 纯 C 桩（现行） |
|---|---|---|
| 算法在哪 | `StrDec.java` → smali（在 dex） | `csrc/nc_strdec.c`（在 `libnc.so`） |
| 密钥在哪 | `SEED:J` 字段（dex 字面量） | 编译进 `nc_strdec_cfg.h`（dex 零密钥） |
| 算法进 so 的方式 | 需 `dex2c_stub` 交引擎转译 | **天然就在 so** |
| dex 侧残留 | 桩类 + `<clinit>` | 只有 native 声明 + `loadLibrary` |
| 构建耗时 | 多一次解包/回编（+30~60s） | 无额外轮次 |

**C 桩在每一项上都更优**，且两条路产出的**密文格式完全相同**
（`encrypt-strings.py` 的 `STUB_IMPL` 不参与加密，只决定生成哪种桩）。
所以 Java 桩是纯粹的历史包袱。

## 归档内容

```
stub-src/StrDec.java      语义真相源（人读；smali 按此生成）
stub-src/StrDec.smali     生成物，勿手改
build-stub.sh             编译链：javac → d8 → baksmali
```

## 如果以后要恢复

1. 把 `stub-src/` 与 `build-stub.sh` 移回 `scripts/string-enc/`
2. 恢复 `encrypt-strings.py` 的 `--stub-impl java` 分支与
   `--emit-stub-dex` / `--emit-stub-filter` / `--compiled-methods` /
   `--stub-seed-from-shell` / `--assume-stub-transpiled` 五个参数
3. 恢复 `protect.sh` 的 `LINK_STUB` 前置轮（见 git 历史 `b655f0a` 之前的版本）
4. 恢复 schema 的 `stringenc.stub_impl` choice 子项
5. 恢复 `tests/test-link-dex2c.sh` 等联动测试

**git 历史里有完整实现**，不需要从这里抄：

```bash
git log --oneline -- scripts/string-enc/stub-src/
git show <commit>:scripts/string-enc/stub-src/StrDec.java
```

## 关键区别：`dex2c_stub` 接口本身保留

**别把两件事搞混**：

| | 是什么 | 现状 |
|---|---|---|
| `--dex2c-stub` **接口机制** | 允许**流水线中途注入的 Java 代码**被 dex2c 转译 | ✅ **保留** |
| `--dex2c-stub` 的**当前唯一调用方** | Java 解密桩（`d()/dn()/mix64()/keyByte()`） | ❌ 随 Java 桩一起归档 |

接口存在的理由是：dex2c **模块**（STEP2）作用在**原始 APK** 上，只能看到
原包里已存在的类；而流水线**注入**的类（解密桩、`inject-javacheck` 的桥接类等）
在 STEP2 执行时还不存在。所以需要第二个入口，在注入之后调用 dex2c。

```
dex2c 模块  →  作用在原始 APK（用户规则/主类）
dex2c 接口  →  作用在「注入之后」的 dex（内部模块调用）
```

Java 桩删掉后接口暂时没有调用方，但**机制要留着**——加新的 Java 插桩模块时
它会重新有对象。见 `docs/手动归档说明` 与 `protect.sh` 的 `LINK_STUB` 段。
