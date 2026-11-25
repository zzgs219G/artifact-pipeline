# scripts/repack — APK 解包后的原地改写工具

一组**单一职责**的 py/sh 工具，被 `protect.sh` 在"解包 → 处理 → 回编"之间调用。
每个都只改一件事，改动都是**原位二进制改写**（不重新序列化 AXML），因为
apktool 回编会丢属性、降 dex 版本。

## 文件

| 脚本 | 职责 |
|---|---|
| `mark-native.py` | 把 dex2c 转过的方法在 smali 里改成 native 壳（不可跳过） |
| `patch-extractnativelibs.py` | 二进制 AXML 改写 `extractNativeLibs`（可复用的 AXML 基础模块） |
| `patch-debuggable.py` | 二进制 AXML 强制 `debuggable=false` |
| `patch-dex-version.py` | 修复 apktool 回编降级 dex 版本导致的问题 |
| `dex-capacity.py` | dex 方法数容量检测 + 注入落点选择（纯 stdlib，零依赖） |
| `dex-rebalance.py` | 重排 smali 目录，让每个 dex 的 `method_ids` 留足余量 |
| `partial-reuse.py` | 手写 ZIP，让与 `origin.apk` 内容相同的条目指回它的内部偏移（119MB → 69MB） |
| `keep-sig-block.py` | 回编后把原包的 APK Signing Block 原地写回（证书 DER 可读） |
| `verify_text_crc_ready.py` | 校验 `.text` 是否满足「代码自绑定」的前提 |

## 为什么用二进制 AXML 改写而不是 apktool

apktool 解包→回编会丢掉它不认识的属性，且会把 dex 版本降级。
`extractNativeLibs` / `debuggable` 这类**安全相关属性**丢了的后果是静默的
（App 照跑，但那层防护没生效）。所以这几项一律直接改 Manifest 二进制。

⚠️ 改 AXML 有两条硬红线（属性按 resourceId 升序插入 / rawValue 必须是字符串池索引），
详见 `scripts/uncheck/README.md` §AXML ——**同一套 AXML 知识，两处共用**。

## 谁调用

```
scripts/pipelines/protect.sh STEP5（解包后）
  ├─ patch-extractnativelibs.py   强制 extractNativeLibs=true
  ├─ patch-debuggable.py          强制 debuggable=false
  ├─ patch-dex-version.py         修 dex 版本
  ├─ mark-native.py               dex2c 方法 → native 壳
  └─ dex-capacity.py / dex-rebalance.py  插桩后局部拆分
```

## 改之前

- `dex-capacity.py` 是**纯 stdlib**（读 dex header，0.24s）—— 别引入 androguard，
  它慢几十倍且这里只需要 `method_ids_size`。
- `dex-rebalance.py` **不要改成全量重排** —— 试过三次全部失败
  （见 `docs/流程文档.md` §3.13.6）。
- 改完跑 `scripts/repack/tests/`。
