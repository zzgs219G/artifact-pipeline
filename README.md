# artifact-pipeline

GitHub Actions 脚本集合，按配置顺序执行构建步骤。

## 文档导航

| 你要做什么 | 读哪份 |
|---|---|
| **改完代码要发版**（打 tag / 换分发包 / 跑构建的顺序） | **[docs/发布与验证流程.md](docs/发布与验证流程.md)** ← 每次发版前必读 |
| **第一次接触**（这个仓库干什么、目录怎么分） | [docs/项目导览.md](docs/项目导览.md) |
| **跑一次构建**（流程、参数、验收） | [docs/流程文档.md](docs/流程文档.md) |
| **遇到报错**（现象 → 根因 → 修法） | [docs/报错速查.md](docs/报错速查.md) |
| **要看 so 自检报告**（出调试包） | [docs/调试包怎么出.md](docs/调试包怎么出.md) |
| **改代码前的硬约束**（冻结清单、契约、纪律） | [docs/AI接手文档.md](docs/AI接手文档.md) |
| **改 so 层防护**（段布局 / VMP / 密钥链） | [../nox/docs/so防护架构.md](../nox/docs/so防护架构.md) §0 和 §15 |
| **查某个决定当时为什么这么做** | [docs/变更历史/](docs/变更历史/README.md)（4 份分卷，**按关键词 grep**） |
| **配置项怎么填** | [docs/配置schema.md](docs/配置schema.md) |
| **模块之间怎么联动** | [docs/模块联动关系.md](docs/模块联动关系.md) |
| **去签名校验模块**（`scripts/uncheck/`，**不是加固**） | [scripts/uncheck/README.md](scripts/uncheck/README.md) |

### ⚠️ 本仓库有两条方向相反的线

```
scripts/guard/    等  → 加固：给 APK 加防御（configs/v1 卡片）
scripts/uncheck/       → 去校验：拆掉别人的防御（configs/v2 卡片）
```

两者**不共用代码、不共用一个 workflow、不共用一个文档**。
改其中一条之前先确认自己在哪条线上 —— 把去校验的改动混进加固文档是明确禁止的。

### ⚠️ 两条文档使用纪律

1. **`docs/变更历史/` 有 151 条记录，按关键词 grep，不要通读** ——
   原来是单文件 368 KB（现已按主题拆成 4 卷）。用
   `grep -rn '关键词' docs/变更历史/` 按需搜。
2. **文档里的「历史状态」不等于「当前状态」** ——
   长期演进的文档（尤其 `变更历史/`、`so防护架构.md`）里大量
   "某功能已关闭/已回滚"这类表述，指的是当时的临时状态。
   **验证当前状态最可靠的方式是跑一遍产物看实际行为**，
   不是读文档。

---

## 快速上手

```bash
# 触发一次构建（产物自动下载到 /sdcard/Download/）
RELAY_TOKEN=<token> python3 scripts/trigger_build.py app.apk \
    --sigcheck --dex2c --vmp --sign
```

各模块含义见 [docs/项目导览.md](docs/项目导览.md)。
