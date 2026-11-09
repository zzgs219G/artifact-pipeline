# config-schema.json 字段字典与扩写手册

> **本文件是 `configs/v1/config-schema.json` 的唯一说明文档。**
> 改 schema 前先读这里；读完仍不确定，再去看 `scripts/actions/resolve-config.py`。
>
> ⚠️ **本文与源码冲突时以源码为准。** 字段语义的真相源是
> `scripts/actions/resolve-config.py`（执行侧）与 `scripts/actions/check-schema.py`（校验侧）。
>
> 为什么需要这份文档（2026-11-09）：此前"改 schema / 加勾选项"的指引只有一句
> 「读 `config-schema.json` + `resolve-config.py`」。而 schema 有 **4 个消费者**，
> 每个对同一份文件的期望不同，全靠读代码推断 —— 加一个子选项要动几个文件、
> 哪些地方会 fail-fast、UI 层拦不拦，没人能一次说清。

---

## 0. 三十秒定位

```
configs/v1/config-schema.json          ← 唯一真相源（UI + 校验 + 执行映射三合一）
        │
        ├─→ jian_box／ProtectConfigSchema.kt   解析 → 渲染勾选界面 → 生成 protect_config
        │                                      （APP 读的是 zzgs219G/json 的镜像，不直连本仓库）
        ├─→ scripts/actions/check-schema.py   静态结构自检（CI 第一批）
        ├─→ scripts/actions/resolve-config.py protect_config JSON → protect.sh 参数
        └─→ scripts/pipelines/protect.sh      收到参数后自己再校验一遍
```

**加一个新模块 = 只改 schema 一处**（这是设计目标，见 `docs/流程文档.md` §0.1）。
**加一个子选项 = 改 schema + 查 `resolve-config.py` 有没有对应 `value_kind` 分支。**
两种改动的成本差一个量级，别混为一谈。

---

## 1. 模块级字段

`schema.modules[]` 的每一项。**`type` 只有两个合法值**，`check-schema.py` 会断言。

| 字段 | 必填 | 取值 | 说明 |
|---|---|---|---|
| `key` | ✅ | 全仓唯一 | 同时是 `protect_config` 的顶层 key、argv 的来源、`schema_rules/<key>.txt` 的文件名 |
| `label` | ✅ | 中文字符串 | UI 行标题 |
| `desc` | ✅ | 中文字符串 | UI 帮助弹窗；**性能影响必须写在这里**（项目约定，见 §5） |
| `type` | ✅ | `"leaf"` \| `"parent"` | leaf=无子选项；parent=有 `children` |
| `default` | ✅ | 布尔 | 首次进入页面时的勾选态 |
| `arg` | ✅ | `--xxx[-yyy]` | 勾选时追加给 `protect.sh` 的参数。**必须匹配 `--[a-z0-9]+(-[a-z0-9]+)*`** |
| `group_label` | ❌ | 字符串 | 子项区顶部的分组标题。**当前 UI 刻意不渲染它**（子项自己的 label 就是标题，见 §6.1） |
| `children` | parent 必填 | 数组 | 子项，见 §2 |

### 1.1 `leaf` vs `parent` 的 enabled 语义不同（最容易搞错）

`protect_config` 里两种形态的**值类型不同**：

```jsonc
// leaf：顶层直接是布尔
{ "schema_version": 1, "sigcheck": true, "antidiff": false }

// parent：顶层是对象，勾选态在 .enabled
{ "schema_version": 1,
  "stringenc": { "enabled": true, "rules_file": "**", "dex2c_stub": false } }
```

`resolve-config.py` 的 `read_enabled()` 两条路径都实现，且**双向兼容旧快照**：

- `parent` 收到顶层 bool（旧版 App 把 parent 当 leaf 提交）→ 按 leaf 读
- `leaf` 收到 dict（旧版 App 把 leaf 当 parent 提交）→ 按 `.enabled` 读

**这意味着 `leaf` ⇄ `parent` 互转是向后兼容的**，历史上有过两次（`antidiff` 升 parent 又退回 leaf）。
但**新增子选项不需要升 `schema_version`** —— 旧快照缺该键被当作 `default`（见 §3.3）。

⚠️ **升 `schema_version` 是有代价的**：APP 侧写死 `MAX_SUPPORTED_SCHEMA_VERSION = 1`，
远端版本更高 → UI 弹「请升级 App」。所以**加字段/加模块一律保持 `schema_version: 1`**，
升版本只用于"旧 App 拿到新配置会做出错误行为"的不兼容改动。历史所有模块增删
（`dcc` 下线、`packer` 接入、`obfuscate` 接入、`stub_impl` 新增）都没升过版本。
`check-schema.py` 只断言 `schema_version` 与目录名一致（`v1` → `1`）。

---

## 2. 子项字段（`children[]`）

| 字段 | 必填 | 说明 |
|---|---|---|
| `key` | ✅ | 模块内唯一，扁平化成 `"<模块key>.<子key>"` 给 UI 状态用 |
| `label` | ✅ | UI 标题 |
| `type` | ✅ | **渲染形态**：`"text"` \| `"checkbox"` \| `"select"`。决定 UI 怎么画，**不决定执行语义** |
| `desc` | ❌ | 子项说明（checkbox/select 显示在 label 下方或帮助里） |
| `multiline` | ❌ | 仅 `type=text`，多行输入框 |
| `hint` | ❌ | 校验失败时拼进报错文案（`required` 校验用） |
| `default` | ✅ | `type=text`/`select` 用**字符串**；`type=checkbox` 用**布尔** |
| `value_kind` | ❌ | **执行语义**，见 §3。`null` = 不进 `protect_config`、不产生任何参数 |
| `required` | ❌ | `{"when": "always", "unless": {"key": "<模块key>", "is": <bool>}}` |
| `arg_on` | ❌ | `value_kind=flag/arg_value` 必填；`choice` 时挂在 option 上 |
| `arg_value` | ❌ | 仅 `value_kind=arg_value`，与 `arg_on` 成对（见 §3.2） |
| `options` | ❌ | 仅 `type=select`/`choice`，`[{value,label},...]` |

### 2.1 `type` 与 `value_kind` 是**两套正交语义**

这是整份 schema 最容易误解的地方：

```
type       = 怎么画        （UI 层唯一关心的）
value_kind = 怎么执行      （resolve-config.py 唯一关心的）
```

两者**没有强制配对关系**。同一个 `value_kind=flag` 可以画成 checkbox；同一个
`value_kind=choice` 可以画成 select 或 radio（见 §4）。当前 schema 里恰好都是
"顺理成章"的搭配，所以看不出正交性 —— 但改的时候必须意识到它。

**为什么 `value_kind` 可以是 `null`**：某些子字段只是 UI 展示或纯 APP 侧用，
不进流水线参数。历史上 `lightobf.mode` 就是这样（已随模块下线）。

---

## 3. `value_kind` 四种执行语义

`resolve-config.py` 里是一串 `if value_kind == ...`，**没有 else 兜底**——
未知的 `value_kind` 直接 `die()`（保险丝 c）。所以加新种类**必须两端同时改**。

### 3.1 `flag` —— 布尔开关，勾了追加一个参数

```jsonc
{ "key": "smaller", "type": "checkbox", "default": true,
  "value_kind": "flag", "arg_on": "--packer-smaller" }
```

| 输入 | 输出 |
|---|---|
| `true` | `--packer-smaller` |
| `false` | （无） |
| 键缺失 | 按 `default` |
| 非布尔（如 `"native"`） | **报错退出** |

⚠️ **值是布尔，不是字符串。** 踩过：`trigger_build.py` 首版传 `"native"` →
云端 400「值必须是布尔，实际 'native'」（`4a1ba9c`）。
"用哪种实现"由 `arg_on` 本身表达，schema 不承载第三种取值。

### 3.2 `arg_value` —— 带值参数，勾了追加**两行**

```jsonc
{ "key": "exclude_x86", "type": "checkbox", "default": true,
  "value_kind": "arg_value",
  "arg_on": "--exclude-abi", "arg_value": "x86,x86_64" }
```

| 输入 | 输出（args.txt 逐行） |
|---|---|
| `true` | `--exclude-abi`<br>`x86,x86_64` |
| `false` / 缺失 | （无） |

两行是为了保持「**一行一个 token**」契约（workflow 用 `mapfile` 读）。
`arg_value` 必须是**无空白单 token** 且匹配 `[A-Za-z0-9_,.\-]+`（逗号合法）。

### 3.3 `rules_file` —— 规则文本，写文件 + 追加文件路径

```jsonc
{ "key": "rules_file", "type": "text", "multiline": true, "default": "",
  "value_kind": "rules_file",
  "required": { "when": "always",
                "unless": { "key": "sigcheck", "is": true } },
  "hint": "留空并勾选签名校验：自动抽取主界面类" }
```

| 输入 | 输出 |
|---|---|
| 非空 | 写 `schema_rules/<模块key>.txt`，argv 追加该**相对路径** |
| 空 + 通过 `unless` 豁免 | 只吐模块 `arg`，不追加文件 |
| 空 + 无豁免 | **保险丝 d 集中报错**（拼上 `hint`） |

⚠️ **规则内容永不进 argv**（保险丝 f）。路径以 `schema_rules/` 相对形式追加，
不是绝对路径 —— 绝对路径碰上 Actions workspace 前缀会混进 argv。

⚠️ **`.txt` 文件名用的是「模块 key」，不是子项 key。** 两个模块的
`rules_file` 互不覆盖靠这一点。

### 3.4 `choice` —— 从 `options` 里选一个（**待实现**）

> 状态：**未实现**。`check-schema.py` 与 jian_box 的 UI 已支持 `type=select`，
> 缺的是 `resolve-config.py` 的 `value_kind == "choice"` 分支（约 25 行）。
> 实现前先读 §4.2 的设计判据。

```jsonc
{ "key": "stub_impl", "label": "解密桩实现", "type": "select",
  "value_kind": "choice", "default": "java",
  "options": [
    { "value": "java", "label": "Java 桩（默认）", "arg_on": "" },
    { "value": "c",    "label": "纯 C 桩",        "arg_on": "--stringenc-native" }
  ] }
```

| 输入 | 输出 |
|---|---|
| `"c"` | `--stringenc-native` |
| `"java"` | （无 —— `arg_on` 为空串，表示"默认路径无需追加"） |
| 键缺失 | 按 `default`（`"java"`） |
| 值不在 `options` 里 | **报错退出**（fail-fast，同保险丝 c 的口径） |
| 非字符串 | 报错退出 |

**实现要点**（照这三条做，别自由发挥）：

1. 值必须是字符串，用 `cfg_node.get(ckey, c.get("default", ""))` 取
2. 查 `options` 找匹配项，**找不到即 `die()`** —— 静默回退默认值等于"用户的选择被悄悄丢弃"
3. `arg_on` 为空串时**跳过 ARG_RE 校验**（`ARG_RE.fullmatch("")` 会失败），
   非空时才校验并去重追加

---

## 4. `type` 怎么选：checkbox / select / radio

### 4.1 现状

| `type` | 渲染（`ProtectConfigCard.kt:143` 分发） | 状态值类型 |
|---|---|---|
| `"checkbox"` | `ChildCheckRow`（20dp 方框 + 整行可点） | 布尔 |
| `"select"` | `ChildSelect`（折叠下拉，`ExposedDropdownMenuBox`） | 字符串 |
| `"text"` | `ChildText`（含 `multiline`） | 字符串 |
| 其他任意值 | **落到 `else` → `ChildText`**（静默降级，不报错） |

⚠️ 最后一行是个陷阱：`type` 拼错（如 `"Select"` 大写、`"dropdown"`）不会报错，
会**静默变成文本输入框**。`check-schema.py` **也不校验 `type` 的取值**（只校验模块级
`type`，不校验子项 `type`）。这是当前的真实缺口。

### 4.2 单选框 vs 下拉框 —— 判据（2026-11-09 用户裁决）

**结论：本项目子项区默认用下拉框；只有满足下面条件才用单选框。**

| 判据 | 下拉框 `select`（默认） | 单选框 `radio` |
|---|---|---|
| 与多选框的可辨识度 | ✅ **折叠态与勾选框形态完全不同，一眼可区分** | ❌ 见下方 |
| 选项数 | 任意（含将来会增长） | ≤4 |
| 需要同时看见**所有**选项的代价说明 | ❌ 收起后只剩选中项 | ✅ 全露出 |
| 占用纵向空间 | 1 行 | N 行 |

**为什么"可辨识度"是决定性判据**（用户原话要点）：

> 我们本身就有多选框，你搞两个单选框在那里用户就会懵 —— 他怎么知道这是多选框
> 还是单选框呢？因为长得一模一样啊，都是框框。

这条在本项目里成立得比通用 UI 规范更强，原因是具体的：

- 子项复选框被刻意压到 **20dp**（`ProtectConfigCard.kt:210`，因为子行只有 36dp，
  Material3 默认 48dp 触控区会撑破行高）
- 20dp 的**圆**（radio）与 20dp 的**圆角方框**（checkbox），在一列密集行里扫过去，
  形状差异基本不存在
- Material 规范说"radio 圆、checkbox 方"，那是按 48dp 触控区设计的；压到 20dp 后
  这个区分度就没了

**所以：子项区用 radio = 制造"这个框是单选还是多选"的歧义。下拉框用形态（折叠/展开）
把语义区分开，代价是看不到未选项的说明。**

**反例（radio 用得对的地方）**：APP 顶层的「加固方案」选择
（`CreateApkTaskScreen.kt:328`）用的是 `CheckRow(role = Role.RadioButton)`，
因为它是**独立 `SectionCard` + 每个选项带 `subtitle`**，上下文已声明"这是一组互斥选择"，
没有多选框混在旁边。**判据不是"radio 不好"，是"别让 radio 和 checkbox 并排且同尺寸"**。

### 4.3 两个渲染共用一个语义，所以成本不是两套

```
value_kind = "choice"            ← 执行层只认这个（argv 输出完全一样）
type = "select" | "radio"        ← 渲染层只认这个（多一个 Composable 而已）
state["模块.子项"] = "java"       ← 两种渲染的状态模型完全相同
```

改渲染形态**不需要动 schema 语义、不需要动 `resolve-config.py`、不需要动
`protect_config` 格式**。所以"两个都支持"的成本 = 一个新 Composable，
不是两套逻辑。**先落地 `choice` 语义，渲染形态可以后面单独换。**

---

## 5. 加字段 / 加模块的 SOP

### 5.1 加一个子选项（最常见）

| 步骤 | 文件 | 注意 |
|---|---|---|
| 1 | `configs/v1/config-schema.json` | 加子项。**`value_kind` 必须是 `resolve-config.py` 已支持的种类** |
| 2 | `scripts/actions/resolve-config.py` | 仅当 `value_kind` 是**新种类**时才改 |
| 3 | `scripts/actions/tests/test-resolve-config.py` | **必补用例**：勾选 / 不勾 / 键缺失按 default / 非布尔或非枚举值报错 |
| 4 | `scripts/pipelines/protect.sh` | 新增 CLI 参数分支（`--xxx` → 环境变量 → 下游模块） |
| 5 | 下游模块脚本 | 如 `scripts/packer/packer.sh` 消费该环境变量 |
| 6 | `docs/流程文档.md` 对应模块章节 | |

⚠️ **不要给 `parent` 模块加"只有一个选项的 checkbox"**。曾经有 `antidiff.reencode`
这种"勾不勾都一样的复选框"，最后被删了 —— 零损耗功能直接并进模块本体，
别让用户面对一个没有意义的选择。

### 5.2 加一个模块

| 步骤 | 文件 | 注意 |
|---|---|---|
| 1 | `configs/v1/config-schema.json` | **位置即执行顺序**，见下 |
| 2 | `scripts/actions/check-schema.py:44` | **断言里写着模块 key 的完整有序列表**，不更新必红 |
| 3 | `scripts/pipelines/protect.sh` | 新增 `--xxx` 分支与执行块 |
| 4 | `scripts/actions/tests/test-workflow-yml.sh` | 若新增了 workflow input |
| 5 | `docs/流程文档.md` | 新增章节 |

**模块顺序不是排版，是执行顺序**：`check-schema.py` 断言

```python
keys == ["sigcheck", "dex2c", "obfuscate", "stringenc",
         "antidiff", "envcheck", "packer"]
```

这个顺序对应 `protect.sh` 的固定阶段序。插入新模块必须同时改这个断言与
`protect.sh` —— **改一处漏一处会让"UI 勾选顺序"与"实际执行顺序"静默不一致**。

> 例外：`envcheck` 的实际落点在 NDK 组装阶段（检测代码并入 `libnc.so`），
> 列表末位只是展示顺序。

### 5.3 `desc` 的写法约定

项目对 `desc` 有硬要求（2026-11-02 三轮文案改写的结论）：

- **写结论，不写机制**：「几乎为零」「启动稍慢（系统无法预编译 dex）」
- **不吹不贬**：不写"大幅提升""业界最强"，也不用"可能有效"这类免责话
- **必须标性能影响**：每个模块/子项都有一句 `性能：...`

---

## 6. 消费者各自会拦什么（三层 fail-fast）

### 6.1 UI 层（jian_box）—— **基本不拦**

- 渲染：`type` 未知 → **静默退化成文本框**
- 校验：`ProtectConfigSchema.validate()` **只校验 `required`**（值为空且无 `unless` 豁免）
- **不拦**：`stub_impl` 与 `dex2c_stub` 同时勾这种**跨字段互斥**（UI 层没有互斥机制）

`group_label` 目前**不渲染**：子项自己的输入框 label 就是标题，外层再加一条标题 +
帮助按钮 = 纯占位噪音（2026-10 用户裁决）。字段保留是为了云端可控文案。

### 6.2 `resolve-config.py` —— 六道保险丝

| 保险丝 | 拦什么 | 行为 |
|---|---|---|
| **a0** | `protect_config.schema_version` 缺失/非整数/比流水线新 | `die` |
| **a** | 出现 schema 未定义的顶层 key 或模块内子 key | `die`（缺失 key 不算错，视为 disabled） |
| **b** | 模块 `arg` / 子项 `arg_on` 不匹配 `--[a-z0-9]+(-[a-z0-9]+)*` | `die` |
| **c** | `value_kind` 未知 | `die` |
| **d** | `required` 不满足（`when` 只支持 `always`） | 收集后**集中** `die` |
| **e** | 一个模块都没启用 | `die` |
| **f** | —— | 全程结构化拼 argv；规则内容只写文件，永不进 argv |

**a 的语义要说清**：schema 有、config 没有 → 视为 disabled（**不报错**，兼容旧快照）；
config 有、schema 没有 → **拒绝执行**。方向性不对称是刻意的。

### 6.3 `protect.sh` —— 参数级再校验一遍

如 `--stringenc-native` 与 `--dex2c-stub` 互斥在 `protect.sh` 里有独立 fail-fast，
不依赖 schema 层拦截。**三层任一层拦住都算成功，但不能只有 UI 层拦。**

---

## 7. 已知缺口（审查时知悉，不算 bug）

| 缺口 | 说明 |
|---|---|
| `check-schema.py` 不校验子项 `type` | 拼错成 `"dropdown"` 会静默变成文本框（§4.1） |
| `check-schema.py` 不校验 `value_kind` | 写错的 `value_kind` 到运行期才被保险丝 c 抓到 |
| UI 层无跨字段互斥 | `stub_impl` × `dex2c_stub` 靠 CLI / `protect.sh` / `resolve-config` 三层兜底 |
| `choice` 未实现 | 见 §3.4 |
| APP 读的是镜像不是本仓库 | 改 schema 后若镜像未同步，**APP 上看到的是旧 schema** |

---

## 8. 一句话

**`type` 管怎么画，`value_kind` 管怎么执行，模块顺序管什么时候执行。**
加子选项改 1 个文件，加模块改 3 个文件，加新的 `value_kind` 改 2 个文件 + 补测试。
