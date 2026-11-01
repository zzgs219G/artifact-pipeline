# CI 签名（可选）

默认**不签名** —— 本仓库契约是「产出未签名包，开发者自行重签」。
只有显式请求 `sign=true` 时才用仓库 Secrets 里的 keystore 重签，
产出可直接 `adb install` 的包。

## 为什么做成可选

| 场景 | 是否需要签名 |
|---|---|
| App 正常流程 | ❌ 不需要，开发者自己重签（既有契约） |
| CLI 调试（`trigger_build.py --sign`） | ✅ 需要，省掉手工重签 |

## 四个 Secrets

存在 **Settings → Secrets and variables → Actions**：

| Secret 名 | 内容 | 怎么生成 |
|---|---|---|
| `KEYSTORE_BASE64` | keystore 文件 base64 | `base64 -w0 release.keystore` |
| `KEYSTORE_PASSWORD` | **store 密码**（keystore 容器密码） | 你自己的 |
| `KEY_ALIAS` | key 别名 | 你自己的 |
| `KEY_PASSWORD` | **key 密码**（该别名对应的私钥密码） | 你自己的 |

> ⚠️ **store 密码与 key 密码不一定相同**，实测踩过：两个填成同一个 →
> `java.security.UnrecoverableKeyException: Cannot recover key`。
>
> 陷阱在于 `keytool -list -storepass <store密码>` 能通过——它**只校验 store 密码、
> 不校验 key 密码**，所以"keystore 载入成功"不等于"密码正确"，
> 真正的失败要等到 `apksigner sign` 才暴露。
>
> 不确定时先本地验一次：`keytool -list -keystore release.keystore`（会分别问两个密码）。

## ⚠️ keystore 必须与上传 APK 同源

加 `--sigcheck` 后，`libnc.so` 里写的是**上传 APK 的证书指纹**
（`k_so = HKDF(master, SHA256(certDER), ...)`）。

换证书重签 → 运行期派生失败 → 包起不来（返回 -12）。

所以 Secrets 里的 keystore 必须就是签那个 APK 的同一个证书。

## 用 CLI 存

```bash
export RELAY_TOKEN=...
REPO=zzgs219G/artifact-pipeline

# 1. keystore 转 base64 后存
base64 -w0 release.keystore | gh secret set KEYSTORE_BASE64 --repo "$REPO"

# 2. 密码与别名（会提示输入）
gh secret set KEYSTORE_PASSWORD --repo "$REPO"
gh secret set KEY_ALIAS        --repo "$REPO"
gh secret set KEY_PASSWORD     --repo "$REPO"
```

注意 `gh secret set` 不带 `--body` 时会**交互式提示**，值不回显、不进 history。
带 `--body` 传值会进 shell history，别用。

## 验证

```bash
python3 scripts/trigger_build.py app.apk --sign
# 产物下载后：
apksigner verify --print-certs ~/Download/xxx_signed_HH_MM_SS.apk
```

## 排查

| 现象 | 原因 |
|---|---|
| `❌ 请求了 sign=true 但缺少 Secrets: ...` | 四个 secret 没配齐 |
| `❌ keystore 解密失败` | base64 截断（常见于 `base64` 没加 `-w0`，带了换行）或密码错 |
| 装上去启动即退出 | keystore 与上传 APK 不同源 → 证书绑定 fail-closed(-12) |
