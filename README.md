# dsh-secret-guard

Secret Guard 敏感内容守卫 — 一个 DeepSeek Harness 宿主插件，在 Agent 接触凭据之前就把门关上。

## 安装

### 方式一：插件中心一键装（推荐，2 步）

**1.** 打开 **设置 → 插件 → 安装**

**2.** 在安装框里粘贴下面这一行，回车：

```
github:FM112/dsh-secret-guard
```

安装完成后，在 **设置 → 插件 → 已安装** 里找到 `Secret Guard`，打开开关即生效——**无需重启**。

> 想锁定某个版本（避免上游更新带来变化），在末尾加 `#` 和标签或 commit：
> ```
> github:FM112/dsh-secret-guard#v1.0.0
> ```

### 方式二：插件市场里搜「Secret Guard」

> **当前状态：已提交收录，等待评审。**
> 收录申请见 [PR #15036](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin/pull/15036)
> （CI 已通过，等待维护者人工审阅）。合并后站点与市场会自动同步，通常一天内生效。

收录生效后，在 **设置 → 插件 → 市场** 搜索 `Secret Guard`，点安装即可，无需再记地址。
在此之前市场里搜不到，请用**方式一**。

### 装不上？先看这里

`github:` 安装会从 GitHub 拉取仓库。如果你的网络访问 GitHub 不稳定（连接超时、时断时连），**这不是插件的问题**，按下面任一条处理：

1. **用市场内置的加速线路**（最省事）：**设置 → 插件 → 插件配置 → GitHub 加速**，填入一个可用的 HTTPS 前缀。市场会记住上次可用的线路，失败自动换线。
2. **改用 SSH 通道克隆后再本地挂载**：见**方式四**。SSH 走 22 端口，在部分网络下比 HTTPS 稳定。
3. 换到网络通畅的环境安装，装好后再回来——插件文件已落盘，不受影响。

### 方式三：手动写进 profile（高级）

编辑本机 profile 的 `package.json`，加入依赖与 bundle：

```json
{
  "dependencies": {
    "dsh-secret-guard": "github:FM112/dsh-secret-guard"
  },
  "dsh": {
    "profile": {
      "bundles": ["dsh-secret-guard"]
    }
  }
}
```

然后在该 profile 目录执行 `pnpm install`。

### 方式四：本地开发挂载

如果你在改这个插件本身，直接用本地目录，改完热重载：

```powershell
git clone git@github.com:FM112/dsh-secret-guard.git
```

安装时填本地绝对路径（或用 `link:` 前缀），例如 `link:C:\code\dsh-secret-guard`。

### 验证是否生效

安装启用后，让 Agent 读一个 `.env` 文件。预期结果是**被拒绝**并给出 deny 原因，而不是文件内容。若返回了内容，检查「已安装」里的开关状态。

### 卸载

**设置 → 插件 → 已安装** → 找到 `Secret Guard` → 卸载。配置项会一并清除，不留残留。

## 它做什么

两层防护，时机不同：

| 层 | 时机 | 效果 |
|---|---|---|
| 路径拦截 | `tools/pre-execute`（工具执行**前**） | 返回 deny，**文件根本不会被打开** |
| 结果脱敏 | `tools/post-execute`（结果回模型**前**） | 就地替换凭据，保留上下文 |

外加一条系统提示规则，让模型从一开始就不去碰这些路径。

## 拦截范围

### 路径（不打开文件）

- **环境变量**：`.env`、`.env.local`、`.env.production`、`.env.*`
- **密钥材料**：`*.pem`、`*.key`、`*.p12`、`*.pfx`、`*.jks`、`*.keystore`、`*.ppk`、`*.kdbx`、`*.crt`、`*.cer`、`*.der`
- **SSH 私钥**：`id_rsa`、`id_dsa`、`id_ecdsa`、`id_ed25519`
- **云凭据**：`.ssh/`、`.aws/`、`.azure/`、`.kube/`、`.gnupg/`、`.docker/config.json`
- **包管理器**：`.git-credentials`、`.netrc`、`.npmrc`、`.pypirc`、`.pgpass`
- **通用密钥文件**：`secrets.{json,yaml,yml,ini,toml}`、`credentials.{...}`、`.credentials.{...}`
- **应用配置**：`wp-config.php`

### shell 命令

`cat`、`type`、`Get-Content` 这类命令引用上述文件名时同样拒绝。

### 明确放行

`.env.example`、`.env.sample`、`.env.template`、`.env.dist`、`.env.defaults`、`.ssh/known_hosts`、`.ssh/config`、`.ssh/authorized_keys`、`.ssh/*.pub`、`.aws/config`

### 内容脱敏

| 类型 | 示例特征 |
|---|---|
| 私钥 / PGP 块 | `-----BEGIN ... PRIVATE KEY-----` |
| OpenAI / Anthropic | `sk-...`、`sk-ant-...` |
| GitHub | `ghp_`、`gho_`、`ghu_`、`ghs_`、`ghr_`、`github_pat_` |
| AWS | `AKIA` / `ASIA` / `ABIA` / `ACCA` + 16 位 |
| Google | `AIza` + 35 位 |
| Slack | `xoxa-`、`xoxb-`、`xoxp-` … |
| Stripe | `sk_live_`、`rk_test_` … |
| npm | `npm_` + 30 位以上 |
| JWT / Bearer / Basic | `eyJ...`、`Bearer ...`、`Basic ...` |
| 连接串密码 | `postgres://user:[REDACTED:password]@host` → 只抹密码段 |
| `.env` 键值 | 键名含 `SECRET`/`TOKEN`/`PASSWORD`/`API_KEY` 等 |

替换后形如 `[REDACTED:openai-key]`，键名与结构保留，模型仍能理解上下文。

## 配置

`cordis.patch.yml` 中可调：

```yaml
- insert:
    - id: secret-guard
      name: 'dsh-secret-guard'
      config:
        blockReads: true
        blockShell: true
        redactResults: true
        extraPaths: []
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `blockReads` | `true` | 拒绝读取敏感路径 |
| `blockShell` | `true` | 拒绝引用敏感文件的 shell 命令 |
| `redactResults` | `true` | 结果回到模型前脱敏 |
| `extraPaths` | `[]` | 追加拦截的子串，如 `terraform.tfstate`、`serviceaccount.json` |

启用/停用：设置 → 插件 → 已安装，热生效，无需重启。

## 已知限制

这是降低风险的工具，不是安全边界。请知悉：

1. **不拦写入。** `write` / `edit` 往 `.env` 写内容是正常开发动作。
2. **`apply_patch` 的路径检查不完整。** 路径藏在 `patchText` 里，只靠结果脱敏兜底。
3. **shell 名单比路径名单窄。** `.npmrc`、`.pypirc`、`.azure/` 等的**命令行访问**不会被拒（内容仍会被脱敏）。
4. **正则会漏。** 编码过的、多行拆分的、自定义格式的凭据都可能绕过。
5. **不改沙箱权限。** 文件系统 ACL 层面仍可读，只是工具层的门关上了。
6. **不覆盖** `.envrc`、`*.tfstate`、`.bash_history`、`.htpasswd`、GCP service account JSON 等——需要用 `extraPaths` 自行补充。

## 兼容性

- 依赖 Cordis waterfall：`tools/pre-execute`、`tools/post-execute`
- 硬依赖仅 `tools` 一个服务；`systemPrompt` 与 `logger` 为可选
- 与 DSH 免费车道、付费车道均无关——在工具层统一生效

## License

MIT
