// Secret Guard — 敏感路径读取拦截 + 工具结果脱敏
//
// 这是一个真正的 DSH 宿主插件：挂在 Cordis 的 `tools/pre-execute` 与
// `tools/post-execute` 瀑布上，对每一条模型调用生效，不区分免费/付费车道。
//
//   pre-execute  → 在工具真正执行之前拒绝（deny），文件根本不会被打开
//   post-execute → 结果回到模型之前脱敏，兜住 pre-execute 没覆盖的路径
//
// 只注入 tools（唯一硬依赖）。systemPrompt 与 logger 用 ctx.get() 取，
// 缺失时只是少一条提示/一条日志，不会让 fiber 卡在 pending。

export const name = 'secret-guard'

export const inject = ['tools']

const DEFAULTS = {
  blockReads: true,
  blockShell: true,
  redactResults: true,
  extraPaths: [],
}

// 模板文件是给人看的样例，不含真实凭据，放行。
const ENV_TEMPLATE = /(^|[\\/])\.env\.(example|sample|template|dist|defaults)$/i

// 这些文件虽然住在敏感目录里，本身并不带密钥：放行登录名、主机指纹和
// 公开配置，避免为了拦凭据把正常排查工作也一起堵死。
const PUBLIC_IN_VAULT = [
  /(^|[\\/])\.ssh[\\/](known_hosts|known_hosts\.old|config|authorized_keys)$/i,
  /(^|[\\/])\.ssh[\\/][^\\/]+\.pub$/i,
  /(^|[\\/])\.aws[\\/]config$/i,
]

// 命中即拒绝的路径。只判路径，不打开文件。
const SENSITIVE_PATH = [
  /(^|[\\/])\.env(\.[\w-]+)?$/i,
  /\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx?|crt|cer|der)$/i,
  /(^|[\\/])id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i,
  /(^|[\\/])\.git-credentials$/i,
  /(^|[\\/])\.netrc$/i,
  /(^|[\\/])\.npmrc$/i,
  /(^|[\\/])\.pypirc$/i,
  /(^|[\\/])\.pgpass$/i,
  /(^|[\\/])\.credentials\.(json|ya?ml)$/i,
  /(^|[\\/])(secrets?|credentials?)\.(json|ya?ml|ini|toml)$/i,
  /(^|[\\/])\.ssh([\\/]|$)/i,
  /(^|[\\/])\.aws([\\/]|$)/i,
  /(^|[\\/])\.azure([\\/]|$)/i,
  /(^|[\\/])\.kube([\\/]|$)/i,
  /(^|[\\/])\.gnupg([\\/]|$)/i,
  /(^|[\\/])\.docker([\\/])config\.json$/i,
  /(^|[\\/])wp-config\.php$/i,
]

// 文件名出现在 shell 命令里也拦，cat/type/Get-Content 都绕不过去。
const SHELL_TOKEN = [
  /\.env(\.[\w-]+)?/i,
  /\bid_(rsa|dsa|ecdsa|ed25519)\b/i,
  /\S+\.(pem|p12|pfx|jks|keystore|ppk|kdbx)\b/i,
  /\.git-credentials\b/i,
  /\.netrc\b/i,
  /\.pgpass\b/i,
  /[\\/]\.ssh[\\/]/i,
  /[\\/]\.aws[\\/]/i,
  /[\\/]\.kube[\\/]/i,
  /[\\/]\.gnupg[\\/]/i,
]

const READ_TOOLS = new Set(['read', 'read_image', 'apply_patch'])
const SEARCH_TOOLS = new Set(['grep', 'glob', 'list'])
const GLOB_TOOLS = new Set(['glob'])
const SHELL_TOOLS = new Set(['bash', 'pwsh'])

const PATH_FIELDS = ['file_path', 'path', 'target', 'file', 'filename', 'include']

function normalize(raw) {
  const cfg = { ...DEFAULTS, extraPaths: [] }
  if (raw === null || typeof raw !== 'object') return cfg
  for (const key of ['blockReads', 'blockShell', 'redactResults']) {
    if (typeof raw[key] === 'boolean') cfg[key] = raw[key]
  }
  if (Array.isArray(raw.extraPaths)) {
    cfg.extraPaths = raw.extraPaths.filter((item) => typeof item === 'string' && item.trim() !== '')
  }
  return cfg
}

function isSensitive(value, cfg) {
  if (typeof value !== 'string' || value.trim() === '') return false
  if (ENV_TEMPLATE.test(value)) return false
  if (PUBLIC_IN_VAULT.some((re) => re.test(value))) return false
  if (SENSITIVE_PATH.some((re) => re.test(value))) return true
  return cfg.extraPaths.some((needle) => value.includes(needle))
}

function pathArgs(exec) {
  const args = exec?.arguments
  if (args === null || typeof args !== 'object') return []
  const found = []
  for (const field of PATH_FIELDS) {
    if (typeof args[field] === 'string') found.push(args[field])
  }
  return found
}

// glob 的 pattern 就是匹配范围：`**/.env`、`*.pem`、`.ssh/**` 都算命中。
// 这里按「模式里是否出现敏感文件名」判断，而不是要求完整路径。
const GLOB_SECRET = [
  /\.env(\b|\.(?!example|sample|template|dist|defaults))/i,
  /\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx)\b/i,
  /id_(rsa|dsa|ecdsa|ed25519)\b/i,
  /\.git-credentials/i,
  /\.netrc/i,
  /\.pgpass/i,
  /\.ssh\b/i,
  /\.aws\b/i,
  /\.kube\b/i,
  /\.gnupg\b/i,
]

function globHitsSecret(pattern) {
  return GLOB_SECRET.some((re) => re.test(pattern))
}

// ── 出站文本脱敏 ───────────────────────────────────────────────────

const REDACT = (kind) => `[REDACTED:${kind}]`

const TOKEN_RULES = [
  ['private-key', /-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/g],
  ['pgp-block', /-----BEGIN PGP (?:PRIVATE|MESSAGE)[A-Z ]*-----[\s\S]*?-----END PGP [A-Z ]*-----/g],
  ['anthropic-key', /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  ['openai-key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g],
  ['github-token', /\bgh[pousr]_[A-Za-z0-9]{20,}/g],
  ['github-pat', /\bgithub_pat_[A-Za-z0-9_]{20,}/g],
  ['aws-access-key', /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g],
  ['google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['slack-token', /\bxox[abposr]-[A-Za-z0-9-]{10,}/g],
  ['stripe-key', /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g],
  ['npm-token', /\bnpm_[A-Za-z0-9]{30,}/g],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
  ['bearer-token', /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/gi],
  ['basic-auth', /\bBasic\s+[A-Za-z0-9+/]{20,}={0,2}/g],
]

const CONNECTION_RE = /([a-z][a-z0-9+.-]*:\/\/)([^\s:/@]{1,64}):([^\s@/]{1,160})@/gi

const ENV_RE =
  /\b([A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL|AUTH_KEY)[A-Za-z0-9_]*)\s*[:=]\s*(["']?)([^\s"',;{}[\]]{6,})\2/gi

function redactText(text) {
  if (typeof text !== 'string' || text === '') return text
  let out = text
  for (const [kind, re] of TOKEN_RULES) {
    re.lastIndex = 0
    out = out.replace(re, REDACT(kind))
  }
  CONNECTION_RE.lastIndex = 0
  out = out.replace(CONNECTION_RE, (all, scheme, user) => `${scheme}${user}:${REDACT('password')}@`)
  ENV_RE.lastIndex = 0
  out = out.replace(ENV_RE, (all, key) => `${key}=${REDACT('value')}`)
  return out
}

// 返回 null 表示内容没有任何变化，避免无谓地替换结果对象。
function redactBlocks(blocks) {
  if (!Array.isArray(blocks)) return null
  let changed = false
  const next = blocks.map((block) => {
    if (block === null || typeof block !== 'object') return block
    if (typeof block.text !== 'string') return block
    const text = redactText(block.text)
    if (text === block.text) return block
    changed = true
    return { ...block, text }
  })
  return changed ? next : null
}

// ── 插件主体 ───────────────────────────────────────────────────────

export function apply(ctx, rawConfig) {
  const cfg = normalize(rawConfig)

  const logger = (() => {
    try {
      return ctx.get('logger')
    } catch {
      return undefined
    }
  })()

  const log = (message) => {
    try {
      logger?.info?.(message)
    } catch {
      /* 日志失败绝不能影响守护本身 */
    }
  }

  // 1) 执行前拒绝。prepend 让它排在其他策略之前：命中即拒，
  //    不会先弹一次审批再被拒，文件也根本不会被打开。
  ctx.on(
    'tools/pre-execute',
    async (exec, next) => {
      if (!cfg.blockReads && !cfg.blockShell) return next()
      const tool = String(exec?.name ?? '')

      if (cfg.blockReads && (READ_TOOLS.has(tool) || SEARCH_TOOLS.has(tool))) {
        for (const value of pathArgs(exec)) {
          if (!isSensitive(value, cfg)) continue
          log(`secret-guard: 拒绝 ${tool} 读取敏感路径 ${value}`)
          return {
            kind: 'deny',
            reason:
              `Secret Guard 拒绝读取 ${value}：这类文件可能包含真实凭据，内容不会交给模型。` +
              '如需了解结构，请读对应的 .env.example 等模板文件，或请用户直接给出所需的非敏感配置项。',
            info: { name: 'SecretGuardDenied', code: 'SECRET_PATH_DENIED', reason: value },
          }
        }
        // glob 的路径靠 pattern 表达（**/.env、*.pem），字段值本身就是匹配式，
        // 不含目录分隔符也算命中，所以单独用更宽的判定。
        if (GLOB_TOOLS.has(tool)) {
          const pattern = typeof exec?.arguments?.pattern === 'string' ? exec.arguments.pattern : ''
          if (pattern !== '' && globHitsSecret(pattern)) {
            log(`secret-guard: 拒绝 ${tool} 匹配敏感模式 ${pattern}`)
            return {
              kind: 'deny',
              reason:
                `Secret Guard 拒绝该模式 ${pattern}：它会列出可能包含真实凭据的文件。` +
                '请缩小到具体的非敏感路径。',
              info: { name: 'SecretGuardDenied', code: 'SECRET_PATH_DENIED', reason: pattern },
            }
          }
        }
      }

      if (cfg.blockShell && SHELL_TOOLS.has(tool)) {
        const command = typeof exec?.arguments?.command === 'string' ? exec.arguments.command : ''
        if (command !== '') {
          for (const re of SHELL_TOKEN) {
            const matched = command.match(re)?.[0]
            if (matched === undefined) continue
            if (ENV_TEMPLATE.test(matched)) continue
            log(`secret-guard: 拒绝 shell 访问 ${matched}`)
            return {
              kind: 'deny',
              reason:
                `Secret Guard 拒绝该命令：它引用了 ${matched}，这类文件可能包含真实凭据。` +
                '请改用不接触凭据的做法，或读取对应的模板文件。',
              info: { name: 'SecretGuardDenied', code: 'SECRET_PATH_DENIED', reason: matched },
            }
          }
        }
      }

      return next()
    },
    { prepend: true },
  )

  // 2) 结果回模型前脱敏：兜住 pre-execute 没覆盖到的路径。
  ctx.on('tools/post-execute', async (exec, result, next) => {
    const decision = await next()
    if (cfg.redactResults !== true) return decision

    const source = decision?.kind === 'block' ? decision.feedback : (decision?.content ?? result?.content)
    const redacted = redactBlocks(source)
    if (redacted === null) return decision

    log(`secret-guard: 已脱敏 ${exec?.name ?? '工具'} 的结果`)
    if (decision?.kind === 'block') return { ...decision, feedback: redacted }
    return { ...decision, kind: 'accept', content: redacted }
  })

  // 3) 提示词规则：让模型一开始就不去碰这些路径。
  //    systemPrompt 不是硬依赖，缺了只是少一条提示。
  const systemPrompt = (() => {
    try {
      return ctx.get('systemPrompt')
    } catch {
      return undefined
    }
  })()
  if (systemPrompt !== undefined && typeof systemPrompt.section === 'function') {
    try {
      systemPrompt.section({
        name: 'secret-guard',
        order: 1050,
        text: () =>
          '敏感文件规则（Secret Guard 正在强制执行，违反会被直接拒绝）：' +
          '不要读取 .env、*.pem、*.key、*.p12、*.pfx、id_rsa/id_ed25519 等私钥、.git-credentials、' +
          '.netrc、.npmrc、.pypirc、.pgpass、.ssh/、.aws/、.azure/、.kube/、.gnupg/、secrets.json、' +
          'credentials.yaml，也不要在 shell 命令里引用它们（cat/type/Get-Content 同样会被拒）。' +
          '需要配置值时，读对应的 .env.example 等模板，或请用户提供具体的非敏感字段。',
      })
    } catch {
      /* 一个重复或越权的 section 不应拖垮整个插件 */
    }
  }

  log(
    `secret-guard: 已启用（读取拦截=${cfg.blockReads} 命令拦截=${cfg.blockShell} 结果脱敏=${cfg.redactResults} 额外路径=${cfg.extraPaths.length}）`,
  )
}
