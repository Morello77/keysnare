# Detection rules

How the scanner recognises a secret once it has opened a file from
[credential-locations.md](credential-locations.md). Each rule's severity and plain-English risk
are in `src/keysnare/risk.py`.

Rules marked **(from docs)** are based on published documentation and have not yet been confirmed
on a real install.

## Three kinds of rule

| Kind | Matches | Confidence | Example |
|---|---|---|---|
| **Format** | A value whose shape is unique to one provider, in any scanned file | High | GitHub token starting `ghp_` |
| **Structure** | A known key inside a known credential file | High | `aws_secret_access_key` in `~/.aws/credentials` |
| **Key name** | A secret-sounding name with a real-looking value, in `.env`, MCP `env` blocks and shell history | Low | `STRIPE_SECRET=...` |

Format rules run on every scanned file. Structure rules run only on their own file. Key-name rules
are the fallback, used only when no format or structure rule matched the same value, so one secret
gives one finding.

## Shared rules

**Placeholder values are never findings.** A value is a placeholder when it is:

- empty, or shorter than 8 characters
- an environment reference: `${NAME}`, `$NAME`, `%NAME%`, `$(command)`, `env:NAME`
- an angle-bracket hint: `<your-token>`
- made of one repeated character: `xxxxxxxx`, `********`, `00000000`
- exactly one of these bare words, ignoring case: `password`, `secret`, `token`, `apikey`,
  `api_key` (as in `https://user:password@host`)
- or contains, ignoring case: `example`, `placeholder`, `changeme`, `your_`, `your-`, `dummy`,
  `redacted`, `keysnare-decoy`, `keysnaredecoy` (the last two mark KeySnare's own decoys)

**Known public example values are never findings**, for example the sample access key and secret
key in AWS's documentation, which both end in `EXAMPLE`/`EXAMPLEKEY`. The `example` rule above
already covers them.

**Fake secrets in tests are built from pieces at runtime** (for example `"ghp_" + "a" * 36`), never
written as complete strings in files, so the repository never trips GitHub push protection or
other secret scanners.

**Masking:** findings show the first 4 and last 4 characters (`AKIA****WXYZ`). Values
shorter than 16 characters are shown as `****` only, because 8 visible characters would reveal
most of a short secret.

---

## Format rules

Patterns use Python `re` syntax. `\b` means "word boundary", so a pattern does not match inside a
longer word.

| ID | Secret | Pattern | Why it is risky |
|---|---|---|---|
| F-AWS-KEY-ID | AWS access key ID | `\b(AKIA\|ASIA)[A-Z0-9]{16}\b` | `AKIA` is a long-lived key; `ASIA` is temporary. Useful to an attacker only with the matching secret, so report it with the secret when both are found. |
| F-GITHUB-TOKEN | GitHub classic / OAuth / app token | `\bgh[pousr]_[A-Za-z0-9]{36}\b` | Push code, read private repos, publish packages and Actions. |
| F-GITHUB-PAT | GitHub fine-grained token | `\bgithub_pat_[A-Za-z0-9_]{82}\b` | Same as above, limited to chosen repos. |
| F-NPM-TOKEN | npm access token | `\bnpm_[A-Za-z0-9]{36}\b` | Publish a poisoned version of your packages. This is how worms like Shai-Hulud spread. |
| F-PYPI-TOKEN | PyPI / TestPyPI upload token | `\bpypi-(AgEIcHlwaS5vcmc\|AgENdGVzdC5weXBpLm9yZw)[A-Za-z0-9_-]{50,}` | Publish a poisoned version of your packages. |
| F-OPENAI-KEY | OpenAI API key | `\bsk-(proj-\|svcacct-\|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}` | Run up large bills on your account. `T3BlbkFJ` is base64 for "OpenAI", which keeps false positives near zero. |
| F-ANTHROPIC-KEY | Anthropic API key or OAuth token | `\bsk-ant-[a-z]{3,5}\d{2}-[A-Za-z0-9_-]{40,}` | Run up bills; OAuth tokens give access to your Claude account. |
| F-GOOGLE-API-KEY | Google API key (incl. Gemini) | `\bAIza[0-9A-Za-z_-]{35}\b` | Bills on your Google Cloud project. |
| F-HF-TOKEN | Hugging Face token | `\bhf_[A-Za-z0-9]{34,}\b` | Read private models and datasets; write access can poison models. |
| F-PRIVATE-KEY | Private key block | `-----BEGIN ((RSA\|EC\|DSA\|OPENSSH) )?PRIVATE KEY-----` | Full identity of a server, user or service. Encrypted keys are excluded; see S-SSH-KEY. |
| F-STRIPE-LIVE-KEY | Stripe live secret or restricted key | `\b[sr]k_live_[0-9A-Za-z]{24,}\b` | Acts on your live Stripe account: refunds, payout details, customer data. |
| F-STRIPE-TEST-KEY | Stripe test-mode key | `\b[sr]k_test_[0-9A-Za-z]{24,}\b` | Low risk on its own (no real money), but the live key is often nearby. |
| F-SLACK-TOKEN | Slack bot, user, app or refresh token | `\bxox[abprs]-(?:[0-9]+-){1,3}[0-9A-Za-z]{8,}\b` | Reads and posts in your workspace; easy phishing of colleagues. |
| F-SENDGRID-KEY | SendGrid API key | `\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}(?![0-9A-Za-z_-])` | Sends email from your verified domains. |
| F-URL-CREDENTIALS | Username and password in a URL | `\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@[^\s/]+` | Database, registry or Git passwords in plain view. The password part must pass the placeholder check. |

`BEGIN ENCRYPTED PRIVATE KEY` (passphrase-protected PKCS#8) is deliberately **not** matched.

---

## Structure rules

Each rule applies only to the files named in its section of `credential-locations.md`.

### AWS (`~/.aws/credentials`, `~/.aws/config`, `cli/cache`, `sso/cache`)

| ID | Matches |
|---|---|
| S-AWS-SECRET | `aws_secret_access_key = <value>` in any profile. |
| S-AWS-SECRET-ENV | In `.env` files, MCP `env` blocks and shell history: a value assigned to `AWS_SECRET_ACCESS_KEY` (any case) that has the exact AWS secret key shape, 40 characters of `A-Z a-z 0-9 / +`. AWS secret keys have no prefix, but this name plus this shape is as certain as a format rule, so it is reported as High instead of the key-name rule's Low. |
| S-AWS-SESSION | `aws_session_token = <value>`. Temporary, lower risk. |
| S-AWS-CACHE | JSON in `cli/cache` with `Credentials.SecretAccessKey`, or in `sso/cache` with `accessToken`. Lower risk once `Expiration`/`expiresAt` has passed. |

### npm and Yarn (`.npmrc`, `.yarnrc.yml`)

| ID | Matches |
|---|---|
| S-NPMRC-TOKEN | A line whose key ends in `_authToken`, `_auth` or `_password`. `_auth` is base64 of `user:password`. |
| S-YARNRC-TOKEN | `npmAuthToken: <value>`. |

### Docker (`config.json`)

| ID | Matches |
|---|---|
| S-DOCKER-AUTH | `auths.<registry>.auth` or `auths.<registry>.identitytoken` is non-empty. Skipped for registries covered by `credsStore`/`credHelpers` when the entry has no `auth`. |

### Git and GitHub

| ID | Matches |
|---|---|
| S-GIT-CREDENTIALS | Any line in `.git-credentials` matching F-URL-CREDENTIALS. |
| S-GIT-REMOTE | A `url =` line in `.git/config` matching F-URL-CREDENTIALS. |
| S-GH-HOSTS | `oauth_token: <value>` in `hosts.yml`. |

### Python (`.pypirc`, pip config, Poetry `auth.toml`)

| ID | Matches |
|---|---|
| S-PYPIRC-PASSWORD | `password = <value>` in any section. |
| S-PIP-INDEX-URL | `index-url` or `extra-index-url` matching F-URL-CREDENTIALS. |
| S-POETRY-AUTH | `password` under `[http-basic.*]`, or any value under `[pypi-token]`. |

### NuGet (`NuGet.Config`, `nuget.config`)

| ID | Matches |
|---|---|
| S-NUGET-CLEARTEXT | `<add key="ClearTextPassword" value="..."/>` inside `<packageSourceCredentials>`. |
| S-NUGET-DPAPI | `<add key="Password" value="..."/>`. Encrypted, but any program running as the user can decrypt it on Windows. Lower risk. |

### AI tools

| ID | Matches |
|---|---|
| S-CLAUDE-OAUTH | `claudeAiOauth.accessToken` or `claudeAiOauth.refreshToken` is non-empty. |
| S-CODEX-AUTH | `OPENAI_API_KEY` is a non-null string, or `tokens.refresh_token` is non-empty. |
| S-MCP-ENV | Any value under `mcpServers.<name>.env` in Claude Desktop or Cursor MCP config. Checked with format rules first, then the key-name rule. |
| S-HF-TOKEN-FILE | Hugging Face `token` file is non-empty. |
| S-GEMINI-OAUTH | `refresh_token` in `oauth_creds.json`. (from docs) |
| S-COPILOT-TOKEN | `oauth_token` in Copilot `hosts.json` / `apps.json`. (from docs) |
| S-CONFIG-APIKEY | `apiKey` / `api_key` / `api-key` values in Continue and Aider config. (from docs) |

### Private keys (`~/.ssh/`, `IdentityFile` targets, and `*.ppk`, `id_*`, `*.pem`, `*.key` found by the folder walk)

**S-SSH-KEY** reports an SSH key (`~/.ssh/`, `IdentityFile` targets, `*.ppk`, and `id_*` files
other than `*.pub`) **only when it has no passphrase**. **S-PRIVATE-KEY-FILE** does the same for
`*.pem` and `*.key` files, which often hold TLS or service keys. A `.pem` file that holds only
certificates, or a `.key` file that is not a key at all (such as a Keynote presentation), is not
reported.

| Key format | Header | Unencrypted when |
|---|---|---|
| OpenSSH (modern) | `BEGIN OPENSSH PRIVATE KEY` | The base64 body decodes to `openssh-key-v1\0`, followed by a length-prefixed cipher name equal to `none`. |
| PEM (older RSA/EC/DSA) | `BEGIN RSA PRIVATE KEY` etc. | There is no `Proc-Type: 4,ENCRYPTED` header line. |
| PKCS#8 | `BEGIN PRIVATE KEY` | Always unencrypted. The encrypted form uses `BEGIN ENCRYPTED PRIVATE KEY`. |
| PuTTY | `PuTTY-User-Key-File-2:` or `-3:` | The `Encryption:` line says `none`. |

Only the header and the cipher field are used to make this decision: KeySnare reads at most the
first 4 KB of a key file, and never decodes the key itself beyond the cipher name. A key placed
after 4 KB of other content in the same file (for example after a long certificate chain) is
not found.

### Azure CLI (`~/.azure/`)

| ID | Matches |
|---|---|
| S-AZURE-MSAL | `msal_token_cache.json` has a non-empty `RefreshToken` section. (from docs) |
| S-AZURE-SP | `service_principal_entries.json` has a `client_secret` value. (from docs) |
| S-AZURE-DPAPI | `msal_token_cache.bin` or `service_principal_entries.bin` exists and is non-empty. Encrypted; lower risk. |
| S-AZURE-LEGACY | `accessTokens.json` exists and is non-empty. |

### Google Cloud (`gcloud` folder, `GOOGLE_APPLICATION_CREDENTIALS`)

| ID | Matches |
|---|---|
| S-GCP-SERVICE-ACCOUNT | JSON with `"type": "service_account"` and a non-empty `private_key`. Applies anywhere, including files named by `GOOGLE_APPLICATION_CREDENTIALS`. |
| S-GCP-ADC-USER | JSON with `"type": "authorized_user"` and a non-empty `refresh_token`. |
| S-GCP-CREDENTIALS-DB | `credentials.db` exists and is non-empty. The file is not opened. |

### Kubernetes (`~/.kube/config`, `KUBECONFIG` files)

| ID | Matches |
|---|---|
| S-KUBE-TOKEN | `token:` under a `users[].user` entry. |
| S-KUBE-CLIENT-KEY | `client-key-data:` (base64 private key) under a user. |
| S-KUBE-PASSWORD | `password:` under a user. |
| S-KUBE-AUTH-PROVIDER | `access-token:` or `refresh-token:` under `auth-provider.config`. |

A user that only has an `exec:` block is not a finding.

### Shell history

| ID | Matches |
|---|---|
| S-HISTORY-SECRET | Any line matching a format rule, or the key-name rule in one of these forms: `export NAME=value`, `set NAME=value`, `$env:NAME = "value"`, `--password value`, `-p value` after `docker login`, `Authorization: Bearer <value>`. |

The history file existing is never a finding on its own. A line matching a format rule keeps
that rule's ID (for example `F-GITHUB-TOKEN`), which says more than the generic history ID.

### Files that are not strict JSON

Some JSON config files contain comments, which the standard JSON reader rejects. For these, the
structure rules are skipped and the format rules still run on every line.

---

## Key-name rule

**K-SECRET-NAME** (low confidence) matches a `NAME=value` or `NAME: value` pair when:

1. `NAME` has a whole word part, ignoring case, that is one of: `secret`, `token`, `password`,
   `passwd`, `pwd`, `auth`, `credential`, `credentials`, `apikey`; or contains the pairs
   `api_key`, `access_key`, `private_key`. Word parts are split on `_`, `-`, `.` and camelCase,
   so `clientSecret` matches but `AUTHOR_NAME` and `TOKENIZER_MODEL` do not.
2. The value passes the placeholder check.
3. The value is not a boolean, a number, a file path, a URL without credentials, a reference
   starting with `$` or `%`, or text containing spaces. These names often hold settings, not
   secrets: `TOKEN_EXPIRY=3600`, `AUTH_ENABLED=true`, `AUTH_URL=https://login.corp`.

Used only in `.env` files, MCP `env` blocks and shell history.

---

## Reading YAML files

Several files are YAML (`hosts.yml`, `.yarnrc.yml`, kubeconfig, Continue `config.yaml`). KeySnare
has zero runtime dependencies: every third-party package is a supply-chain risk, which is exactly
what KeySnare defends against. So it does not use a YAML library such as PyYAML. YAML files are
matched line by line instead: every rule above needs only a key name and its value on one line,
plus the indentation to know which section the line is in.
