# Credential locations

Where plain-text credentials live on a developer machine, per platform. This is the list the
scanner works from. It describes *where* to look; *how* to recognise a secret inside each file is
in the detection rules.

## Conventions

- `~` is the user's home folder: `%USERPROFILE%` on Windows (e.g. `C:\Users\alice`), `$HOME` on
  macOS and Linux.
- `%APPDATA%` is `C:\Users\<name>\AppData\Roaming`. `%LOCALAPPDATA%` is
  `C:\Users\<name>\AppData\Local`.
- `$XDG_CONFIG_HOME` defaults to `~/.config` on Linux when the variable is not set.
- **Override** lists environment variables that move a file somewhere else. The scanner must
  check them, or it misses relocated files. Stealers check them too.
- **Not a finding when** lists the cases where the file exists but holds no plain-text secret.
  These keep false positives down.
- Entries marked **(from docs)** are based on published documentation and have not yet been
  confirmed on a real install. **(verified: Windows)** means the file and its key names were
  confirmed on a real Windows machine.

---

## 1. Environment files (`.env`)

| | |
|---|---|
| Files | `.env`, `.env.local`, `.env.development`, `.env.production`, `.env.*` |
| Where | Inside project folders, anywhere under `~` |
| Holds | `NAME=value` lines: API keys, database URLs with passwords, cloud keys |
| Not a finding when | The file is a template (`.env.example`, `.env.sample`, `.env.template`) with placeholder values only |

### How the scanner searches for `.env` files

- By default it walks the whole home folder `~`. The user can give a specific path to scan instead.
- It skips folders that never hold the user's own secrets: `node_modules`, `.venv`, `venv`,
  `__pycache__`, tool caches (`.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.tox`), temp and
  cache folders (`.cache`, `cache`, `caches`, `temp`, `tmp`, `.tmp`), package caches (`.npm`,
  `.nuget`, `.gradle`, `.m2`, `.cargo`, `.rustup`), and VS Code folders (`.vscode`,
  `.vscode-server`, `.vscode-insiders`), to stay well away from extension storage.
- For a `.git` folder it checks only `.git/config` and does not walk the rest.
- It skips `AppData` (Windows) and `Library` (macOS) directly under the home folder. The known
  credential files inside them are checked by exact path instead.
- It never follows symbolic links, Windows junctions or other Windows reparse points. This avoids
  scanning the same files twice, endless loops, wandering outside the folder being scanned, and
  downloading cloud-only files (OneDrive placeholders are reparse points).
- It skips files larger than 1 MB. Credential files are small.
- On Windows it reads folders and files whose path is longer than the classic 260-character limit,
  whether or not long-path support is turned on for the machine.
- Files it picks up: `.env` and `.env.*` (templates too, since a real secret in a template is
  still a leak), `.npmrc`, `nuget.config`, `.cursor/mcp.json`, `.git/config`, and private keys:
  `*.ppk`, `id_*` (except `*.pub`), `*.pem` and `*.key`. Only the first 4 KB of a key file is
  read, which holds its header and cipher name.
- A single file given by the user that is none of the known types is checked like a `.env` file.
- Files and folders that cannot be read, and walked files over 1 MB, are reported as skipped,
  never silently ignored.
- These limits apply to the walk only. The known locations in the sections below are checked by
  exact path even when the file is a link (dotfile managers often link `~/.npmrc` and similar
  files, and a stealer reads through the link too), and are read in full whatever their size
  (shell history can be over 1 MB).
- Measured on the primary Windows dev machine: a full home-folder scan takes about 8 seconds.
- Target: a typical scan finishes in under 10 seconds.

## 2. AWS

| | Windows | macOS / Linux |
|---|---|---|
| Credentials | `~\.aws\credentials` | `~/.aws/credentials` |
| Config | `~\.aws\config` | `~/.aws/config` |
| CLI cache | `~\.aws\cli\cache\*.json` | `~/.aws/cli/cache/*.json` |
| SSO cache | `~\.aws\sso\cache\*.json` | `~/.aws/sso/cache/*.json` |

- **Holds:** `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`. The cache folders
  hold short-lived session credentials and SSO access tokens.
- **Override:** `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`.
- **Not a finding when:** a profile uses `credential_process` or `sso_*` settings and has no key
  values. Expired cache files are lower risk than long-lived keys.

## 3. npm and other JavaScript package managers

| | Windows | macOS / Linux |
|---|---|---|
| User npmrc | `~\.npmrc` | `~/.npmrc` |
| Global npmrc | `%APPDATA%\npm\etc\npmrc` | `<npm prefix>/etc/npmrc` |
| Project npmrc | `.npmrc` in any project folder | same |
| Yarn 2+ | `~\.yarnrc.yml` | `~/.yarnrc.yml` |

- **Holds:** `//registry.npmjs.org/:_authToken=...`, `_auth=` (base64 `user:password`),
  `_password=`. Yarn uses `npmAuthToken:`. pnpm reads the same `.npmrc` files.
- **Override:** `NPM_CONFIG_USERCONFIG`, `NPM_CONFIG_GLOBALCONFIG`.
- **Not a finding when:** the token value is an environment reference such as
  `${NPM_TOKEN}`. The secret then lives elsewhere, not in the file.

## 4. Docker

| | Windows | macOS / Linux |
|---|---|---|
| Config | `~\.docker\config.json` | `~/.docker/config.json` |

- **Holds:** an `auths` section, where each registry has an `auth` field. `auth` is base64 of
  `username:password`, which is encoding, not encryption.
- **Override:** `DOCKER_CONFIG` (a folder that contains `config.json`).
- **Not a finding when:** `credsStore` or `credHelpers` is set and the `auths` entries have no
  `auth` value. Docker Desktop normally does this and keeps the secret in the OS keychain.

## 5. Git and GitHub

| | Windows | macOS / Linux |
|---|---|---|
| Git "store" helper | `~\.git-credentials` | `~/.git-credentials` |
| Git XDG location | `~\.config\git\credentials` | `$XDG_CONFIG_HOME/git/credentials` |
| GitHub CLI | `%APPDATA%\GitHub CLI\hosts.yml` | `~/.config/gh/hosts.yml` |
| Repo remotes | `.git/config` in any repository | same |

- **Holds:** `.git-credentials` has one URL per line, such as
  `https://user:TOKEN@github.com`. `hosts.yml` can hold `oauth_token:`. A repository's
  `.git/config` can embed a token in a remote URL.
- **Override:** `GH_CONFIG_DIR` (GitHub CLI).
- **Not a finding when:** Git uses `credential.helper=manager` (Windows default) or `osxkeychain`,
  and `hosts.yml` has no `oauth_token` (newer `gh` versions use the keychain).

## 6. Python package indexes (PyPI)

| | Windows | macOS | Linux |
|---|---|---|---|
| pypirc | `~\.pypirc` | `~/.pypirc` | `~/.pypirc` |
| pip config | `%APPDATA%\pip\pip.ini` | `~/Library/Application Support/pip/pip.conf`, `~/.config/pip/pip.conf` | `~/.config/pip/pip.conf`, `~/.pip/pip.conf` |
| Poetry fallback | `%APPDATA%\pypoetry\auth.toml` (from docs) | `~/Library/Application Support/pypoetry/auth.toml` (from docs) | `~/.config/pypoetry/auth.toml` (from docs) |

- **Holds:** `.pypirc` has `password = pypi-...` upload tokens. pip config can contain
  `index-url = https://user:password@host/...`. Poetry writes `auth.toml` only when no keychain
  is available.
- **Override:** `PIP_CONFIG_FILE`, `POETRY_CONFIG_DIR`.

## 7. NuGet (.NET)

| | Windows | macOS / Linux |
|---|---|---|
| User config | `%APPDATA%\NuGet\NuGet.Config` | `~/.nuget/NuGet/NuGet.Config` |
| Project config | `nuget.config` in any project folder | same |

- **Holds:** a `<packageSourceCredentials>` section with `ClearTextPassword` (plain text) or
  `Password` (encrypted).
- **Why `Password` still matters on Windows:** it is encrypted with DPAPI, and any program running
  as the same user can decrypt it. A stealer runs as that user. Report it as lower risk than
  `ClearTextPassword`, not as safe.

## 8. AI tool keys

AI coding tools are a newer target. Their keys are expensive to abuse and are often stored in
plain config files. Most entries here are **(from docs)**.

| Tool | Location |
|---|---|
| Claude Code | `~/.claude/.credentials.json` on Windows and Linux. Keys: `claudeAiOauth.accessToken`, `claudeAiOauth.refreshToken`. macOS uses the Keychain. (verified: Windows) |
| Claude Desktop MCP config | `%APPDATA%\Claude\claude_desktop_config.json`, `~/Library/Application Support/Claude/claude_desktop_config.json`. API keys are often put in each server's `env` section. |
| Cursor MCP config | `~/.cursor/mcp.json` and `.cursor/mcp.json` in projects (from docs) |
| OpenAI Codex CLI | `~/.codex/auth.json`. Keys: `OPENAI_API_KEY` (may be `null`), `tokens.access_token`, `tokens.refresh_token`, `tokens.id_token`. A `null` API key is not a finding on its own. (verified: Windows) |
| Gemini CLI | `~/.gemini/.env`, `~/.gemini/oauth_creds.json` (from docs) |
| Hugging Face | `~/.cache/huggingface/token`. Override: `HF_HOME`, `HF_TOKEN_PATH`. |
| GitHub Copilot | `~/.config/github-copilot/hosts.json` or `apps.json`. On Windows, `%LOCALAPPDATA%\github-copilot\`. (from docs) |
| Continue | `~/.continue/config.json` or `config.yaml` (`apiKey` fields) (from docs) |
| Aider | `~/.aider.conf.yml` (from docs) |

Keys for OpenAI, Anthropic, Google, etc. also appear in `.env` files (section 1). Detection
rules match them by key format, whichever file they are in.

## 9. SSH private keys

| | Windows | macOS / Linux |
|---|---|---|
| Default keys | `~\.ssh\id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa` | `~/.ssh/` (same names) |
| Custom keys | Any file named by `IdentityFile` in `~\.ssh\config` | same |
| PuTTY keys | `*.ppk` files (location chosen by the user) | rare |
| Keys with custom names | `id_*` files (not `*.pub`) anywhere the walk reaches | same |
| Other private keys | `*.pem` and `*.key` files anywhere the walk reaches (TLS, service keys) | same |

- **Risk:** only keys **without a passphrase**. A key protected by a passphrase is useless to a
  stealer without it.
- **How to tell (detail in the detection rules):** in the modern OpenSSH format the cipher name
  inside the key is `none`. Older PEM keys lack a `Proc-Type: 4,ENCRYPTED` header. PuTTY keys
  have `Encryption: none`.
- **Not a finding:** public keys (`*.pub`), `known_hosts`, `authorized_keys`.

## 10. Azure CLI

| | Windows | macOS / Linux |
|---|---|---|
| Config folder | `~\.azure\` | `~/.azure/` |
| Token cache | `msal_token_cache.bin` (DPAPI-encrypted) (from docs) | `msal_token_cache.json` (plain text) (from docs) |
| Service principals | `service_principal_entries.bin` (DPAPI-encrypted) (from docs) | `service_principal_entries.json` (plain text) (from docs) |
| Old CLI versions | `accessTokens.json` (plain text) (from docs) | same |

- **Holds:** refresh tokens for signed-in accounts. Service principal entries can hold a
  client secret or certificate.
- **Override:** `AZURE_CONFIG_DIR`.
- **Risk note:** as with NuGet, DPAPI-encrypted files can be decrypted by any program running as
  the user. Report them as lower risk, not as safe.
- **Not a finding when:** the folder holds only `config`, `clouds.config` or other settings files
  and no token files.

## 11. Google Cloud (gcloud)

| | Windows | macOS / Linux |
|---|---|---|
| Config folder | `%APPDATA%\gcloud\` | `~/.config/gcloud/` |
| Application default credentials | `application_default_credentials.json` | same |
| Stored credentials | `credentials.db`, `access_tokens.db` (SQLite) (from docs) | same |
| Per-account copies | `legacy_credentials\<account>\adc.json` (from docs) | `legacy_credentials/<account>/adc.json` (from docs) |

- **Holds:** `application_default_credentials.json` has either a user `refresh_token` plus
  `client_secret`, or a service account `private_key`. The `.db` files hold refresh tokens.
- **Override:** `CLOUDSDK_CONFIG` (moves the folder). `GOOGLE_APPLICATION_CREDENTIALS` points to
  a key file that can be anywhere; scan that file too.
- **Risk note:** a service account `private_key` never expires on its own and is the highest risk.

## 12. Kubernetes

| | Windows | macOS / Linux |
|---|---|---|
| Config | `~\.kube\config` | `~/.kube/config` |

- **Holds:** under `users[].user`: `token`, `client-key-data` (a base64 private key), `password`,
  or an `auth-provider` block with a cached `access-token` or `refresh-token`.
- **Override:** `KUBECONFIG`. It can list several files, separated by `;` on Windows and `:` on
  macOS and Linux. Scan every file in the list.
- **Not a finding when:** a user entry only uses `exec` (for example `aws eks get-token` or
  `gke-gcloud-auth-plugin`). The credential is then fetched fresh each time and not stored.

## 13. Shell history

| Shell | Windows | macOS / Linux |
|---|---|---|
| PowerShell | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` (verified: Windows) | `~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt` (from docs) |
| bash | `~/.bash_history` (Git Bash, WSL) | `~/.bash_history` |
| zsh | n/a | `~/.zsh_history` (macOS default shell) |

- **Holds:** every command typed, including any secret typed inline, for example
  `export AWS_SECRET_ACCESS_KEY=...`, `docker login -p ...` or
  `curl -H "Authorization: Bearer ..."`.
- **Override:** `HISTFILE` (bash, zsh). PowerShell's path is a PSReadLine setting
  (`HistorySavePath`), not an environment variable.
- **Not a finding when:** the file exists but no line matches a secret pattern. History files
  exist on every machine; only lines holding a secret are findings.

---

## Planned for v1.1

Common stealer targets deferred to the next release:

- Cargo: `~/.cargo/credentials.toml`
- RubyGems: `~/.gem/credentials`
- Maven: `~/.m2/settings.xml`
- Gradle: `~/.gradle/gradle.properties`
- Composer: `~/.composer/auth.json` (`%APPDATA%\Composer\auth.json` on Windows)
- Terraform: `~/.terraform.d/credentials.tfrc.json` (`%APPDATA%\terraform.d\` on Windows)

## Never in scope

- Browser password stores (Chrome, Edge, Firefox, Safari, etc.)
- VS Code extension storage (`state.vscdb`, `globalStorage`, `secrets`)

KeySnare never reads these. Reading them would make KeySnare behave like the malware it fights.
