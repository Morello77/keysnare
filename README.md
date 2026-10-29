# KeySnare

[![CI](https://github.com/Morello77/keysnare/actions/workflows/ci.yml/badge.svg)](https://github.com/Morello77/keysnare/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Poisoned npm and PyPI packages, malicious VS Code extensions and compromised GitHub Actions all
want the same thing: the credentials sitting in plain text on developer machines. KeySnare shows
you exactly what a credential stealer would grab from your computer, plants clearly marked decoy
credentials that alert you the moment a program reads them, and tells you, step by step, how to
move each real secret somewhere safer. It runs entirely offline, has zero runtime dependencies,
and never prints a full secret.

> **Demo:** coming soon.

## Install

```
pip install keysnare
```

Python 3.10 or newer. Windows, macOS and Linux for scanning; decoy traps are Windows-only for now.

## Quick start

```
keysnare scan                                  # scan your home folder
keysnare scan ~/code/my-project                # scan one folder or file
keysnare scan --brief                          # one line per finding, no fix steps
keysnare scan --sarif --output keysnare.sarif  # report for code-scanning tools
keysnare trap install                          # Windows: plant decoys (see below)
```

Your home folder is shown as `~` in every report, so screenshots are safe to share. Exit codes
make it usable in CI: `0` nothing at or above `--fail-on` (default `high`), `1` findings, `2`
error. Full details: [docs/usage.md](docs/usage.md).

## What it scans

- `.env` files in your projects
- Cloud and cluster credentials: AWS, Azure, Google Cloud, Kubernetes
- Package registry tokens: npm, Yarn, PyPI, pip, Poetry, NuGet
- Docker registry logins, Git credentials, GitHub CLI tokens, tokens inside Git remote URLs
- AI tool keys and logins: OpenAI, Anthropic, Google, Hugging Face, Claude Code, Codex, Gemini
  CLI, GitHub Copilot, MCP server configs
- Service keys: Stripe, Slack, SendGrid
- SSH and other private keys **without** a passphrase
- Secrets typed into shell history (bash, zsh, PowerShell)

Every finding has a severity, says why it is risky, and gives fix steps for your operating
system. The locations and rules are documented in
[docs/credential-locations.md](docs/credential-locations.md) and
[docs/detection-rules.md](docs/detection-rules.md).

## How traps work (Windows)

`keysnare trap install` creates fake credentials where stealers look, for example
`~\.ssh\id_rsa_backup` or `~\.aws\credentials.old`, only where no real tool will ever read them.
Each decoy is clearly marked as a KeySnare decoy and works nowhere. KeySnare then prints a short
list of administrator commands **for you to run yourself**: they turn on Windows file auditing
for the decoys and register a small relay task that uses only built-in Windows programs. When any
program reads a decoy, Windows records it, and you get a notification naming that program.

No KeySnare program runs in the background, and KeySnare never runs as administrator.
`keysnare trap test` simulates a theft so you see an alert, and `keysnare trap remove` undoes
everything. The full design, including every system change and how it is undone:
[docs/design-traps.md](docs/design-traps.md).

## Principles

- **Offline.** No network calls, no telemetry, ever.
- **Zero runtime dependencies.** Only the Python standard library, because every third-party
  package is a supply-chain risk.
- **Never elevated.** KeySnare's own code never runs as administrator or SYSTEM. The admin steps
  are short, published commands that you read and run yourself.
- **Never prints a full secret.** Reports show `AKIA****WXYZ`, never the value.
- **Never reads browser password stores or VS Code extension storage.** That would make it behave
  like the malware it fights.

## Honest limits

- It finds credentials at the [documented locations](docs/credential-locations.md) and in the
  documented formats. A secret in an unusual place or format can be missed.
- Traps **detect** a theft; they do not block it. When you get an alert, rotate your real
  credentials.
- Traps are Windows-only for now, need administrator rights once for setup, and notify you only
  while you are logged in (Windows still records every read).
- Malware already running as you could disable your alert task before stealing. Windows' own
  record of the read survives, but the notification would not come.
- Fewer decoys are possible on machines where the matching tools are installed, because
  KeySnare never puts a decoy where a real tool would read it.
- Anyone who opens a decoy by hand can see it is a KeySnare decoy. That is deliberate.

## Verify a release

Every release is built by GitHub Actions from a tagged commit, with signed build provenance.

GitHub artifact attestations, with the [GitHub CLI](https://cli.github.com/):

```
pip download keysnare --no-deps --dest keysnare-download
gh attestation verify keysnare-download/keysnare-*.whl --repo Morello77/keysnare
```

PyPI attestations: each file on [pypi.org/project/keysnare](https://pypi.org/project/keysnare/)
shows its verified source repository and workflow. To check one yourself, use the
`pypi-attestations` tool in a separate, throwaway environment:

```
python -m pip install pypi-attestations
pypi-attestations verify pypi --repository https://github.com/Morello77/keysnare pypi:keysnare-0.1.0-py3-none-any.whl
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). Copyright 2026 Morello Developers.
