# KeySnare

[![CI](https://github.com/Morello77/keysnare/actions/workflows/ci.yml/badge.svg)](https://github.com/Morello77/keysnare/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Poisoned npm and PyPI packages, malicious VS Code extensions and compromised GitHub Actions all
want the same thing: the credentials sitting in plain text on developer machines. KeySnare shows
you exactly what a credential stealer would grab from your computer, plants clearly marked decoy
credentials that alert you the moment a program reads them, and tells you, step by step, how to
move each real secret somewhere safer. It runs entirely offline, has zero runtime dependencies,
and never prints a full secret.

![KeySnare finding fake credentials in a demo folder, then catching a simulated theft of a decoy](https://raw.githubusercontent.com/Morello77/keysnare/main/docs/demo.gif)

## Why I built this

I’m Morello, a developer in Nigeria. For the better part of this year, most of the cybersecurity news I read pointed to the same thing: exposed keys. Poisoned npm packages, and, most interesting to me, PyPI packages stealing developers’ keys. How do you protect yourself from attacks like that? So I decided to build a tool and see if it helps. It’s called KeySnare. When I first ran it on my PC, it found three tokens I didn’t know were there.

What I wanted was simple: show me what a stealer would grab from my machine, tell me how to fix it, and warn me if something tries to take it. That’s what KeySnare does:

- It looks at your machine, not just your code. Most secret scanners are built to check code before you push it. Stealers don’t care about your repo. They go straight for the files on your computer: .env files, cloud logins, npm and PyPI tokens, SSH keys, AI tool keys, even your shell history. KeySnare checks those.
- It sets traps. On Windows, KeySnare can plant fake keys where stealers look. If any program reads one, you get a notification with the name of that program. It all happens on your machine, with no online service involved.
- It tells you how to fix things. Every finding says why it matters and gives steps for your operating system.
- It’s built so you can trust it. It works fully offline and has no dependencies. It never runs as administrator, never shows a full secret, and never touches your browser passwords. A tool that protects your keys shouldn’t become a risk itself.

It doesn’t block attacks, and I say that openly in the limits section below. But knowing what’s exposed, and knowing fast when something goes after it, is a big step. I hope it helps you the way it helped me.

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
