# Contributing to KeySnare

Thanks for helping. KeySnare protects developers from credential-stealing malware, so it holds
itself to a few rules that every change must keep.

## Rules every change keeps

- **Offline.** No network calls, no telemetry, ever.
- **Zero runtime dependencies.** Standard library only. Every third-party package is a
  supply-chain risk, which is exactly what KeySnare defends against. Development tools are fine.
- **Never a full secret.** Output, logs and errors show masked values only (`AKIA****WXYZ`).
- **Never elevated.** No administrator or SYSTEM context may run code from a user-writable path.
  KeySnare's Python code always runs as the normal user. Text from events, files or other
  programs is data, never code or command arguments.
- **Never browser stores or VS Code extension storage.**
- **Few false positives.** Every finding says why it is risky and how to fix it.
- **Never touch real credentials** without the user's explicit confirmation.

## Setup

```
git clone https://github.com/Morello77/keysnare.git
cd keysnare
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Checks

All four must pass before a pull request is merged. CI runs them on Windows, macOS and Linux, on
Python 3.10 and 3.13.

```
ruff check .
black --check .
mypy
pytest
```

## Tests

- Write the test first, then the code.
- **Fake secrets are built from pieces at runtime** (`"ghp_" + "a1B2" * 9`), never written as
  complete strings, so the repository never trips GitHub push protection or other scanners.
- **Never run trap tests on your own machine.** `keysnare trap install` changes the audit policy,
  scheduled tasks and file permissions. The trap integration test
  (`tests/integration/trap_harness.ps1`) runs only on disposable GitHub Actions Windows runners,
  and refuses to start anywhere else.
- Changes to the admin command templates (`src/keysnare/trap/admin.py`) must update
  `docs/design-traps.md` and `docs/usage.md` to match; a test checks that they are identical.

## Style

- Clear names over comments. Comments explain *why*, never repeat *what*.
- Short docstrings on public functions.
- No unused code and no speculative features.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`, `chore:`.

## Releases

Releases are built only by the release workflow; never upload locally built packages.

## Security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
