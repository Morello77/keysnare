# Changelog

## 0.1.0 (2026-10-30)

The first release of KeySnare. It shows what a credential stealer would grab from a developer
machine, warns you if something tries to take it, and tells you how to fix it.

- **Scan.** Finds credentials stored in plain text: `.env` files, cloud logins, package registry
  tokens, Git credentials, AI tool keys, private keys without a passphrase and secrets in shell
  history. Works on Windows, macOS and Linux.
- **Fix.** Every finding has a severity, says why it is risky and gives steps for your operating
  system.
- **Trap (Windows only).** Plants clearly marked fake credentials where stealers look. If a
  program reads one, you get a notification naming that program. Traps detect a theft; they do not
  block it.
- **Reports.** Terminal, `--brief`, `--json` and `--sarif` output, with exit codes for CI.

KeySnare runs fully offline, has no runtime dependencies, never runs as administrator and never
prints a full secret.
