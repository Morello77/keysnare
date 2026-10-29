# Security policy

KeySnare is a security tool, so a weakness in KeySnare itself matters. Thank you for reporting
one privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and click
**Report a vulnerability**. Only the maintainers see the report.

Please do not open a public issue, pull request or discussion for a vulnerability until a fix is
released.

Include:

- what an attacker can do, and what they need first (for example "malware running as the user
  without admin rights");
- steps to reproduce, ideally on a fresh Windows VM;
- the KeySnare version (`keysnare --version`) and your operating system.

**Never include real secrets** in a report. If a finding involves a credential, use a fake one.

The maintainer aims to acknowledge reports within 7 days and will keep you updated until a fix
is released. With your permission, you will be credited in the release notes.

## Supported versions

Only the latest release receives security fixes.

## What counts as a vulnerability

KeySnare makes promises that a vulnerability would break. Reports are especially welcome for:

- any way for code running **without** administrator rights to make KeySnare's admin commands,
  the SYSTEM relay task or anything else run code **as administrator or SYSTEM**;
- writing to, or redirecting, `C:\ProgramData\KeySnare` as a standard user (junctions, symlinks,
  pre-created folders);
- KeySnare printing, logging or writing a full secret anywhere (terminal, JSON, SARIF, logs);
- event text or file content being treated as code or command arguments;
- any network connection made by KeySnare;
- KeySnare reading browser password stores or VS Code extension storage;
- a decoy that is a working credential anywhere;
- `trap remove` deleting or changing a file KeySnare did not create.

Known, documented limits (see "Remaining risks" in
[docs/design-traps.md](docs/design-traps.md)) are not vulnerabilities, but ideas to reduce them
are welcome as normal issues.
