"""What every report format shares: safe paths, masked values, counts and grouping."""

from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from keysnare.risk import Risk, Severity, risk_for
from keysnare.scanner import Finding, ScanResult


@dataclass(frozen=True)
class FindingGroup:
    """All findings of one rule, so its explanation and fix are shown once."""

    severity: Severity
    rule_id: str
    risk: Risk
    findings: list[Finding]


@dataclass(frozen=True)
class ReportContext:
    """A scan result plus what every report needs to present it."""

    result: ScanResult
    duration_seconds: float
    home: Path
    show_full_paths: bool

    def path(self, path: Path) -> str:
        """Return the path as reports show it."""
        return display_path(path, self.home, self.show_full_paths)

    @cached_property
    def counts(self) -> dict[Severity, int]:
        """Number of findings per severity, including zeros."""
        counts = dict.fromkeys(Severity, 0)
        for finding in self.result.findings:
            counts[finding.risk.severity] += 1
        return counts

    @cached_property
    def groups(self) -> list[FindingGroup]:
        """Findings grouped by rule, most severe first."""
        by_rule: dict[str, list[Finding]] = {}
        for finding in self.result.findings:
            by_rule.setdefault(finding.rule_id, []).append(finding)
        groups = [
            FindingGroup(risk_for(rule_id).severity, rule_id, risk_for(rule_id), findings)
            for rule_id, findings in by_rule.items()
        ]
        for group in groups:
            group.findings.sort(key=lambda f: (str(f.path), f.line or 0))
        return sorted(groups, key=lambda g: (g.severity, g.rule_id))

    @property
    def highest_severity(self) -> Severity | None:
        """The most severe level found, or None when there are no findings."""
        return min((f.risk.severity for f in self.result.findings), default=None)


def display_path(path: Path, home: Path, show_full_paths: bool) -> str:
    """Show paths inside the home folder as ~ so reports and screenshots are safe to share."""
    if show_full_paths:
        return str(path)
    try:
        relative = path.relative_to(home)
    except ValueError:
        return str(path)
    return str(Path("~") / relative) if relative.parts else "~"


def display_masked(finding: Finding) -> str | None:
    """Return the masked secret with line breaks and other control characters escaped."""
    masked = finding.masked
    if masked is None:
        return None
    return masked.encode("unicode_escape").decode("ascii")
