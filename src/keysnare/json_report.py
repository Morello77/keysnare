"""Machine-readable JSON report. Contains masked values only, never full secrets."""

import json

from keysnare import __version__
from keysnare.guidance import fix_for
from keysnare.report import ReportContext, display_masked

# Raised only when the layout below changes in a way that breaks existing readers.
FORMAT_VERSION = 1


def render_json(context: ReportContext) -> str:
    """Return the report as indented JSON text."""
    result = context.result
    findings = [
        {
            "rule_id": group.rule_id,
            "severity": group.severity.value,
            "title": group.risk.title,
            "category": finding.category.value,
            "path": context.path(finding.path),
            "line": finding.line,
            "masked_value": display_masked(finding),
            "why": group.risk.why,
            "fix": list(fix_for(group.rule_id, result.platform)),
        }
        for group in context.groups
        for finding in group.findings
    ]
    report = {
        "tool": {"name": "keysnare", "version": __version__},
        "format_version": FORMAT_VERSION,
        "platform": result.platform,
        "summary": {
            "findings": len(result.findings),
            "by_severity": {severity.value: n for severity, n in context.counts.items()},
            "files_checked": len(result.files_checked),
            "skipped": len(result.skipped),
            "duration_seconds": round(context.duration_seconds, 2),
        },
        "findings": findings,
        "skipped": [
            {"path": context.path(skipped.path), "reason": skipped.reason}
            for skipped in result.skipped
        ],
    }
    return json.dumps(report, indent=2) + "\n"
