"""SARIF 2.1.0 report for code-scanning tools. Contains masked values only, never full secrets."""

import json
from pathlib import Path
from typing import Any

from keysnare import __version__
from keysnare.guidance import fix_for
from keysnare.report import FindingGroup, ReportContext, display_masked
from keysnare.risk import Severity
from keysnare.scanner import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
HOME_BASE_ID = "HOME"
LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
# GitHub code scanning maps these scores to its Critical/High/Medium/Low labels.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}


def render_sarif(context: ReportContext) -> str:
    """Return the report as a SARIF 2.1.0 log."""
    groups = context.groups
    results = [
        _result(group, index, finding, context)
        for index, group in enumerate(groups)
        for finding in group.findings
    ]
    run = {
        "tool": {
            "driver": {
                "name": "KeySnare",
                "version": __version__,
                "informationUri": "https://github.com/Morello77/keysnare",
                "rules": [_rule(group, context) for group in groups],
            }
        },
        # Named but deliberately without a uri, so the log never reveals the home folder.
        "originalUriBaseIds": {
            HOME_BASE_ID: {"description": {"text": "The home folder of the scanned user."}}
        },
        "results": results,
    }
    log = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(log, indent=2) + "\n"


def _rule(group: FindingGroup, context: ReportContext) -> dict[str, Any]:
    steps = fix_for(group.rule_id, context.result.platform)
    numbered = [f"{number}. {step}" for number, step in enumerate(steps, start=1)]
    return {
        "id": group.rule_id,
        "name": group.risk.title,
        "shortDescription": {"text": group.risk.title},
        "fullDescription": {"text": group.risk.why},
        "help": {"text": "\n".join(numbered), "markdown": "\n".join(numbered)},
        "defaultConfiguration": {"level": LEVELS[group.severity]},
        "properties": {
            "security-severity": SECURITY_SEVERITY[group.severity],
            "tags": ["security", "secrets"],
        },
    }


def _result(
    group: FindingGroup, rule_index: int, finding: Finding, context: ReportContext
) -> dict[str, Any]:
    masked = display_masked(finding)
    message = f"{group.risk.title} found."
    if masked:
        message += f" Masked value: {masked}."
    physical: dict[str, Any] = {"artifactLocation": _artifact_location(finding.path, context)}
    if finding.line is not None:
        physical["region"] = {"startLine": finding.line}
    return {
        "ruleId": group.rule_id,
        "ruleIndex": rule_index,
        "level": LEVELS[group.severity],
        "message": {"text": message},
        "locations": [{"physicalLocation": physical}],
    }


def _artifact_location(path: Path, context: ReportContext) -> dict[str, str]:
    absolute = path.absolute()
    if not context.show_full_paths:
        try:
            relative = absolute.relative_to(context.home)
        except ValueError:
            pass
        else:
            return {"uri": relative.as_posix(), "uriBaseId": HOME_BASE_ID}
    return {"uri": absolute.as_uri()}
