import json
from pathlib import Path

from keysnare import __version__
from keysnare.json_report import render_json
from keysnare.locations import Category
from keysnare.report import ReportContext
from keysnare.scanner import Finding, ScanResult, SkippedPath

HOME = Path.home()
SECRET = "fake" + "Secret" + "Value123"


def render(show_full_paths: bool = False) -> dict[str, object]:
    findings = [
        Finding("K-SECRET-NAME", Category.ENV_FILE, HOME / "app" / ".env", 3, SECRET),
        Finding("S-SSH-KEY", Category.SSH_KEY, HOME / ".ssh" / "id_rsa", 1),
    ]
    skipped = [SkippedPath(HOME / "locked", "could not read: Permission denied")]
    result = ScanResult(findings, [HOME / "a", HOME / "b"], skipped, "linux")
    data = json.loads(render_json(ReportContext(result, 2.345, HOME, show_full_paths)))
    assert isinstance(data, dict)
    return data


def test_tool_and_summary() -> None:
    data = render()

    assert data["tool"] == {"name": "keysnare", "version": __version__}
    assert data["format_version"] == 1
    assert data["platform"] == "linux"
    assert data["summary"] == {
        "findings": 2,
        "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 1},
        "files_checked": 2,
        "skipped": 1,
        "duration_seconds": 2.35,
    }


def test_findings_are_most_severe_first_with_masked_values_only() -> None:
    findings = render()["findings"]
    assert isinstance(findings, list)

    ssh, possible = findings
    assert ssh["rule_id"] == "S-SSH-KEY"
    assert ssh["severity"] == "critical"
    assert ssh["masked_value"] is None
    assert possible["masked_value"] == "fake****e123"
    assert possible["path"] == str(Path("~") / "app" / ".env")
    assert possible["line"] == 3
    assert possible["category"] == "env-file"
    assert possible["title"] == "Possible secret"
    assert possible["why"]
    assert possible["fix"] and all(isinstance(step, str) for step in possible["fix"])


def test_skipped_paths_are_listed() -> None:
    assert render()["skipped"] == [
        {"path": str(Path("~") / "locked"), "reason": "could not read: Permission denied"}
    ]


def test_full_paths_can_be_requested() -> None:
    findings = render(show_full_paths=True)["findings"]
    assert isinstance(findings, list)

    assert findings[1]["path"] == str(HOME / "app" / ".env")
