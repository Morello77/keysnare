from pathlib import Path

from keysnare.locations import Category
from keysnare.report import ReportContext, display_masked, display_path
from keysnare.risk import Severity
from keysnare.scanner import Finding, ScanResult

HOME = Path.home()


def finding(rule_id: str, path: Path, line: int | None = 1, secret: str | None = None) -> Finding:
    return Finding(rule_id, Category.ENV_FILE, path, line, secret)


def context(findings: list[Finding], show_full_paths: bool = False) -> ReportContext:
    result = ScanResult(findings, [], [], "windows")
    return ReportContext(result, 1.5, HOME, show_full_paths)


def test_paths_inside_home_start_with_tilde() -> None:
    shown = display_path(HOME / ".aws" / "credentials", HOME, show_full_paths=False)

    assert shown == str(Path("~") / ".aws" / "credentials")
    assert str(HOME) not in shown


def test_home_itself_is_shown_as_tilde() -> None:
    assert display_path(HOME, HOME, show_full_paths=False) == "~"


def test_paths_outside_home_are_shown_in_full() -> None:
    outside = Path(HOME.anchor) / "elsewhere" / ".env"

    assert display_path(outside, HOME, show_full_paths=False) == str(outside)


def test_full_paths_can_be_requested() -> None:
    path = HOME / ".npmrc"

    assert display_path(path, HOME, show_full_paths=True) == str(path)


def test_masked_value_hides_control_characters() -> None:
    private_key = "-----BEGIN " + "PRIVATE KEY-----\nMIIabc\n-----END " + "PRIVATE KEY-----\n"

    shown = display_masked(finding("S-GCP-SERVICE-ACCOUNT", HOME / "k.json", secret=private_key))

    assert shown is not None and "\n" not in shown


def test_finding_without_a_secret_has_no_masked_value() -> None:
    assert display_masked(finding("S-SSH-KEY", HOME / "id_rsa")) is None


def test_counts_include_every_severity() -> None:
    counts = context(
        [finding("S-SSH-KEY", HOME / "a"), finding("K-SECRET-NAME", HOME / "b")]
    ).counts

    assert counts == {
        Severity.CRITICAL: 1,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 1,
    }


def test_groups_are_ordered_by_severity_then_rule() -> None:
    findings = [
        finding("K-SECRET-NAME", HOME / "a"),
        finding("S-SSH-KEY", HOME / "z"),
        finding("F-NPM-TOKEN", HOME / "b"),
        finding("S-SSH-KEY", HOME / "y"),
    ]

    groups = context(findings).groups

    assert [(g.severity, g.rule_id, [f.path.name for f in g.findings]) for g in groups] == [
        (Severity.CRITICAL, "F-NPM-TOKEN", ["b"]),
        (Severity.CRITICAL, "S-SSH-KEY", ["y", "z"]),
        (Severity.LOW, "K-SECRET-NAME", ["a"]),
    ]


def test_highest_severity_is_none_without_findings() -> None:
    assert context([]).highest_severity is None
    assert context([finding("K-SECRET-NAME", HOME / "a")]).highest_severity is Severity.LOW
