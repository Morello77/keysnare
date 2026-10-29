import re
from pathlib import Path

import pytest

from keysnare.locations import Category
from keysnare.risk import RISKS, Severity, risk_for
from keysnare.rules import FORMAT_RULES
from keysnare.scanner import Finding

REPO = Path(__file__).resolve().parent.parent
RULE_ID = re.compile(r"\b[FSK]-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\b")


def test_every_documented_rule_has_a_risk() -> None:
    documented = set(RULE_ID.findall((REPO / "docs/detection-rules.md").read_text("utf-8")))

    assert documented == set(RISKS)


def test_every_rule_the_code_can_report_has_a_risk() -> None:
    in_detect = set(RULE_ID.findall((REPO / "src/keysnare/detect.py").read_text("utf-8")))
    in_format_rules = {rule.rule_id for rule in FORMAT_RULES}

    assert in_detect | in_format_rules <= set(RISKS)


@pytest.mark.parametrize(
    ("rule_id", "severity"),
    [
        ("S-SSH-KEY", Severity.CRITICAL),
        ("F-NPM-TOKEN", Severity.CRITICAL),
        ("F-OPENAI-KEY", Severity.HIGH),
        ("S-NUGET-DPAPI", Severity.MEDIUM),
        ("S-AWS-SESSION", Severity.MEDIUM),
        ("K-SECRET-NAME", Severity.LOW),
    ],
)
def test_severity_reflects_what_an_attacker_can_do(rule_id: str, severity: Severity) -> None:
    assert risk_for(rule_id).severity is severity


def test_every_risk_explains_itself_briefly() -> None:
    for rule_id, risk in RISKS.items():
        assert risk.title and risk.why.endswith("."), rule_id
        assert len(risk.why) <= 240, rule_id


def test_severities_sort_from_most_to_least_severe() -> None:
    ordered = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM, Severity.HIGH])

    assert ordered == [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    assert Severity.CRITICAL <= Severity.HIGH <= Severity.HIGH
    assert Severity.LOW > Severity.MEDIUM >= Severity.MEDIUM


def test_unknown_rule_id_is_an_error() -> None:
    with pytest.raises(KeyError):
        risk_for("F-NOT-A-RULE")


def test_finding_exposes_its_risk() -> None:
    finding = Finding("S-SSH-KEY", Category.SSH_KEY, Path("id_rsa"), 1)

    assert finding.risk is RISKS["S-SSH-KEY"]
