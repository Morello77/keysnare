import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from keysnare.locations import Category
from keysnare.report import ReportContext
from keysnare.sarif_report import render_sarif
from keysnare.scanner import Finding, ScanResult

HOME = Path.home()
SECRET = "fake" + "Secret" + "Value123"
# Official OASIS schema, kept as a test resource only:
# https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
SCHEMA_PATH = Path(__file__).parent / "resources" / "sarif-schema-2.1.0.json"

FINDINGS = [
    Finding("K-SECRET-NAME", Category.ENV_FILE, HOME / "app" / ".env", 3, SECRET),
    Finding("S-SSH-KEY", Category.SSH_KEY, HOME / ".ssh" / "id_rsa", None),
    Finding("S-NUGET-DPAPI", Category.NUGET, Path(HOME.anchor) / "shared" / "NuGet.Config", 7),
    Finding("F-NPM-TOKEN", Category.NPMRC, HOME / ".npmrc", 1, "npm_" + "a1B2" * 9),
]


def render(findings: list[Finding], show_full_paths: bool = False) -> dict[str, Any]:
    result = ScanResult(findings, [], [], "windows")
    data = json.loads(render_sarif(ReportContext(result, 1.0, HOME, show_full_paths)))
    assert isinstance(data, dict)
    return data


@pytest.mark.parametrize("findings", [FINDINGS, []])
@pytest.mark.parametrize("show_full_paths", [False, True])
def test_output_is_valid_sarif_2_1_0(findings: list[Finding], show_full_paths: bool) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    jsonschema.validators.validator_for(schema)(schema).validate(render(findings, show_full_paths))


def test_schema_check_rejects_invalid_sarif() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    invalid = render(FINDINGS)
    invalid["runs"][0]["results"][0]["level"] = "fatal"

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validators.validator_for(schema)(schema).validate(invalid)


def test_one_result_per_finding_with_rule_and_level() -> None:
    run = render(FINDINGS)["runs"][0]
    rules = run["tool"]["driver"]["rules"]

    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels == {
        "F-NPM-TOKEN": "error",
        "S-SSH-KEY": "error",
        "S-NUGET-DPAPI": "warning",
        "K-SECRET-NAME": "note",
    }
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_rules_carry_explanation_fix_and_security_severity() -> None:
    rules = render(FINDINGS)["runs"][0]["tool"]["driver"]["rules"]
    ssh = next(rule for rule in rules if rule["id"] == "S-SSH-KEY")

    assert ssh["shortDescription"]["text"] == "SSH key without a passphrase"
    assert ssh["fullDescription"]["text"].startswith("Anyone who copies this file")
    assert "Start-Service ssh-agent" in ssh["help"]["text"]
    assert ssh["properties"]["security-severity"] == "9.5"


def test_paths_in_home_are_relative_to_a_home_base_without_revealing_it() -> None:
    sarif = render(FINDINGS)
    run = sarif["runs"][0]
    env_result = next(r for r in run["results"] if r["ruleId"] == "K-SECRET-NAME")
    location = env_result["locations"][0]["physicalLocation"]

    assert location["artifactLocation"] == {"uri": "app/.env", "uriBaseId": "HOME"}
    assert location["region"] == {"startLine": 3}
    assert "uri" not in run["originalUriBaseIds"]["HOME"]
    assert HOME.as_uri() not in json.dumps(sarif)


def test_paths_outside_home_and_full_paths_use_file_uris() -> None:
    outside = next(
        r for r in render(FINDINGS)["runs"][0]["results"] if r["ruleId"] == "S-NUGET-DPAPI"
    )
    full = next(
        r
        for r in render(FINDINGS, show_full_paths=True)["runs"][0]["results"]
        if r["ruleId"] == "K-SECRET-NAME"
    )

    outside_uri = outside["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    full_uri = full["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert outside_uri == (Path(HOME.anchor) / "shared" / "NuGet.Config").as_uri()
    assert full_uri == (HOME / "app" / ".env").as_uri()


def test_finding_without_a_line_has_no_region() -> None:
    ssh = next(r for r in render(FINDINGS)["runs"][0]["results"] if r["ruleId"] == "S-SSH-KEY")

    assert "region" not in ssh["locations"][0]["physicalLocation"]


def test_message_shows_masked_value_only() -> None:
    npm = next(r for r in render(FINDINGS)["runs"][0]["results"] if r["ruleId"] == "F-NPM-TOKEN")

    assert npm["message"]["text"] == "npm access token found. Masked value: npm_****a1B2."
