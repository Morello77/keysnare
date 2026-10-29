from pathlib import Path

import pytest

from keysnare.guidance import FIXES, fix_for
from keysnare.locations import Platform
from keysnare.risk import RISKS
from keysnare.scanner import scan

PLATFORMS: tuple[Platform, ...] = ("windows", "macos", "linux")


def test_every_rule_has_fix_guidance() -> None:
    assert set(FIXES) == set(RISKS)


@pytest.mark.parametrize("platform", PLATFORMS)
def test_every_rule_has_steps_on_every_platform(platform: Platform) -> None:
    for rule_id in RISKS:
        steps = fix_for(rule_id, platform)
        assert steps, rule_id
        assert all(step.strip() for step in steps), rule_id


def test_platform_specific_steps_differ() -> None:
    windows = " ".join(fix_for("S-SSH-KEY", "windows"))
    macos = " ".join(fix_for("S-SSH-KEY", "macos"))

    assert "Start-Service ssh-agent" in windows
    assert "--apple-use-keychain" in macos
    assert "--apple-use-keychain" not in windows


def test_steps_shared_by_all_platforms_appear_everywhere() -> None:
    for platform in PLATFORMS:
        assert any("ssh-keygen -p" in step for step in fix_for("S-SSH-KEY", platform))


def test_unknown_rule_id_is_an_error() -> None:
    with pytest.raises(KeyError):
        fix_for("F-NOT-A-RULE", "windows")


def test_scan_result_records_its_platform(tmp_path: Path) -> None:
    assert scan(home=tmp_path, env={}, platform="macos").platform == "macos"
