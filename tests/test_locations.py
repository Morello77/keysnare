from pathlib import Path

import pytest

from keysnare.locations import (
    WALK_ONLY_CATEGORIES,
    Category,
    Location,
    Platform,
    existing_files,
    known_locations,
)

HOME = Path("/home/dev")
WIN_HOME = Path("C:/Users/dev")
WIN_ENV = {
    "APPDATA": "C:/Users/dev/AppData/Roaming",
    "LOCALAPPDATA": "C:/Users/dev/AppData/Local",
}
PLATFORMS: tuple[Platform, ...] = ("windows", "macos", "linux")


def paths_for(category: Category, locations: list[Location]) -> list[Path]:
    return [loc.path for loc in locations if loc.category is category]


def test_aws_credentials_default_to_home_folder() -> None:
    locations = known_locations(HOME, {}, "linux")

    assert paths_for(Category.AWS_CREDENTIALS, locations) == [HOME / ".aws/credentials"]


def test_environment_override_replaces_default_path() -> None:
    env = {"AWS_SHARED_CREDENTIALS_FILE": "/secrets/aws-creds"}

    locations = known_locations(HOME, env, "linux")

    assert paths_for(Category.AWS_CREDENTIALS, locations) == [Path("/secrets/aws-creds")]


@pytest.mark.parametrize(
    ("platform", "kubeconfig", "expected"),
    [
        ("linux", "/a/config:/b/config", [Path("/a/config"), Path("/b/config")]),
        ("windows", "C:/a/config;C:/b/config", [Path("C:/a/config"), Path("C:/b/config")]),
    ],
)
def test_kubeconfig_lists_every_file_with_platform_separator(
    platform: Platform, kubeconfig: str, expected: list[Path]
) -> None:
    locations = known_locations(HOME, {"KUBECONFIG": kubeconfig}, platform)

    assert paths_for(Category.KUBECONFIG, locations) == expected


def test_windows_uses_appdata_for_nuget() -> None:
    locations = known_locations(WIN_HOME, WIN_ENV, "windows")

    assert paths_for(Category.NUGET, locations) == [
        Path("C:/Users/dev/AppData/Roaming/NuGet/NuGet.Config")
    ]


def test_windows_falls_back_to_default_appdata_when_variable_missing() -> None:
    locations = known_locations(WIN_HOME, {}, "windows")

    assert paths_for(Category.NUGET, locations) == [WIN_HOME / "AppData/Roaming/NuGet/NuGet.Config"]


def test_linux_uses_dot_nuget_folder() -> None:
    locations = known_locations(HOME, {}, "linux")

    assert paths_for(Category.NUGET, locations) == [HOME / ".nuget/NuGet/NuGet.Config"]


def test_linux_respects_xdg_config_home() -> None:
    locations = known_locations(HOME, {"XDG_CONFIG_HOME": "/xdg"}, "linux")

    assert paths_for(Category.GH_HOSTS, locations) == [Path("/xdg/gh/hosts.yml")]


def test_macos_pip_config_lives_in_library() -> None:
    locations = known_locations(HOME, {}, "macos")

    assert HOME / "Library/Application Support/pip/pip.conf" in paths_for(
        Category.PIP_CONFIG, locations
    )


def test_powershell_history_path_differs_per_platform() -> None:
    windows = known_locations(WIN_HOME, WIN_ENV, "windows")
    linux = known_locations(HOME, {}, "linux")

    assert Path(
        "C:/Users/dev/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/"
        "ConsoleHost_history.txt"
    ) in paths_for(Category.SHELL_HISTORY, windows)
    assert HOME / ".local/share/powershell/PSReadLine/ConsoleHost_history.txt" in paths_for(
        Category.SHELL_HISTORY, linux
    )


def test_google_application_credentials_file_is_included() -> None:
    env = {"GOOGLE_APPLICATION_CREDENTIALS": "/keys/sa.json"}

    locations = known_locations(HOME, env, "linux")

    assert Path("/keys/sa.json") in paths_for(Category.GCP_JSON, locations)


def test_every_category_is_covered_on_some_platform() -> None:
    covered = {
        loc.category for platform in PLATFORMS for loc in known_locations(HOME, {}, platform)
    }

    assert covered == set(Category) - WALK_ONLY_CATEGORIES


def test_no_location_points_at_browser_or_vscode_storage() -> None:
    forbidden = ("chrome", "edge", "firefox", "safari", "code/user", "state.vscdb", "vscode")
    for platform in PLATFORMS:
        for loc in known_locations(HOME, {}, platform):
            lowered = loc.path.as_posix().lower()
            assert not any(word in lowered for word in forbidden), loc.path


def test_existing_files_keeps_only_files_that_exist(tmp_path: Path) -> None:
    present = tmp_path / "credentials"
    present.write_text("x")
    (tmp_path / "a_directory").mkdir()
    locations = [
        Location(Category.AWS_CREDENTIALS, present),
        Location(Category.AWS_CONFIG, tmp_path / "missing"),
        Location(Category.DOCKER, tmp_path / "a_directory"),
    ]

    found = existing_files(locations)

    assert [(f.category, f.path) for f in found] == [(Category.AWS_CREDENTIALS, present)]


def test_existing_files_expands_folder_patterns(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "b.json").write_text("{}")
    (cache / "a.json").write_text("{}")
    (cache / "notes.txt").write_text("")

    found = existing_files([Location(Category.AWS_CACHE, cache, "*.json")])

    assert [f.path.name for f in found] == ["a.json", "b.json"]


def test_existing_files_lists_each_file_once(tmp_path: Path) -> None:
    history = tmp_path / ".bash_history"
    history.write_text("ls")

    found = existing_files(
        [
            Location(Category.SHELL_HISTORY, history),
            Location(Category.SHELL_HISTORY, history),
        ]
    )

    assert len(found) == 1
