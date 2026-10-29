import os
import sys
from pathlib import Path

import pytest

from keysnare.locations import Category
from keysnare.scanner import MAX_WALK_FILE_BYTES, Finding, scan

# Fake secrets are assembled at runtime so no complete token appears in the repository.
SECRET = "fake" + "Secret" + "Value123"
GITHUB_TOKEN = "ghp_" + "a1B2" * 9


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def found_paths(home: Path, root: Path | None = None) -> set[tuple[str, Path]]:
    result = scan(root, home=home, env={}, platform="linux")
    return {(f.rule_id, f.path) for f in result.findings}


def test_known_location_is_scanned(tmp_path: Path) -> None:
    creds = write(tmp_path / ".aws/credentials", f"[d]\naws_secret_access_key = {SECRET}\n")

    assert found_paths(tmp_path) == {("S-AWS-SECRET", creds)}


def test_env_files_are_found_in_nested_projects(tmp_path: Path) -> None:
    env = write(tmp_path / "code/app/.env", f"API_TOKEN={SECRET}\n")
    example = write(tmp_path / "code/app/.env.example", "API_TOKEN=your_token_here\n")

    result = scan(home=tmp_path, env={}, platform="linux")

    assert {(f.rule_id, f.path) for f in result.findings} == {("K-SECRET-NAME", env)}
    assert example in result.files_checked


def test_skipped_folders_are_not_walked(tmp_path: Path) -> None:
    for folder in ("node_modules/pkg", ".venv", "venv", "__pycache__", ".cache", "Temp"):
        write(tmp_path / "app" / folder / ".env", f"API_TOKEN={SECRET}\n")

    assert found_paths(tmp_path) == set()


def test_git_config_is_checked_but_git_folder_is_not_walked(tmp_path: Path) -> None:
    git = tmp_path / "app/.git"
    config = write(git / "config", f'[remote "o"]\n\turl = https://u:{SECRET}@github.com/a\n')
    write(git / "hooks/.env", f"API_TOKEN={SECRET}\n")

    assert found_paths(tmp_path) == {("S-GIT-REMOTE", config)}


def test_project_npmrc_nuget_and_ppk_files_are_found(tmp_path: Path) -> None:
    npmrc = write(tmp_path / "web/.npmrc", f"//r/:_authToken={SECRET}\n")
    nuget = write(
        tmp_path / "dotnet/NuGet.Config", f'<add key="ClearTextPassword" value="{SECRET}"/>'
    )
    ppk = write(
        tmp_path / "keys/server.ppk", "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"
    )
    cursor = write(tmp_path / "web/.cursor/mcp.json", f'{{"token": "{GITHUB_TOKEN}"}}')

    assert found_paths(tmp_path) == {
        ("S-NPMRC-TOKEN", npmrc),
        ("S-NUGET-CLEARTEXT", nuget),
        ("S-SSH-KEY", ppk),
        ("F-GITHUB-TOKEN", cursor),
    }


def test_appdata_is_skipped_in_walk_but_known_files_inside_are_checked(tmp_path: Path) -> None:
    roaming = tmp_path / "AppData/Roaming"
    nuget = write(
        roaming / "NuGet/NuGet.Config", f'<add key="ClearTextPassword" value="{SECRET}"/>'
    )
    write(roaming / "some-app/.env", f"API_TOKEN={SECRET}\n")

    result = scan(home=tmp_path, env={}, platform="windows")

    assert {(f.rule_id, f.path) for f in result.findings} == {("S-NUGET-CLEARTEXT", nuget)}


def test_large_walked_files_are_skipped_and_reported(tmp_path: Path) -> None:
    big = write(tmp_path / "app/.env", "A=1\n" * (MAX_WALK_FILE_BYTES // 4 + 1))

    result = scan(home=tmp_path, env={}, platform="linux")

    assert [(s.path, s.reason) for s in result.skipped] == [(big, "larger than 1 MB")]


def test_symlinked_folders_are_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    write(outside / ".env", f"API_TOKEN={SECRET}\n")
    home = tmp_path / "home"
    home.mkdir()
    try:
        os.symlink(outside, home / "link", target_is_directory=True)
    except OSError:
        pytest.skip("creating symlinks needs extra permissions on this machine")

    assert found_paths(home) == set()


def test_folders_beyond_the_windows_path_limit_are_scanned(tmp_path: Path) -> None:
    deep = tmp_path.joinpath(*["a" * 50] * 6)
    os_deep = "\\\\?\\" + str(deep) if sys.platform == "win32" else str(deep)
    os.makedirs(os_deep)
    with open(os.path.join(os_deep, ".env"), "w", encoding="utf-8") as env_file:
        env_file.write(f"API_TOKEN={SECRET}\n")

    result = scan(home=tmp_path, env={}, platform="linux")

    assert len(str(deep / ".env")) > 260
    assert [(f.rule_id, f.path) for f in result.findings] == [("K-SECRET-NAME", deep / ".env")]
    assert result.skipped == []


def test_scanning_a_folder_only_covers_that_folder(tmp_path: Path) -> None:
    write(tmp_path / ".aws/credentials", f"[d]\naws_secret_access_key = {SECRET}\n")
    env = write(tmp_path / "code/.env", f"API_TOKEN={SECRET}\n")

    assert found_paths(tmp_path, root=tmp_path / "code") == {("K-SECRET-NAME", env)}


def test_scanning_a_folder_still_recognises_known_files_inside_it(tmp_path: Path) -> None:
    creds = write(tmp_path / ".aws/credentials", f"[d]\naws_secret_access_key = {SECRET}\n")

    assert found_paths(tmp_path, root=tmp_path / ".aws") == {("S-AWS-SECRET", creds)}


def test_scanning_a_single_unrecognised_file_uses_generic_rules(tmp_path: Path) -> None:
    notes = write(tmp_path / "notes.txt", f"token: {GITHUB_TOKEN}\n")

    assert found_paths(tmp_path, root=notes) == {("F-GITHUB-TOKEN", notes)}


def test_binary_stores_are_reported_by_presence(tmp_path: Path) -> None:
    db = tmp_path / ".config/gcloud/credentials.db"
    db.parent.mkdir(parents=True)
    db.write_bytes(b"\x00SQLite")
    (tmp_path / ".config/gcloud/access_tokens.db").write_bytes(b"")

    result = scan(home=tmp_path, env={}, platform="linux")

    assert [(f.rule_id, f.path, f.secret) for f in result.findings] == [
        ("S-GCP-CREDENTIALS-DB", db, None)
    ]


def test_each_file_is_scanned_once(tmp_path: Path) -> None:
    write(tmp_path / ".npmrc", f"//r/:_authToken={SECRET}\n")

    result = scan(home=tmp_path, env={}, platform="linux")

    assert len(result.findings) == 1
    assert len(result.files_checked) == 1


def test_unreadable_files_are_reported_as_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    locked = write(tmp_path / ".pypirc", f"password = {SECRET}\n")
    original = Path.read_text

    def read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self == locked:
            raise PermissionError("locked")
        return original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", read_text)

    result = scan(home=tmp_path, env={}, platform="linux")

    assert result.findings == []
    assert [(s.path, s.reason) for s in result.skipped] == [(locked, "could not read: locked")]


def test_skip_reasons_never_repeat_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    locked = write(tmp_path / ".pypirc", f"password = {SECRET}\n")

    def read_text(self: Path, *args: object, **kwargs: object) -> str:
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "read_text", read_text)

    [skipped] = scan(home=tmp_path, env={}, platform="linux").skipped

    assert skipped.path == locked
    assert skipped.reason == "could not read: Permission denied"


def test_decoys_are_never_opened_and_listed_as_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = write(tmp_path / ".aws/credentials", f"[d]\naws_secret_access_key = {SECRET}\n")
    original = Path.read_text

    def read_text(self: Path, *args: object, **kwargs: object) -> str:
        assert self != decoy, "the scanner opened a decoy"
        return original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", read_text)
    other_spelling = Path(str(decoy).upper()) if sys.platform == "win32" else decoy

    result = scan(home=tmp_path, env={}, platform="linux", decoys=[other_spelling])

    assert result.findings == []
    assert [(s.path, s.reason) for s in result.skipped] == [(decoy, "KeySnare decoy (not read)")]


def test_progress_counts_every_walked_folder(tmp_path: Path) -> None:
    for name in ("a", "b", "a/c"):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    counts: list[int] = []

    scan(home=tmp_path, env={}, platform="linux", progress=counts.append)

    assert counts == [1, 2, 3, 4]


def test_results_are_in_the_same_order_every_time(tmp_path: Path) -> None:
    for index in range(20):
        write(tmp_path / f"p{index}" / ".env", f"API_TOKEN={SECRET}{index}\n")

    first = scan(home=tmp_path, env={}, platform="linux")
    second = scan(home=tmp_path, env={}, platform="linux")

    assert first.files_checked == second.files_checked
    assert [f.path for f in first.findings] == [f.path for f in second.findings]


def test_findings_show_only_masked_secrets() -> None:
    finding = Finding("F-GITHUB-TOKEN", Category.ENV_FILE, Path(".env"), 1, GITHUB_TOKEN)

    assert finding.masked == "ghp_****a1B2"
    assert GITHUB_TOKEN not in repr(finding)
