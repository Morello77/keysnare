import io
import json
from pathlib import Path

import pytest

from keysnare import __version__, cli
from keysnare.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

# Fake secrets are assembled at runtime so no complete token appears in the repository.
FAKE_SECRETS = {
    "aws": "AKIA" + "Q7" * 8,
    "github": "ghp_" + "a1B2" * 9,
    "npm": "npm_" + "c3D4" * 9,
    "pypi": "pypi-" + "AgEIcHlwaS5vcmc" + "e5F6-" * 12,
    "openai": "sk-proj-" + "g7H8" * 6 + "T3BlbkFJ" + "i9J0" * 6,
    "anthropic": "sk-ant-" + "api03-" + "k1L2" * 23,
    "google": "AIza" + "m3N4o" * 7,
    "huggingface": "hf_" + "p5Q6" * 9,
    "url_password": "url" + "Pass" + "w0rdValue",
    "named": "stripe" + "Secret" + "Value99",
    "npmrc": "npmrc" + "Token" + "Value123",
    "git_remote": "remote" + "Token" + "Value12",
    "nuget": "nuget" + "Feed" + "Password1",
}


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def plant_secrets(root: Path) -> None:
    s = FAKE_SECRETS
    write(
        root / "app" / ".env",
        f"AWS_ACCESS_KEY_ID={s['aws']}\nGITHUB_TOKEN={s['github']}\nNPM={s['npm']}\n"
        f"PYPI={s['pypi']}\nOPENAI={s['openai']}\nANTHROPIC={s['anthropic']}\n"
        f"GOOGLE={s['google']}\nHF={s['huggingface']}\n"
        f"DATABASE_URL=postgres://admin:{s['url_password']}@db.local/app\n"
        f"STRIPE_SECRET={s['named']}\n",
    )
    write(root / "web" / ".npmrc", f"//registry.npmjs.org/:_authToken={s['npmrc']}\n")
    write(
        root / "repo" / ".git" / "config",
        f'[remote "origin"]\n\turl = https://dev:{s["git_remote"]}@github.com/a/b.git\n',
    )
    write(
        root / "dotnet" / "NuGet.Config",
        f'<add key="ClearTextPassword" value="{s["nuget"]}" />\n',
    )


def run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.mark.parametrize("output", [[], ["--quiet"], ["--json"], ["--sarif"]])
@pytest.mark.parametrize("paths", [[], ["--show-full-paths"]])
def test_no_output_format_ever_contains_an_unmasked_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], output: list[str], paths: list[str]
) -> None:
    plant_secrets(tmp_path)

    code, out, err = run(["scan", str(tmp_path), *output, *paths], capsys)

    assert code == EXIT_FINDINGS
    for name, secret in FAKE_SECRETS.items():
        hidden_middle = secret[4:-4]
        assert secret not in out + err, name
        assert hidden_middle not in out + err, name


def test_every_planted_secret_is_detected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plant_secrets(tmp_path)

    _, out, _ = run(["scan", str(tmp_path), "--json"], capsys)

    masked = {f["masked_value"] for f in json.loads(out)["findings"]}
    expected = {secret[:4] + "****" + secret[-4:] for secret in FAKE_SECRETS.values()}
    assert expected <= masked


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == EXIT_OK
    assert capsys.readouterr().out.strip() == f"keysnare {__version__}"


def test_clean_folder_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(["scan", str(tmp_path)], capsys)

    assert code == EXIT_OK
    assert "No plain-text credentials found" in out


@pytest.mark.parametrize(
    ("fail_on", "expected"),
    [("critical", EXIT_OK), ("high", EXIT_OK), ("medium", EXIT_OK), ("low", EXIT_FINDINGS)],
)
def test_fail_on_threshold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fail_on: str, expected: int
) -> None:
    write(tmp_path / ".env", f"STRIPE_SECRET={FAKE_SECRETS['named']}\n")

    code, _, _ = run(["scan", str(tmp_path), "--fail-on", fail_on], capsys)

    assert code == expected


def test_default_threshold_is_high(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / ".env", f"OPENAI={FAKE_SECRETS['openai']}\n")

    code, _, _ = run(["scan", str(tmp_path)], capsys)

    assert code == EXIT_FINDINGS


def test_missing_path_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(["scan", str(tmp_path / "missing")], capsys)

    assert code == EXIT_ERROR
    assert out == ""
    assert "does not exist" in err


def test_unexpected_failure_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_scan(*args: object, **kwargs: object) -> None:
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(cli, "scan", broken_scan)

    code, _, err = run(["scan", str(tmp_path)], capsys)

    assert code == EXIT_ERROR
    assert "disk on fire" in err


def test_output_formats_cannot_be_combined(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", "--json", "--sarif"])

    assert exit_info.value.code == EXIT_ERROR


def test_quiet_prints_only_the_summary_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plant_secrets(tmp_path)

    _, out, _ = run(["scan", str(tmp_path), "--quiet"], capsys)

    assert len(out.splitlines()) == 1
    assert "findings (" in out


def test_paths_are_home_relative_unless_full_paths_requested(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plant_secrets(tmp_path)

    _, short, _ = run(["scan", str(tmp_path), "--json"], capsys)
    _, full, _ = run(["scan", str(tmp_path), "--json", "--show-full-paths"], capsys)

    short_paths = [f["path"] for f in json.loads(short)["findings"]]
    full_paths = [f["path"] for f in json.loads(full)["findings"]]
    if tmp_path.is_relative_to(Path.home()):
        assert all(p.startswith("~") for p in short_paths)
    assert all(Path(p).is_absolute() for p in full_paths)


@pytest.mark.parametrize("output", [[], ["--quiet"], ["--json"], ["--sarif"]])
def test_output_file_is_utf8_without_bom(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], output: list[str]
) -> None:
    plant_secrets(tmp_path / "scan")
    report = tmp_path / "report.out"

    code, out, _ = run(["scan", str(tmp_path / "scan"), *output, "--output", str(report)], capsys)

    raw = report.read_bytes()
    assert code == EXIT_FINDINGS
    assert out == ""
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r\n" not in raw
    assert b"\x1b[" not in raw
    text = raw.decode("utf-8")
    if output in (["--json"], ["--sarif"]):
        json.loads(text)
    for secret in FAKE_SECRETS.values():
        assert secret not in text


def test_unwritable_output_file_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "missing-folder" / "report.json"

    code, out, err = run(["scan", str(tmp_path), "--json", "--output", str(target)], capsys)

    assert code == EXIT_ERROR
    assert out == ""
    assert "could not write" in err


def test_keysnare_refuses_to_run_elevated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "is_elevated", lambda: True)

    code, out, err = run(["scan", str(tmp_path)], capsys)

    assert code == EXIT_ERROR
    assert out == ""
    assert "refuses to run as administrator" in err


def test_traps_are_windows_only(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "is_windows", lambda: False)

    code, _, err = run(["trap", "status"], capsys)

    assert code == EXIT_ERROR
    assert "Windows-only" in err


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.mark.parametrize(
    ("flags", "stream", "expected"),
    [
        ([], Terminal(), True),
        (["--output", "report.txt"], Terminal(), True),
        (["--quiet"], Terminal(), False),
        (["--json"], Terminal(), False),
        (["--sarif"], Terminal(), False),
        ([], io.StringIO(), False),
    ],
)
def test_progress_shows_only_for_a_person_at_a_terminal(
    flags: list[str], stream: io.StringIO, expected: bool
) -> None:
    args = cli.build_parser().parse_args(["scan", *flags])

    assert cli.shows_progress(args, stream) is expected


def test_piped_scan_prints_no_progress(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plant_secrets(tmp_path)

    _, _, err = run(["scan", str(tmp_path)], capsys)

    assert "Scanning..." not in err


def test_piped_output_has_no_colors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plant_secrets(tmp_path)

    _, out, _ = run(["scan", str(tmp_path)], capsys)

    assert "\x1b[" not in out
