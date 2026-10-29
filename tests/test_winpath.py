from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from keysnare.winpath import PathForms, canonical, parent_of, same_windows_path

DECOY = r"C:\Users\dev\.aws\credentials.old"


def expand_short(text: str) -> str:
    return text.replace("DEV~1", "dev").replace("PROGRA~1", "Program Files")


FORMS = PathForms(
    devices={
        r"\Device\HarddiskVolume3": "C:",
        r"\Device\HarddiskVolume7": "D:",
        r"\SystemRoot": r"C:\Windows",
    },
    expand_short_names=expand_short,
)


@pytest.mark.parametrize(
    "form",
    [
        r"C:\Users\dev\.aws\credentials.old",
        "C:/Users/dev/.aws/credentials.old",
        r"c:\users\DEV\.AWS\Credentials.OLD",
        r"C:\Users\dev\.aws\x\..\credentials.old",
        r"C:\Users\dev\.\.aws\credentials.old",
        r"\\?\C:\Users\dev\.aws\credentials.old",
        r"\\.\C:\Users\dev\.aws\credentials.old",
        r"\??\C:\Users\dev\.aws\credentials.old",
        r"\Device\HarddiskVolume3\Users\dev\.aws\credentials.old",
        r"\device\harddiskvolume3\Users\dev\.aws\credentials.old",
        r"C:\Users\DEV~1\.aws\credentials.old",
        r"\\?\C:\Users\DEV~1\.aws\credentials.old",
    ],
)
def test_every_form_of_the_same_path_is_equal(form: str) -> None:
    assert same_windows_path(form, DECOY, FORMS)


@pytest.mark.parametrize(
    "path",
    [
        PureWindowsPath(DECOY),
        PurePosixPath("C:/Users/dev/.aws/credentials.old"),
        Path("C:/Users/dev/.aws/credentials.old"),
    ],
)
def test_path_objects_from_any_os_are_read_as_windows_paths(path: object) -> None:
    assert same_windows_path(path, DECOY, FORMS)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("form", "expected"),
    [
        (r"\\?\UNC\server\share\x.txt", r"\\server\share\x.txt"),
        (r"\Device\Mup\server\share\x.txt", r"\\server\share\x.txt"),
        (r"\SystemRoot\System32\cmd.exe", r"C:\Windows\System32\cmd.exe"),
        (r"\Device\HarddiskVolume7\tools\a.exe", r"D:\tools\a.exe"),
        (
            r"C:\PROGRA~1\Windows Defender\MsMpEng.exe",
            r"C:\Program Files\Windows Defender\MsMpEng.exe",
        ),
    ],
)
def test_other_windows_forms_are_translated(form: str, expected: str) -> None:
    assert canonical(form, FORMS) == canonical(expected)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (DECOY, r"C:\Users\dev\.aws\credentials"),
        (DECOY, r"D:\Users\dev\.aws\credentials.old"),
        (r"C:\Users\straße", r"C:\Users\STRASSE"),
        (r"\Device\HarddiskVolume9\Users\dev\.aws\credentials.old", DECOY),
        ("", DECOY),
    ],
)
def test_different_paths_are_not_equal(a: str, b: str) -> None:
    assert not same_windows_path(a, b, FORMS)


def test_accented_letters_compare_without_case() -> None:
    assert same_windows_path(r"C:\Users\ÉLODIE", r"c:\users\élodie")


def test_short_names_are_only_expanded_when_present() -> None:
    calls: list[str] = []

    def spy(text: str) -> str:
        calls.append(text)
        return text

    canonical(DECOY, PathForms(expand_short_names=spy))

    assert calls == []


def test_root_keeps_its_separator() -> None:
    assert canonical("C:/") == canonical("C:\\") == "C:\\"


def test_parent_of_any_form() -> None:
    assert parent_of(r"\\?\C:\Program Files\Windows Defender\MsMpEng.exe") == canonical(
        r"C:\Program Files\Windows Defender"
    )
