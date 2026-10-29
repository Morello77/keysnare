import re
import sys
from pathlib import Path

import pytest

import keysnare

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_version_matches_pyproject() -> None:
    # The release workflow checks the tag against pyproject.toml; --version must agree with it.
    match = re.search(r'^version = "([^"]+)"', PYPROJECT.read_text(encoding="utf-8"), re.MULTILINE)

    assert match is not None
    assert keysnare.__version__ == match.group(1)


def test_package_has_zero_runtime_dependencies_and_valid_links() -> None:
    if sys.version_info < (3, 11):
        pytest.skip("tomllib is new in Python 3.11")
    else:
        import tomllib

        project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]

        assert project["dependencies"] == []
        assert all(isinstance(url, str) for url in project["urls"].values())
