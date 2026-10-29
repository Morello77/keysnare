import pytest

from keysnare import cli


@pytest.fixture(autouse=True)
def not_elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    # GitHub's Windows runners always run as administrator, where KeySnare refuses to start.
    # Tests that check the refusal itself patch this back.
    monkeypatch.setattr(cli, "is_elevated", lambda: False)
