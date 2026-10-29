import pytest

from keysnare.rules import FORMAT_RULES, is_placeholder, match_format_rules

# Fake secrets are assembled at runtime so no complete token appears in the repository.
FAKES = {
    "F-AWS-KEY-ID": "AKIA" + "Q7" * 8,
    "F-GITHUB-TOKEN": "ghp_" + "a1B2" * 9,
    "F-GITHUB-PAT": "github_pat_" + "a1B2_" * 16 + "xy",
    "F-NPM-TOKEN": "npm_" + "a1B2" * 9,
    "F-PYPI-TOKEN": "pypi-" + "AgEIcHlwaS5vcmc" + "a1B2-" * 12,
    "F-OPENAI-KEY": "sk-proj-" + "a1B2" * 6 + "T3BlbkFJ" + "c3D4" * 6,
    "F-ANTHROPIC-KEY": "sk-ant-" + "api03-" + "a1B2" * 23,
    "F-GOOGLE-API-KEY": "AIza" + "a1B2c" * 7,
    "F-HF-TOKEN": "hf_" + "a1B2" * 9,
    "F-PRIVATE-KEY": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    "F-STRIPE-LIVE-KEY": "sk_" + "live_" + "a1B2" * 6,
    "F-STRIPE-TEST-KEY": "rk_" + "test_" + "a1B2" * 6,
    "F-SLACK-TOKEN": "xox" + "b-" + "1234567890" + "-" + "9876543210123" + "-" + "a1B2" * 6,
    "F-SENDGRID-KEY": "SG" + "." + "a1B2c" * 4 + "xy" + "." + "a1B2c-" * 7 + "x",
}


def test_every_format_rule_has_a_fake_sample() -> None:
    sampled = set(FAKES) | {"F-URL-CREDENTIALS"}

    assert sampled == {rule.rule_id for rule in FORMAT_RULES}


@pytest.mark.parametrize(("rule_id", "fake"), FAKES.items())
def test_format_rule_finds_its_secret_inside_a_line(rule_id: str, fake: str) -> None:
    matches = match_format_rules(f"SOME_SETTING={fake}  # trailing comment")

    assert [(m.rule_id, m.secret) for m in matches] == [(rule_id, fake)]


def test_match_reports_the_column_where_the_secret_starts() -> None:
    fake = FAKES["F-NPM-TOKEN"]

    [match] = match_format_rules(f"token: {fake}")

    assert match.column == len("token: ")


def test_url_rule_returns_only_the_password() -> None:
    password = "s3cr" + "etPass" + "w0rd!"

    [match] = match_format_rules(f"DATABASE_URL=postgres://admin:{password}@db.local:5432/app")

    assert (match.rule_id, match.secret) == ("F-URL-CREDENTIALS", password)


def test_finds_several_secrets_on_one_line() -> None:
    line = f"{FAKES['F-AWS-KEY-ID']} {FAKES['F-GITHUB-TOKEN']}"

    assert {m.rule_id for m in match_format_rules(line)} == {"F-AWS-KEY-ID", "F-GITHUB-TOKEN"}


@pytest.mark.parametrize(
    "line",
    [
        "ghp_" + "a" * 35,  # one character too short
        "xghp_" + "a1B2" * 9,  # glued to a longer word
        "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",  # passphrase-protected
        "AKIA" + "IOSFODNN7" + "EXAMPLE",  # AWS documentation example
        "https://user:TOKEN@github.com",  # placeholder password
        "https://user:" + "password" + "@host/simple",  # placeholder password
        "postgres://admin:${DB_PASSWORD}@db.local/app",  # environment reference
        "just an ordinary line of text",
        "sk_" + "live_" + "short",  # too short for a Stripe key
        "xox" + "b-notatoken",  # no numeric parts
        "SG" + "." + "tooShort" + "." + "x",  # wrong segment lengths
        "task_live_" + "a1B2" * 6,  # glued to a longer word
    ],
)
def test_lines_without_real_secrets_give_no_match(line: str) -> None:
    assert match_format_rules(line) == []


def test_printing_a_match_never_shows_the_secret() -> None:
    fake = FAKES["F-GITHUB-TOKEN"]

    [match] = match_format_rules(fake)

    assert fake not in repr(match)
    assert fake not in str(match)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "short",
        "${NPM_TOKEN}",
        "$NPM_TOKEN",
        "%NPM_TOKEN%",
        "$(cat ~/token.txt)",
        "env:NPM_TOKEN",
        "<your-token-here>",
        "xxxxxxxxxxxx",
        "************",
        "000000000000",
        "my-EXAMPLE-key-123",
        "placeholder-value",
        "changeme-please",
        "your_api_key_here",
        "your-api-key-here",
        "dummy-token-123",
        "REDACTED-123456",
        "keysnare-decoy-0001",
        "password",
        "Secret",
        "TOKEN",
    ],
)
def test_placeholder_values_are_recognised(value: str) -> None:
    assert is_placeholder(value)


@pytest.mark.parametrize(
    "value",
    [
        "ghp_" + "a1B2" * 9,
        "s3cr" + "etPass" + "w0rd!",
        "Password" + "123!",  # a real (weak) password, not the bare word
    ],
)
def test_real_looking_values_are_not_placeholders(value: str) -> None:
    assert not is_placeholder(value)
