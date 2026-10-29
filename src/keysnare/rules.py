"""Format rules: recognise secrets by their shape, and ignore placeholder values."""

import re
from dataclasses import dataclass, field

MIN_SECRET_LENGTH = 8

PLACEHOLDER_WORDS = (
    "example",
    "placeholder",
    "changeme",
    "your_",
    "your-",
    "dummy",
    "redacted",
    "keysnare-decoy",
    "keysnaredecoy",
)
# Bare words people type where a real value belongs, e.g. https://user:password@host.
PLACEHOLDER_EXACT = frozenset({"password", "secret", "token", "apikey", "api_key"})

ENVIRONMENT_REFERENCE = re.compile(
    r"\$\{[^}]*\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\$\(.*\)|env:\S+",
)
ANGLE_BRACKET_HINT = re.compile(r"<.*>")

SECRET_NAME_WORDS = frozenset(
    {"secret", "token", "password", "passwd", "pwd", "auth", "credential", "credentials", "apikey"}
)
SECRET_NAME_PAIRS = ("api_key", "access_key", "private_key")
NAME_SEPARATORS = re.compile(r"[_\-.]+")
CAMEL_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
# Values these names often hold that are settings, not secrets: TOKEN_EXPIRY=3600, AUTH_URL=...
SETTING_VALUE = re.compile(r"true|false|yes|no|on|off|-?\d+(?:\.\d+)?", re.IGNORECASE)
PATH_VALUE = re.compile(r"(?:/|~/|\./|\.\./|[A-Za-z]:[\\/]).*")
URL_VALUE = re.compile(r"[a-z][a-z0-9+.-]*://\S*", re.IGNORECASE)


@dataclass(frozen=True)
class FormatRule:
    """A secret recognised by a provider-specific shape."""

    rule_id: str
    description: str
    pattern: re.Pattern[str]
    secret_group: int = 0


@dataclass(frozen=True)
class RuleMatch:
    """A secret found in a line."""

    rule_id: str
    column: int
    # repr=False: printing or logging this object must never show the secret.
    secret: str = field(repr=False)


FORMAT_RULES = (
    FormatRule("F-AWS-KEY-ID", "AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    FormatRule(
        "F-GITHUB-TOKEN",
        "GitHub classic, OAuth or app token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    ),
    FormatRule(
        "F-GITHUB-PAT",
        "GitHub fine-grained token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ),
    FormatRule("F-NPM-TOKEN", "npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    FormatRule(
        "F-PYPI-TOKEN",
        "PyPI or TestPyPI upload token",
        re.compile(r"\bpypi-(?:AgEIcHlwaS5vcmc|AgENdGVzdC5weXBpLm9yZw)[A-Za-z0-9_-]{50,}"),
    ),
    FormatRule(
        "F-OPENAI-KEY",
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}"),
    ),
    FormatRule(
        "F-ANTHROPIC-KEY",
        "Anthropic API key or OAuth token",
        re.compile(r"\bsk-ant-[a-z]{3,5}\d{2}-[A-Za-z0-9_-]{40,}"),
    ),
    FormatRule(
        "F-GOOGLE-API-KEY",
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    FormatRule("F-HF-TOKEN", "Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    FormatRule(
        "F-PRIVATE-KEY",
        "Private key block",
        re.compile(r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----"),
    ),
    FormatRule(
        "F-URL-CREDENTIALS",
        "Username and password in a URL",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s:/@]+)@[^\s/]+"),
        secret_group=1,
    ),
)


def is_placeholder(value: str) -> bool:
    """Return True when a value is a template or reference rather than a real secret."""
    lowered = value.lower()
    return (
        len(value) < MIN_SECRET_LENGTH
        or len(set(value)) == 1
        or lowered in PLACEHOLDER_EXACT
        or ENVIRONMENT_REFERENCE.fullmatch(value) is not None
        or ANGLE_BRACKET_HINT.fullmatch(value) is not None
        or any(word in lowered for word in PLACEHOLDER_WORDS)
    )


def is_secret_name(name: str) -> bool:
    """Return True when a variable name says it holds a secret, matching whole word parts."""
    snake = CAMEL_CASE_BOUNDARY.sub("_", name).lower()
    parts = [part for part in NAME_SEPARATORS.split(snake) if part]
    joined = "_" + "_".join(parts) + "_"
    return any(part in SECRET_NAME_WORDS for part in parts) or any(
        f"_{pair}_" in joined for pair in SECRET_NAME_PAIRS
    )


def is_secret_value(value: str) -> bool:
    """Return True when a value next to a secret-sounding name looks like a real secret."""
    return not (
        is_placeholder(value)
        or value.startswith(("$", "%"))
        or any(char.isspace() for char in value)
        or SETTING_VALUE.fullmatch(value)
        or PATH_VALUE.fullmatch(value)
        or URL_VALUE.fullmatch(value)
    )


def url_password(text: str) -> str | None:
    """Return the password from the first URL with embedded credentials, if any."""
    for match in match_format_rules(text):
        if match.rule_id == "F-URL-CREDENTIALS":
            return match.secret
    return None


def match_format_rules(line: str) -> list[RuleMatch]:
    """Return every non-placeholder secret in a line that matches a format rule."""
    matches = []
    for rule in FORMAT_RULES:
        for found in rule.pattern.finditer(line):
            secret = found.group(rule.secret_group)
            if not is_placeholder(secret):
                matches.append(RuleMatch(rule.rule_id, found.start(rule.secret_group), secret))
    return matches
