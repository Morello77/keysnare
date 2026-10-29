"""Find secrets in a credential file's text, following docs/detection-rules.md."""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from keysnare.locations import Category
from keysnare.readers import (
    Entry,
    KeyProtection,
    read_json_entries,
    read_key_values,
    read_nuget_entries,
    ssh_key_protection,
)
from keysnare.rules import (
    is_placeholder,
    is_secret_name,
    is_secret_value,
    match_format_rules,
    url_password,
)

KeyTest = Callable[[tuple[str, ...]], bool]

# Binary credential stores: reported when present and non-empty, never opened.
PRESENCE_RULES = {
    Category.AZURE_DPAPI: "S-AZURE-DPAPI",
    Category.GCP_DB: "S-GCP-CREDENTIALS-DB",
}

AWS_SECRET_SHAPE = re.compile(r"[A-Za-z0-9/+]{40}")
HISTORY_ASSIGNMENT = re.compile(
    r"(?:\b(?:export|set)\s+|\$env:)([A-Za-z_]\w*)\s*=\s*[\"']?([^\"'\s;]+)"
)
HISTORY_SECRET_ARGUMENTS = (
    re.compile(r"--password[=\s]+[\"']?([^\"'\s]+)"),
    re.compile(r"\bdocker\s+login\b.*?\s-p\s+[\"']?([^\"'\s]+)"),
    re.compile(r"authorization:\s*bearer\s+([^\"'\s]+)", re.IGNORECASE),
)


@dataclass(frozen=True)
class Detection:
    """A secret found in a file. `secret` is None when the file itself is the finding."""

    rule_id: str
    line: int | None
    # repr=False: printing or logging this object must never show the secret.
    secret: str | None = field(default=None, repr=False)


def _last(*names: str) -> KeyTest:
    wanted = frozenset(name.lower() for name in names)
    return lambda key: bool(key) and key[-1].lower() in wanted


def _exact(*path: str) -> KeyTest:
    return lambda key: key == path


def _is_api_key(key: tuple[str, ...]) -> bool:
    return bool(key) and key[-1].lower().replace("-", "").replace("_", "").endswith("apikey")


AWS_RULES = [
    (_last("aws_secret_access_key"), "S-AWS-SECRET"),
    (_last("aws_session_token"), "S-AWS-SESSION"),
]

KEY_VALUE_RULES: dict[Category, list[tuple[KeyTest, str]]] = {
    Category.AWS_CREDENTIALS: AWS_RULES,
    Category.AWS_CONFIG: AWS_RULES,
    Category.NPMRC: [
        (
            lambda key: key[-1].lower().endswith(("_authtoken", "_auth", "_password")),
            "S-NPMRC-TOKEN",
        )
    ],
    Category.YARNRC: [(_last("npmAuthToken"), "S-YARNRC-TOKEN")],
    Category.GH_HOSTS: [(_last("oauth_token"), "S-GH-HOSTS")],
    Category.PYPIRC: [(_last("password"), "S-PYPIRC-PASSWORD")],
    Category.POETRY_AUTH: [
        (lambda key: key[0].startswith("http-basic.") and key[-1] == "password", "S-POETRY-AUTH"),
        (lambda key: key[0] == "pypi-token", "S-POETRY-AUTH"),
    ],
    Category.KUBECONFIG: [
        (
            lambda key: "auth-provider" in key and key[-1] in ("access-token", "refresh-token"),
            "S-KUBE-AUTH-PROVIDER",
        ),
        (lambda key: key[0] == "users" and key[-1] == "token", "S-KUBE-TOKEN"),
        (lambda key: key[0] == "users" and key[-1] == "client-key-data", "S-KUBE-CLIENT-KEY"),
        (lambda key: key[0] == "users" and key[-1] == "password", "S-KUBE-PASSWORD"),
    ],
}

JSON_RULES: dict[Category, list[tuple[KeyTest, str]]] = {
    Category.AWS_CACHE: [
        (_exact("Credentials", "SecretAccessKey"), "S-AWS-CACHE"),
        (_exact("accessToken"), "S-AWS-CACHE"),
    ],
    Category.DOCKER: [
        (
            lambda key: len(key) == 3 and key[0] == "auths" and key[2] in ("auth", "identitytoken"),
            "S-DOCKER-AUTH",
        ),
    ],
    Category.CLAUDE_CODE: [
        (_exact("claudeAiOauth", "accessToken"), "S-CLAUDE-OAUTH"),
        (_exact("claudeAiOauth", "refreshToken"), "S-CLAUDE-OAUTH"),
    ],
    Category.CODEX: [
        (_exact("OPENAI_API_KEY"), "S-CODEX-AUTH"),
        (_exact("tokens", "refresh_token"), "S-CODEX-AUTH"),
    ],
    Category.GEMINI_OAUTH: [(_exact("refresh_token"), "S-GEMINI-OAUTH")],
    Category.COPILOT: [(_last("oauth_token"), "S-COPILOT-TOKEN")],
    Category.AZURE_JSON: [
        (lambda key: key[0] == "RefreshToken" and key[-1] == "secret", "S-AZURE-MSAL"),
        (_last("client_secret"), "S-AZURE-SP"),
        (_last("accessToken", "refreshToken"), "S-AZURE-LEGACY"),
    ],
}

URL_RULES: dict[Category, tuple[KeyTest, str]] = {
    Category.GIT_REMOTE: (_last("url"), "S-GIT-REMOTE"),
    Category.PIP_CONFIG: (_last("index-url", "extra-index-url"), "S-PIP-INDEX-URL"),
}

GCP_SECRET_KEYS = {
    "service_account": (("private_key",), "S-GCP-SERVICE-ACCOUNT"),
    "authorized_user": (("refresh_token",), "S-GCP-ADC-USER"),
}


def find_secrets(category: Category, text: str) -> list[Detection]:
    """Return one detection per secret in a credential file's text.

    Categories in PRESENCE_RULES are binary stores that the caller reports without reading.
    """
    if category is Category.SSH_KEY:
        return _private_key(text, "S-SSH-KEY")
    if category is Category.PRIVATE_KEY:
        return _private_key(text, "S-PRIVATE-KEY-FILE")
    detections = [*_structure(category, text), *_format(text), *_fallback(category, text)]
    return _one_per_secret(detections)


def _structure(category: Category, text: str) -> list[Detection]:
    if category in KEY_VALUE_RULES:
        return _apply(read_key_values(text), KEY_VALUE_RULES[category])
    if category in JSON_RULES:
        return _apply(_json_entries(text), JSON_RULES[category])
    if category in URL_RULES:
        key_test, rule_id = URL_RULES[category]
        return _url_entries(read_key_values(text), key_test, rule_id)
    special = {
        Category.AI_TOOL_CONFIG: _ai_tool_config,
        Category.GCP_JSON: _gcp_json,
        Category.NUGET: _nuget,
        Category.HUGGING_FACE: _hugging_face,
        Category.GIT_CREDENTIALS: _git_credentials,
    }.get(category)
    return special(text) if special else []


def _format(text: str) -> list[Detection]:
    return [
        Detection(match.rule_id, number, match.secret)
        for number, line in enumerate(text.splitlines(), start=1)
        for match in match_format_rules(line)
    ]


def _fallback(category: Category, text: str) -> list[Detection]:
    if category in (Category.ENV_FILE, Category.GEMINI_ENV):
        return _named_secrets(read_key_values(text), "K-SECRET-NAME")
    if category is Category.MCP_CONFIG:
        env_entries = [
            entry
            for entry in _json_entries(text)
            if len(entry.key) == 4 and entry.key[0] == "mcpServers" and entry.key[2] == "env"
        ]
        return _named_secrets(env_entries, "S-MCP-ENV")
    if category is Category.SHELL_HISTORY:
        return _shell_history(text)
    return []


def _apply(entries: list[Entry], rules: list[tuple[KeyTest, str]]) -> list[Detection]:
    detections = []
    for entry in entries:
        if is_placeholder(entry.value):
            continue
        rule_id = next((rule_id for key_test, rule_id in rules if key_test(entry.key)), None)
        if rule_id:
            detections.append(Detection(rule_id, entry.line, entry.value))
    return detections


def _named_secrets(entries: list[Entry], rule_id: str) -> list[Detection]:
    return [
        Detection(_named_rule(entry.key[-1], entry.value, rule_id), entry.line, entry.value)
        for entry in entries
        if is_secret_name(entry.key[-1]) and is_secret_value(entry.value)
    ]


def _named_rule(name: str, value: str, default_rule: str) -> str:
    # An AWS secret key has no recognisable prefix, but its standard variable name plus its
    # exact 40-character shape make it as certain as a format rule.
    if name.lower() == "aws_secret_access_key" and AWS_SECRET_SHAPE.fullmatch(value):
        return "S-AWS-SECRET-ENV"
    return default_rule


def _url_entries(entries: list[Entry], key_test: KeyTest, rule_id: str) -> list[Detection]:
    detections = []
    for entry in entries:
        password = url_password(entry.value) if key_test(entry.key) else None
        if password:
            detections.append(Detection(rule_id, entry.line, password))
    return detections


def _json_entries(text: str) -> list[Entry]:
    try:
        return read_json_entries(text)
    except (ValueError, RecursionError):
        # Not strict JSON (often JSON with comments). Format rules still run on its lines.
        return []


def _ai_tool_config(text: str) -> list[Detection]:
    is_json = text.lstrip().startswith("{")
    entries = _json_entries(text) if is_json else read_key_values(text)
    return _apply(entries, [(_is_api_key, "S-CONFIG-APIKEY")])


def _gcp_json(text: str) -> list[Detection]:
    values = {entry.key: entry for entry in _json_entries(text)}
    kind = values.get(("type",))
    if kind is None or kind.value not in GCP_SECRET_KEYS:
        return []
    key, rule_id = GCP_SECRET_KEYS[kind.value]
    entry = values.get(key)
    if entry is None or is_placeholder(entry.value):
        return []
    return [Detection(rule_id, entry.line, entry.value)]


def _nuget(text: str) -> list[Detection]:
    rules = [
        (_last("ClearTextPassword"), "S-NUGET-CLEARTEXT"),
        (_last("Password"), "S-NUGET-DPAPI"),
    ]
    return _apply(read_nuget_entries(text), rules)


def _hugging_face(text: str) -> list[Detection]:
    token = text.strip()
    return [] if is_placeholder(token) else [Detection("S-HF-TOKEN-FILE", 1, token)]


def _git_credentials(text: str) -> list[Detection]:
    detections = []
    for number, line in enumerate(text.splitlines(), start=1):
        password = url_password(line)
        if password:
            detections.append(Detection("S-GIT-CREDENTIALS", number, password))
    return detections


def _private_key(text: str, rule_id: str) -> list[Detection]:
    if ssh_key_protection(text) is not KeyProtection.UNENCRYPTED:
        return []
    header_line = next(
        (
            number
            for number, line in enumerate(text.splitlines(), start=1)
            if "PRIVATE KEY-----" in line or line.startswith("PuTTY-User-Key-File-")
        ),
        None,
    )
    return [Detection(rule_id, header_line)]


def _shell_history(text: str) -> list[Detection]:
    detections = []
    for number, line in enumerate(text.splitlines(), start=1):
        for name, value in HISTORY_ASSIGNMENT.findall(line):
            if is_secret_name(name) and is_secret_value(value):
                rule_id = _named_rule(name, value, "S-HISTORY-SECRET")
                detections.append(Detection(rule_id, number, value))
        for pattern in HISTORY_SECRET_ARGUMENTS:
            for value in pattern.findall(line):
                if is_secret_value(value):
                    detections.append(Detection("S-HISTORY-SECRET", number, value))
    return detections


def _one_per_secret(detections: list[Detection]) -> list[Detection]:
    kept: list[Detection] = []
    for detection in detections:
        if not any(_same_secret(detection, earlier) for earlier in kept):
            kept.append(detection)
    return kept


def _same_secret(a: Detection, b: Detection) -> bool:
    if a.line != b.line or a.secret is None or b.secret is None:
        return False
    return a.secret in b.secret or b.secret in a.secret
