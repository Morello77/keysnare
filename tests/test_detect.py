import base64
import json
import struct

import pytest

from keysnare.detect import PRESENCE_RULES, find_secrets
from keysnare.locations import Category
from keysnare.rules import is_secret_name

# Fake secrets are assembled at runtime so no complete token appears in the repository.
SECRET = "fake" + "Secret" + "Value123"
GITHUB_TOKEN = "ghp_" + "a1B2" * 9
BEGIN = "-----BEGIN "


def found(category: Category, text: str) -> list[tuple[str, int | None, str | None]]:
    return [(d.rule_id, d.line, d.secret) for d in find_secrets(category, text)]


def rule_ids(category: Category, text: str) -> list[str]:
    return [d.rule_id for d in find_secrets(category, text)]


@pytest.mark.parametrize(
    ("category", "text", "expected_rule"),
    [
        (Category.AWS_CREDENTIALS, f"[dev]\naws_secret_access_key = {SECRET}\n", "S-AWS-SECRET"),
        (Category.AWS_CONFIG, f"[profile x]\naws_session_token={SECRET}\n", "S-AWS-SESSION"),
        (Category.NPMRC, f"//registry.npmjs.org/:_authToken={SECRET}\n", "S-NPMRC-TOKEN"),
        (
            Category.YARNRC,
            f'npmRegistries:\n  "//r":\n    npmAuthToken: {SECRET}\n',
            "S-YARNRC-TOKEN",
        ),
        (Category.GH_HOSTS, f"github.com:\n    oauth_token: {SECRET}\n", "S-GH-HOSTS"),
        (
            Category.PYPIRC,
            f"[pypi]\nusername = __token__\npassword = {SECRET}\n",
            "S-PYPIRC-PASSWORD",
        ),
        (Category.POETRY_AUTH, f'[http-basic.corp]\npassword = "{SECRET}"\n', "S-POETRY-AUTH"),
        (Category.POETRY_AUTH, f'[pypi-token]\npypi = "{SECRET}"\n', "S-POETRY-AUTH"),
        (Category.KUBECONFIG, f"users:\n- name: a\n  user:\n    token: {SECRET}\n", "S-KUBE-TOKEN"),
        (
            Category.KUBECONFIG,
            f"users:\n- name: a\n  user:\n    client-key-data: {SECRET}\n",
            "S-KUBE-CLIENT-KEY",
        ),
        (Category.KUBECONFIG, f"users:\n- user:\n    password: {SECRET}\n", "S-KUBE-PASSWORD"),
        (
            Category.KUBECONFIG,
            "users:\n- user:\n    auth-provider:\n      config:\n"
            f"        refresh-token: {SECRET}\n",
            "S-KUBE-AUTH-PROVIDER",
        ),
    ],
)
def test_key_value_structure_rules(category: Category, text: str, expected_rule: str) -> None:
    assert found(category, text) == [(expected_rule, text.count("\n"), SECRET)]


@pytest.mark.parametrize(
    ("category", "document", "expected_rule"),
    [
        (Category.AWS_CACHE, {"Credentials": {"SecretAccessKey": SECRET}}, "S-AWS-CACHE"),
        (Category.AWS_CACHE, {"accessToken": SECRET}, "S-AWS-CACHE"),
        (Category.DOCKER, {"auths": {"ghcr.io": {"auth": SECRET}}}, "S-DOCKER-AUTH"),
        (Category.CLAUDE_CODE, {"claudeAiOauth": {"refreshToken": SECRET}}, "S-CLAUDE-OAUTH"),
        (Category.CODEX, {"OPENAI_API_KEY": SECRET}, "S-CODEX-AUTH"),
        (Category.CODEX, {"tokens": {"refresh_token": SECRET}}, "S-CODEX-AUTH"),
        (Category.GEMINI_OAUTH, {"refresh_token": SECRET}, "S-GEMINI-OAUTH"),
        (Category.COPILOT, {"github.com": {"oauth_token": SECRET}}, "S-COPILOT-TOKEN"),
        (Category.AI_TOOL_CONFIG, {"models": [{"apiKey": SECRET}]}, "S-CONFIG-APIKEY"),
        (Category.AZURE_JSON, {"RefreshToken": {"id1": {"secret": SECRET}}}, "S-AZURE-MSAL"),
        (Category.AZURE_JSON, [{"client_secret": SECRET}], "S-AZURE-SP"),
        (Category.AZURE_JSON, [{"refreshToken": SECRET}], "S-AZURE-LEGACY"),
        (
            Category.GCP_JSON,
            {"type": "authorized_user", "refresh_token": SECRET},
            "S-GCP-ADC-USER",
        ),
        (
            Category.GCP_JSON,
            {"type": "service_account", "private_key": SECRET},
            "S-GCP-SERVICE-ACCOUNT",
        ),
        (
            Category.MCP_CONFIG,
            {"mcpServers": {"db": {"env": {"DB_PASSWORD": SECRET, "DB_HOST": "db.local.lan"}}}},
            "S-MCP-ENV",
        ),
    ],
)
def test_json_structure_rules(category: Category, document: object, expected_rule: str) -> None:
    assert rule_ids(category, json.dumps(document, indent=2)) == [expected_rule]


def test_docker_without_auth_value_is_not_a_finding() -> None:
    text = json.dumps({"auths": {"ghcr.io": {}}, "credsStore": "desktop"})

    assert find_secrets(Category.DOCKER, text) == []


def test_codex_null_api_key_is_not_a_finding() -> None:
    assert find_secrets(Category.CODEX, '{"OPENAI_API_KEY": null}') == []


def test_gcp_json_without_secret_type_is_not_a_finding() -> None:
    text = json.dumps({"type": "external_account", "private_key": SECRET})

    assert find_secrets(Category.GCP_JSON, text) == []


def test_nuget_cleartext_and_encrypted_passwords_get_different_rules() -> None:
    text = (
        f'<add key="ClearTextPassword" value="{SECRET}" />\n'
        f'<add key="Password" value="{SECRET}x" />\n'
    )

    assert rule_ids(Category.NUGET, text) == ["S-NUGET-CLEARTEXT", "S-NUGET-DPAPI"]


def test_git_credentials_report_the_password_of_each_url() -> None:
    text = f"https://dev:{SECRET}@github.com\n"

    assert found(Category.GIT_CREDENTIALS, text) == [("S-GIT-CREDENTIALS", 1, SECRET)]


def test_git_remote_url_with_token_is_found() -> None:
    text = f'[remote "origin"]\n\turl = https://dev:{SECRET}@github.com/a/b.git\n'

    assert found(Category.GIT_REMOTE, text) == [("S-GIT-REMOTE", 2, SECRET)]


def test_pip_index_url_with_password_is_found() -> None:
    text = f"[global]\nindex-url = https://dev:{SECRET}@pypi.corp/simple\n"

    assert rule_ids(Category.PIP_CONFIG, text) == ["S-PIP-INDEX-URL"]


def test_hugging_face_token_file_is_reported_once() -> None:
    token = "hf_" + "a1B2" * 9

    assert found(Category.HUGGING_FACE, token + "\n") == [("S-HF-TOKEN-FILE", 1, token)]


def openssh_key(cipher: bytes) -> str:
    body = b"openssh-key-v1\0" + struct.pack(">I", len(cipher)) + cipher + b"\0" * 64
    return f"{BEGIN}OPENSSH PRIVATE KEY-----\n{base64.b64encode(body).decode()}\n"


def test_unencrypted_ssh_key_is_found_without_exposing_key_material() -> None:
    assert found(Category.SSH_KEY, openssh_key(b"none")) == [("S-SSH-KEY", 1, None)]


def test_encrypted_ssh_key_is_not_a_finding() -> None:
    assert find_secrets(Category.SSH_KEY, openssh_key(b"aes256-ctr")) == []


def test_format_rules_apply_to_every_text_file() -> None:
    assert rule_ids(Category.AWS_CONFIG, f"note = {GITHUB_TOKEN}\n") == ["F-GITHUB-TOKEN"]


def test_one_secret_gives_one_finding() -> None:
    text = f"GITHUB_TOKEN={GITHUB_TOKEN}\n"

    assert rule_ids(Category.ENV_FILE, text) == ["F-GITHUB-TOKEN"]


def test_env_file_uses_key_name_rule_as_fallback() -> None:
    text = (
        f"STRIPE_SECRET={SECRET}\n"
        "TOKEN_EXPIRY=3600\n"
        "AUTH_ENABLED=true\n"
        "AUTHOR_NAME=JaneDoeTheAuthor\n"
        "AUTH_URL=https://login.corp.internal\n"
        "PASSWORD_HINT=my favourite pet\n"
        "API_KEY=${OPENAI_API_KEY}\n"
        "SSH_KEY_PATH=/home/dev/.ssh/id_ed25519\n"
    )

    assert found(Category.ENV_FILE, text) == [("K-SECRET-NAME", 1, SECRET)]


def test_malformed_json_still_gets_format_rules() -> None:
    text = '{\n  // comment\n  "token": "' + GITHUB_TOKEN + '"\n}\n'

    assert rule_ids(Category.MCP_CONFIG, text) == ["F-GITHUB-TOKEN"]


@pytest.mark.parametrize(
    "line",
    [
        f"export DB_PASSWORD={SECRET}",
        f"set DB_PASSWORD={SECRET}",
        f'$env:DB_PASSWORD = "{SECRET}"',
        f"mysql --password {SECRET}",
        f"mysql --password={SECRET}",
        f"docker login registry.corp -u dev -p {SECRET}",
        f'curl -H "Authorization: Bearer {SECRET}" https://api.corp',
    ],
)
def test_shell_history_secrets_are_found(line: str) -> None:
    assert found(Category.SHELL_HISTORY, line + "\n") == [("S-HISTORY-SECRET", 1, SECRET)]


@pytest.mark.parametrize(
    "line",
    [
        "git status",
        "export PATH=/usr/local/bin:$PATH",
        "docker login --password-stdin registry.corp",
        "export API_TOKEN=$(cat ~/.token)",
    ],
)
def test_ordinary_shell_history_is_not_a_finding(line: str) -> None:
    assert find_secrets(Category.SHELL_HISTORY, line + "\n") == []


def test_presence_rules_cover_binary_credential_stores() -> None:
    assert PRESENCE_RULES == {
        Category.AZURE_DPAPI: "S-AZURE-DPAPI",
        Category.GCP_DB: "S-GCP-CREDENTIALS-DB",
    }


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("GITHUB_TOKEN", True),
        ("db_password", True),
        ("OPENAI_API_KEY", True),
        ("clientSecret", True),
        ("NPM_AUTH_TOKEN", True),
        ("AWS_SECRET_ACCESS_KEY", True),
        ("AUTHOR_NAME", False),
        ("DB_HOST", False),
        ("TOKENIZER_MODEL", False),
    ],
)
def test_secret_names_match_whole_word_parts(name: str, expected: bool) -> None:
    assert is_secret_name(name) is expected


def test_printing_a_detection_never_shows_the_secret() -> None:
    [detection] = find_secrets(Category.PYPIRC, f"password = {SECRET}\n")

    assert SECRET not in repr(detection)
