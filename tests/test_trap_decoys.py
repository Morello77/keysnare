import base64
import json
import re
from pathlib import Path

import pytest

from keysnare.readers import KeyProtection, ssh_key_protection
from keysnare.rules import FORMAT_RULES, is_placeholder
from keysnare.trap.decoys import MARKER, VALUE_MARKER, DecoyKind, make_decoy

FORMAT = {rule.rule_id: rule.pattern for rule in FORMAT_RULES}


def content(kind: DecoyKind) -> str:
    return make_decoy(kind, Path("decoy")).content


@pytest.mark.parametrize("kind", list(DecoyKind))
def test_every_decoy_is_visibly_marked(kind: DecoyKind) -> None:
    text = content(kind)

    if kind is DecoyKind.SSH_KEY:
        assert MARKER.encode() in _openssh_body(text)
    else:
        assert "KeySnare decoy - not a real credential." in text


@pytest.mark.parametrize("kind", list(DecoyKind))
def test_decoys_differ_each_time(kind: DecoyKind) -> None:
    assert content(kind) != content(kind)


def test_aws_decoy_has_real_format_and_marker() -> None:
    text = content(DecoyKind.AWS_CREDENTIALS)
    key_id = re.search(r"aws_access_key_id = (\S+)", text)
    secret = re.search(r"aws_secret_access_key = (\S+)", text)

    assert key_id and FORMAT["F-AWS-KEY-ID"].fullmatch(key_id.group(1))
    assert key_id.group(1).startswith("AKIA" + VALUE_MARKER.upper())
    assert secret and len(secret.group(1)) == 40 and VALUE_MARKER in secret.group(1)


def test_github_decoys_have_real_token_format() -> None:
    for kind in (DecoyKind.GH_HOSTS, DecoyKind.GIT_CREDENTIALS):
        token = re.search(r"ghp_\w+", content(kind))
        assert token and FORMAT["F-GITHUB-TOKEN"].fullmatch(token.group(0))
        assert token.group(0).startswith("ghp_" + VALUE_MARKER)


def test_npm_decoy_has_real_token_format() -> None:
    token = re.search(r"_authToken=(\S+)", content(DecoyKind.NPMRC))

    assert token and FORMAT["F-NPM-TOKEN"].fullmatch(token.group(1))
    assert VALUE_MARKER in token.group(1)


def test_docker_decoy_auth_decodes_to_marked_login() -> None:
    config = json.loads(content(DecoyKind.DOCKER_CONFIG))
    auth = config["auths"]["https://index.docker.io/v1/"]["auth"]

    user, password = base64.b64decode(auth).decode().split(":")
    assert user == MARKER
    assert VALUE_MARKER in password


def test_kube_decoy_points_at_a_name_that_can_never_resolve() -> None:
    text = content(DecoyKind.KUBECONFIG)

    assert "server: https://kubernetes." + MARKER + ".invalid:6443" in text
    assert re.search(r"token: " + VALUE_MARKER + r"\.\w+", text)


def test_gcloud_decoy_is_a_marked_user_credential() -> None:
    data = json.loads(content(DecoyKind.GCLOUD_ADC))

    assert data["type"] == "authorized_user"
    assert all(VALUE_MARKER in data[k] for k in ("client_secret", "refresh_token"))
    assert MARKER in data["client_id"]


def test_ssh_decoy_looks_like_an_unencrypted_openssh_key() -> None:
    text = content(DecoyKind.SSH_KEY)

    assert text.startswith("-----BEGIN " + "OPENSSH PRIVATE KEY-----\n")
    assert ssh_key_protection(text) is KeyProtection.UNENCRYPTED
    assert all(len(line) <= 70 for line in text.splitlines())


def test_decoy_values_are_placeholders_to_keysnares_own_scanner() -> None:
    assert is_placeholder("ghp_" + VALUE_MARKER + "a1B2c3")


def _openssh_body(text: str) -> bytes:
    lines = text.splitlines()
    body = base64.b64decode("".join(lines[1:-1]))
    assert body.startswith(b"openssh-key-v1\0")
    return body
