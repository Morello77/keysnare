"""Decoy credential files: realistic in format, clearly marked, never valid anywhere."""

import base64
import json
import secrets
import string
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

MARKER = "keysnare-decoy"
# Inside secret values, where a hyphen would break the provider's token format.
VALUE_MARKER = "KeySnareDecoy"
NOTICE = "KeySnare decoy - not a real credential."

ALPHANUMERIC = string.ascii_letters + string.digits
BASE32 = string.ascii_uppercase + "234567"
BASE64 = ALPHANUMERIC + "/+"
SSH_LINE_LENGTH = 70
SSH_BLOCK_SIZE = 8
# Built from pieces so this source file never contains a complete key header.
SSH_BEGIN = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
SSH_END = "-----END " + "OPENSSH PRIVATE KEY-----"


class DecoyKind(Enum):
    """The file format a decoy imitates."""

    SSH_KEY = "ssh-key"
    AWS_CREDENTIALS = "aws-credentials"
    DOCKER_CONFIG = "docker-config"
    KUBECONFIG = "kubeconfig"
    GH_HOSTS = "gh-hosts"
    GCLOUD_ADC = "gcloud-adc"
    GIT_CREDENTIALS = "git-credentials"
    NPMRC = "npmrc"


@dataclass(frozen=True)
class Decoy:
    """A decoy file to plant: where it goes and exactly what it contains."""

    kind: DecoyKind
    path: Path
    content: str = field(repr=False)


def make_decoy(kind: DecoyKind, path: Path) -> Decoy:
    """Generate fresh decoy content of the given kind. Every call gives different values."""
    return Decoy(kind, path, _GENERATORS[kind]())


def _random(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _github_token() -> str:
    return "ghp_" + VALUE_MARKER + _random(ALPHANUMERIC, 36 - len(VALUE_MARKER))


def _aws_credentials() -> str:
    key_id = "AKIA" + VALUE_MARKER.upper() + _random(BASE32, 16 - len(VALUE_MARKER))
    secret = VALUE_MARKER + _random(BASE64, 40 - len(VALUE_MARKER))
    return (
        f"# {NOTICE}\n[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\n"
    )


def _docker_config() -> str:
    login = f"{MARKER}:{VALUE_MARKER}{_random(ALPHANUMERIC, 24)}"
    auth = base64.b64encode(login.encode()).decode()
    config = {"_comment": NOTICE, "auths": {"https://index.docker.io/v1/": {"auth": auth}}}
    return json.dumps(config, indent=2) + "\n"


def _kubeconfig() -> str:
    token = f"{VALUE_MARKER}.{_random(ALPHANUMERIC, 40)}"
    return (
        f"# {NOTICE}\n"
        "apiVersion: v1\n"
        "kind: Config\n"
        "clusters:\n"
        "- name: production\n"
        "  cluster:\n"
        # .invalid is reserved and can never resolve to a real server.
        f"    server: https://kubernetes.{MARKER}.invalid:6443\n"
        "contexts:\n"
        "- name: production\n"
        "  context:\n"
        "    cluster: production\n"
        "    user: admin\n"
        "current-context: production\n"
        "users:\n"
        "- name: admin\n"
        "  user:\n"
        f"    token: {token}\n"
    )


def _gh_hosts() -> str:
    return (
        f"# {NOTICE}\n"
        "github.com:\n"
        f"    user: {MARKER}\n"
        f"    oauth_token: {_github_token()}\n"
        "    git_protocol: https\n"
    )


def _gcloud_adc() -> str:
    credentials = {
        "_comment": NOTICE,
        "type": "authorized_user",
        "client_id": f"{MARKER}-{_random(string.digits, 12)}.apps.googleusercontent.com",
        "client_secret": f"GOCSPX-{VALUE_MARKER}{_random(ALPHANUMERIC, 15)}",
        "refresh_token": f"1//{VALUE_MARKER}{_random(ALPHANUMERIC, 80)}",
    }
    return json.dumps(credentials, indent=2) + "\n"


def _git_credentials() -> str:
    return f"# {NOTICE}\nhttps://{MARKER}:{_github_token()}@github.com\n"


def _npmrc() -> str:
    token = "npm_" + VALUE_MARKER + _random(ALPHANUMERIC, 36 - len(VALUE_MARKER))
    return f"; {NOTICE}\n//registry.npmjs.org/:_authToken={token}\n"


def _ssh_key() -> str:
    # Random bytes in the unencrypted OpenSSH ed25519 layout: right format, but not a key pair.
    public = secrets.token_bytes(32)
    check = secrets.token_bytes(4)
    public_blob = _ssh_string(b"ssh-ed25519") + _ssh_string(public)
    private = (
        check
        + check
        + _ssh_string(b"ssh-ed25519")
        + _ssh_string(public)
        + _ssh_string(secrets.token_bytes(32) + public)
        + _ssh_string(MARKER.encode())
    )
    padding_length = -len(private) % SSH_BLOCK_SIZE
    private += bytes(range(1, padding_length + 1))
    body = (
        b"openssh-key-v1\0"
        + _ssh_string(b"none")
        + _ssh_string(b"none")
        + _ssh_string(b"")
        + struct.pack(">I", 1)
        + _ssh_string(public_blob)
        + _ssh_string(private)
    )
    encoded = base64.b64encode(body).decode()
    lines = [encoded[i : i + SSH_LINE_LENGTH] for i in range(0, len(encoded), SSH_LINE_LENGTH)]
    return "\n".join([SSH_BEGIN, *lines, SSH_END]) + "\n"


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


_GENERATORS = {
    DecoyKind.SSH_KEY: _ssh_key,
    DecoyKind.AWS_CREDENTIALS: _aws_credentials,
    DecoyKind.DOCKER_CONFIG: _docker_config,
    DecoyKind.KUBECONFIG: _kubeconfig,
    DecoyKind.GH_HOSTS: _gh_hosts,
    DecoyKind.GCLOUD_ADC: _gcloud_adc,
    DecoyKind.GIT_CREDENTIALS: _git_credentials,
    DecoyKind.NPMRC: _npmrc,
}
