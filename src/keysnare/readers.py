"""Turn credential files into key/value entries, using only the standard library."""

import base64
import binascii
import html
import json
import re
import struct
from dataclasses import dataclass, field
from enum import Enum

SECTION = re.compile(r"\[([^\]]+)\]")
COLON_SEPARATOR = re.compile(r":(?:\s|$)")
NUGET_ADD_TAG = re.compile(r"<add\s[^>]*>", re.IGNORECASE)
NUGET_ATTRIBUTE = re.compile(r'(key|value)\s*=\s*"([^"]*)"', re.IGNORECASE)
NUGET_PASSWORD_KEYS = ("ClearTextPassword", "Password")

OPENSSH_MAGIC = b"openssh-key-v1\0"
# Enough base64 to decode the magic, the length prefix and any cipher name, and nothing more.
OPENSSH_HEADER_CHARS = 64
PUTTY_PREFIX = "PuTTY-User-Key-File-"


@dataclass(frozen=True)
class Entry:
    """One key and its value. `line` is None when the position cannot be determined."""

    line: int | None
    key: tuple[str, ...]
    # repr=False: printing or logging this object must never show the secret.
    value: str = field(repr=False)


class KeyProtection(Enum):
    """Whether a private key file is protected by a passphrase."""

    UNENCRYPTED = "unencrypted"
    ENCRYPTED = "encrypted"
    NOT_A_KEY = "not-a-key"


def read_key_values(text: str) -> list[Entry]:
    """Read INI, .env, TOML, npmrc and simple YAML files line by line."""
    entries: list[Entry] = []
    section: tuple[str, ...] = ()
    parents: list[tuple[int, str]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if heading := SECTION.fullmatch(stripped):
            section, parents = (heading.group(1).strip(),), []
            continue
        indent = len(raw) - len(raw.lstrip())
        if stripped.startswith("- "):
            indent, stripped = indent + 2, stripped[2:].lstrip()
        pair = _split_pair(stripped)
        if pair is None:
            continue
        key, value = pair
        while parents and parents[-1][0] >= indent:
            parents.pop()
        if value:
            path = section + tuple(name for _, name in parents) + (key,)
            entries.append(Entry(number, path, value))
        else:
            parents.append((indent, key))
    return entries


def read_json_entries(text: str) -> list[Entry]:
    """Flatten a JSON document into one entry per string value. Raises ValueError if invalid."""
    entries: list[Entry] = []

    def walk(node: object, path: tuple[str, ...]) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                walk(child, (*path, str(key)))
        elif isinstance(node, list):
            for child in node:
                walk(child, path)
        elif isinstance(node, str):
            entries.append(Entry(_json_line(text, node), path, node))

    walk(json.loads(text), ())
    return entries


def read_nuget_entries(text: str) -> list[Entry]:
    """Find NuGet source passwords without an XML parser, which hostile files could abuse."""
    entries = []
    for number, line in enumerate(text.splitlines(), start=1):
        for tag in NUGET_ADD_TAG.findall(line):
            attributes = {name.lower(): value for name, value in NUGET_ATTRIBUTE.findall(tag)}
            if attributes.get("key") in NUGET_PASSWORD_KEYS and "value" in attributes:
                key = ("packageSourceCredentials", attributes["key"])
                entries.append(Entry(number, key, html.unescape(attributes["value"])))
    return entries


def ssh_key_protection(text: str) -> KeyProtection:
    """Tell whether a private key has a passphrase, reading only its header and cipher name."""
    lines = text.splitlines()
    if lines and lines[0].startswith(PUTTY_PREFIX):
        unencrypted = any(line.strip() == "Encryption: none" for line in lines)
        return KeyProtection.UNENCRYPTED if unencrypted else KeyProtection.ENCRYPTED
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("-----BEGIN ") and stripped.endswith("PRIVATE KEY-----"):
            kind = stripped.removeprefix("-----BEGIN ").removesuffix("-----")
            return _pem_protection(kind, lines[index + 1 :])
    return KeyProtection.NOT_A_KEY


def _split_pair(line: str) -> tuple[str, str] | None:
    equals = line.find("=")
    colon_match = COLON_SEPARATOR.search(line)
    colon = colon_match.start() if colon_match else -1
    if colon == -1 and line.endswith(":"):
        colon = len(line) - 1
    positions = [p for p in (equals, colon) if p > 0]
    if not positions:
        return None
    split_at = min(positions)
    key = line[:split_at].strip().removeprefix("export ").strip()
    if not key or any(char.isspace() for char in key):
        return None
    return key, _clean_value(line[split_at + 1 :].strip())


def _clean_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    comment = value.find(" #")
    return value[:comment].rstrip() if comment != -1 else value


def _json_line(text: str, value: str) -> int | None:
    position = text.find(json.dumps(value))
    return text.count("\n", 0, position) + 1 if position != -1 else None


def _pem_protection(kind: str, body: list[str]) -> KeyProtection:
    if kind == "ENCRYPTED PRIVATE KEY":
        return KeyProtection.ENCRYPTED
    if kind == "PRIVATE KEY":
        return KeyProtection.UNENCRYPTED
    if kind == "OPENSSH PRIVATE KEY":
        return _openssh_protection(body)
    if any(line.strip() == "Proc-Type: 4,ENCRYPTED" for line in body):
        return KeyProtection.ENCRYPTED
    return KeyProtection.UNENCRYPTED


def _openssh_protection(body: list[str]) -> KeyProtection:
    encoded = "".join(line.strip() for line in body if not line.startswith("-----"))
    usable = encoded[:OPENSSH_HEADER_CHARS]
    try:
        header = base64.b64decode(usable[: len(usable) - len(usable) % 4], validate=True)
    except binascii.Error:
        return KeyProtection.NOT_A_KEY
    length_end = len(OPENSSH_MAGIC) + 4
    if not header.startswith(OPENSSH_MAGIC) or len(header) < length_end:
        return KeyProtection.NOT_A_KEY
    (cipher_length,) = struct.unpack(">I", header[len(OPENSSH_MAGIC) : length_end])
    cipher = header[length_end : length_end + cipher_length]
    if len(cipher) < cipher_length:
        return KeyProtection.NOT_A_KEY
    return KeyProtection.UNENCRYPTED if cipher == b"none" else KeyProtection.ENCRYPTED
