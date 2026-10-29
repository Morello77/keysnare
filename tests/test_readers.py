import base64
import json
import struct

import pytest

from keysnare.readers import (
    Entry,
    KeyProtection,
    read_json_entries,
    read_key_values,
    read_nuget_entries,
    ssh_key_protection,
)

# Built from pieces so no complete secret or key header appears in the repository.
FAKE_SECRET = "fake" + "Secret" + "Value123"
BEGIN = "-----BEGIN "
END = "-----END "


def as_tuples(entries: list[Entry]) -> list[tuple[int | None, tuple[str, ...], str]]:
    return [(e.line, e.key, e.value) for e in entries]


def test_ini_entries_carry_their_section() -> None:
    text = f"[default]\naws_access_key_id = AKIA\naws_secret_access_key = {FAKE_SECRET}\n"

    entries = read_key_values(text)

    assert as_tuples(entries)[1] == (3, ("default", "aws_secret_access_key"), FAKE_SECRET)


def test_comments_and_blank_lines_are_skipped() -> None:
    text = "# comment\n; also comment\n\nKEY=value1234\n"

    assert as_tuples(read_key_values(text)) == [(4, ("KEY",), "value1234")]


def test_dotenv_export_prefix_and_quotes_are_removed() -> None:
    text = f"export API_TOKEN=\"{FAKE_SECRET}\"\nOTHER='{FAKE_SECRET}'\n"

    assert [(e.key, e.value) for e in read_key_values(text)] == [
        (("API_TOKEN",), FAKE_SECRET),
        (("OTHER",), FAKE_SECRET),
    ]


def test_inline_comment_after_unquoted_value_is_removed() -> None:
    [entry] = read_key_values(f"TOKEN={FAKE_SECRET} # my token\n")

    assert entry.value == FAKE_SECRET


def test_npmrc_registry_key_keeps_its_colon() -> None:
    [entry] = read_key_values(f"//registry.npmjs.org/:_authToken={FAKE_SECRET}\n")

    assert entry.key == ("//registry.npmjs.org/:_authToken",)


def test_url_values_are_not_split_on_their_colon() -> None:
    [entry] = read_key_values("url = https://example.com/repo.git\n")

    assert (entry.key, entry.value) == (("url",), "https://example.com/repo.git")


def test_yaml_nesting_builds_a_key_path() -> None:
    text = (
        "users:\n"
        "- name: dev\n"
        "  user:\n"
        f"    token: {FAKE_SECRET}\n"
        "    auth-provider:\n"
        "      config:\n"
        f"        refresh-token: {FAKE_SECRET}\n"
        "contexts:\n"
        "- name: other\n"
    )

    keys = [e.key for e in read_key_values(text)]

    assert keys == [
        ("users", "name"),
        ("users", "user", "token"),
        ("users", "user", "auth-provider", "config", "refresh-token"),
        ("contexts", "name"),
    ]


def test_prose_lines_are_not_mistaken_for_keys() -> None:
    assert read_key_values("Note that this is: just text\n") == []


def test_json_strings_are_flattened_with_line_numbers() -> None:
    text = json.dumps({"claudeAiOauth": {"accessToken": FAKE_SECRET, "expiresAt": 123}}, indent=2)

    assert as_tuples(read_json_entries(text)) == [
        (3, ("claudeAiOauth", "accessToken"), FAKE_SECRET)
    ]


def test_json_null_values_are_not_entries() -> None:
    assert read_json_entries('{"OPENAI_API_KEY": null}') == []


def test_json_list_items_share_the_parent_key() -> None:
    entries = read_json_entries(json.dumps({"servers": [{"key": FAKE_SECRET}]}))

    assert [e.key for e in entries] == [("servers", "key")]


def test_invalid_json_raises_value_error() -> None:
    with pytest.raises(ValueError):
        read_json_entries("{not json")


def test_nuget_password_entries_are_found_in_either_attribute_order() -> None:
    text = (
        "<configuration>\n"
        "  <packageSourceCredentials>\n"
        "    <MyFeed>\n"
        '      <add key="Username" value="dev" />\n'
        f'      <add key="ClearTextPassword" value="{FAKE_SECRET}" />\n'
        f'      <add value="{FAKE_SECRET}&amp;x" key="Password" />\n'
        "    </MyFeed>\n"
        "  </packageSourceCredentials>\n"
        "</configuration>\n"
    )

    assert as_tuples(read_nuget_entries(text)) == [
        (5, ("packageSourceCredentials", "ClearTextPassword"), FAKE_SECRET),
        (6, ("packageSourceCredentials", "Password"), FAKE_SECRET + "&x"),
    ]


def test_printing_an_entry_never_shows_the_value() -> None:
    [entry] = read_key_values(f"TOKEN={FAKE_SECRET}\n")

    assert FAKE_SECRET not in repr(entry)


def openssh_key(cipher: bytes) -> str:
    body = b"openssh-key-v1\0" + struct.pack(">I", len(cipher)) + cipher + b"\0" * 64
    encoded = base64.b64encode(body).decode()
    return f"{BEGIN}OPENSSH PRIVATE KEY-----\n{encoded}\n{END}OPENSSH PRIVATE KEY-----\n"


def pem_key(kind: str, headers: str = "") -> str:
    return f"{BEGIN}{kind}-----\n{headers}QUJDRA==\n{END}{kind}-----\n"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (openssh_key(b"none"), KeyProtection.UNENCRYPTED),
        (openssh_key(b"aes256-ctr"), KeyProtection.ENCRYPTED),
        (pem_key("RSA PRIVATE KEY"), KeyProtection.UNENCRYPTED),
        (
            pem_key("RSA PRIVATE KEY", "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n"),
            KeyProtection.ENCRYPTED,
        ),
        (pem_key("PRIVATE KEY"), KeyProtection.UNENCRYPTED),
        (pem_key("ENCRYPTED PRIVATE KEY"), KeyProtection.ENCRYPTED),
        ("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n", KeyProtection.UNENCRYPTED),
        (
            "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: aes256-cbc\n",
            KeyProtection.ENCRYPTED,
        ),
        ("ssh-ed25519 AAAAC3Nza dev@laptop\n", KeyProtection.NOT_A_KEY),
        (f"{BEGIN}OPENSSH PRIVATE KEY-----\n!!!notbase64\n", KeyProtection.NOT_A_KEY),
    ],
)
def test_ssh_key_protection_is_detected(text: str, expected: KeyProtection) -> None:
    assert ssh_key_protection(text) is expected
