from pathlib import Path

import pytest

from keysnare.trap.decoys import DecoyKind
from keysnare.trap.placement import UNKNOWN_HELPER, Machine, parse_identity_files, plan_decoys

HOME = Path("C:/Users/dev")
SIBLINGS = {
    HOME / ".ssh/id_rsa_backup",
    HOME / ".aws/credentials.old",
    HOME / ".docker/config.json.bak",
    HOME / ".kube/config.bak",
}
CROSS_PLATFORM = {
    HOME / ".config/gh/hosts.yml",
    HOME / ".config/gcloud/application_default_credentials.json",
}
STANDARD = {
    HOME / ".git-credentials",
    HOME / ".aws/credentials",
    HOME / ".docker/config.json",
    HOME / ".npmrc",
    HOME / ".kube/config",
}


def machine(**changes: object) -> Machine:
    defaults: dict[str, object] = {
        "home": HOME,
        "env": {},
        "installed_tools": frozenset(),
        "git_credential_helpers": (),
        "ssh_identity_files": frozenset(),
        "existing_paths": frozenset(),
    }
    defaults.update(changes)
    return Machine(**defaults)  # type: ignore[arg-type]


def planned(m: Machine) -> set[Path]:
    return {decoy.path for decoy in plan_decoys(m).decoys}


def test_clean_machine_gets_every_decoy() -> None:
    assert planned(machine()) == SIBLINGS | CROSS_PLATFORM | STANDARD


def test_developer_machine_still_gets_siblings_and_cross_platform_decoys() -> None:
    tools = frozenset({"aws", "docker", "npm", "kubectl", "gh", "gcloud", "git"})

    plan = plan_decoys(machine(installed_tools=tools))

    assert {d.path for d in plan.decoys} == SIBLINGS | CROSS_PLATFORM | {HOME / ".git-credentials"}
    assert {s.path for s in plan.skipped} == STANDARD - {HOME / ".git-credentials"}


def test_existing_files_are_never_replaced() -> None:
    existing = frozenset({HOME / ".npmrc", HOME / ".ssh/id_rsa_backup"})

    plan = plan_decoys(machine(existing_paths=existing))

    assert not existing & {d.path for d in plan.decoys}
    assert {s.reason for s in plan.skipped if s.path in existing} == {"a file already exists"}


@pytest.mark.parametrize("helper", ["store", "store --file=C:/x"])
def test_git_credentials_skipped_when_git_uses_the_store_helper(helper: str) -> None:
    assert HOME / ".git-credentials" not in planned(machine(git_credential_helpers=(helper,)))


def test_git_credentials_skipped_when_git_settings_cannot_be_read() -> None:
    assert HOME / ".git-credentials" not in planned(
        machine(git_credential_helpers=(UNKNOWN_HELPER,))
    )


def test_git_credentials_planted_with_other_helpers() -> None:
    assert HOME / ".git-credentials" in planned(machine(git_credential_helpers=("manager",)))


def test_ssh_decoy_skipped_when_ssh_config_uses_that_name() -> None:
    identity = frozenset({HOME / ".ssh/id_rsa_backup"})

    assert HOME / ".ssh/id_rsa_backup" not in planned(machine(ssh_identity_files=identity))


@pytest.mark.parametrize(
    ("env", "skipped"),
    [
        ({"XDG_CONFIG_HOME": str(HOME / ".config")}, HOME / ".config/gh/hosts.yml"),
        ({"GH_CONFIG_DIR": str(HOME / ".config/gh")}, HOME / ".config/gh/hosts.yml"),
        (
            {"CLOUDSDK_CONFIG": str(HOME / ".config/gcloud")},
            HOME / ".config/gcloud/application_default_credentials.json",
        ),
        (
            {
                "GOOGLE_APPLICATION_CREDENTIALS": str(
                    HOME / ".config/gcloud/application_default_credentials.json"
                )
            },
            HOME / ".config/gcloud/application_default_credentials.json",
        ),
        ({"KUBECONFIG": f"C:/other;{HOME / '.kube/config.bak'}"}, HOME / ".kube/config.bak"),
    ],
)
def test_environment_variables_that_point_tools_at_a_decoy_skip_it(
    env: dict[str, str], skipped: Path
) -> None:
    assert skipped not in planned(machine(env=env))


@pytest.mark.parametrize(
    "changes",
    [
        {"ssh_identity_files": frozenset({Path("c:/users/DEV/.SSH/ID_RSA_BACKUP")})},
        {"env": {"XDG_CONFIG_HOME": "c:\\USERS\\dev\\.CONFIG\\"}},
        {"env": {"KUBECONFIG": "\\\\?\\C:\\Users\\dev\\.kube\\CONFIG.BAK"}},
    ],
)
def test_conflicts_are_found_whatever_the_path_spelling(changes: dict[str, object]) -> None:
    plan = plan_decoys(machine(**changes))

    assert len(plan.decoys) == len(SIBLINGS | CROSS_PLATFORM | STANDARD) - 1


def test_no_decoys_when_the_home_folder_contains_an_apostrophe() -> None:
    plan = plan_decoys(machine(home=Path("C:/Users/o'brien")))

    assert plan.decoys == []
    assert all("contains '" in skipped.reason for skipped in plan.skipped)


def test_xdg_config_home_elsewhere_keeps_the_gh_decoy() -> None:
    assert HOME / ".config/gh/hosts.yml" in planned(machine(env={"XDG_CONFIG_HOME": "D:/xdg"}))


def test_every_decoy_has_a_safety_reason_and_matching_kind() -> None:
    plan = plan_decoys(machine())

    assert all(d.reason for d in plan.decoys)
    kinds = {d.path.name: d.kind for d in plan.decoys}
    assert kinds["id_rsa_backup"] is DecoyKind.SSH_KEY
    assert kinds["credentials.old"] is DecoyKind.AWS_CREDENTIALS
    assert kinds["hosts.yml"] is DecoyKind.GH_HOSTS


def test_identity_files_are_parsed_from_ssh_config() -> None:
    text = (
        "Host github.com\n"
        "    IdentityFile ~/.ssh/id_rsa_backup\n"
        "Host *\n"
        '  identityfile="C:/keys/work key"\n'
        "# IdentityFile ~/.ssh/commented\n"
    )

    assert parse_identity_files(text, HOME) == frozenset(
        {HOME / ".ssh/id_rsa_backup", Path("C:/keys/work key")}
    )
