"""Decide where decoys are safe: new files only, where no tool or client library reads them."""

import os
import re
import shutil
import subprocess  # noqa: S404 - runs `git config` with fixed arguments, never a shell
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from keysnare.trap.decoys import DecoyKind
from keysnare.winpath import same_windows_path

TOOLS = ("aws", "docker", "npm", "kubectl", "git")
IDENTITY_FILE = re.compile(r"^\s*identityfile\s*(?:=\s*|\s+)(.+?)\s*$", re.IGNORECASE)
GIT_TIMEOUT_SECONDS = 10
# Recorded when Git's settings cannot be read, so the .git-credentials decoy is skipped.
UNKNOWN_HELPER = "<unknown>"

# (path relative to home, kind, why no tool reads it)
SIBLINGS = (
    (".ssh/id_rsa_backup", DecoyKind.SSH_KEY, "ssh only tries default key names"),
    (".aws/credentials.old", DecoyKind.AWS_CREDENTIALS, "AWS tools read only 'credentials'"),
    (".docker/config.json.bak", DecoyKind.DOCKER_CONFIG, "Docker reads only 'config.json'"),
    (".kube/config.bak", DecoyKind.KUBECONFIG, "kubectl reads only 'config' or KUBECONFIG"),
)
# (path relative to home, kind, tool that reads it when installed)
STANDARD = (
    (".aws/credentials", DecoyKind.AWS_CREDENTIALS, "aws"),
    (".docker/config.json", DecoyKind.DOCKER_CONFIG, "docker"),
    (".npmrc", DecoyKind.NPMRC, "npm"),
    (".kube/config", DecoyKind.KUBECONFIG, "kubectl"),
)
GH_HOSTS = ".config/gh/hosts.yml"
GCLOUD_ADC = ".config/gcloud/application_default_credentials.json"
GIT_CREDENTIALS = ".git-credentials"


@dataclass(frozen=True)
class Machine:
    """Read-only facts about the machine that decide where decoys are safe."""

    home: Path
    env: Mapping[str, str]
    installed_tools: frozenset[str]
    git_credential_helpers: tuple[str, ...]
    ssh_identity_files: frozenset[Path]
    existing_paths: frozenset[Path]


@dataclass(frozen=True)
class PlannedDecoy:
    """A decoy that is safe to plant, and why."""

    kind: DecoyKind
    path: Path
    reason: str


@dataclass(frozen=True)
class SkippedDecoy:
    """A decoy location that was not used, and why."""

    path: Path
    reason: str


@dataclass(frozen=True)
class DecoyPlan:
    """Where decoys will be planted, and where not."""

    decoys: list[PlannedDecoy]
    skipped: list[SkippedDecoy]


def plan_decoys(machine: Machine) -> DecoyPlan:
    """Return the safe decoy locations on this machine, with reasons for every choice."""
    candidates = [
        *((path, kind, reason, None) for path, kind, reason in SIBLINGS),
        (GH_HOSTS, DecoyKind.GH_HOSTS, "GitHub CLI uses %AppData% on Windows", _gh_conflict),
        (GCLOUD_ADC, DecoyKind.GCLOUD_ADC, "gcloud uses %APPDATA% on Windows", _gcloud_conflict),
        (GIT_CREDENTIALS, DecoyKind.GIT_CREDENTIALS, "Git's helper is not 'store'", _git_conflict),
        *(
            (path, kind, f"{tool} is not installed", _tool_conflict(tool))
            for path, kind, tool in STANDARD
        ),
    ]
    plan = DecoyPlan([], [])
    for relative, kind, reason, conflict_check in candidates:
        path = machine.home / relative
        conflict = _common_conflict(path, machine) or (
            conflict_check(machine) if conflict_check else None
        )
        if conflict:
            plan.skipped.append(SkippedDecoy(path, conflict))
        else:
            plan.decoys.append(PlannedDecoy(kind, path, reason))
    return plan


def gather_machine(home: Path, env: Mapping[str, str]) -> Machine:
    """Collect the facts plan_decoys needs. Read-only: it changes nothing on the machine."""
    candidate_paths = [home / relative for relative, *_ in (*SIBLINGS, *STANDARD)]
    candidate_paths += [home / GH_HOSTS, home / GCLOUD_ADC, home / GIT_CREDENTIALS]
    ssh_config = home / ".ssh" / "config"
    return Machine(
        home=home,
        env=env,
        installed_tools=frozenset(tool for tool in TOOLS if shutil.which(tool)),
        git_credential_helpers=_git_credential_helpers(home),
        ssh_identity_files=(
            parse_identity_files(ssh_config.read_text(encoding="utf-8", errors="replace"), home)
            if ssh_config.is_file()
            else frozenset()
        ),
        existing_paths=frozenset(p for p in candidate_paths if os.path.lexists(p)),
    )


def parse_identity_files(ssh_config: str, home: Path) -> frozenset[Path]:
    """Return every IdentityFile named in an ssh config, with ~ expanded."""
    paths = set()
    for line in ssh_config.splitlines():
        match = IDENTITY_FILE.match(line)
        if match:
            value = match.group(1).strip('"')
            paths.add(home / value[2:] if value.startswith("~/") else Path(value))
    return frozenset(paths)


def _common_conflict(path: Path, machine: Machine) -> str | None:
    if "'" in str(path):
        return "the path contains ', which the relay's event query cannot hold"
    if any(_same(path, existing) for existing in machine.existing_paths):
        return "a file already exists"
    if any(_same(path, identity) for identity in machine.ssh_identity_files):
        return "named as an IdentityFile in ~/.ssh/config"
    kubeconfig = machine.env.get("KUBECONFIG", "")
    if any(_same(path, part) for part in kubeconfig.split(";") if part):
        return "listed in KUBECONFIG"
    if _same(path, machine.env.get("GOOGLE_APPLICATION_CREDENTIALS")):
        return "named by GOOGLE_APPLICATION_CREDENTIALS"
    return None


def _gh_conflict(machine: Machine) -> str | None:
    if _same(machine.home / ".config", machine.env.get("XDG_CONFIG_HOME")):
        return "XDG_CONFIG_HOME makes GitHub CLI use ~/.config"
    if _same(machine.home / ".config/gh", machine.env.get("GH_CONFIG_DIR")):
        return "GH_CONFIG_DIR makes GitHub CLI use ~/.config/gh"
    return None


def _gcloud_conflict(machine: Machine) -> str | None:
    if _same(machine.home / ".config/gcloud", machine.env.get("CLOUDSDK_CONFIG")):
        return "CLOUDSDK_CONFIG makes gcloud use ~/.config/gcloud"
    return None


def _git_conflict(machine: Machine) -> str | None:
    if UNKNOWN_HELPER in machine.git_credential_helpers:
        return "could not check Git's credential helper"
    if any(helper.split()[0] == "store" for helper in machine.git_credential_helpers if helper):
        return "Git's credential helper 'store' reads this file"
    return None


def _tool_conflict(tool: str) -> Callable[[Machine], str | None]:
    def check(machine: Machine) -> str | None:
        return (
            f"{tool} is installed and reads this file" if tool in machine.installed_tools else None
        )

    return check


def _same(path: Path, other: str | Path | None) -> bool:
    return other is not None and same_windows_path(path, other)


def _git_credential_helpers(home: Path) -> tuple[str, ...]:
    git = shutil.which("git")
    if git is None:
        return ()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed arguments, resolved git path, no shell
            [git, "config", "--get-all", "credential.helper"],
            cwd=home,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return (UNKNOWN_HELPER,)
    return tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())
