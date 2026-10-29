"""Known credential file locations for each platform, from docs/credential-locations.md."""

import sys
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

Platform = Literal["windows", "macos", "linux"]

SSH_DEFAULT_KEYS = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")


class Category(Enum):
    """The kind of credential file, which decides how it is read and which rules apply."""

    AWS_CREDENTIALS = "aws-credentials"
    AWS_CONFIG = "aws-config"
    AWS_CACHE = "aws-cache"
    NPMRC = "npmrc"
    YARNRC = "yarnrc"
    DOCKER = "docker"
    GIT_CREDENTIALS = "git-credentials"
    GH_HOSTS = "gh-hosts"
    PYPIRC = "pypirc"
    PIP_CONFIG = "pip-config"
    POETRY_AUTH = "poetry-auth"
    NUGET = "nuget"
    CLAUDE_CODE = "claude-code"
    MCP_CONFIG = "mcp-config"
    CODEX = "codex"
    GEMINI_ENV = "gemini-env"
    GEMINI_OAUTH = "gemini-oauth"
    HUGGING_FACE = "hugging-face"
    COPILOT = "copilot"
    AI_TOOL_CONFIG = "ai-tool-config"
    SSH_KEY = "ssh-key"
    AZURE_JSON = "azure-json"
    AZURE_DPAPI = "azure-dpapi"
    GCP_JSON = "gcp-json"
    GCP_DB = "gcp-db"
    KUBECONFIG = "kubeconfig"
    SHELL_HISTORY = "shell-history"
    # Found by walking folders, not at fixed locations.
    ENV_FILE = "env-file"
    GIT_REMOTE = "git-remote"
    PRIVATE_KEY = "private-key"


WALK_ONLY_CATEGORIES = frozenset({Category.ENV_FILE, Category.GIT_REMOTE, Category.PRIVATE_KEY})
# Key files are judged by their header and cipher name, which always sit at the start.
KEY_CATEGORIES = frozenset({Category.SSH_KEY, Category.PRIVATE_KEY})


@dataclass(frozen=True)
class Location:
    """A credential file path, or a folder plus a glob pattern when `pattern` is set."""

    category: Category
    path: Path
    pattern: str | None = None


@dataclass(frozen=True)
class CredentialFile:
    """A credential file that exists on disk."""

    category: Category
    path: Path


@dataclass(frozen=True)
class _Folders:
    home: Path
    env: Mapping[str, str]
    platform: Platform

    def override(self, variable: str) -> Path | None:
        value = self.env.get(variable)
        return Path(value) if value else None

    @property
    def appdata(self) -> Path:
        return self.override("APPDATA") or self.home / "AppData/Roaming"

    @property
    def localappdata(self) -> Path:
        return self.override("LOCALAPPDATA") or self.home / "AppData/Local"

    @property
    def xdg_config(self) -> Path:
        return self.override("XDG_CONFIG_HOME") or self.home / ".config"

    @property
    def app_support(self) -> Path:
        return self.home / "Library/Application Support"

    def config_dir(self) -> Path:
        """Where per-user app settings live: AppData, Application Support or XDG config."""
        if self.platform == "windows":
            return self.appdata
        if self.platform == "macos":
            return self.app_support
        return self.xdg_config


def current_platform() -> Platform:
    """Return the platform KeySnare is running on."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def known_locations(home: Path, env: Mapping[str, str], platform: Platform) -> list[Location]:
    """Return every known credential location for a platform, honouring environment overrides."""
    folders = _Folders(home, env, platform)
    return [
        *_aws(folders),
        *_javascript(folders),
        *_docker_and_git(folders),
        *_python(folders),
        *_nuget(folders),
        *_ai_tools(folders),
        *_ssh(folders),
        *_cloud(folders),
        *_kubernetes(folders),
        *_shell_history(folders),
    ]


def existing_files(locations: list[Location]) -> list[CredentialFile]:
    """Return the files that exist for the given locations, expanding patterns, each path once."""
    found: dict[Path, CredentialFile] = {}
    for location in locations:
        if location.pattern is None:
            candidates = [location.path]
        elif location.path.is_dir():
            candidates = sorted(location.path.glob(location.pattern))
        else:
            candidates = []
        for path in candidates:
            if path.is_file() and path not in found:
                found[path] = CredentialFile(location.category, path)
    return list(found.values())


def _aws(f: _Folders) -> list[Location]:
    aws = f.home / ".aws"
    return [
        Location(
            Category.AWS_CREDENTIALS,
            f.override("AWS_SHARED_CREDENTIALS_FILE") or aws / "credentials",
        ),
        Location(Category.AWS_CONFIG, f.override("AWS_CONFIG_FILE") or aws / "config"),
        Location(Category.AWS_CACHE, aws / "cli/cache", "*.json"),
        Location(Category.AWS_CACHE, aws / "sso/cache", "*.json"),
    ]


def _javascript(f: _Folders) -> list[Location]:
    if global_npmrc := f.override("NPM_CONFIG_GLOBALCONFIG"):
        global_paths = [global_npmrc]
    elif f.platform == "windows":
        global_paths = [f.appdata / "npm/etc/npmrc"]
    elif f.platform == "macos":
        global_paths = [Path("/usr/local/etc/npmrc"), Path("/opt/homebrew/etc/npmrc")]
    else:
        global_paths = [Path("/usr/local/etc/npmrc"), Path("/usr/etc/npmrc")]
    return [
        Location(Category.NPMRC, f.override("NPM_CONFIG_USERCONFIG") or f.home / ".npmrc"),
        *(Location(Category.NPMRC, path) for path in global_paths),
        Location(Category.YARNRC, f.home / ".yarnrc.yml"),
    ]


def _docker_and_git(f: _Folders) -> list[Location]:
    docker = f.override("DOCKER_CONFIG") or f.home / ".docker"
    if gh_dir := f.override("GH_CONFIG_DIR"):
        gh_hosts = gh_dir / "hosts.yml"
    elif f.platform == "windows":
        gh_hosts = f.appdata / "GitHub CLI/hosts.yml"
    else:
        gh_hosts = f.xdg_config / "gh/hosts.yml"
    return [
        Location(Category.DOCKER, docker / "config.json"),
        Location(Category.GIT_CREDENTIALS, f.home / ".git-credentials"),
        Location(Category.GIT_CREDENTIALS, f.xdg_config / "git/credentials"),
        Location(Category.GH_HOSTS, gh_hosts),
    ]


def _python(f: _Folders) -> list[Location]:
    if pip_file := f.override("PIP_CONFIG_FILE"):
        pip_paths = [pip_file]
    elif f.platform == "windows":
        pip_paths = [f.appdata / "pip/pip.ini"]
    elif f.platform == "macos":
        pip_paths = [f.app_support / "pip/pip.conf", f.xdg_config / "pip/pip.conf"]
    else:
        pip_paths = [f.xdg_config / "pip/pip.conf", f.home / ".pip/pip.conf"]
    poetry_dir = f.override("POETRY_CONFIG_DIR") or f.config_dir() / "pypoetry"
    return [
        Location(Category.PYPIRC, f.home / ".pypirc"),
        *(Location(Category.PIP_CONFIG, path) for path in pip_paths),
        Location(Category.POETRY_AUTH, poetry_dir / "auth.toml"),
    ]


def _nuget(f: _Folders) -> list[Location]:
    if f.platform == "windows":
        return [Location(Category.NUGET, f.appdata / "NuGet/NuGet.Config")]
    return [Location(Category.NUGET, f.home / ".nuget/NuGet/NuGet.Config")]


def _ai_tools(f: _Folders) -> list[Location]:
    locations = [
        Location(Category.CLAUDE_CODE, f.home / ".claude/.credentials.json"),
        Location(Category.MCP_CONFIG, f.home / ".cursor/mcp.json"),
        Location(Category.CODEX, f.home / ".codex/auth.json"),
        Location(Category.GEMINI_ENV, f.home / ".gemini/.env"),
        Location(Category.GEMINI_OAUTH, f.home / ".gemini/oauth_creds.json"),
        Location(Category.HUGGING_FACE, _hugging_face_token(f)),
        Location(Category.AI_TOOL_CONFIG, f.home / ".continue/config.json"),
        Location(Category.AI_TOOL_CONFIG, f.home / ".continue/config.yaml"),
        Location(Category.AI_TOOL_CONFIG, f.home / ".aider.conf.yml"),
    ]
    if f.platform != "linux":
        desktop = f.config_dir() / "Claude/claude_desktop_config.json"
        locations.append(Location(Category.MCP_CONFIG, desktop))
    copilot = f.localappdata if f.platform == "windows" else f.xdg_config
    for name in ("hosts.json", "apps.json"):
        locations.append(Location(Category.COPILOT, copilot / "github-copilot" / name))
    return locations


def _hugging_face_token(f: _Folders) -> Path:
    if token_path := f.override("HF_TOKEN_PATH"):
        return token_path
    hf_home = f.override("HF_HOME") or f.home / ".cache/huggingface"
    return hf_home / "token"


def _ssh(f: _Folders) -> list[Location]:
    return [Location(Category.SSH_KEY, f.home / ".ssh" / name) for name in SSH_DEFAULT_KEYS]


def _cloud(f: _Folders) -> list[Location]:
    azure = f.override("AZURE_CONFIG_DIR") or f.home / ".azure"
    gcloud_parent = f.appdata if f.platform == "windows" else f.xdg_config
    gcloud = f.override("CLOUDSDK_CONFIG") or gcloud_parent / "gcloud"
    locations = [
        Location(Category.AZURE_JSON, azure / "msal_token_cache.json"),
        Location(Category.AZURE_JSON, azure / "service_principal_entries.json"),
        Location(Category.AZURE_JSON, azure / "accessTokens.json"),
        Location(Category.AZURE_DPAPI, azure / "msal_token_cache.bin"),
        Location(Category.AZURE_DPAPI, azure / "service_principal_entries.bin"),
        Location(Category.GCP_JSON, gcloud / "application_default_credentials.json"),
        Location(Category.GCP_JSON, gcloud / "legacy_credentials", "*/adc.json"),
        Location(Category.GCP_DB, gcloud / "credentials.db"),
        Location(Category.GCP_DB, gcloud / "access_tokens.db"),
    ]
    if key_file := f.override("GOOGLE_APPLICATION_CREDENTIALS"):
        locations.append(Location(Category.GCP_JSON, key_file))
    return locations


def _kubernetes(f: _Folders) -> list[Location]:
    separator = ";" if f.platform == "windows" else ":"
    listed = [part for part in f.env.get("KUBECONFIG", "").split(separator) if part]
    paths = [Path(part) for part in listed] or [f.home / ".kube/config"]
    return [Location(Category.KUBECONFIG, path) for path in paths]


def _shell_history(f: _Folders) -> list[Location]:
    if f.platform == "windows":
        powershell = f.appdata / "Microsoft/Windows/PowerShell/PSReadLine"
    else:
        powershell = f.home / ".local/share/powershell/PSReadLine"
    paths = [f.home / ".bash_history", powershell / "ConsoleHost_history.txt"]
    if f.platform != "windows":
        paths.append(f.home / ".zsh_history")
    if histfile := f.override("HISTFILE"):
        paths.append(histfile)
    return [Location(Category.SHELL_HISTORY, path) for path in paths]
