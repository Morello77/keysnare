"""Step-by-step fixes for each finding, with platform-specific commands where they differ."""

from collections.abc import Mapping
from dataclasses import dataclass

from keysnare.locations import Platform

Step = str | Mapping[Platform, str]


@dataclass(frozen=True)
class Fix:
    """The steps that remove a secret from disk or make it harmless."""

    steps: tuple[Step, ...]

    def steps_for(self, platform: Platform) -> tuple[str, ...]:
        """Return the steps that apply on one platform."""
        resolved = []
        for step in self.steps:
            text = step if isinstance(step, str) else step.get(platform)
            if text:
                resolved.append(text)
        return tuple(resolved)


KEYCHAIN_ENV: Step = {
    "windows": (
        "Keep the secret in an encrypted vault and load it only in the terminal that needs it. "
        "With PowerShell: `Install-Module Microsoft.PowerShell.SecretManagement, "
        "Microsoft.PowerShell.SecretStore`, `Register-SecretVault -Name local -ModuleName "
        "Microsoft.PowerShell.SecretStore -DefaultVault`, `Set-Secret -Name API_KEY`, then "
        "`$env:API_KEY = Get-Secret API_KEY -AsPlainText` when you need it."
    ),
    "macos": (
        "Keep the secret in the Keychain and load it only in the terminal that needs it: "
        '`security add-generic-password -a "$USER" -s API_KEY -w` (it prompts for the value), '
        "then `export API_KEY=$(security find-generic-password -s API_KEY -w)` when you need it."
    ),
    "linux": (
        "Keep the secret in your desktop keyring and load it only in the terminal that needs it: "
        "`secret-tool store --label=API_KEY service API_KEY` (it prompts for the value), "
        "then `export API_KEY=$(secret-tool lookup service API_KEY)` when you need it."
    ),
}
REMOVE_FROM_FILE = "Delete the secret from the file KeySnare reported."
ROTATE = (
    "If the file may already have been copied, revoke the secret and create a new one. "
    "Removing it from disk does not undo a theft."
)

GIT_HELPER: Step = {
    "windows": (
        "Let Git Credential Manager keep Git logins in Windows Credential Manager: "
        "`git config --global credential.helper manager`."
    ),
    "macos": (
        "Keep Git logins in the Keychain: `git config --global credential.helper osxkeychain`."
    ),
    "linux": (
        "Install Git Credential Manager and run `git-credential-manager configure` "
        "so Git logins go to your desktop keyring."
    ),
}
REVOKE_GITHUB = (
    "Revoke the token at https://github.com/settings/tokens (OAuth apps: Settings → Applications). "
    "If you need a new one, create a fine-grained token with an expiry date and only the "
    "repositories it needs."
)
GITHUB_FIX = Fix((REVOKE_GITHUB, GIT_HELPER, REMOVE_FROM_FILE))

NPM_FIX = Fix(
    (
        "Revoke the token: `npm token list`, then `npm token revoke <id>` "
        "(or on npmjs.com under Access Tokens).",
        "Publish from CI with npm trusted publishing instead of keeping a token on your machine.",
        "If you need a token locally, create a granular access token with an expiry date and "
        "reference it instead of pasting it: `//registry.npmjs.org/:_authToken=${NPM_TOKEN}` in "
        '.npmrc, or `npmAuthToken: "${NPM_TOKEN}"` in .yarnrc.yml.',
        KEYCHAIN_ENV,
    )
)

PYPI_FIX = Fix(
    (
        "Delete the token on pypi.org under Account settings → API tokens. "
        "If you need a new one, scope it to a single project.",
        "Publish from CI with PyPI trusted publishing instead of keeping a token on your machine.",
        "To upload by hand, keep the token in your OS keychain: "
        "`keyring set https://upload.pypi.org/legacy/ __token__`. Twine reads it from there.",
        REMOVE_FROM_FILE,
    )
)

POETRY_FIX = Fix(
    (
        "Remove the stored credential: `poetry config --unset http-basic.<repo>` "
        "(or `pypi-token.<repo>`).",
        "Set it again with a working OS keyring, so Poetry stores it there instead of auth.toml: "
        "`poetry config http-basic.<repo> <username>` prompts for the password.",
        ROTATE,
    )
)

AWS_KEY_FIX = Fix(
    (
        "Switch to short-lived credentials: run `aws configure sso` to sign in through "
        "IAM Identity Center, so no long-lived key is stored.",
        "Deactivate and delete the old key in the IAM console, or with "
        "`aws iam delete-access-key --access-key-id <key id>`.",
        REMOVE_FROM_FILE,
    )
)

AWS_TEMPORARY_FIX = Fix(
    (
        "Run `aws sso logout` when you finish working, to clear cached SSO tokens.",
        "Keep session durations short in your IAM roles and Identity Center permission sets.",
    )
)

AI_KEY_FIX = Fix(
    (
        "Revoke the key in the provider's dashboard and create a new one with a spending limit.",
        KEYCHAIN_ENV,
        REMOVE_FROM_FILE,
    )
)

HUGGING_FACE_FIX = Fix(
    (
        "Revoke the token at https://huggingface.co/settings/tokens. If you need a new one, "
        "create a fine-grained, read-only token.",
        "Sign out on this machine when you are done: `hf auth logout` "
        "(older versions: `huggingface-cli logout`).",
    )
)

DOCKER_FIX = Fix(
    (
        {
            "windows": 'Set `"credsStore": "wincred"` in config.json '
            '(Docker Desktop uses `"desktop"`, which also stores logins in Windows Credential '
            "Manager).",
            "macos": 'Set `"credsStore": "osxkeychain"` in config.json '
            '(Docker Desktop uses `"desktop"`, which also stores logins in the Keychain).',
            "linux": 'Set `"credsStore": "pass"` or `"secretservice"` in config.json, '
            "after installing the matching docker-credential helper.",
        },
        "Run `docker logout <registry>` and then `docker login <registry>`, "
        "so the login moves into the credential store.",
        "Revoke the old token in your registry's settings "
        "(Docker Hub: Account settings → Personal access tokens).",
    )
)

NUGET_FIX = Fix(
    (
        "Replace the password with an environment variable reference, "
        'such as `value="%NUGET_FEED_PASSWORD%"`. NuGet expands it when it reads the file.',
        "For Azure Artifacts feeds, use the Azure Artifacts Credential Provider "
        "instead of a stored password.",
        KEYCHAIN_ENV,
        ROTATE,
    )
)

SSH_FIX = Fix(
    (
        "Add a passphrase: `ssh-keygen -p -f <key file>`. "
        "For a PuTTY .ppk key, open it in PuTTYgen, set a passphrase and save it.",
        {
            "windows": "Use the built-in ssh-agent so you type the passphrase once per login. In "
            "an administrator PowerShell: `Get-Service ssh-agent | Set-Service -StartupType "
            "Automatic; Start-Service ssh-agent`, then `ssh-add <key file>`.",
            "macos": "Store the passphrase in the Keychain: "
            "`ssh-add --apple-use-keychain <key file>`.",
            "linux": "Load the key into ssh-agent so you type the passphrase once per session: "
            "`ssh-add <key file>`.",
        },
        "Stronger still: use a hardware security key with `ssh-keygen -t ed25519-sk`.",
        "If the key may have been copied, create a new key and remove the old public key from "
        "GitHub and from `authorized_keys` on your servers.",
    )
)

KUBE_FIX = Fix(
    (
        "Use your cloud's login plugin so no credential is stored: "
        "EKS `aws eks update-kubeconfig --name <cluster>`, "
        "GKE `gcloud container clusters get-credentials <cluster>` with gke-gcloud-auth-plugin, "
        "AKS `kubelogin convert-kubeconfig -l azurecli`.",
        "Remove the static token, password or client key from the kubeconfig, "
        "and revoke it on the cluster.",
    )
)

AI_LOGIN_FIX = Fix(
    (
        "This tool keeps its login in a file and may not offer a keychain option on this "
        "platform. Reduce exposure: sign out when you stop using it, and sign in again when "
        "needed.",
        "If the file may have been copied, sign out of all sessions and change your password "
        "in the provider's account settings.",
    )
)

FIXES: dict[str, Fix] = {
    "F-AWS-KEY-ID": AWS_KEY_FIX,
    "F-GITHUB-TOKEN": GITHUB_FIX,
    "F-GITHUB-PAT": GITHUB_FIX,
    "F-NPM-TOKEN": NPM_FIX,
    "F-PYPI-TOKEN": PYPI_FIX,
    "F-OPENAI-KEY": AI_KEY_FIX,
    "F-ANTHROPIC-KEY": AI_KEY_FIX,
    "F-GOOGLE-API-KEY": AI_KEY_FIX,
    "F-HF-TOKEN": HUGGING_FACE_FIX,
    "F-PRIVATE-KEY": Fix(
        (
            "Move the key into its own file protected by a passphrase, "
            "and delete it from the file KeySnare reported.",
            ROTATE,
        )
    ),
    "F-URL-CREDENTIALS": Fix(
        (
            "Remove the password from the URL and supply it separately, "
            "through the tool's credential helper or an environment variable.",
            KEYCHAIN_ENV,
            ROTATE,
        )
    ),
    "S-AWS-SECRET": AWS_KEY_FIX,
    "S-AWS-SESSION": AWS_TEMPORARY_FIX,
    "S-AWS-CACHE": AWS_TEMPORARY_FIX,
    "S-NPMRC-TOKEN": NPM_FIX,
    "S-YARNRC-TOKEN": NPM_FIX,
    "S-DOCKER-AUTH": DOCKER_FIX,
    "S-GIT-CREDENTIALS": Fix(
        (
            GIT_HELPER,
            "Check that pushing still works, then delete the reported credentials file. "
            "Git's 'store' helper keeps passwords in plain text.",
            REVOKE_GITHUB,
        )
    ),
    "S-GIT-REMOTE": Fix(
        (
            "Remove the token from the remote URL: "
            "`git remote set-url <remote> https://github.com/<owner>/<repo>.git`.",
            GIT_HELPER,
            REVOKE_GITHUB,
        )
    ),
    "S-GH-HOSTS": Fix(
        (
            "Run `gh auth logout`, then `gh auth login`. Recent GitHub CLI versions store the "
            "token in your OS keyring when one is available.",
            REVOKE_GITHUB,
        )
    ),
    "S-PYPIRC-PASSWORD": PYPI_FIX,
    "S-PIP-INDEX-URL": Fix(
        (
            "Remove the password from the index URL.",
            "Let pip read it from your OS keychain: install `keyring` and run pip with "
            "`--keyring-provider subprocess`.",
            ROTATE,
        )
    ),
    "S-POETRY-AUTH": POETRY_FIX,
    "S-NUGET-CLEARTEXT": NUGET_FIX,
    "S-NUGET-DPAPI": NUGET_FIX,
    "S-CLAUDE-OAUTH": Fix(
        (
            "Claude Code keeps its login in this file on Windows and Linux; on macOS it uses the "
            "Keychain. Reduce exposure: run `/logout` in Claude Code when you stop using it.",
            *AI_LOGIN_FIX.steps[1:],
        )
    ),
    "S-CODEX-AUTH": Fix(
        (
            "Run `codex logout` when you stop using Codex.",
            "If an API key is stored, revoke it in the OpenAI dashboard and create a new one "
            "with a spending limit.",
        )
    ),
    "S-MCP-ENV": Fix(
        (
            "Start the MCP server through a small wrapper script that reads the key from your "
            "OS keychain, instead of writing the key into the config file.",
            KEYCHAIN_ENV,
            ROTATE,
        )
    ),
    "S-HF-TOKEN-FILE": HUGGING_FACE_FIX,
    "S-GEMINI-OAUTH": Fix(
        (
            *AI_LOGIN_FIX.steps,
            "Review and revoke Gemini CLI access at https://myaccount.google.com/permissions.",
        )
    ),
    "S-COPILOT-TOKEN": Fix(
        (
            "Sign out of GitHub Copilot in your editor when you stop using it.",
            "Revoke the token on GitHub under Settings → Applications → Authorized OAuth Apps.",
        )
    ),
    "S-CONFIG-APIKEY": AI_KEY_FIX,
    "S-SSH-KEY": SSH_FIX,
    "S-AZURE-MSAL": Fix(
        (
            "Run `az logout` when you stop using Azure, or `az account clear` "
            "to remove every cached account.",
            ROTATE,
        )
    ),
    "S-AZURE-SP": Fix(
        (
            "Prefer managed identities or workload identity federation, which need no stored "
            "secret. If you need a service principal, use a certificate instead of a secret.",
            "Replace the secret: `az ad sp credential reset --id <app id>`, "
            "then `az logout` to remove the stored copy.",
        )
    ),
    "S-AZURE-DPAPI": Fix(("Run `az logout` when you stop using Azure.",)),
    "S-AZURE-LEGACY": Fix(
        (
            "Upgrade the Azure CLI (`az upgrade`) and sign in again. Current versions do not use "
            "accessTokens.json; delete it once the new login works.",
            ROTATE,
        )
    ),
    "S-GCP-SERVICE-ACCOUNT": Fix(
        (
            "Delete the key: `gcloud iam service-accounts keys delete <key id> "
            "--iam-account=<service account email>`.",
            "Use impersonation instead of a key file: `gcloud auth application-default login "
            "--impersonate-service-account=<service account email>`.",
            REMOVE_FROM_FILE,
        )
    ),
    "S-GCP-ADC-USER": Fix(
        ("Run `gcloud auth application-default revoke` when you no longer need it.", ROTATE)
    ),
    "S-GCP-CREDENTIALS-DB": Fix(
        ("Sign out of accounts you do not use: `gcloud auth revoke <account>`, or `--all`.",)
    ),
    "S-KUBE-TOKEN": KUBE_FIX,
    "S-KUBE-CLIENT-KEY": KUBE_FIX,
    "S-KUBE-PASSWORD": KUBE_FIX,
    "S-KUBE-AUTH-PROVIDER": Fix(
        (
            "The `auth-provider` login method is deprecated. Switch to your cloud's exec plugin.",
            *KUBE_FIX.steps[:1],
        )
    ),
    "S-HISTORY-SECRET": Fix(
        (
            "Revoke and replace the secret. It was written to disk in plain text.",
            {
                "windows": "Open the file from `(Get-PSReadLineOption).HistorySavePath` in an "
                "editor and delete the line. Recent PSReadLine versions skip some lines that "
                "contain words like 'password', but not secrets under other names.",
                "macos": "Delete the line from `~/.zsh_history` (or `~/.bash_history`), "
                "then open a new terminal.",
                "linux": "Delete the line from `~/.bash_history` (or `~/.zsh_history`), "
                "then open a new terminal.",
            },
            {
                "windows": "In future, avoid typing secrets into commands: "
                "`Read-Host -AsSecureString` prompts without showing or saving the value.",
                "macos": "In future, avoid typing secrets into commands: "
                "`read -rs API_KEY` prompts without showing or saving the value.",
                "linux": "In future, avoid typing secrets into commands: "
                "`read -rs API_KEY` prompts without showing or saving the value.",
            },
        )
    ),
    "K-SECRET-NAME": Fix(
        (
            "Check whether this value is a real secret. If it is not, you can ignore this finding.",
            KEYCHAIN_ENV,
            REMOVE_FROM_FILE,
        )
    ),
}


def fix_for(rule_id: str, platform: Platform) -> tuple[str, ...]:
    """Return the fix steps for a rule on one platform. Raises KeyError for an unknown ID."""
    return FIXES[rule_id].steps_for(platform)
