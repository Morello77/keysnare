"""How dangerous each kind of finding is, and why, in plain English."""

from dataclasses import dataclass
from enum import Enum
from functools import total_ordering


@total_ordering
class Severity(Enum):
    """Finding severity, declared from most to least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """0 for the most severe level."""
        return list(Severity).index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


@dataclass(frozen=True)
class Risk:
    """What a finding is and why a stealer wants it."""

    severity: Severity
    title: str
    why: str


CRITICAL, HIGH, MEDIUM, LOW = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

GITHUB_WHY = (
    "Lets an attacker push code, read private repositories and change GitHub Actions, "
    "which is how one stolen token turns into a supply-chain attack."
)
NPM_WHY = (
    "Lets an attacker publish a poisoned version of your npm packages. "
    "Worms like Shai-Hulud spread exactly this way."
)
PYPI_WHY = "Lets an attacker publish a poisoned version of your Python packages to PyPI."
AI_KEY_WHY = (
    "Lets an attacker run up large bills on your account and read anything sent through it."
)
AI_LOGIN_WHY = (
    "A login token for an AI coding tool. An attacker can use your account, "
    "and the tool's access to your code, until the token is revoked."
)
DPAPI_WHY = (
    "Encrypted with Windows DPAPI, but any program running as you can decrypt it, "
    "and a stealer runs as you. Lower risk than plain text, not safe."
)
KUBE_WHY = "Gives an attacker access to your Kubernetes cluster with your permissions."

RISKS: dict[str, Risk] = {
    "F-AWS-KEY-ID": Risk(
        HIGH,
        "AWS access key ID",
        "An AWS key ID is usually stored next to its secret key. "
        "Together they give full access to your AWS account with your permissions.",
    ),
    "F-GITHUB-TOKEN": Risk(CRITICAL, "GitHub token", GITHUB_WHY),
    "F-GITHUB-PAT": Risk(CRITICAL, "GitHub fine-grained token", GITHUB_WHY),
    "F-NPM-TOKEN": Risk(CRITICAL, "npm access token", NPM_WHY),
    "F-PYPI-TOKEN": Risk(CRITICAL, "PyPI upload token", PYPI_WHY),
    "F-OPENAI-KEY": Risk(HIGH, "OpenAI API key", AI_KEY_WHY),
    "F-ANTHROPIC-KEY": Risk(HIGH, "Anthropic API key", AI_KEY_WHY),
    "F-GOOGLE-API-KEY": Risk(HIGH, "Google API key", AI_KEY_WHY),
    "F-HF-TOKEN": Risk(
        HIGH,
        "Hugging Face token",
        "Lets an attacker read your private models and datasets, "
        "and with write access, replace them with poisoned versions.",
    ),
    "F-PRIVATE-KEY": Risk(
        HIGH,
        "Private key",
        "A private key proves your identity to servers and services. "
        "Whoever copies it can act as you.",
    ),
    "F-URL-CREDENTIALS": Risk(
        HIGH,
        "Password in a URL",
        "A username and password written into a URL, often for a database or private registry.",
    ),
    "F-STRIPE-LIVE-KEY": Risk(
        CRITICAL,
        "Stripe live key",
        "Lets an attacker act on your live Stripe account within the key's permissions: issue "
        "refunds, change payout details or read customer data.",
    ),
    "F-STRIPE-TEST-KEY": Risk(
        LOW,
        "Stripe test-mode key",
        "A test-mode key cannot move real money, but it identifies your Stripe account, and the "
        "matching live key is often stored nearby.",
    ),
    "F-SLACK-TOKEN": Risk(
        HIGH,
        "Slack token",
        "Lets an attacker read and post messages in your Slack workspace with the token's "
        "permissions, which makes phishing your colleagues easy.",
    ),
    "F-SENDGRID-KEY": Risk(
        HIGH,
        "SendGrid API key",
        "Lets an attacker send email from your verified domains, which makes phishing look "
        "genuine and can get your domains blocklisted.",
    ),
    "S-AWS-SECRET-ENV": Risk(
        HIGH,
        "AWS secret access key",
        "An AWS secret key in a project or shell file. With its key ID it gives full access to "
        "your AWS account with your permissions.",
    ),
    "S-AWS-SECRET": Risk(
        CRITICAL,
        "AWS secret access key",
        "A long-lived AWS key. It gives full access to your AWS account with your permissions "
        "and never expires on its own.",
    ),
    "S-AWS-SESSION": Risk(
        MEDIUM,
        "AWS session token",
        "Temporary AWS credentials. Dangerous until they expire, usually within hours.",
    ),
    "S-AWS-CACHE": Risk(
        MEDIUM,
        "Cached AWS credentials",
        "Short-lived AWS credentials or SSO tokens cached by the AWS CLI. "
        "Dangerous until they expire.",
    ),
    "S-NPMRC-TOKEN": Risk(CRITICAL, "npm token in .npmrc", NPM_WHY),
    "S-YARNRC-TOKEN": Risk(CRITICAL, "npm token in .yarnrc.yml", NPM_WHY),
    "S-DOCKER-AUTH": Risk(
        CRITICAL,
        "Docker registry login",
        "Stored as base64, which anyone can decode. Lets an attacker push poisoned images "
        "under your name.",
    ),
    "S-GIT-CREDENTIALS": Risk(
        CRITICAL,
        "Git password or token",
        "Stored in plain text by Git's 'store' helper. Lets an attacker push code as you.",
    ),
    "S-GIT-REMOTE": Risk(
        CRITICAL,
        "Token in a Git remote URL",
        "A token written into a repository's remote URL. Lets an attacker push code as you.",
    ),
    "S-GH-HOSTS": Risk(CRITICAL, "GitHub CLI token", GITHUB_WHY),
    "S-PYPIRC-PASSWORD": Risk(CRITICAL, "PyPI token in .pypirc", PYPI_WHY),
    "S-PIP-INDEX-URL": Risk(
        HIGH,
        "Package index password",
        "A password for a private Python package index. Lets an attacker read, "
        "and sometimes publish, your private packages.",
    ),
    "S-POETRY-AUTH": Risk(CRITICAL, "Poetry repository credential", PYPI_WHY),
    "S-NUGET-CLEARTEXT": Risk(
        HIGH,
        "NuGet feed password",
        "A plain-text password for a NuGet feed. Lets an attacker read, "
        "and sometimes publish, your private .NET packages.",
    ),
    "S-NUGET-DPAPI": Risk(MEDIUM, "Encrypted NuGet feed password", DPAPI_WHY),
    "S-CLAUDE-OAUTH": Risk(HIGH, "Claude Code login", AI_LOGIN_WHY),
    "S-CODEX-AUTH": Risk(HIGH, "OpenAI Codex login", AI_LOGIN_WHY),
    "S-MCP-ENV": Risk(
        HIGH,
        "Secret in MCP server config",
        "An API key or password written into an MCP server's settings, "
        "where any program can read it.",
    ),
    "S-HF-TOKEN-FILE": Risk(
        HIGH,
        "Hugging Face login",
        "Lets an attacker read your private models and datasets, "
        "and with write access, replace them with poisoned versions.",
    ),
    "S-GEMINI-OAUTH": Risk(HIGH, "Gemini CLI login", AI_LOGIN_WHY),
    "S-COPILOT-TOKEN": Risk(
        MEDIUM,
        "GitHub Copilot token",
        "Lets an attacker use your Copilot subscription. Its access to your code is limited.",
    ),
    "S-CONFIG-APIKEY": Risk(HIGH, "API key in AI tool config", AI_KEY_WHY),
    "S-SSH-KEY": Risk(
        CRITICAL,
        "SSH key without a passphrase",
        "Anyone who copies this file can log in to your servers and push to your repositories "
        "as you. A passphrase would make the copy useless.",
    ),
    "S-AZURE-MSAL": Risk(
        HIGH,
        "Azure CLI login",
        "Azure refresh tokens in plain text. Lets an attacker use your Azure account "
        "until you sign out.",
    ),
    "S-AZURE-SP": Risk(
        CRITICAL,
        "Azure service principal secret",
        "A long-lived secret for an Azure service principal, "
        "often with broad access to cloud resources.",
    ),
    "S-AZURE-DPAPI": Risk(MEDIUM, "Encrypted Azure CLI login", DPAPI_WHY),
    "S-AZURE-LEGACY": Risk(
        HIGH,
        "Old Azure CLI token file",
        "Azure tokens in plain text, written by old Azure CLI versions.",
    ),
    "S-GCP-SERVICE-ACCOUNT": Risk(
        CRITICAL,
        "Google Cloud service account key",
        "A service account private key never expires on its own and often has broad access "
        "to your Google Cloud project.",
    ),
    "S-GCP-ADC-USER": Risk(
        HIGH,
        "Google Cloud login",
        "A refresh token that lets an attacker use Google Cloud as you until it is revoked.",
    ),
    "S-GCP-CREDENTIALS-DB": Risk(
        HIGH,
        "gcloud credential store",
        "gcloud keeps refresh tokens for every signed-in account in this unencrypted database.",
    ),
    "S-KUBE-TOKEN": Risk(CRITICAL, "Kubernetes token", KUBE_WHY),
    "S-KUBE-CLIENT-KEY": Risk(CRITICAL, "Kubernetes client key", KUBE_WHY),
    "S-KUBE-PASSWORD": Risk(CRITICAL, "Kubernetes password", KUBE_WHY),
    "S-KUBE-AUTH-PROVIDER": Risk(
        HIGH,
        "Cached Kubernetes login",
        "A cached token from a Kubernetes login plugin. Gives cluster access until it expires.",
    ),
    "S-HISTORY-SECRET": Risk(
        HIGH,
        "Secret in shell history",
        "A secret typed on the command line was saved to your shell history file, "
        "which stealers read.",
    ),
    "K-SECRET-NAME": Risk(
        LOW,
        "Possible secret",
        "A value stored under a secret-sounding name. KeySnare cannot confirm it is real, "
        "so check it yourself.",
    ),
}


def risk_for(rule_id: str) -> Risk:
    """Return the risk for a rule ID. Raises KeyError for an unknown ID."""
    return RISKS[rule_id]
