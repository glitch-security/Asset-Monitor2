"""
GitHub monitoring module.

Provides repository scanning, secret detection, and finding storage
for GitHub repositories.
"""

from __future__ import annotations

from src.github.client import GitHubClient, GitHubCommit, GitHubRepo
from src.github.secret_scanner import (
    SecretFinding,
    SecretScanner,
    scan_repository_file,
)
from src.github.monitor import GitHubMonitor

__all__ = [
    "GitHubClient",
    "GitHubCommit",
    "GitHubRepo",
    "SecretScanner",
    "SecretFinding",
    "scan_repository_file",
    "GitHubMonitor",
]
