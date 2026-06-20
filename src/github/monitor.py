"""
GitHub monitoring orchestrator.
Coordinates repository scanning, secret detection, and finding storage.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.github.client import GitHubClient, GitHubCommit
from src.github.secret_scanner import SecretScanner, scan_repository_file
from src.database import DatabaseManager

logger = logging.getLogger(__name__)


class GitHubMonitor:
    """GitHub monitoring orchestrator."""

    def __init__(
        self,
        db: DatabaseManager,
        github_token: Optional[str] = None,
        secret_scanner: Optional[SecretScanner] = None,
    ):
        """
        Initialize GitHub monitor.

        Args:
            db: Database manager instance
            github_token: GitHub personal access token
            secret_scanner: Secret scanner instance (created if not provided)
        """
        self.db = db
        self.github_token = github_token
        self.secret_scanner = secret_scanner or SecretScanner()

    async def scan_repository(self, repo_id: int) -> Dict[str, Any]:
        """
        Scan a monitored repository for new findings.

        Args:
            repo_id: Database ID of the repository to scan

        Returns:
            Scan result summary with finding counts
        """
        # Get repo from database
        repo = self.db.get_github_repo(repo_id)
        if not repo:
            logger.error(f"Repository ID {repo_id} not found in database")
            return {"error": "Repository not found", "findings_count": 0}

        logger.info(f"Scanning GitHub repository: {repo.full_name}")

        total_findings = 0
        last_commit = repo.last_commit_hash

        try:
            async with GitHubClient(token=self.github_token) as client:
                # Get commits since last scan
                commits = await client.get_commits_since(
                    repo.organization,
                    repo.repository,
                    since_sha=repo.last_commit_hash,
                    branch=None  # Use default branch
                )

                if not commits:
                    logger.info(f"No new commits for {repo.full_name}")
                    return {"findings_count": 0, "commits_scanned": 0}

                logger.info(f"Found {len(commits)} new commits in {repo.full_name}")

                # Scan each commit
                for commit in commits:
                    findings = await self._scan_commit(
                        repo, commit, client
                    )
                    total_findings += len(findings)

                    # Update last commit
                    if not last_commit or commit.timestamp > datetime.utcnow():
                        last_commit = commit.sha

                # Update repo scan timestamp
                self.db.update_github_repo_last_scan(repo_id, last_commit)

                return {
                    "findings_count": total_findings,
                    "commits_scanned": len(commits),
                    "last_commit": last_commit
                }

        except Exception as e:
            logger.error(f"Error scanning repository {repo.full_name}: {e}")
            return {"error": str(e), "findings_count": total_findings}

    async def _scan_commit(
        self,
        repo,
        commit: GitHubCommit,
        client: GitHubClient,
    ) -> List[int]:
        """
        Scan a single commit for secrets.

        Args:
            repo: GitHubMonitoredRepo object
            commit: GitHubCommit object
            client: GitHubClient instance

        Returns:
            List of finding IDs created
        """
        finding_ids: List[int] = []
        files_to_scan = commit.added_files + commit.modified_files

        logger.info(f"Scanning {len(files_to_scan)} files from commit {commit.sha[:8]}")

        for file_path in files_to_scan:
            try:
                # Get file content
                content = await client.get_raw_file(
                    repo.organization,
                    repo.repository,
                    file_path,
                    ref=commit.sha
                )

                # Scan for secrets
                findings = await scan_repository_file(
                    f"{repo.full_name}/{file_path}",
                    content,
                    self.secret_scanner
                )

                # Store findings in database
                for finding in findings:
                    finding['commit_hash'] = commit.sha
                    finding['commit_url'] = commit.url
                    finding['author'] = commit.author

                    finding_id = self.db.add_github_finding(repo.id, finding)
                    finding_ids.append(finding_id)

                if findings:
                    logger.info(f"Found {len(findings)} secrets in {file_path}")

            except Exception as e:
                logger.warning(f"Error scanning file {file_path}: {e}")
                continue

        return finding_ids

    async def scan_all_repos(self) -> Dict[str, Any]:
        """
        Scan all monitored repositories.

        Returns:
            Summary dict with total repos scanned, findings found, and any errors
        """
        repos = self.db.list_github_repos()
        logger.info(f"Scanning {len(repos)} monitored repositories")

        total_findings = 0
        errors: List[Dict[str, Any]] = []

        for repo in repos:
            try:
                result = await self.scan_repository(repo.id)
                total_findings += result.get('findings_count', 0)

                if result.get('error'):
                    errors.append({
                        'repo': repo.full_name,
                        'error': result.get('error')
                    })

            except Exception as e:
                logger.error(f"Error scanning repo {repo.full_name}: {e}")
                errors.append({
                    'repo': repo.full_name,
                    'error': str(e)
                })

        return {
            'total_repos': len(repos),
            'total_findings': total_findings,
            'errors': errors
        }
