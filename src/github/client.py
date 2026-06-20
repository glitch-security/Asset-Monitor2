"""
GitHub API client for repository monitoring.
Handles authentication, rate limiting, and common API operations.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)


@dataclass
class GitHubRepo:
    """GitHub repository information."""

    organization: str
    repository: str
    full_name: str
    default_branch: str
    private: bool
    url: str
    description: Optional[str] = None
    last_commit: Optional[str] = None


@dataclass
class GitHubCommit:
    """GitHub commit information."""

    sha: str
    message: str
    author: str
    timestamp: datetime
    url: str
    added_files: List[str]
    modified_files: List[str]
    removed_files: List[str]


class GitHubClient:
    """GitHub API client with authentication and rate limiting."""

    API_BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub client.

        Args:
            token: GitHub personal access token (recommended for higher rate limits)
        """
        self.token = token
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limit_remaining = 5000
        self._rate_limit_reset: Optional[datetime] = None

    async def __aenter__(self) -> GitHubClient:
        """
        Create async client.

        Returns:
            The client instance for use in async context
        """
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AssetMonitor/2.0",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        self._client = httpx.AsyncClient(
            base_url=self.API_BASE,
            headers=headers,
            timeout=30.0,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close async client."""
        if self._client:
            await self._client.aclose()

    async def _get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make GET request to GitHub API.

        Args:
            endpoint: API endpoint path (e.g., 'repos/org/repo')
            params: Optional query parameters

        Returns:
            Parsed JSON response

        Raises:
            RuntimeError: If client is not initialized
            httpx.HTTPStatusError: If request fails
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context.")

        response = await self._client.get(endpoint, params=params)
        response.raise_for_status()

        # Update rate limit info from headers
        self._rate_limit_remaining = int(response.headers.get("X-RateLimit-Remaining", 0))
        reset_time = response.headers.get("X-RateLimit-Reset")
        if reset_time:
            self._rate_limit_reset = datetime.fromtimestamp(int(reset_time))

        logger.debug(
            f"GitHub API: {endpoint} - Rate limit remaining: {self._rate_limit_remaining}"
        )

        return response.json()

    async def get_repo(self, owner: str, repo: str) -> GitHubRepo:
        """
        Get repository information.

        Args:
            owner: Repository owner (organization or user)
            repo: Repository name

        Returns:
            GitHubRepo object with repository information

        Raises:
            httpx.HTTPStatusError: If repository not found or API error
        """
        data = await self._get(f"repos/{owner}/{repo}")
        return GitHubRepo(
            organization=owner,
            repository=repo,
            full_name=data["full_name"],
            default_branch=data.get("default_branch", "main"),
            private=data.get("private", False),
            url=data["html_url"],
            description=data.get("description"),
        )

    async def list_org_repos(self, organization: str) -> List[GitHubRepo]:
        """
        List all repositories for an organization.

        Args:
            organization: Organization name

        Returns:
            List of GitHubRepo objects

        Raises:
            httpx.HTTPStatusError: If organization not found or API error
        """
        repos: List[GitHubRepo] = []
        page = 1
        per_page = 100

        while True:
            data = await self._get(
                f"orgs/{organization}/repos",
                params={"page": page, "per_page": per_page, "type": "all"},
            )

            for repo_data in data:
                repos.append(
                    GitHubRepo(
                        organization=organization,
                        repository=repo_data["name"],
                        full_name=repo_data["full_name"],
                        default_branch=repo_data.get("default_branch", "main"),
                        private=repo_data.get("private", False),
                        url=repo_data["html_url"],
                        description=repo_data.get("description"),
                    )
                )

            # Check if we've retrieved all repos
            if len(data) < per_page:
                break

            page += 1

        logger.info(f"Listed {len(repos)} repositories for organization {organization}")
        return repos

    async def get_commits_since(
        self,
        owner: str,
        repo: str,
        since_sha: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> List[GitHubCommit]:
        """
        Get commits since a specific SHA.

        Args:
            owner: Repository owner
            repo: Repository name
            since_sha: Starting commit SHA (exclusive). If None, gets latest commits.
            branch: Branch name (defaults to repo's default branch)

        Returns:
            List of GitHubCommit objects, newest first

        Raises:
            httpx.HTTPStatusError: If repository not found or API error
        """
        commits: List[GitHubCommit] = []
        endpoint = f"repos/{owner}/{repo}/commits"
        params: Dict[str, Any] = {"per_page": 100}

        if since_sha:
            params["sha"] = since_sha
        if branch:
            params["sha"] = branch

        data = await self._get(endpoint, params=params)

        for commit_data in data:
            sha = commit_data["sha"]
            commit_info = commit_data.get("commit", {})

            # Extract files changed in this commit
            files = commit_data.get("files", [])
            added = [f["filename"] for f in files if f.get("status") == "added"]
            modified = [f["filename"] for f in files if f.get("status") == "modified"]
            removed = [f["filename"] for f in files if f.get("status") == "removed"]

            # Parse timestamp
            date_str = commit_info.get("committer", {}).get("date")
            if date_str:
                timestamp = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            else:
                timestamp = datetime.utcnow()

            commits.append(
                GitHubCommit(
                    sha=sha,
                    message=commit_info.get("message", ""),
                    author=commit_info.get("author", {}).get("name", ""),
                    timestamp=timestamp,
                    url=commit_data.get("html_url", ""),
                    added_files=added,
                    modified_files=modified,
                    removed_files=removed,
                )
            )

        logger.debug(f"Retrieved {len(commits)} commits for {owner}/{repo}")
        return commits

    async def get_raw_file(
        self,
        owner: str,
        repo: str,
        file_path: str,
        ref: Optional[str] = None,
    ) -> str:
        """
        Get raw file content from repository.

        Args:
            owner: Repository owner
            repo: Repository name
            file_path: Path to file in repository
            ref: Git reference (branch, tag, or SHA). Defaults to default branch.

        Returns:
            File content as string

        Raises:
            httpx.HTTPStatusError: If file not found or API error
        """
        endpoint = f"repos/{owner}/{repo}/contents/{file_path}"
        params: Dict[str, Any] = {}
        if ref:
            params["ref"] = ref

        data = await self._get(endpoint, params=params)

        # Content is base64 encoded
        content = data.get("content", "")
        encoding = data.get("encoding", "base64")

        if encoding == "base64":
            return base64.b64decode(content).decode("utf-8", errors="replace")

        return content

    async def check_rate_limit(self) -> Tuple[int, Optional[datetime]]:
        """
        Check current rate limit status.

        Returns:
            Tuple of (remaining_requests, reset_time)
            - remaining_requests: Number of requests remaining in current window
            - reset_time: When the rate limit resets (UTC), or None if unknown
        """
        return self._rate_limit_remaining, self._rate_limit_reset
