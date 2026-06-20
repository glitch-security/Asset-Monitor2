# Sprint 2: GitHub Monitoring Foundation - Implementation Instructions

> GitHub repository monitoring with secret scanning and dangerous function detection

---

## Overview

Implement GitHub monitoring foundation including:
1. Database schema for GitHub monitoring (github_monitored_repos, github_findings)
2. Secret pattern database (500+ detection patterns)
3. Secret scanning engine with false positive filtering
4. GitHub integration (repository discovery, commit monitoring, issue/wiki/gist scanning)

---

## Task 2.1: Database Schema

**File:** `src/database.py` (add new models)

**Add Two New Tables:**

```python
class GitHubMonitoredRepo(Base):
    """GitHub repositories under monitoring."""
    __tablename__ = 'github_monitored_repos'

    id: Mapped[int] = mapped_column(primary_key=True)
    organization: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    repository: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(511), nullable=False)  # org/repo
    monitor_secrets: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    monitor_dangerous_functions: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    monitor_issues: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    monitor_wiki: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    monitor_gists: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_commit_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_scan_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    alert_on_new_repos: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationship
    findings: Mapped[List["GitHubFinding"]] = relationship(back_populates="repo", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint('organization', 'repository', name='uix_github_repo'),
        Index('ix_github_full_name', 'full_name'),
    )


class GitHubFinding(Base):
    """Security findings from GitHub monitoring."""
    __tablename__ = 'github_findings'

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey('github_monitored_repos.id', ondelete='CASCADE'), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # 'secret', 'dangerous_function', 'sensitive_data'
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    commit_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    commit_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    author: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    pattern_name: Mapped[str] = mapped_column(String(255), nullable=False)
    matched_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context_before: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context_after: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship
    repo: Mapped["GitHubMonitoredRepo"] = relationship(back_populates="findings")

    __table_args__ = (
        Index('ix_github_finding_type_severity', 'finding_type', 'severity'),
        Index('ix_github_finding_timestamp', 'timestamp'),
        CheckConstraint('severity IN ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")', name='ck_github_severity'),
        CheckConstraint('finding_type IN ("secret", "dangerous_function", "sensitive_data")', name='ck_github_finding_type'),
    )
```

**Add DatabaseManager Methods:**

```python
def add_github_repo(self, organization: str, repository: str, **kwargs) -> int:
    """Add a GitHub repository to monitoring. Returns repo ID."""
    full_name = f"{organization}/{repository}"
    repo = GitHubMonitoredRepo(
        organization=organization,
        repository=repository,
        full_name=full_name,
        **kwargs
    )
    self.session.add(repo)
    self.session.commit()
    return repo.id

def get_github_repo(self, repo_id: int) -> Optional[GitHubMonitoredRepo]:
    """Get a GitHub repo by ID."""
    return self.session.query(GitHubMonitoredRepo).filter_by(id=repo_id).first()

def list_github_repos(self, organization: Optional[str] = None) -> List[GitHubMonitoredRepo]:
    """List all monitored GitHub repos, optionally filtered by organization."""
    query = self.session.query(GitHubMonitoredRepo)
    if organization:
        query = query.filter_by(organization=organization)
    return query.order_by(GitHubMonitoredRepo.created_at.desc()).all()

def update_github_repo_last_scan(self, repo_id: int, commit_hash: Optional[str] = None):
    """Update last scan timestamp and commit hash."""
    repo = self.get_github_repo(repo_id)
    if repo:
        repo.last_scan_timestamp = datetime.utcnow()
        if commit_hash:
            repo.last_commit_hash = commit_hash
        self.session.commit()

def add_github_finding(self, repo_id: int, finding: dict) -> int:
    """Add a GitHub finding. Returns finding ID."""
    github_finding = GitHubFinding(
        repo_id=repo_id,
        finding_type=finding.get('finding_type', 'secret'),
        severity=finding.get('severity', 'MEDIUM'),
        file_path=finding.get('file_path', ''),
        line_number=finding.get('line_number'),
        commit_hash=finding.get('commit_hash'),
        commit_url=finding.get('commit_url'),
        author=finding.get('author'),
        pattern_name=finding.get('pattern_name', ''),
        matched_text=finding.get('matched_text'),
        context_before=finding.get('context_before'),
        context_after=finding.get('context_after'),
    )
    self.session.add(github_finding)
    self.session.commit()
    return github_finding.id

def get_github_findings(self, repo_id: Optional[int] = None, finding_type: Optional[str] = None,
                       severity: Optional[str] = None, unreviewed_only: bool = False,
                       limit: int = 100) -> List[GitHubFinding]:
    """Get GitHub findings with optional filters."""
    query = self.session.query(GitHubFinding).join(GitHubMonitoredRepo)

    if repo_id:
        query = query.filter(GitHubFinding.repo_id == repo_id)
    if finding_type:
        query = query.filter(GitHubFinding.finding_type == finding_type)
    if severity:
        query = query.filter(GitHubFinding.severity == severity)
    if unreviewed_only:
        query = query.filter(GitHubFinding.reviewed == False)

    return query.order_by(GitHubFinding.timestamp.desc()).limit(limit).all()

def mark_finding_false_positive(self, finding_id: int, is_fp: bool = True):
    """Mark a finding as false positive (or not)."""
    finding = self.session.query(GitHubFinding).filter_by(id=finding_id).first()
    if finding:
        finding.false_positive = is_fp
        finding.reviewed = True
        self.session.commit()

def mark_finding_reviewed(self, finding_id: int):
    """Mark a finding as reviewed."""
    finding = self.session.query(GitHubFinding).filter_by(id=finding_id).first()
    if finding:
        finding.reviewed = True
        self.session.commit()

def delete_github_repo(self, repo_id: int):
    """Delete a GitHub repo and all its findings (cascade)."""
    repo = self.get_github_repo(repo_id)
    if repo:
        self.session.delete(repo)
        self.session.commit()
```

---

## Task 2.2: Secret Pattern Database

**New File:** `data/secret_patterns.yaml`

**Pattern Database Structure:**

```yaml
patterns:
  # ==================== API Keys & Tokens ====================
  - name: "AWS Access Key"
    category: "cloud"
    severity: "CRITICAL"
    regex: "(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}"
    false_positive_patterns:
      - "EXAMPLE"
      - "AKIAIOSFODNN7EXAMPLE"
      - "AKIAI44QH8DHBEXAMPLE"
    description: "AWS Access Key ID"

  - name: "AWS Secret Key"
    category: "cloud"
    severity: "CRITICAL"
    regex: "[A-Za-z0-9/+=]{40}"
    context_keywords:
      - "aws_secret"
      - "aws_secret_access_key"
      - "secret key"
    description: "AWS Secret Access Key (40 chars base64)"

  - name: "GitHub Personal Access Token"
    category: "git"
    severity: "HIGH"
    regex: "ghp_[A-Za-z0-9]{36}"
    false_positive_patterns:
      - "ghp_example"
    description: "GitHub Personal Access Token (classic)"

  - name: "GitHub OAuth Token"
    category: "git"
    severity: "HIGH"
    regex: "gho_[A-Za-z0-9]{36}"
    description: "GitHub OAuth Token"

  - name: "GitHub App Token"
    category: "git"
    severity: "HIGH"
    regex: "(ghu|ghs|ghr)_[A-Za-z0-9]{36}"
    description: "GitHub App/User/Server Token"

  - name: "GitHub Fine-Grained Token"
    category: "git"
    severity: "HIGH"
    regex: "github_pat_[A-Za-z0-9_]{82}"
    description: "GitHub Fine-grained Personal Access Token"

  # ==================== Communication ====================
  - name: "Slack Token"
    category: "communication"
    severity: "HIGH"
    regex: "xox[baprs]-[A-Za-z0-9-]{10,}"
    false_positive_patterns:
      - "xoxb-example"
    description: "Slack API Token"

  - name: "Slack Webhook"
    category: "communication"
    severity: "MEDIUM"
    regex: "hooks\\.slack\\.com/services/[A-Z0-9]{9,12}/[A-Z0-9]{9,12}/[A-Za-z0-9_]{24}"
    description: "Slack Incoming Webhook URL"

  # ==================== Payment Processing ====================
  - name: "Stripe API Key"
    category: "payment"
    severity: "CRITICAL"
    regex: "(sk_live_|sk_test_)[A-Za-z0-9]{24,}"
    false_positive_patterns:
      - "sk_test_example"
      - "sk_live_example"
    description: "Stripe API Key"

  - name: "Stripe Publishable Key"
    category: "payment"
    severity: "MEDIUM"
    regex: "(pk_live_|pk_test_)[A-Za-z0-9]{24,}"
    description: "Stripe Publishable Key"

  - name: "PayPal Token"
    category: "payment"
    severity: "HIGH"
    regex: "AccessToken:\\s*[A-Za-z0-9-]{50,}"
    description: "PayPal Access Token"

  # ==================== Database Credentials ====================
  - name: "Database Connection String (Generic)"
    category: "database"
    severity: "CRITICAL"
    regex: "(mysql|postgresql|mongodb|redis):\\/\\/[^:]+:[^@]+@"
    description: "Database connection string with credentials"

  - name: "MySQL Password"
    category: "database"
    severity: "CRITICAL"
    regex: "[Pp]assword\\s*=?\\s*['\"]?[A-Za-z0-9_!@#$%^&*()+=]{8,}"
    context_keywords:
      - "mysql"
      - "database"
      - "db_host"
      - "db_user"

  - name: "MongoDB Connection String"
    category: "database"
    severity: "CRITICAL"
    regex: "mongodb\\+srv://[^:]+:[^@]+@"
    description: "MongoDB connection string"

  # ==================== Cloud Services ====================
  - name: "Google Cloud API Key"
    category: "cloud"
    severity: "HIGH"
    regex: "AIza[A-Za-z0-9\\-_]{35}"
    false_positive_patterns:
      - "AIza示例"
    description: "Google Cloud API Key"

  - name: "Google OAuth Client ID"
    category: "cloud"
    severity: "MEDIUM"
    regex: "[0-9-]+\\.apps\\.googleusercontent\\.com"
    description: "Google OAuth Client ID"

  - name: "Google Service Account"
    category: "cloud"
    severity: "CRITICAL"
    regex: "\"type\":\\s*\"service_account\""
    context_keywords:
      - "project_id"
      - "private_key_id"
      - "private_key"
    description: "Google Cloud Service Account credentials"

  - name: "Azure Storage Key"
    category: "cloud"
    severity: "CRITICAL"
    regex: "[A-Za-z0-9/+=]{88}"
    context_keywords:
      - "azure"
      - "storage"
      - "account_key"
    description: "Azure Storage Account Key"

  - name: "Azure Client Secret"
    category: "cloud"
    severity: "HIGH"
    regex: "[A-Za-z0-9\\-~]{35,}"
    context_keywords:
      - "client_secret"
      - "azure"
      - "tenant_id"
    description: "Azure AD Client Secret"

  # ==================== Private Keys & Certificates ====================
  - name: "RSA Private Key"
    category: "crypto"
    severity: "CRITICAL"
    regex: "-----BEGIN RSA PRIVATE KEY-----"
    description: "RSA private key (PEM format)"

  - name: "Private Key (Generic)"
    category: "crypto"
    severity: "CRITICAL"
    regex: "-----BEGIN [A-Z]+ PRIVATE KEY-----"
    description: "Private key in PEM format"

  - name: "SSH Private Key"
    category: "crypto"
    severity: "CRITICAL"
    regex: "-----BEGIN OPENSSH PRIVATE KEY-----"
    description: "OpenSSH private key"

  - name: "PGP Private Key"
    category: "crypto"
    severity: "CRITICAL"
    regex: "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    description: "PGP private key block"

  # ==================== API Tokens (Various) ====================
  - name: "Twilio API Key"
    category: "api"
    severity: "HIGH"
    regex: "SK[a-z0-9]{32}"
    context_keywords:
      - "twilio"
      - "account_sid"
    description: "Twilio API Key"

  - name: "SendGrid API Key"
    category: "api"
    severity: "HIGH"
    regex: "SG\\.[A-Za-z0-9_-]{22,}\\.[A-Za-z0-9_-]{43,}"
    description: "SendGrid API Key"

  - name: "Datadog API Key"
    category: "api"
    severity: "HIGH"
    regex: "[A-Za-z0-9]{32}"
    context_keywords:
      - "datadog"
      - "api_key"
      - "application_key"
    description: "Datadog API Key"

  - name: "Heroku API Key"
    category: "api"
    severity: "HIGH"
    regex: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    context_keywords:
      - "heroku"
      - "api_key"
    description: "Heroku API Key"

  - name: "CircleCI Token"
    category: "api"
    severity: "HIGH"
    regex: "[A-Za-z0-9_-]{40}"
    context_keywords:
      - "circleci"
      - "circle"
    description: "CircleCI Token"

  - name: "GitLab Personal Access Token"
    category: "git"
    severity: "HIGH"
    regex: "glpat-[A-Za-z0-9_-]{20}"
    description: "GitLab Personal Access Token"

  - name: "Bitbucket Repository Token"
    category: "git"
    severity: "HIGH"
    regex: "BBDC-[A-Za-z0-9]{34}"
    description: "Bitbucket Repository Access Token"

  # ==================== JWT & OAuth ====================
  - name: "JWT Token"
    category: "auth"
    severity: "MEDIUM"
    regex: "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"
    description: "JSON Web Token (Bearer token)"

  - name: "OAuth Bearer Token"
    category: "auth"
    severity: "MEDIUM"
    regex: "Bearer\\s+[A-Za-z0-9\\-._~+/]+=*"
    description: "OAuth Bearer Token"

  # ==================== Infrastructure as Code ====================
  - name: "Ansible Vault Password"
    category: "iac"
    severity: "HIGH"
    regex: "\\$ANSIBLE_VAULT"
    description: "Ansible Vault encrypted data"

  - name: "Kubernetes Secret"
    category: "iac"
    severity: "HIGH"
    regex: "(apiVersion|kind):\\s*['\"]?(Secret|ConfigMap)['\"]?"
    context_keywords:
      - "data:"
      - "stringData:"
    description: "Kubernetes Secret/ConfigMap definition"

  # ==================== Additional Critical Patterns ====================
  - name: "Password in Environment Variable"
    category: "credentials"
    severity: "CRITICAL"
    regex: "[Pp]assword\\s*=\\s*['\"]?[A-Za-z0-9_!@#$%^&*()+=]{8,}"
    description: "Password in environment variable assignment"

  - name: "API Key in Environment Variable"
    category: "credentials"
    severity: "HIGH"
    regex: "[Aa]pi[_-]?[Kk]ey\\s*=\\s*['\"]?[A-Za-z0-9_\\-]{20,}"
    description: "API key in environment variable"

  - name: "Secret Key in Environment Variable"
    category: "credentials"
    severity: "CRITICAL"
    regex: "[Ss]ecret[_-]?[Kk]ey\\s*=\\s*['\"]?[A-Za-z0-9_\\-]{20,}"
    description: "Secret key in environment variable"

  - name: "Token in Environment Variable"
    category: "credentials"
    severity: "HIGH"
    regex: "[Tt]oken\\s*=\\s*['\"]?[A-Za-z0-9_\\-]{20,}"
    description: "Token in environment variable"

  # ==================== S3 Buckets ====================
  - name: "AWS S3 Bucket URL"
    category: "cloud"
    severity: "LOW"
    regex: "s3\\.amazonaws\\.com|[a-z0-9-]+\\.s3-[a-z0-9-]+\\.amazonaws\\.com"
    description: "AWS S3 Bucket URL"

  - name: "AWS S3 Bucket with Credentials"
    category: "cloud"
    severity: "CRITICAL"
    regex: "[A-Za-z0-9]+:[A-Za-z0-9/+]{40}@s3\\.amazonaws\\.com"
    description: "S3 bucket with embedded credentials"

# False positive keywords
false_positive_keywords:
  - "example"
  - "test"
  - "demo"
  - "sample"
  - "placeholder"
  - "fake"
  - "xxx"
  - "yyy"
  - "zzz"
  - "localhost"
  - "127.0.0.1"
  - "password123"
  - "secret123"

# File extensions to prioritize scanning
priority_extensions:
  - ".py"
  - ".js"
  - ".ts"
  - ".java"
  - ".go"
  - ".rs"
  - ".rb"
  - ".php"
  - ".sh"
  - ".bash"
  - ".yml"
  - ".yaml"
  - ".json"
  - ".env"
  - ".config"
  - ".conf"
  - ".ini"
  - ".tf"
  - ".toml"

# File paths to exclude (common test/example/docs)
exclude_paths:
  - "test/"
  - "tests/"
  - "spec/"
  - "vendor/"
  - "node_modules/"
  - ".git/"
  - "example/"
  - "examples/"
  - "docs/"
  - "documentation/"
  - "mock/"
  - "stub/"
  - "fixture/"
  - "sample/"
  - ".md$"
  - ".txt$"
  - ".min.js$"
  - ".min.css$"
```

---

## Task 2.3: Secret Pattern Loader Module

**New File:** `src/detectors/secrets/patterns.py`

```python
"""
Secret pattern database loader.
Loads and manages secret detection patterns from YAML.
"""

import yaml
import re
from pathlib import Path
from typing import Any, List, Dict, Optional
from dataclasses import dataclass


@dataclass
class SecretPattern:
    """A single secret detection pattern."""
    name: str
    category: str
    severity: str
    regex: str
    false_positive_patterns: List[str]
    context_keywords: List[str]
    description: str

    def __post_init__(self):
        """Compile regex pattern."""
        try:
            self._compiled_regex = re.compile(self.regex, re.IGNORECASE | re.MULTILINE)
        except re.error:
            # Fallback for invalid regex
            self._compiled_regex = None

    def match(self, text: str) -> Optional[re.Match]:
        """Match pattern against text."""
        if not self._compiled_regex:
            return None
        return self._compiled_regex.search(text)

    def is_false_positive(self, matched_text: str) -> bool:
        """Check if matched text is a known false positive."""
        text_lower = matched_text.lower()
        for fp in self.false_positive_patterns:
            if fp.lower() in text_lower:
                return True
        return False


class PatternDatabase:
    """Secret pattern database manager."""

    def __init__(self, patterns_path: str = "data/secret_patterns.yaml"):
        self.patterns_path = Path(patterns_path)
        self.patterns: List[SecretPattern] = []
        self.false_positive_keywords: List[str] = []
        self.priority_extensions: List[str] = []
        self.exclude_paths: List[str] = []
        self._load()

    def _load(self):
        """Load patterns from YAML file."""
        try:
            with open(self.patterns_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            # Load patterns
            for pattern_data in data.get('patterns', []):
                pattern = SecretPattern(
                    name=pattern_data.get('name', ''),
                    category=pattern_data.get('category', 'other'),
                    severity=pattern_data.get('severity', 'MEDIUM'),
                    regex=pattern_data.get('regex', ''),
                    false_positive_patterns=pattern_data.get('false_positive_patterns', []),
                    context_keywords=pattern_data.get('context_keywords', []),
                    description=pattern_data.get('description', '')
                )
                if pattern.regex:  # Only add if regex exists
                    self.patterns.append(pattern)

            # Load false positive keywords
            self.false_positive_keywords = data.get('false_positive_keywords', [])

            # Load priority extensions
            self.priority_extensions = data.get('priority_extensions', [])

            # Load exclude paths
            self.exclude_paths = data.get('exclude_paths', [])

        except FileNotFoundError:
            print(f"Warning: Pattern database not found at {self.patterns_path}")
        except Exception as e:
            print(f"Error loading pattern database: {e}")

    def get_patterns_by_category(self, category: str) -> List[SecretPattern]:
        """Get all patterns for a specific category."""
        return [p for p in self.patterns if p.category == category]

    def get_patterns_by_severity(self, severity: str) -> List[SecretPattern]:
        """Get all patterns for a specific severity."""
        return [p for p in self.patterns if p.severity == severity]

    def should_scan_file(self, file_path: str) -> bool:
        """Check if file should be scanned based on extension and path."""
        path = Path(file_path)

        # Check exclusions
        for exclude in self.exclude_paths:
            if exclude in file_path:
                # If it's a regex (ends with $), check as regex
                if exclude.endswith('$'):
                    try:
                        if re.search(exclude, file_path):
                            return False
                    except re.error:
                        pass
                elif exclude in file_path:
                    return False

        # Check extension
        if self.priority_extensions:
            return any(str(path).endswith(ext) for ext in self.priority_extensions)

        return True

    def is_global_false_positive(self, text: str) -> bool:
        """Check if text contains any global false positive keywords."""
        text_lower = text.lower()
        for keyword in self.false_positive_keywords:
            if keyword in text_lower:
                return True
        return False


# Global pattern database instance
_pattern_db: Optional[PatternDatabase] = None


def get_pattern_db() -> PatternDatabase:
    """Get or create global pattern database instance."""
    global _pattern_db
    if _pattern_db is None:
        _pattern_db = PatternDatabase()
    return _pattern_db
```

---

## Task 2.4: Secret Scanning Engine

**New File:** `src/github/secret_scanner.py`

```python
"""
Secret scanning engine for GitHub repositories.
Scans file content for leaked secrets and credentials.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from src.detectors.secrets.patterns import get_pattern_db, PatternDatabase


@dataclass
class SecretFinding:
    """A secret finding from scanning."""
    pattern_name: str
    category: str
    severity: str
    file_path: str
    line_number: int
    matched_text: str
    context_before: str
    context_after: str
    start_column: int
    end_column: int


class SecretScanner:
    """Secret scanning engine."""

    def __init__(self, pattern_db: Optional[PatternDatabase] = None):
        self.pattern_db = pattern_db or get_pattern_db()
        self._context_lines = 3  # Lines of context before/after

    async def scan_file(self, file_path: str, content: str) -> List[SecretFinding]:
        """
        Scan a single file for secrets.

        Args:
            file_path: Path to the file being scanned
            content: File content as string

        Returns:
            List of SecretFinding objects
        """
        findings = []

        # Check if file should be scanned
        if not self.pattern_db.should_scan_file(file_path):
            return findings

        # Split into lines
        lines = content.split('\n')

        # Scan with each pattern
        for pattern in self.pattern_db.patterns:
            pattern_findings = self._scan_with_pattern(
                pattern, file_path, lines, content
            )
            findings.extend(pattern_findings)

        return findings

    def _scan_with_pattern(
        self,
        pattern,
        file_path: str,
        lines: List[str],
        full_content: str
    ) -> List[SecretFinding]:
        """Scan content with a specific pattern."""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            # Try to match pattern
            match = pattern.match(line)
            if not match:
                continue

            matched_text = match.group(0)

            # Check for false positives
            if pattern.is_false_positive(matched_text):
                continue

            # Check global false positive keywords
            if self.pattern_db.is_global_false_positive(matched_text):
                continue

            # Extract context
            context_before = self._get_context_before(lines, line_num)
            context_after = self._get_context_after(lines, line_num)

            finding = SecretFinding(
                pattern_name=pattern.name,
                category=pattern.category,
                severity=pattern.severity,
                file_path=file_path,
                line_number=line_num,
                matched_text=matched_text,
                context_before=context_before,
                context_after=context_after,
                start_column=match.start() + 1,
                end_column=match.end() + 1
            )
            findings.append(finding)

        return findings

    def _get_context_before(self, lines: List[str], line_num: int) -> str:
        """Get context lines before the match."""
        start = max(0, line_num - self._context_lines - 1)
        return '\n'.join(lines[start:line_num - 1])

    def _get_context_after(self, lines: List[str], line_num: int) -> str:
        """Get context lines after the match."""
        end = min(len(lines), line_num + self._context_lines)
        return '\n'.join(lines[line_num:end])

    def finding_to_dict(self, finding: SecretFinding) -> Dict[str, Any]:
        """Convert a SecretFinding to a dict for database storage."""
        return {
            'finding_type': 'secret',
            'severity': finding.severity,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'pattern_name': finding.pattern_name,
            'matched_text': finding.matched_text,
            'context_before': finding.context_before,
            'context_after': finding.context_after,
        }


async def scan_repository_file(
    file_path: str,
    content: str,
    scanner: Optional[SecretScanner] = None
) -> List[Dict[str, Any]]:
    """
    Scan a repository file for secrets.

    Returns a list of finding dicts ready for database insertion.
    """
    if scanner is None:
        scanner = SecretScanner()

    findings = await scanner.scan_file(file_path, content)
    return [scanner.finding_to_dict(f) for f in findings]
```

---

## Task 2.5: GitHub Integration Module

**New File:** `src/github/client.py`

```python
"""
GitHub API client for repository monitoring.
Handles authentication, rate limiting, and common API operations.
"""

import httpx
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


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
        self._rate_limit_reset = None

    async def __aenter__(self):
        """Create async client."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AssetMonitor/2.0"
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        self._client = httpx.AsyncClient(
            base_url=self.API_BASE,
            headers=headers,
            timeout=30.0
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close async client."""
        if self._client:
            await self._client.aclose()

    async def _get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make GET request to GitHub API."""
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context.")

        response = await self._client.get(endpoint, params=params)
        response.raise_for_status()

        # Update rate limit info from headers
        self._rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
        reset_time = response.headers.get('X-RateLimit-Reset')
        if reset_time:
            self._rate_limit_reset = datetime.fromtimestamp(int(reset_time))

        return response.json()

    async def get_repo(self, owner: str, repo: str) -> GitHubRepo:
        """Get repository information."""
        data = await self._get(f"repos/{owner}/{repo}")
        return GitHubRepo(
            organization=owner,
            repository=repo,
            full_name=data['full_name'],
            default_branch=data.get('default_branch', 'main'),
            private=data.get('private', False),
            url=data['html_url'],
            description=data.get('description')
        )

    async def list_org_repos(self, organization: str) -> List[GitHubRepo]:
        """List all repositories for an organization."""
        repos = []
        page = 1
        per_page = 100

        while True:
            data = await self._get(
                f"orgs/{organization}/repos",
                params={"page": page, "per_page": per_page, "type": "all"}
            )

            for repo_data in data:
                repos.append(GitHubRepo(
                    organization=organization,
                    repository=repo_data['name'],
                    full_name=repo_data['full_name'],
                    default_branch=repo_data.get('default_branch', 'main'),
                    private=repo_data.get('private', False),
                    url=repo_data['html_url'],
                    description=repo_data.get('description')
                ))

            if len(data) < per_page:
                break

            page += 1

        return repos

    async def get_commits_since(
        self,
        owner: str,
        repo: str,
        since_sha: Optional[str] = None,
        branch: Optional[str] = None
    ) -> List[GitHubCommit]:
        """
        Get commits since a specific SHA.

        Args:
            owner: Repository owner
            repo: Repository name
            since_sha: Starting commit SHA (exclusive). If None, gets latest commits.
            branch: Branch name (defaults to repo's default branch)

        Returns:
            List of commits, newest first
        """
        commits = []
        endpoint = f"repos/{owner}/{repo}/commits"
        params = {"per_page": 100}

        if since_sha:
            params["since_sha"] = since_sha
        if branch:
            params["sha"] = branch

        data = await self._get(endpoint, params=params)

        for commit_data in data:
            sha = commit_data['sha']
            commit_info = commit_data.get('commit', {})

            # Extract files
            files = commit_data.get('files', [])
            added = [f['filename'] for f in files if f.get('status') == 'added']
            modified = [f['filename'] for f in files if f.get('status') == 'modified']
            removed = [f['filename'] for f in files if f.get('status') == 'removed']

            # Parse timestamp
            date_str = commit_info.get('committer', {}).get('date')
            timestamp = datetime.fromisoformat(date_str.replace('Z', '+00:00')) if date_str else datetime.utcnow()

            commits.append(GitHubCommit(
                sha=sha,
                message=commit_info.get('message', ''),
                author=commit_info.get('author', {}).get('name', ''),
                timestamp=timestamp,
                url=commit_data.get('html_url', ''),
                added_files=added,
                modified_files=modified,
                removed_files=removed
            ))

        return commits

    async def get_raw_file(
        self,
        owner: str,
        repo: str,
        file_path: str,
        ref: Optional[str] = None
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
        """
        endpoint = f"repos/{owner}/{repo}/contents/{file_path}"
        params = {}
        if ref:
            params["ref"] = ref

        data = await self._get(endpoint, params=params)

        # Content is base64 encoded
        import base64
        content = data.get('content', '')
        encoding = data.get('encoding', 'base64')

        if encoding == 'base64':
            return base64.b64decode(content).decode('utf-8', errors='replace')

        return content

    async def check_rate_limit(self) -> Tuple[int, Optional[datetime]]:
        """Check current rate limit status.

        Returns:
            Tuple of (remaining_requests, reset_time)
        """
        return self._rate_limit_remaining, self._rate_limit_reset
```

---

## Task 2.6: GitHub Monitor Orchestrator

**New File:** `src/github/monitor.py`

```python
"""
GitHub monitoring orchestrator.
Coordinates repository scanning, secret detection, and finding storage.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

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
        secret_scanner: Optional[SecretScanner] = None
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
        client: GitHubClient
    ) -> List[int]:
        """
        Scan a single commit for secrets.

        Returns list of finding IDs created.
        """
        finding_ids = []
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
        """Scan all monitored repositories."""
        repos = self.db.list_github_repos()
        logger.info(f"Scanning {len(repos)} monitored repositories")

        total_findings = 0
        errors = []

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
```

---

## Task 2.7: Configuration Updates

**File:** `src/config.py`

Add GitHub configuration section:

```python
class GitHubConfig(BaseModel):
    """GitHub monitoring configuration."""

    # GitHub API token (optional, but recommended)
    token: Optional[str] = None

    # Enable/disable GitHub monitoring
    enabled: bool = False

    # Scan interval in hours
    scan_interval_hours: int = 24

    # What to scan
    monitor_secrets: bool = True
    monitor_dangerous_functions: bool = True
    monitor_issues: bool = True
    monitor_wiki: bool = True
    monitor_gists: bool = False

    # Alert on new findings
    alert_on_severity: str = "MEDIUM"  # Minimum severity for alerts

    # Organizations to auto-discover
    auto_discover_organizations: List[str] = []


# Add to AppConfig
class AppConfig(BaseSettings):
    # ... existing config ...

    github: GitHubConfig = Field(default_factory=GitHubConfig)
```

---

## Task 2.8: Scheduler Integration

**File:** `src/scheduler.py`

Add GitHub monitoring to scan cycle:

```python
async def _run_github_monitoring(self):
    """Run GitHub monitoring if enabled."""
    if not self.config.github.enabled:
        return

    logger.info("Starting GitHub monitoring...")

    from src.github.monitor import GitHubMonitor

    monitor = GitHubMonitor(
        db=self.db,
        github_token=self.config.github.token
    )

    result = await monitor.scan_all_repos()

    logger.info(
        f"GitHub monitoring complete: "
        f"{result.get('total_findings', 0)} findings found"
    )

    # Emit change events for findings above threshold
    if result.get('total_findings', 0) > 0:
        await self._emit_github_events(result)
```

---

## Task 2.9: API Endpoints

**File:** `src/web/server.py`

Add GitHub monitoring API endpoints:

```python
# GitHub Monitoring Routes
@app.get("/api/github/repos")
async def api_list_github_repos(user: str = Depends(_require_auth)) -> JSONResponse:
    """List all monitored GitHub repositories."""
    repos = db.list_github_repos()
    return JSONResponse({
        "repos": [
            {
                "id": r.id,
                "organization": r.organization,
                "repository": r.repository,
                "full_name": r.full_name,
                "monitor_secrets": r.monitor_secrets,
                "monitor_dangerous_functions": r.monitor_dangerous_functions,
                "last_scan": r.last_scan_timestamp.isoformat() if r.last_scan_timestamp else None,
                "last_commit": r.last_commit_hash,
                "created_at": r.created_at.isoformat(),
            }
            for r in repos
        ]
    })


@app.post("/api/github/repos")
async def api_add_github_repo(payload: dict, user: str = Depends(_require_admin)) -> JSONResponse:
    """Add a GitHub repository to monitoring."""
    org = payload.get("organization")
    repo = payload.get("repository")

    if not org or not repo:
        raise HTTPException(400, "organization and repository required")

    repo_id = db.add_github_repo(
        organization=org,
        repository=repo,
        monitor_secrets=payload.get("monitor_secrets", True),
        monitor_dangerous_functions=payload.get("monitor_dangerous_functions", True),
        monitor_issues=payload.get("monitor_issues", True),
        monitor_wiki=payload.get("monitor_wiki", True),
        alert_on_new_repos=payload.get("alert_on_new_repos", False),
    )

    return JSONResponse({"repo_id": repo_id, "status": "added"})


@app.delete("/api/github/repos/{repo_id}")
async def api_delete_github_repo(repo_id: int, user: str = Depends(_require_admin)) -> JSONResponse:
    """Delete a GitHub repository from monitoring."""
    db.delete_github_repo(repo_id)
    return JSONResponse({"status": "deleted"})


@app.get("/api/github/findings")
async def api_get_github_findings(
    repo_id: Optional[int] = None,
    finding_type: Optional[str] = None,
    severity: Optional[str] = None,
    unreviewed_only: bool = False,
    limit: int = 100,
    user: str = Depends(_require_auth)
) -> JSONResponse:
    """Get GitHub findings with optional filters."""
    findings = db.get_github_findings(
        repo_id=repo_id,
        finding_type=finding_type,
        severity=severity,
        unreviewed_only=unreviewed_only,
        limit=limit
    )

    return JSONResponse({
        "findings": [
            {
                "id": f.id,
                "repo_id": f.repo_id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "pattern_name": f.pattern_name,
                "matched_text": f.matched_text[:100] + "..." if f.matched_text and len(f.matched_text) > 100 else f.matched_text,
                "context_before": f.context_before,
                "context_after": f.context_after,
                "commit_hash": f.commit_hash,
                "commit_url": f.commit_url,
                "author": f.author,
                "timestamp": f.timestamp.isoformat(),
                "false_positive": f.false_positive,
                "reviewed": f.reviewed,
            }
            for f in findings
        ]
    })


@app.put("/api/github/findings/{finding_id}/review")
async def api_review_finding(
    finding_id: int,
    payload: dict,
    user: str = Depends(_require_admin)
) -> JSONResponse:
    """Mark a finding as reviewed (and optionally as false positive)."""
    is_fp = payload.get("false_positive", False)

    if is_fp:
        db.mark_finding_false_positive(finding_id, is_fp)
    else:
        db.mark_finding_reviewed(finding_id)

    return JSONResponse({"status": "reviewed"})


@app.post("/api/github/scan/{repo_id}")
async def api_trigger_github_scan(
    repo_id: int,
    background_tasks: BackgroundTasks,
    user: str = Depends(_require_admin)
) -> JSONResponse:
    """Trigger an immediate scan of a GitHub repository."""
    # Run scan in background
    async def run_scan():
        from src.github.monitor import GitHubMonitor
        monitor = GitHubMonitor(db=db, github_token=config.github.token)
        await monitor.scan_repository(repo_id)

    background_tasks.add_task(run_scan)

    return JSONResponse({"status": "scan_started"})
```

---

## Task 2.10: Testing Checklist

- [ ] Database tables created successfully
- [ ] Pattern database loads without errors
- [ ] Secret scanner detects test secrets
- [ ] False positive filtering works
- [ ] GitHub client authenticates and fetches data
- [ ] Commit monitoring works
- [ ] Findings are stored in database
- [ ] API endpoints return correct data
- [ ] Scheduler integration works
- [ ] Notifications are sent for new findings

---

## Implementation Order

1. **Database Schema** (Task 2.1) - Foundation for everything
2. **Pattern Database** (Task 2.2) - Needs to exist before scanner
3. **Pattern Loader** (Task 2.3) - Required for scanner
4. **Secret Scanner** (Task 2.4) - Core detection engine
5. **GitHub Client** (Task 2.5) - API integration
6. **Monitor Orchestrator** (Task 2.6) - Coordinates everything
7. **Configuration** (Task 2.7) - Settings
8. **Scheduler Integration** (Task 2.8) - Automation
9. **API Endpoints** (Task 2.9) - UI integration
10. **Testing** (Task 2.10) - Validation

---

## Context Management Strategy

To avoid context overflow during Sprint 2 implementation:

1. **One task at a time** - Complete each task fully before starting the next
2. **Use sub-agents** for complex tasks (pattern database, secret scanner, GitHub client)
3. **Commit often** - After each completed task, commit the work
4. **Minimal context loading** - Only read files that are directly needed
5. **Work instructions as reference** - Use this file as the single source of truth
6. **Update CODEBASE.md** - After completion, update with new modules

---

**Status:** Ready to implement
**Estimated Time:** 8-10 hours
**Last Updated:** 2025-01-19
