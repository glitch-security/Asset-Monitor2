"""
Secret scanning engine for GitHub repositories.
Scans file content for leaked secrets and credentials.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.detectors.secrets.patterns import PatternDatabase, get_pattern_db

logger = logging.getLogger(__name__)


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
        """
        Initialize secret scanner.

        Args:
            pattern_db: Pattern database instance. Uses global default if not provided.
        """
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
        findings: List[SecretFinding] = []

        # Check if file should be scanned
        if not self.pattern_db.should_scan_file(file_path):
            logger.debug(f"Skipping file excluded by pattern database: {file_path}")
            return findings

        # Split into lines
        lines = content.split("\n")

        # Scan with each pattern
        for pattern in self.pattern_db.patterns:
            pattern_findings = self._scan_with_pattern(
                pattern, file_path, lines, content
            )
            findings.extend(pattern_findings)

        logger.debug(f"Found {len(findings)} secrets in {file_path}")
        return findings

    def _scan_with_pattern(
        self,
        pattern,
        file_path: str,
        lines: List[str],
        full_content: str,
    ) -> List[SecretFinding]:
        """
        Scan content with a specific pattern.

        Args:
            pattern: SecretPattern to scan with
            file_path: Path to the file
            lines: List of file lines
            full_content: Full file content string

        Returns:
            List of SecretFinding objects from this pattern
        """
        findings: List[SecretFinding] = []

        for line_num, line in enumerate(lines, start=1):
            # Try to match pattern
            match = pattern.match(line)
            if not match:
                continue

            matched_text = match.group(0)

            # Check for false positives
            if pattern.is_false_positive(matched_text):
                logger.debug(
                    f"False positive detected for pattern '{pattern.name}' at line {line_num}"
                )
                continue

            # Check global false positive keywords
            if self.pattern_db.is_global_false_positive(matched_text):
                logger.debug(
                    f"Global false positive keyword detected for pattern '{pattern.name}' at line {line_num}"
                )
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
                end_column=match.end() + 1,
            )
            findings.append(finding)

        return findings

    def _get_context_before(self, lines: List[str], line_num: int) -> str:
        """
        Get context lines before the match.

        Args:
            lines: List of all file lines
            line_num: Line number of the match (1-indexed)

        Returns:
            Context lines before the match as a string
        """
        start = max(0, line_num - self._context_lines - 1)
        return "\n".join(lines[start : line_num - 1])

    def _get_context_after(self, lines: List[str], line_num: int) -> str:
        """
        Get context lines after the match.

        Args:
            lines: List of all file lines
            line_num: Line number of the match (1-indexed)

        Returns:
            Context lines after the match as a string
        """
        end = min(len(lines), line_num + self._context_lines)
        return "\n".join(lines[line_num:end])

    def finding_to_dict(self, finding: SecretFinding) -> Dict[str, Any]:
        """
        Convert a SecretFinding to a dict for database storage.

        Args:
            finding: SecretFinding to convert

        Returns:
            Dictionary suitable for database insertion
        """
        return {
            "finding_type": "secret",
            "severity": finding.severity,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "pattern_name": finding.pattern_name,
            "matched_text": finding.matched_text,
            "context_before": finding.context_before,
            "context_after": finding.context_after,
        }


async def scan_repository_file(
    file_path: str,
    content: str,
    scanner: Optional[SecretScanner] = None,
) -> List[Dict[str, Any]]:
    """
    Scan a repository file for secrets.

    This is a convenience function that creates a scanner if needed
    and returns findings as dictionaries ready for database insertion.

    Args:
        file_path: Path to the file to scan
        content: File content as string
        scanner: Optional SecretScanner instance. Created if not provided.

    Returns:
        List of finding dicts ready for database insertion
    """
    if scanner is None:
        scanner = SecretScanner()

    findings = await scanner.scan_file(file_path, content)
    return [scanner.finding_to_dict(f) for f in findings]
