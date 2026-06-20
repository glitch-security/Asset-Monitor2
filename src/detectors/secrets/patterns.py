"""
Secret pattern database loader.
Loads and manages secret detection patterns from YAML.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

import yaml

logger = logging.getLogger(__name__)


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
        except re.error as e:
            # Fallback for invalid regex
            logger.warning(f"Invalid regex for pattern '{self.name}': {e}")
            self._compiled_regex = None

    def match(self, text: str) -> Optional[re.Match]:
        """
        Match pattern against text.

        Args:
            text: Text to search for matches

        Returns:
            Match object if found, None otherwise
        """
        if not self._compiled_regex:
            return None
        return self._compiled_regex.search(text)

    def is_false_positive(self, matched_text: str) -> bool:
        """
        Check if matched text is a known false positive.

        Args:
            matched_text: The text that was matched

        Returns:
            True if this is a known false positive pattern
        """
        text_lower = matched_text.lower()
        for fp in self.false_positive_patterns:
            if fp.lower() in text_lower:
                return True
        return False


class PatternDatabase:
    """Secret pattern database manager."""

    def __init__(self, patterns_path: str = "data/secret_patterns.yaml"):
        """
        Initialize pattern database.

        Args:
            patterns_path: Path to the YAML pattern database file
        """
        self.patterns_path = Path(patterns_path)
        self.patterns: List[SecretPattern] = []
        self.false_positive_keywords: List[str] = []
        self.priority_extensions: List[str] = []
        self.exclude_paths: List[str] = []
        self._load()

    def _load(self) -> None:
        """Load patterns from YAML file."""
        try:
            with open(self.patterns_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                logger.warning(f"Empty pattern database at {self.patterns_path}")
                return

            # Load patterns
            for pattern_data in data.get("patterns", []):
                pattern = SecretPattern(
                    name=pattern_data.get("name", ""),
                    category=pattern_data.get("category", "other"),
                    severity=pattern_data.get("severity", "MEDIUM"),
                    regex=pattern_data.get("regex", ""),
                    false_positive_patterns=pattern_data.get("false_positive_patterns", []),
                    context_keywords=pattern_data.get("context_keywords", []),
                    description=pattern_data.get("description", ""),
                )
                if pattern.regex:  # Only add if regex exists
                    self.patterns.append(pattern)

            # Load false positive keywords
            self.false_positive_keywords = data.get("false_positive_keywords", [])

            # Load priority extensions
            self.priority_extensions = data.get("priority_extensions", [])

            # Load exclude paths
            self.exclude_paths = data.get("exclude_paths", [])

            logger.info(
                f"Loaded {len(self.patterns)} patterns, "
                f"{len(self.false_positive_keywords)} FP keywords, "
                f"{len(self.priority_extensions)} priority extensions"
            )

        except FileNotFoundError:
            logger.warning(f"Pattern database not found at {self.patterns_path}")
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML pattern database: {e}")
        except Exception as e:
            logger.error(f"Error loading pattern database: {e}")

    def get_patterns_by_category(self, category: str) -> List[SecretPattern]:
        """
        Get all patterns for a specific category.

        Args:
            category: Category name (e.g., 'cloud', 'git', 'api')

        Returns:
            List of patterns matching the category
        """
        return [p for p in self.patterns if p.category == category]

    def get_patterns_by_severity(self, severity: str) -> List[SecretPattern]:
        """
        Get all patterns for a specific severity.

        Args:
            severity: Severity level (e.g., 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

        Returns:
            List of patterns matching the severity
        """
        return [p for p in self.patterns if p.severity == severity]

    def should_scan_file(self, file_path: str) -> bool:
        """
        Check if file should be scanned based on extension and path.

        Args:
            file_path: Path to the file to check

        Returns:
            True if the file should be scanned, False if excluded
        """
        path_str = str(file_path)

        # Check exclusions
        for exclude in self.exclude_paths:
            if exclude in path_str:
                # If it's a regex pattern (ends with $), check as regex
                if exclude.endswith("$"):
                    try:
                        if re.search(exclude, path_str):
                            return False
                    except re.error:
                        pass
                elif exclude in path_str:
                    return False

        # Check extension
        if self.priority_extensions:
            return any(file_path.endswith(ext) for ext in self.priority_extensions)

        return True

    def is_global_false_positive(self, text: str) -> bool:
        """
        Check if text contains any global false positive keywords.

        Args:
            text: Text to check

        Returns:
            True if the text contains false positive indicators
        """
        text_lower = text.lower()
        for keyword in self.false_positive_keywords:
            if keyword in text_lower:
                return True
        return False


# Global pattern database instance
_pattern_db: Optional[PatternDatabase] = None


def get_pattern_db() -> PatternDatabase:
    """
    Get or create global pattern database instance.

    Returns:
        The global PatternDatabase singleton instance
    """
    global _pattern_db
    if _pattern_db is None:
        _pattern_db = PatternDatabase()
    return _pattern_db


def reload_pattern_db() -> PatternDatabase:
    """
    Force reload the pattern database.

    Returns:
        The newly loaded PatternDatabase instance
    """
    global _pattern_db
    _pattern_db = PatternDatabase()
    return _pattern_db
