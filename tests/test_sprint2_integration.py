#!/usr/bin/env python3
"""
Sprint 2 Integration Test - GitHub Monitoring Foundation

This test validates that the Sprint 2 components work together correctly:
- Pattern database loading
- Secret scanning with sample content
- Finding structure and serialization
- Database models integration
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detectors.secrets.patterns import get_pattern_db
from src.github import SecretScanner, GitHubClient, GitHubMonitor
from src.database import DatabaseManager, GitHubMonitoredRepo, GitHubFinding


def test_pattern_database():
    """Test 1: Pattern database loads correctly."""
    print("\n=== Test 1: Pattern Database ===")
    db = get_pattern_db()
    print(f"  Pattern count: {len(db.patterns)}")
    assert len(db.patterns) == 133, f"Expected 133 patterns, got {len(db.patterns)}"
    print("  Pattern database loaded correctly")
    return True


async def test_secret_scanner():
    """Test 2: Secret scanner detects patterns in sample content."""
    print("\n=== Test 2: Secret Scanner ===")
    scanner = SecretScanner()

    # Sample content with various secrets
    # Use realistic source file paths (not test/ directory which is excluded)
    test_cases = [
        {
            "name": "AWS Access Key",
            "filepath": "src/config.py",
            "content": "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nAWS_SECRET_ACCESS_KEY=abcd1234ABCD1234ABCD1234ABCD1234ABCD",
            "expected_keywords": ["AWS Access Key", "AWS Secret"],  # More flexible matching
        },
        {
            "name": "GitHub Token",
            "filepath": "src/main.py",
            "content": "github_token: ghp_1234567890abcdefGHIJKLMNOPQRSTUVWXYZ",
            "expected_keywords": ["GitHub Personal Access"],
        },
        {
            "name": "API Key",
            "filepath": "app/config.py",
            # OpenAI API key requires exactly 48 chars after sk-
            "content": "API_KEY=sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV",
            "expected_keywords": ["OpenAI"],
        },
        {
            "name": "Clean content",
            "filepath": "src/utils.py",
            "content": "# This is a comment\nprint('Hello, world!')\nreturn True",
            "expected_keywords": [],
        },
    ]

    for test in test_cases:
        print(f"\n  Testing: {test['name']}")
        findings = await scanner.scan_file(test['filepath'], test['content'])
        detected = [f.pattern_name for f in findings]
        print(f"    Expected keywords: {test['expected_keywords']}")
        print(f"    Detected: {detected}")

        if test['expected_keywords']:
            assert len(findings) > 0, f"Expected to find secrets in {test['name']}"
            # Check that at least one expected keyword was found in pattern names
            found_any = False
            for keyword in test['expected_keywords']:
                if any(keyword in pattern for pattern in detected):
                    found_any = True
                    break
            assert found_any, f"Expected to find patterns with keywords {test['expected_keywords']}, got {detected}"
        else:
            assert len(findings) == 0, f"Expected no findings in clean content, got {findings}"

    print("\n  Secret scanner tests passed")
    return True


async def test_finding_structure():
    """Test 3: SecretFinding structure is correct."""
    print("\n=== Test 3: Finding Structure ===")
    scanner = SecretScanner()
    findings = await scanner.scan_file(
        "src/config.py",
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"
    )

    assert len(findings) > 0, "Should have found AWS key"
    finding = findings[0]

    # Check required fields (actual SecretFinding dataclass fields)
    assert hasattr(finding, 'pattern_name'), "Missing pattern_name"
    assert hasattr(finding, 'category'), "Missing category"
    assert hasattr(finding, 'severity'), "Missing severity"
    assert hasattr(finding, 'line_number'), "Missing line_number"
    assert hasattr(finding, 'matched_text'), "Missing matched_text"
    assert hasattr(finding, 'context_before'), "Missing context_before"
    assert hasattr(finding, 'context_after'), "Missing context_after"
    assert hasattr(finding, 'start_column'), "Missing start_column"
    assert hasattr(finding, 'end_column'), "Missing end_column"

    print(f"  Sample finding: {finding.pattern_name}")
    print(f"  Severity: {finding.severity}")
    print(f"  Line number: {finding.line_number}")
    print(f"  Finding structure is correct")

    return True


def test_database_models():
    """Test 4: Database models exist and have correct attributes."""
    print("\n=== Test 4: Database Models ===")

    # Check GitHubMonitoredRepo model (actual column names from database.py)
    assert hasattr(GitHubMonitoredRepo, '__tablename__'), "GitHubMonitoredRepo missing tablename"
    expected_repo_cols = ['id', 'organization', 'repository', 'full_name', 'monitor_secrets',
                          'monitor_dangerous_functions', 'monitor_issues', 'monitor_wiki',
                          'monitor_gists', 'last_commit_hash', 'last_scan_timestamp',
                          'alert_on_new_repos', 'created_at', 'updated_at']
    for col in expected_repo_cols:
        assert hasattr(GitHubMonitoredRepo, col), f"GitHubMonitoredRepo missing column: {col}"
    print(f"  GitHubMonitoredRepo has required columns")

    # Check GitHubFinding model (actual column names from database.py)
    assert hasattr(GitHubFinding, '__tablename__'), "GitHubFinding missing tablename"
    expected_finding_cols = ['id', 'repo_id', 'finding_type', 'severity', 'file_path',
                              'line_number', 'commit_hash', 'commit_url', 'author', 'timestamp',
                              'pattern_name', 'matched_text', 'context_before', 'context_after',
                              'false_positive', 'reviewed', 'notes']
    for col in expected_finding_cols:
        assert hasattr(GitHubFinding, col), f"GitHubFinding missing column: {col}"
    print(f"  GitHubFinding has required columns")

    print("  Database models are correct")
    return True


def test_github_monitor_creation():
    """Test 5: GitHubMonitor can be instantiated."""
    print("\n=== Test 5: GitHubMonitor Creation ===")

    # We can't test full functionality without a real GitHub token and DB,
    # but we can verify the class structure
    assert GitHubMonitor is not None, "GitHubMonitor class should exist"
    print(f"  GitHubMonitor class exists")

    # Check required methods (actual methods from monitor.py)
    required_methods = ['scan_repository', 'scan_all_repos']
    for method in required_methods:
        assert hasattr(GitHubMonitor, method), f"GitHubMonitor missing method: {method}"
    print(f"  GitHubMonitor has required methods")

    print("  GitHubMonitor structure is correct")
    return True


async def run_async_tests():
    """Run async tests."""
    await test_secret_scanner()
    await test_finding_structure()


def main():
    """Run all integration tests."""
    print("=" * 60)
    print("Sprint 2 Integration Tests")
    print("=" * 60)

    # Run sync tests
    sync_tests = [
        test_pattern_database,
        test_database_models,
        test_github_monitor_creation,
    ]

    passed = 0
    failed = 0

    for test in sync_tests:
        try:
            if test():
                passed += 1
        except AssertionError as e:
            print(f"\n  FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"\n  ERROR: {e}")
            failed += 1

    # Run async tests
    try:
        asyncio.run(run_async_tests())
        passed += 2  # Two async tests
    except AssertionError as e:
        print(f"\n  FAILED (async): {e}")
        failed += 1
    except Exception as e:
        print(f"\n  ERROR (async): {e}")
        failed += 1

    print("\n" + "=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
