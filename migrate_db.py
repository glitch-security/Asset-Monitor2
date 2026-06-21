"""
Database migration script to fix schema issues.
Run this to update the database schema.
"""

import sqlite3
import sys
from pathlib import Path

def migrate(db_path: str = "data/monitor.db"):
    """Run database migrations."""

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"Checking database: {db_path}")

    # Get list of tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cursor.fetchall()}
    print(f"Existing tables: {tables}")

    # Check domains table structure
    if 'domains' in tables:
        cursor.execute('PRAGMA table_info(domains)')
        columns = {col[1]: col for col in cursor.fetchall()}
        print(f"Domains columns: {list(columns.keys())}")

        # Add company_id if missing
        if 'company_id' not in columns:
            print("Adding company_id column to domains table...")
            cursor.execute('ALTER TABLE domains ADD COLUMN company_id INTEGER')
            cursor.execute('''
                UPDATE domains
                SET company_id = NULL
                WHERE company_id IS NULL
            ''')
            print("OK Added company_id column")
        else:
            print("OK company_id column exists")

        # Add scope_type if missing
        if 'scope_type' not in columns:
            print("Adding scope_type column to domains table...")
            cursor.execute('ALTER TABLE domains ADD COLUMN scope_type VARCHAR(20) DEFAULT "root"')
            print("OK Added scope_type column")
        else:
            print("OK scope_type column exists")

    # Check companies table
    if 'companies' not in tables:
        print("Creating companies table...")
        cursor.execute('''
            CREATE TABLE companies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(256) UNIQUE NOT NULL,
                description TEXT,
                is_active BOOLEAN DEFAULT 1 NOT NULL,
                program_type VARCHAR(64),
                program_url VARCHAR(512),
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
        ''')
        print("OK Created companies table")

    # Check github tables
    if 'github_monitored_repos' not in tables:
        print("Creating github_monitored_repos table...")
        cursor.execute('''
            CREATE TABLE github_monitored_repos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization VARCHAR(255) NOT NULL,
                repository VARCHAR(255) NOT NULL,
                full_name VARCHAR(511) NOT NULL,
                monitor_secrets BOOLEAN DEFAULT 1 NOT NULL,
                monitor_dangerous_functions BOOLEAN DEFAULT 1 NOT NULL,
                monitor_issues BOOLEAN DEFAULT 1 NOT NULL,
                monitor_wiki BOOLEAN DEFAULT 1 NOT NULL,
                monitor_gists BOOLEAN DEFAULT 0 NOT NULL,
                last_commit_hash VARCHAR(64),
                last_scan_timestamp DATETIME,
                alert_on_new_repos BOOLEAN DEFAULT 0 NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(organization, repository)
            )
        ''')
        print("OK Created github_monitored_repos table")

    if 'github_findings' not in tables:
        print("Creating github_findings table...")
        cursor.execute('''
            CREATE TABLE github_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_id INTEGER NOT NULL,
                finding_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                file_path VARCHAR(1024) NOT NULL,
                line_number INTEGER,
                commit_hash VARCHAR(64),
                commit_url VARCHAR(512),
                author VARCHAR(255),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                pattern_name VARCHAR(255) NOT NULL,
                matched_text TEXT,
                context_before TEXT,
                context_after TEXT,
                false_positive BOOLEAN DEFAULT 0 NOT NULL,
                reviewed BOOLEAN DEFAULT 0 NOT NULL,
                notes TEXT,
                FOREIGN KEY(repo_id) REFERENCES github_monitored_repos(id) ON DELETE CASCADE
            )
        ''')
        print("OK Created github_findings table")

    # Create indexes
    print("Creating indexes...")
    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS ix_github_full_name ON github_monitored_repos(full_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS ix_github_finding_type_severity ON github_findings(finding_type, severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS ix_github_finding_timestamp ON github_findings(timestamp)')
    except Exception as e:
        print(f"Index creation note: {e}")

    conn.commit()
    conn.close()
    print("\nOK Migration complete!")

if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/monitor.db"
    migrate(db_path)
