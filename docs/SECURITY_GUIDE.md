# Security Guide for AssetMonitor

## Critical: What Was Fixed

The following sensitive files were removed from git history:
- `login.json` - contained admin credentials
- `cookie.txt` - contained valid session token
- `session.json` - contained session data
- `create.json` - contained test data

## Actions Required Before Pushing to Public Repo

### 1. Rotate the Admin Password
```bash
# If admin123 was a real password anywhere, change it immediately
python assetmonitor.py reset-admin --password <NEW_SECURE_PASSWORD>
```

### 2. Rotate the Flask Secret (Invalidates All Sessions)
The `system:flask_secret` in the database was used to sign the leaked cookie. Rotate it:

```bash
# In Python shell
from src.database import DatabaseManager
import secrets

db = DatabaseManager("data/assetmonitor.db")
# Update the secret
db._engine.execute(
    text("UPDATE app_settings SET value = :secret WHERE key = 'system:flask_secret'"),
    {"secret": secrets.token_hex(32)}
)
```

Or simply delete the app_settings row and let it regenerate:
```bash
sqlite3 data/assetmonitor.db "DELETE FROM app_settings WHERE key='system:flask_secret';"
```

### 3. Verify No Other Secrets in History
```bash
# Check for any remaining secrets
git log --all --full-history --source -- "*secret*" "*password*" "*key*" "*.pem" "*.key"
```

## For Future Development

### Use the Test Directory
All testing and session files go in `../Asset-Monitor-Test/`:
```powershell
cd C:\Users\shiva\claude\projects\Asset-Monitor-Test
# Run curl tests here
curl -c cookie.txt ...
```

### Pre-Commit Hook Setup (Recommended)
Install gitleaks to prevent future secret commits:
```bash
# Install gitleaks (Windows)
winget install gitleaks

# Or download from: https://github.com/gitleaks/gitleaks/releases

# Run manual scan before pushing
gitleaks detect --source . --verbose
```

### Testing Guidelines

1. **Never create test files in the project root**
2. **Use ../Asset-Monitor-Test/ for all testing**
3. **Run `git status` before committing** - verify no test artifacts
4. **Check .gitignore** before adding new file types

## Clean Repository Structure

The public repository should only contain:
```
Asset-Monitor2/
├── src/              # Source code
├── tests/            # Test suite
├── data/             # (gitignored) Database runtime
├── docs/             # Documentation
├── config.yaml.example
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── pyproject.toml
├── README.md
└── .gitignore
```

## Emergency: If Secrets Were Already Pushed

1. **Immediately rotate all exposed credentials**
2. **Rotate Flask secret** (invalidates sessions)
3. **Consider the key compromised** - regenerate any API keys
4. **Notify users** if production data was exposed

## Commands to Run Before Public Push

```bash
# 1. Scan for secrets
gitleaks detect --source . --verbose

# 2. Check for test artifacts
git ls-files | grep -E "(json|txt|md)" | grep -vE "(README|config.example|docs/)"

# 3. Verify .gitignore coverage
git check-ignore -v cookie.txt login.json session.json

# 4. Final status check
git status
```
