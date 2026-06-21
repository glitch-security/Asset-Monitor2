# Public Repository Push Guide

## ✅ Security Status: CLEAN

All sensitive data has been removed from git history:
- ✅ `login.json` (credentials) - REMOVED from all commits
- ✅ `cookie.txt` (session tokens) - REMOVED from all commits
- ✅ `session.json`, `create.json` - REMOVED from all commits
- ✅ Dev docs with secrets - REMOVED from all commits

## ⚠️ CRITICAL: Force Push Required

The git history has been rewritten. You **MUST force push** to update the remote repository.

```bash
# Backup branch created: backup-before-rewrite-20260621-075800
# You can return to it if needed: git checkout backup-before-rewrite-20260621-075800

# FORCE PUSH to rewrite remote history
git push origin main --force

# OR if pushing to a new public repo:
git push https://github.com/YOURUSERNAME/assetmonitor.git main --force
```

## 🔐 Still Required: Rotate Credentials

Even though history is rewritten, **if this repo was ever public or shared**, rotate these credentials:

### 1. Admin Password
```bash
python assetmonitor.py reset-admin --password <NEW_SECURE_PASSWORD>
```

### 2. Flask Secret (Invalidates Sessions)
```bash
sqlite3 data/assetmonitor.db "DELETE FROM app_settings WHERE key='system:flask_secret';"
# OR generate a new secret and update manually
```

### 3. Any API Keys in config.yaml
Check `config.yaml` for any API keys and regenerate them.

## 📋 Pre-Push Verification Checklist

Run these commands **before** pushing to public:

```bash
cd C:\Users\shiva\claude\projects\Asset-Monitor2

# 1. Verify no secrets in history
git log --all --full-history --name-only | Select-String -Pattern "password|secret|key|token|cookie" | Select-String -Pattern "json|txt"

# 2. Check for test artifacts
git ls-files | Select-String -Pattern "json|txt" | Where-Object { $_ -notmatch "README|config.example|docs" }

# 3. Verify .gitignore is working
git check-ignore -v cookie.txt login.json session.json create.json

# 4. Check commit history is clean
git log --oneline -10
```

Expected results:
- Command 1: No output (or only false positives in docs)
- Command 2: No output
- Command 3: Shows files are ignored
- Command 4: Shows clean commit history

## 🚀 Push to Public Repository

```bash
# Option 1: Update existing GitHub repo
git push origin main --force --tags

# Option 2: Push to new public GitHub repo
gh repo create public --public --source=AssetMonitor2
# OR manually:
git remote add public https://github.com/YOURUSERNAME/assetmonitor.git
git push public main --force
```

## 🔄 After First Public Push

1. **Verify on GitHub**: Check the repo online - no test files should be visible
2. **Clone fresh**: Clone the repo to a temp directory to verify it's clean
```bash
cd C:\Users\shiva\AppData\Local\Temp
git clone https://github.com/YOURUSERNAME/assetmonitor.git assetmonitor-test
cd assetmonitor-test
dir  # Should only show: src/, tests/, docs/, docker-compose.yml, etc.
```

3. **Run gitleaks scan** (if you have it installed):
```bash
gitleaks detect --source . --verbose
```

## 📁 Clean Repository Structure (Final)

```
Asset-Monitor2/
├── src/                    # Source code
│   ├── config.py
│   ├── database.py
│   ├── web/
│   └── ...
├── tests/                  # Test suite
├── docs/                   # Documentation only
│   └── SECURITY_GUIDE.md
├── data/                   # (gitignored) Runtime data
├── config.yaml.example     # Template
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── pyproject.toml
├── README.md
├── .gitignore              # Updated with test artifact rules
└── CLAUDE.md               # Project instructions (can be removed if desired)

../Asset-Monitor-Test/      # Use for ALL testing - gitignored
```

## 🛡️ Ongoing Security Practices

1. **All testing in `../Asset-Monitor-Test/`**
2. **Never commit** `*.json`, `*.txt` files to project root
3. **Run `git status`** before every commit
4. **Review diff** before pushing: `git diff origin/main`

## 📞 If Something Goes Wrong

```bash
# You have a backup branch with original history
git checkout backup-before-rewrite-20260621-075800
```

## Summary

Your repository is now ready for public push. The history has been rewritten to remove all sensitive data. After force pushing, the old commits with secrets will be replaced with clean ones.
