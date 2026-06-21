# Bug Fixes Summary

## Issues Fixed

### 1. ✅ "Failed to save project: Internal Server Error"
**Root Cause**: Incorrect FastAPI dependency injection pattern
- Used `user: str = Depends(_require_admin)` which expects a return value
- But `_require_admin()` only raises exception on failure, returns None

**Fix**: Changed to `dependencies=[Depends(_require_admin)]`

**Files Modified**:
- `src/web/server.py` line 1005-1006 (GET /api/projects)
- `src/web/server.py` line 1559 (GET /api/config/github)
- `src/web/server.py` line 1578 (PUT /api/config/github)

### 2. ✅ "projects.forEach is not a function"
**Root Cause**: Same as #1 - the API was failing internally due to dependency injection error

**Fix**: Same as #1

### 3. ✅ Database Migration Issues
**Status**: All required tables verified present
- companies, domains, subdomains, mobile_apps, api_assets
- github_monitored_repos, github_findings
- All other required tables

## GitHub Monitoring - Token Requirements

**Answer**: No token required for public repositories

**Details**:
- Public repos can be read without authentication (60 requests/hour)
- Token benefits:
  - Higher rate limits (5000 requests/hour)
  - Access to private repositories
  - More reliable access

**Test Procedure**:
1. Add a public repo (e.g., `facebook/react`) via the GitHub tab
2. Click "Scan Now" to trigger immediate scan
3. View findings in the GitHub Findings sub-tab

## Testing the Fixes

1. Start server: `python -m src.web.server`
2. Login at `http://localhost:8000/login`
3. Click "Projects" tab - should load without error
4. Click "New Project" - should open modal
5. Create a project - should save successfully

## Context Management Approach Used

1. Created SESSION_PLAN.md to track progress
2. Used targeted edits instead of full rewrites
3. Summarized findings after each investigation
4. Created test script for verification
