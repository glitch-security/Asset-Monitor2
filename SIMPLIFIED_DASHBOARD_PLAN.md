# Simplified Dashboard Implementation Plan

> **Goal**: Avoid context overflow by working in small atomic tasks.
> **Scope**: Dashboard shows only Projects (companies). Clicking a company opens all detail tabs.

## Current State Analysis

- `Company` model EXISTS in database.py (id, name, description, is_active, program_type, program_url, notes)
- API endpoints EXIST: `/api/projects`, `/api/projects/{id}`, POST/PUT/DELETE
- Dashboard template ALREADY has project detail panel with tabs (Targets, Subdomains, Ports, Changes, Headers, Mobile, API)

## Implementation Tasks (Atomic - One File Per Task)

### Task 1: Verify Main Dashboard Shows Only Projects
- **File**: `src/web/templates/dashboard.html`
- **Action**: Confirm main view has the projects table and no competing top-level tabs
- **Expected**: Main dashboard shows "Projects" header and projects table

### Task 2: Verify Project Detail Panel Has All Tabs
- **File**: `src/web/templates/dashboard.html`
- **Action**: Verify clicking company name opens project detail with sub-tabs
- **Tabs needed**: Targets, Subdomains, Ports, Changes, Headers, Mobile Apps, API Assets

### Task 3: Verify API Endpoints Return Correct Data
- **File**: `src/web/server.py`
- **Action**: Test `/api/projects` and `/api/projects/{id}` endpoints
- **Expected**: Returns company list and company details with domains/subdomains

### Task 4: Clean Up Any Unnecessary UI Elements
- **File**: `src/web/templates/dashboard.html`
- **Action**: Remove any redundant "Targets" tab at top level if it exists
- **Expected**: Clean UI with single point of entry (Projects table)

### Task 5: Test End-to-End Flow
- **Action**: Start server, login, create company, add domain, view details
- **Expected**: Full flow works without errors

## Important Notes

1. **Work in WSL for Docker**: All docker commands run via `wsl docker compose ...`
2. **Test after each atomic task**: Don't batch multiple changes without testing
3. **Commit after each working change**: Keep history clean
4. **Read only what's needed**: Don't read entire files when grep suffices

## Session Budget

- Max tokens per turn: 50k
- Atomic task size: ~50-150 lines max
- Total estimated time: 1-2 hours
