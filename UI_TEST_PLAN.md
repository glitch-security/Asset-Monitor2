# AssetMonitor — Comprehensive UI Test Plan

**Created:** 2025-01-21
**Objective:** Systematically verify all UI functionality to catch issues efficiently, not one-by-one

---

## Test Execution Strategy

To avoid context exhaustion, tests will be executed in **focused phases**:
1. **Setup Phase** — Start application, verify basic connectivity
2. **Authentication Phase** — Login flows, password management
3. **Navigation Phase** — All tabs and routes load correctly
4. **Target Management Phase** — Add/edit/delete domains, subdomains, websites
5. **Data Display Phase** — All data views render correctly
6. **Settings Phase** — All settings pages function
7. **User Management Phase** — User CRUD operations
8. **Scan & Profile Phase** — Scan triggers and profile management
9. **Notification Phase** — Alert configurations
10. **Edge Case Phase** — Empty states, error handling, large datasets

Each phase will be: executed → documented → committed before moving to the next.

---

## Phase 1: Setup & Connectivity

### 1.1 Start the application
```powershell
cd C:\Users\shiva\claude\projects\Asset-Monitor2
docker compose up -d --build
```

**Verify:**
- [ ] Container starts without errors
- [ ] Health check passes (`docker compose ps` shows "healthy")
- [ ] No critical errors in logs (`docker compose logs assetmonitor --tail=100`)

### 1.2 Basic connectivity
```powershell
# Health endpoint
curl http://localhost:5000/health

# Root redirect
curl -I http://localhost:5000/

# API auth check
curl http://localhost:5000/api/summary
```

**Verify:**
- [ ] `/health` returns `{"status": "ok"}`
- [ ] `/` redirects to `/login` (302)
- [ ] `/api/summary` returns `{"error": "Unauthorized"}` without auth

---

## Phase 2: Authentication

### 2.1 Initial credentials
```powershell
docker compose exec assetmonitor cat /app/data/initial_credentials.txt
```

**Verify:**
- [ ] Credentials file exists
- [ ] Username is `admin`
- [ ] Password is ≥ 12 characters

### 2.2 Login flow (UI)

**Steps:**
1. Navigate to `http://localhost:5000`
2. Verify login page loads
3. Enter credentials
4. Click login
5. Verify redirect to dashboard

**Verify:**
- [ ] Login page renders without JS errors
- [ ] Username and password fields are present
- [ ] Login button is clickable
- [ ] Successful login redirects to dashboard
- [ ] Session is established (can access authenticated pages)

### 2.3 Logout flow
**Verify:**
- [ ] Logout button/icon exists
- [ ] Logout clears session
- [ ] After logout, protected pages redirect to login

### 2.4 Failed login
**Verify:**
- [ ] Wrong password shows error message
- [ ] No crash or 500 error
- [ ] Error message is user-friendly

---

## Phase 3: Navigation & Layout

### 3.1 Main navigation
**After login, verify each main tab:**
- [ ] **Dashboard** — Summary cards display
- [ ] **Targets** — Target list view
- [ ] **Subdomains** — Subdomain table
- [ ] **Port Scans** — Port scan results
- [ ] **Changes** — Event history
- [ ] **Profiles** — Scan profile list
- [ ] **Settings** — Settings pages (gear icon)

### 3.2 Page load verification
**Verify for each page:**
- [ ] No JavaScript console errors
- [ ] No broken UI elements
- [ ] Loading states show (if applicable)
- [ ] Data eventually loads or shows "no data" message

---

## Phase 4: Target Management

### 4.1 Add Root Domain
**Steps:**
1. Go to Targets tab
2. Click "Add Target"
3. Select type "Root Domain"
4. Enter domain (e.g., `test-domain.com`)
5. (Optional) Select scan profile
6. Click "Add Target"

**Verify:**
- [ ] Modal/form opens correctly
- [ ] Domain input field accepts valid domain
- [ ] Profile dropdown shows available profiles
- [ ] Submit adds domain to list
- [ ] Domain appears in targets table
- [ ] Domain shows correct status badge

### 4.2 Add Known Subdomain
**Verify:**
- [ ] Can add specific subdomain (e.g., `api.example.com`)
- [ ] Subdomain appears in list
- [ ] Subdomain is associated with parent domain

### 4.3 Add Website URL
**Verify:**
- [ ] Can add URL (e.g., `https://example.com`)
- [ ] URL appears in targets
- [ ] URL shows live/dead status

### 4.4 Edit Target
**Verify:**
- [ ] Edit button/icon exists
- [ ] Can modify target properties
- [ ] Changes save correctly

### 4.5 Delete Target
**Verify:**
- [ ] Delete confirmation appears
- [ ] Delete removes target from list
- [ ] Associated data (subdomains, scans) is handled correctly

### 4.6 Assign Profile to Domain
**Verify:**
- [ ] Can assign scan profile via dropdown
- [ ] Profile assignment persists
- [ ] Can clear profile assignment

---

## Phase 5: Data Display

### 5.1 Dashboard Summary Cards
**Verify each card shows:**
- [ ] Total Domains count
- [ ] Total Subdomains count
- [ ] Live Subdomains count
- [ ] Open Ports count
- [ ] Recent Events count
- [ ] Critical/High severity badge counts

### 5.2 Subdomains Table
**Verify:**
- [ ] Table headers are correct (Domain, Status, HTTP Status, Technologies, etc.)
- [ ] Sorting works on clickable columns
- [ ] Pagination or scroll works for large datasets
- [ ] Status badges color correctly (alive=green, dead=red, unknown=gray)
- [ ] HTTP status codes display correctly
- [ ] Technology tags display

### 5.3 Port Scans View
**Verify:**
- [ ] Host/FQDN column shows correctly
- [ ] Port badges color by severity (red=risky, blue=web, yellow=database, green=SSH)
- [ ] Service/version information displays
- [ ] Last scan timestamp shows

### 5.4 Changes/Events View
**Verify:**
- [ ] Event list shows in reverse chronological order
- [ ] Severity badges color correctly
- [ ] Event type is readable
- [ ] Affected asset is linked
- [ ] Timestamp is readable
- [ ] Description is clear

### 5.5 Domain Details Page
**Verify:**
- [ ] Clicking a domain opens details view
- [ ] Shows domain metadata
- [ ] Shows associated subdomains
- [ ] Shows port scan history
- [ ] Shows recent changes
- [ ] All sections render without errors

---

## Phase 6: Settings

### 6.1 Scan Settings
**Verify:**
- [ ] Interval minutes input accepts valid values
- [ ] Timeout input works
- [ ] Crawl depth input works
- [ ] Save button persists settings
- [ ] Settings survive page refresh

### 6.2 Notification Settings
**For each notification type (Slack, Telegram, Discord, Email, Webhook):**
- [ ] Enable/disable toggle works
- [ ] Required fields show when enabled
- [ ] Save stores configuration
- [ ] Test notification button (if present) doesn't error

### 6.3 API Keys Settings
**Verify:**
- [ ] Can enter VirusTotal API key
- [ ] Can enter SecurityTrails API key
- [ ] Can enter Shodan API key
- [ ] Can enter Censys API key
- [ ] Keys save and persist

### 6.4 Users Settings
**Verify:**
- [ ] User list displays
- [ ] Can create new user
- [ ] Can set user role (admin/viewer)
- [ ] Can change user password
- [ ] Can delete user (except self)

---

## Phase 7: User Management

### 7.1 Create User
**Verify:**
- [ ] Form validates username uniqueness
- [ ] Password field accepts input
- [ ] Role dropdown shows admin/viewer
- [ ] Create button adds user
- [ ] New user appears in list
- [ ] New user can log in

### 7.2 Role Enforcement
**Verify:**
- [ ] Viewer role cannot access admin functions
- [ ] Viewer cannot delete users
- [ ] Viewer cannot modify settings
- [ ] Appropriate error/message shown

### 7.3 Password Change
**Verify:**
- [ ] Can change own password
- [ ] Old password required
- [ ] New password works after change
- [ ] Session remains valid

---

## Phase 8: Scan & Profile Management

### 8.1 Built-in Profiles
**Verify:**
- [ ] All 4 built-in profiles listed:
  - Passive Only
  - Stealth
  - Standard
  - Aggressive
- [ ] Built-in profiles show appropriate badges/indicators
- [ ] Built-in profiles cannot be deleted
- [ ] Built-in profiles cannot be edited

### 8.2 Custom Profile Creation
**Verify:**
- [ ] Can create new profile
- [ ] Name and description fields work
- [ ] Settings config saves
- [ ] Custom profile appears in list
- [ ] Custom profile can be edited
- [ ] Custom profile can be deleted

### 8.3 Scan Trigger
**Verify:**
- [ ] "Trigger Scan" button exists
- [ ] Clicking triggers scan (shows status change)
- [ ] Scan status indicator shows running state
- [ ] Scan completes without crashing

---

## Phase 9: Empty States & Edge Cases

### 9.1 Empty Database State
**With fresh/clean database:**
- [ ] Dashboard shows 0 for all counts (not errors)
- [ ] Target list shows "no targets" message
- [ ] Subdomain list shows empty state
- [ ] Port scans view shows empty state
- [ ] Changes view shows empty state
- [ ] All pages load without errors

### 9.2 Large Dataset Handling
**After adding 50+ targets/subdomains:**
- [ ] Tables handle scrolling/pagination
- [ ] Pages load within reasonable time
- [ ] No memory errors in browser console
- [ ] Filters/search still work

### 9.3 Error Handling
**Verify graceful handling of:**
- [ ] Network errors (if API fails)
- [ ] Invalid input in forms
- [ ] Duplicate entries
- [ ] Concurrent modifications

---

## Phase 10: Visual & UX Consistency

### 10.1 Visual Consistency
**Verify across all pages:**
- [ ] Consistent color scheme
- [ ] Consistent button styles
- [ ] Consistent badge colors for status/severity
- [ ] Consistent table headers
- [ ] Consistent modal/dialog styles
- [ ] Consistent form input styles

### 10.2 Responsiveness
**Verify:**
- [ ] Layout adapts to smaller window sizes
- [ ] Tables scroll horizontally if needed
- [ ] Navigation works on mobile/small screens
- [ ] Modals fit on smaller screens

### 10.3 Accessibility
**Verify:**
- [ ] All form inputs have labels
- [ ] Buttons have descriptive text (not just icons)
- [ ] Color is not the only indicator of status
- [ ] Keyboard navigation works (Tab, Enter, Escape)

---

## Test Execution Log

*This section will be filled as tests are executed*

| Phase | Status | Pass | Fail | Notes |
|-------|--------|------|------|-------|
| 1. Setup | Pending | | | |
| 2. Authentication | Pending | | | |
| 3. Navigation | Pending | | | |
| 4. Target Management | Pending | | | |
| 5. Data Display | Pending | | | |
| 6. Settings | Pending | | | |
| 7. User Management | Pending | | | |
| 8. Scan & Profiles | Pending | | | |
| 9. Edge Cases | Pending | | | |
| 10. Visual/UX | Pending | | | |

---

## Bug Report Template

*Issues found will be documented in this format*

### BUG-001: [Title]
- **Severity:** CRITICAL / HIGH / MEDIUM / LOW
- **Phase:** [Phase number]
- **Page/Component:** [Which UI element]
- **Description:** What is wrong
- **Steps to Reproduce:** Exact clicks/inputs
- **Expected:** What should happen
- **Actual:** What actually happens
- **Browser/OS:** [If relevant]

---

## Notes

- Tests will be executed using the `/verify` skill for running and observing the app
- Each phase will be completed and documented before moving to the next
- Screenshots will be captured for visual bugs
- Browser console will be monitored for JavaScript errors
