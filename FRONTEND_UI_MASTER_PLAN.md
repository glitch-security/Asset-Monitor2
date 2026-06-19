# Frontend UI Master Plan

> Comprehensive plan to ensure ALL backend features are accessible via frontend

---

## Design Principles

1. **Discoverability** - All features visible within 2 clicks
2. **Consistency** - Same patterns for similar features
3. **Context** - Actions available where data is visible
4. **Feedback** - Clear success/error messages
5. **Responsive** - Works on desktop/tablet

---

## Navigation Structure

### Current Tabs
- Targets
- Projects ✅ (added)
- Profiles
- Port Scans
- Subdomains
- HTTP Headers
- Change Events

### New Tabs to Add
1. **Security Findings** - Central place for all security issues
2. **GitHub** - GitHub monitoring findings
3. **Mobile Apps** - Mobile application security
4. **API Assets** - API security findings
5. **DNS Intelligence** - DNS security and records
6. **Email Security** - SPF/DKIM/DMARC status
7. **Reports** - Comprehensive reporting

---

## Tab-by-Tab Implementation Plan

---

## 1. Projects Tab ✅ (COMPLETED)

**Status:** Fully implemented

**Features:**
- Create/Edit/Delete projects
- Notes field
- Asset counts display
- Program type badges

**Missing (Optional Enhancements):**
- [ ] Quick notes editor (inline)
- [ ] Project color coding
- [ ] Project tags
- [ ] Activity timeline per project

---

## 2. Security Findings Tab (NEW - HIGH PRIORITY)

**Purpose:** Central hub for all security findings across all features

**API Endpoints Needed:**
```python
GET /api/findings              # All findings with filters
GET /api/findings/{id}         # Single finding detail
PATCH /api/findings/{id}       # Update status (triaged/false positive/fixed)
GET /api/findings/summary      # Counts by severity/type
```

**UI Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ SECURITY FINDINGS                        [New Scan] [Export]│
├─────────────────────────────────────────────────────────┤
│ Filters: [Severity▼] [Type▼] [Project▼] [Status▼] [Search]│
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 🔴 CRITICAL (3) 🟠 HIGH (15) 🟡 MEDIUM (42)        │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ [🔴] [DNS] AXFR Zone Exposed        [Acme] [Triage] │ │
│ │     ns1.acme.com allows full zone transfer          │ │
│ └─────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ [🔴] [Email] SPF Record Missing      [Acme] [Triage] │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Features:**
- Severity badges with color coding
- Type badges (DNS, Email, TLS, Header, etc.)
- Project assignment
- One-click triage (mark as false positive, acknowledged, fixed)
- Filter by project, severity, type, status
- Bulk actions
- Export to CSV/JSON

**Finding Types to Display:**
- DNS issues (AXFR, open resolver, etc.)
- Email security issues (missing SPF, weak DMARC)
- TLS issues (weak ciphers, expired certs)
- HTTP header issues (missing security headers)
- CORS misconfigurations
- JavaScript vulnerabilities
- GitHub secrets found
- Dangerous functions found
- API security issues

---

## 3. DNS Intelligence Tab (NEW)

**Purpose:** Display all DNS-related findings and records

**API Endpoints Needed:**
```python
GET /api/dns/{domain}/records     # All DNS record types
GET /api/dns/{domain}/dnssec      # DNSSEC analysis
GET /api/dns/{domain}/nameservers # Nameserver security
```

**UI Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ DNS INTELLIGENCE                    [Analyze Domain]      │
├─────────────────────────────────────────────────────────┤
│ Domain: [example.com ▼]                                   │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────┐ ┌────────────────────────┐ │
│ │ 📊 DNS Records          │ │ 🔒 DNSSEC Status       │ │
│ │                         │ │                        │ │
│ │ A: 4 records            │ │ Status: Secure ✅      │ │
│ │ AAAA: 2 records         │ │ NSEC: Disabled ✅      │ │
│ │ MX: 3 records           │ │ DS Records: 2         │ │
│ │ NS: 4 records           │ │ DNSKEY: RSA-2048      │ │
│ │ TXT: 6 records          │ │                        │ │
│ │ SRV: 2 records          │ │ [View Details]         │ │
│ │ CAA: 1 record           │ │                        │ │
│ │ SOA: 1 record           │ │                        │ │
│ │                         │ │                        │ │
│ │ [View All Records]      │ │                        │ │
│ └─────────────────────────┘ └────────────────────────┘ │
│                                                           │
│ ┌─────────────────────────┐ ┌────────────────────────┐ │
│ │ 📧 Email Security       │ │ 🖥️ Nameservers         │ │
│ │                         │ │                        │ │
│ │ SPF: ✅ Valid           │ │ ns1.example.com        │ │
│ │ DKIM: ✅ Enabled        │ │   AXFR: ❌ Secure ✅   │ │
│ │ DMARC: p=reject ✅     │ │   Version: Hidden ✅   │ │
│ │ Score: 95/100           │ │                        │ │
│ │                         │ │ ns2.example.com        │ │
│ │ [View Full Report]      │ │   AXFR: ❌ Secure ✅   │
│ └─────────────────────────┘ └────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Features:**
- Domain selector with autocomplete
- Quick status cards for each category
- Expandable details
- Score indicators
- Historical comparison (changes since last scan)
- Export DNS report

---

## 4. Email Security Tab (NEW)

**Purpose:** Detailed email security analysis and trends

**API Endpoints Needed:**
```python
GET /api/email-security/{domain}    # Full email security report
GET /api/email-security/summary     # All domains summary
GET /api/email-security/trends      # Historical trends
```

**UI Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ EMAIL SECURITY                              [Rescan All]  │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Overall Email Security Posture                       │ │
│ │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │ │
│ │ Domains: 12 | Secure: 8 | At Risk: 3 | Critical: 1   │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ DOMAIN          │ SPF │ DKIM │ DMARC │ SCORE │ ACTIONS│ │
│ │─────────────────┼─────┼──────┼───────┼───────┼────────│ │
│ │ acme.com        │ ✅  │ ✅   │ ✅    │ 95   │ [Details]│ │
│ │ example.com     │ ✅  │ ❌   │ ⚠️    │ 60   │ [Details]│ │
│ │ test.com        │ ❌  │ ❌   │ ❌    │ 20   │ [Details]│ │
│ └─────────────────────────────────────────────────────┘ │
│                                                           │
│ [View All Domains] [Export Report]                       │
└─────────────────────────────────────────────────────────┘
```

**Detail View (when clicking a domain):**
- SPF record with highlighted issues
- DKIM selectors and status
- DMARC policy and RUA/RUF
- Recommendations
- Historical trend graph

---

## 5. GitHub Tab (NEW)

**Purpose:** GitHub monitoring, secret scanning, and code analysis findings

**API Endpoints Needed:**
```python
GET /api/github/repos              # Monitored repositories
GET /api/github/findings          # All findings
POST /api/github/repos             # Add repository
GET /api/github/repos/{id}/details # Repo details
```

**UI Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ GITHUB MONITORING                        [+ Add Repo]     │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 📊 Summary                                          │ │
│ │ Repos: 15 | Secrets Found: 3 | Issues: 127         │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ REPOSITORY                    │ SECRETS │ FUNCTIONS │ │
│ │───────────────────────────────┼─────────┼──────────│ │
│ │ org/repo1                      │ 0       │ 3        │ │
│ │ org/repo2                      │ 1 🔴    │ 0        │ │
│ │ org/repo3                      │ 0       │ 15       │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 🔴 Recent Secret Findings                           │ │
│ │                                                     │ │
│ │ org/repo2:src/auth.py (line 42)                    │ │
│ │   AWS Access Key found                             │ │
│ │   [View] [Mark False Positive]                     │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Features:**
- Repository list with status badges
- Secret findings with context (file, line, code snippet)
- Dangerous function findings
- Commit history
- Scan scheduling
- Integration with Security Findings tab

---

## 6. Mobile Apps Tab (NEW)

**Purpose:** Mobile application security analysis

**API Endpoints Needed:**
```python
GET /api/mobile-apps             # All mobile apps
GET /api/mobile-apps/{id}/details # App details with findings
POST /api/mobile-apps            # Add new app
POST /api/mobile-apps/{id}/scan # Trigger security scan
```

**UI Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ MOBILE APPLICATIONS                      [+ Add App]      │
├─────────────────────────────────────────────────────────┤
│ Filter: [All▼] [Android▼] [iOS▼] [Project: All▼]       │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ ┌─┐ Acme Official (Android)     [v2.3.1]            │ │
│ │ │🟢│ com.acme.mobile                      [Scan]    │ │
│ │ └─┘ 📱 Acme Inc.                          [⚙️]     │ │
│ │                                                     │ │
│ │ Last Scan: 2h ago                                  │ │
│ │ Issues: 🔴 2 Critical  🟡 4 Medium                │ │
│ │                                                     │ │
│ │ ┌─────────────────────────────────────────────┐   │ │
│ │ │ 🔴 Hardcoded API Key in strings.xml          │   │ │
│ │ │ 🟡 Exported Activity: MainActivity          │   │ │
│ │ │ 🔴 Weak SSL Configuration                   │   │ │
│ │ │ 🟡 Debug Mode Enabled                       │   │ │
│ │ └─────────────────────────────────────────────┘   │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Features:**
- App cards with status indicators
- One-click security scan
- Issue list with severity
- Certificate information
- Permission analysis
- Integration with Security Findings tab

---

## 7. API Assets Tab (NEW)

**Purpose:** API security and documentation monitoring

**API Endpoints Needed:**
```python
GET /api/api-assets               # All API assets
GET /api/api-assets/{id}/details  # Asset details with findings
POST /api/api-assets              # Add new asset
POST /api/api-assets/{id}/scan    # Trigger scan
```

**UI Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ API ASSETS                               [+ Add API]     │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 🌐 Production API (REST)                            │ │
│ │ https://api.acme.com                               │ │
│ │                                                     │ │
│ │ Auth: Bearer Token | Public: ✅                    │ │
│ │ Last Scan: 1d ago                                  │ │
│ │ Endpoints: 47 | Issues: 3                          │ │
│ │                                                     │ │
│ │ [🔴] Missing rate limiting headers                │ │
│ │ [🟡] No API key rotation policy                   │ │
│ │ [🔴] Debug endpoints exposed                        │ │
│ │                                                     │ │
│ │ [Scan Now] [View Details] [⚙️]                     │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Features:**
- API asset cards
- Endpoint discovery results
- Security testing results
- Spec file viewer (Swagger/OpenAPI)
- Integration with Security Findings tab

---

## 8. TLS/SSL Security Tab (NEW)

**Purpose:** Certificate and TLS configuration analysis

**API Endpoints Needed:**
```python
GET /api/tls/{host}              # Full TLS analysis
GET /api/tls/summary             # All hosts summary
GET /api/tls/certificates        # Certificate inventory
```

**UI Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ TLS/SSL SECURITY                           [Rescan All]   │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 📊 Overall TLS Posture                               │ │
│ │ Grade A: 45 | B: 12 | C: 8 | D/F: 3                │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ HOST              │ GRADE │ EXPIRES │ ISSUES │ ACTION│ │
│ │───────────────────┼───────┼─────────┼────────┼───────│ │
│ │ api.acme.com      │ A+    │ 45d     │ 0      │ [View]│ │
│ │ www.acme.com      │ C     │ 3d ⚠️   │ 4      │ [View]│ │
│ │ mail.acme.com     │ F     │ ❌ Exp  │ 7      │ [View]│ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Detail View:**
- Certificate chain
- Protocol support (TLS 1.0, 1.1, 1.2, 1.3)
- Cipher suite analysis
- Vulnerability checks (Heartbleed, etc.)
- Recommendations

---

## 9. HTTP Security Tab (NEW)

**Purpose:** HTTP security headers and CORS analysis

**API Endpoints Needed:**
```python
GET /api/http-security/{host}    # Full header analysis
GET /api/http-security/summary   # All hosts summary
GET /api/cors/{host}             # CORS analysis
```

**UI Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ HTTP SECURITY HEADERS                      [Analyze All]  │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ HOST              │ HEADERS │ GRADE │ ISSUES │ VIEW │ │
│ │───────────────────┼─────────┼───────┼────────┼──────│ │
│ │ api.acme.com      │ 8/10   │ A     │ 2      │ [🔍]  │ │
│ │ www.acme.com      │ 5/10   │ C     │ 5      │ [🔍]  │ │
│ │ app.acme.com      │ 3/10   │ D     │ 7      │ [🔍]  │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Detail Modal:**
- Header-by-header analysis
- Missing headers highlighted
- Misconfigured headers
- Recommendations
- CORS configuration

---

## 10. Reports Tab (NEW)

**Purpose:** Comprehensive reporting and exports

**UI Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ REPORTS                                   [Generate New]  │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 📊 Recent Reports                                   │ │
│ │                                                     │ │
│ │ 📄 Acme Corp - Full Security Report      [PDF|HTML]│ │
│ │    Generated: 2 hours ago | Status: Complete       │ │
│ │                                                     │ │
│ │ 📄 Weekly Summary - Week 24               [PDF|HTML]│ │
│ │    Generated: 1 day ago | Status: Complete        │ │
│ │                                                     │ │
│ │ 📄 Domain Enumeration - acme.com          [CSV|JSON]│ │
│ │    Generated: 3 days ago | Status: Complete        │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                           │
│ [Generate Report]                                        │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Report Type: [Full Security ▼]                     │ │
│ │ Scope: [All Projects ▼]                             │ │
│ │ Date Range: [Last 7 days ▼]                         │ │
│ │ Format: [PDF ▼]                                     │ │
│ │                                                     │ │
│ │ [Generate]                                         │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## Component Library

### Reusable Components to Create:

1. **Status Card**
```html
<div class="status-card">
  <div class="status-icon success">✅</div>
  <div class="status-text">SPF Valid</div>
  <div class="status-detail">v=spf1 ip4:1.2.3.4 -all</div>
</div>
```

2. **Severity Badge**
```html
<span class="badge severity-critical">🔴 CRITICAL</span>
<span class="badge severity-high">🟠 HIGH</span>
<span class="badge severity-medium">🟡 MEDIUM</span>
<span class="badge severity-low">🔵 LOW</span>
```

3. **Finding Card**
```html
<div class="finding-card">
  <div class="finding-header">
    <span class="severity-badge">🔴 CRITICAL</span>
    <span class="type-badge">DNS</span>
    <span class="project-badge">Acme Corp</span>
  </div>
  <div class="finding-title">AXFR Zone Exposed</div>
  <div class="finding-description">ns1.acme.com allows full zone transfer</div>
  <div class="finding-actions">
    <button>Triage</button>
    <button>Details</button>
  </div>
</div>
```

4. **Score Indicator**
```html
<div class="score-indicator">
  <div class="score-bar" style="width: 95%"></div>
  <div class="score-label">95/100</div>
</div>
```

---

## Color Scheme

```css
/* Severity Colors */
--critical: #dc3545;  /* Red */
--high: #fd7e14;      /* Orange */
--medium: #ffc107;    /* Yellow */
--low: #0dcaf0;       /* Blue */
--info: #6c757d;      /* Gray */

/* Status Colors */
--success: #198754;   /* Green */
--warning: #ffc107;   /* Yellow */
--danger: #dc3545;    /* Red */

/* Grades */
--grade-a: #198754;
--grade-b: #0dcaf0;
--grade-c: #ffc107;
--grade-d: #fd7e14;
--grade-f: #dc3545;
```

---

## Implementation Priority

### Phase 1: Core Security Views (Week 1)
1. Security Findings Tab ⭐ **MOST IMPORTANT**
2. DNS Intelligence Tab
3. Email Security Tab

### Phase 2: Asset Management (Week 2)
4. GitHub Tab
5. Mobile Apps Tab
6. API Assets Tab

### Phase 3: Deep Analysis (Week 3)
7. TLS/SSL Security Tab
8. HTTP Security Tab

### Phase 4: Reporting (Week 4)
9. Reports Tab
10. Dashboard enhancements

---

## Navigation Reorganization

**Final Navigation Order:**
```
[TARGETS] [PROJECTS] [🔴 FINDINGS] [DNS] [EMAIL] [GITHUB] [MOBILE] [API]
[PROFILES] [PORTS] [SUBDOMAINS] [HEADERS] [CHANGES] [REPORTS]
```

**Grouped by function:**
- **Asset Management:** Targets, Projects
- **Security:** Findings, DNS, Email, TLS, Headers
- **Monitoring:** GitHub, Mobile, API, Ports, Subdomains
- **Configuration:** Profiles
- **History:** Changes
- **Output:** Reports

---

## Quick Access Features

### Global Search Bar
```
🔍 [Search for domains, IPs, findings, projects...]
```
- Search domains
- Search findings
- Search projects
- Jump to any resource

### Quick Actions Dropdown
```
⚡ [Quick Actions ▼]
  ├─ Scan All Targets
  ├─ Generate Report
  ├─ Add Project
  └─ Settings
```

---

## Dashboard Home Enhancements

**Add to main dashboard:**
- Critical findings summary (top 5)
- Email security overview
- TLS/SSL status
- GitHub monitoring status
- Quick action buttons

---

## Implementation Checklist

For each new feature, ensure:

- [ ] API endpoint exists
- [ ] API endpoint returns proper data structure
- [ ] Tab/Menu item exists in navigation
- [ ] Content panel exists
- [ ] JavaScript functions to load data
- [ ] Error handling with user feedback
- [ ] Loading states
- [ ] Empty states
- [ ] Action buttons work
- [ ] Modal/dialogs where needed
- [ ] Integration with Security Findings tab
- [ ] Export functionality
- [ ] Responsive design

---

## File Structure

```
src/web/templates/
├── dashboard.html          # Main dashboard (all tabs)
├── components/
│   ├── finding-card.html   # Reusable finding card
│   ├── status-card.html    # Reusable status card
│   └── score-indicator.html # Reusable score display
└── modals/
    ├── finding-details.html
    ├── dns-details.html
    └── email-details.html
```

---

## Summary

**Total New Tabs:** 9
**Total New Modals:** 15+
**Total New API Endpoints:** 40+

**Key Insight:** The Security Findings tab is the MOST IMPORTANT - it aggregates findings from all other features and provides a single place to triage and manage security issues.

---

**Next Steps:**
1. Implement Security Findings tab first
2. Then implement individual feature tabs
3. Each feature tab feeds into Security Findings
4. Reports tab pulls from everything

