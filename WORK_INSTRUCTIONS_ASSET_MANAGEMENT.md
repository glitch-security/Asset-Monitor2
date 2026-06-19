# Asset Management UI Implementation Instructions

> For managing mobile apps and API assets within projects

---

## Overview

Add detailed project view with tabs for:
1. Project details and notes
2. Domains assigned to this project
3. Mobile apps (add/edit/delete)
4. API assets (add/edit/delete)

---

## Step 1: Create Project Details Modal

**File:** `src/web/templates/dashboard.html`

**Location:** After the Project modal (after `</div>` of projectModal)

**Template:**
```html
<!-- Project Details Modal -->
<div class="modal fade" id="projectDetailsModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dark modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-building"></i> <span id="pd-project-name">Project Details</span></h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body p-0">
        <!-- Info header -->
        <div class="p-3 border-bottom" style="border-color:var(--border) !important;">
          <div class="row g-2">
            <div class="col-md-8">
              <h6 class="mb-1" id="pd-project-full-name">Project Name</h6>
              <small class="text-muted" id="pd-project-description">Description</small>
            </div>
            <div class="col-md-4 text-end">
              <span class="badge bg-info" id="pd-project-type">Private</span>
              <a href="#" id="pd-project-link" target="_blank" class="btn btn-sm btn-link" style="display:none;">
                <i class="bi bi-box-arrow-up-right"></i> Program Page
              </a>
            </div>
          </div>
        </div>

        <!-- Tabs -->
        <ul class="nav nav-tabs px-3 pt-2" style="border-bottom:1px solid var(--border);">
          <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#pd-domains">Domains</a></li>
          <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#pd-mobile">Mobile Apps</a></li>
          <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#pd-api">API Assets</a></li>
          <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#pd-notes">Notes</a></li>
        </ul>

        <div class="tab-content p-3">
          <!-- Domains tab -->
          <div class="tab-pane fade show active" id="pd-domains">
            <div class="d-flex justify-content-between mb-2">
              <small class="text-muted">Domains assigned to this project</small>
              <button class="btn btn-sm btn-outline-primary" onclick="showAssignDomainModal()">
                <i class="bi bi-plus-lg"></i> Assign Domain
              </button>
            </div>
            <div class="table-responsive">
              <table class="table table-sm">
                <thead><tr><th>Domain</th><th>Scope</th><th>Subdomains</th><th>Actions</th></tr></thead>
                <tbody id="pd-domains-body"></tbody>
              </table>
            </div>
          </div>

          <!-- Mobile Apps tab -->
          <div class="tab-pane fade" id="pd-mobile">
            <div class="d-flex justify-content-between mb-2">
              <small class="text-muted">Mobile applications</small>
              <button class="btn btn-sm btn-outline-primary" onclick="showAddMobileAppModal()">
                <i class="bi bi-plus-lg"></i> Add Mobile App
              </button>
            </div>
            <div class="table-responsive">
              <table class="table table-sm">
                <thead><tr><th>Name</th><th>Platform</th><th>Package</th><th>Status</th><th>Actions</th></tr></thead>
                <tbody id="pd-mobile-body"></tbody>
              </table>
            </div>
          </div>

          <!-- API Assets tab -->
          <div class="tab-pane fade" id="pd-api">
            <div class="d-flex justify-content-between mb-2">
              <small class="text-muted">API endpoints and documentation</small>
              <button class="btn btn-sm btn-outline-primary" onclick="showAddApiAssetModal()">
                <i class="bi bi-plus-lg"></i> Add API Asset
              </button>
            </div>
            <div class="table-responsive">
              <table class="table table-sm">
                <thead><tr><th>Name</th><th>Type</th><th>Base URL</th><th>Auth</th><th>Actions</th></tr></thead>
                <tbody id="pd-api-body"></tbody>
              </table>
            </div>
          </div>

          <!-- Notes tab -->
          <div class="tab-pane fade" id="pd-notes">
            <div class="mb-2">
              <button class="btn btn-sm btn-primary" onclick="editProjectNotes()">
                <i class="bi bi-pencil"></i> Edit Notes
              </button>
            </div>
            <div id="pd-notes-content" class="p-3 bg-dark rounded" style="min-height:150px;white-space:pre-wrap;"></div>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
```

---

## Step 2: Add Mobile App Modal

**Location:** After Project Details modal

```html
<!-- Add/Edit Mobile App Modal -->
<div class="modal fade" id="mobileAppModal" tabindex="-1">
  <div class="modal-dialog modal-dark">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="mobile-app-modal-title">
          <i class="bi bi-phone"></i> Add Mobile App
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div class="row g-3">
          <div class="col-12">
            <label class="form-label">APP NAME *</label>
            <input type="text" class="form-control" id="ma-name" required>
          </div>
          <div class="col-md-6">
            <label class="form-label">PLATFORM *</label>
            <select class="form-select" id="ma-platform">
              <option value="android">Android</option>
              <option value="ios">iOS</option>
            </select>
          </div>
          <div class="col-md-6">
            <label class="form-label">PACKAGE NAME</label>
            <input type="text" class="form-control" id="ma-package" placeholder="com.example.app">
          </div>
          <div class="col-12">
            <label class="form-label">APP STORE URL</label>
            <input type="url" class="form-control" id="ma-store-url" placeholder="https://">
          </div>
          <div class="col-12">
            <label class="form-label">STORE ID</label>
            <input type="text" class="form-control" id="ma-store-id" placeholder="Play Store / App Store ID">
          </div>
          <div class="col-12">
            <label class="form-label">NOTES</label>
            <textarea class="form-control" id="ma-notes" rows="3"></textarea>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-primary btn-sm" onclick="submitMobileApp()">Save App</button>
      </div>
    </div>
  </div>
</div>
```

---

## Step 3: Add API Asset Modal

```html
<!-- Add/Edit API Asset Modal -->
<div class="modal fade" id="apiAssetModal" tabindex="-1">
  <div class="modal-dialog modal-dark">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="api-asset-modal-title">
          <i class="bi bi-cloud"></i> Add API Asset
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div class="row g-3">
          <div class="col-12">
            <label class="form-label">NAME *</label>
            <input type="text" class="form-control" id="aa-name" placeholder="e.g. Production API" required>
          </div>
          <div class="col-12">
            <label class="form-label">BASE URL *</label>
            <input type="url" class="form-control" id="aa-base-url" placeholder="https://api.example.com" required>
          </div>
          <div class="col-md-6">
            <label class="form-label">API TYPE *</label>
            <select class="form-select" id="aa-type">
              <option value="rest">REST</option>
              <option value="graphql">GraphQL</option>
              <option value="grpc">gRPC</option>
              <option value="soap">SOAP</option>
            </select>
          </div>
          <div class="col-md-6">
            <label class="form-label">AUTHENTICATION</label>
            <select class="form-select" id="aa-auth">
              <option value="none">None</option>
              <option value="bearer">Bearer Token</option>
              <option value="api_key">API Key</option>
              <option value="oauth">OAuth</option>
              <option value="basic">Basic Auth</option>
            </select>
          </div>
          <div class="col-12">
            <label class="form-label">SPECIFICATION URL</label>
            <input type="url" class="form-control" id="aa-spec-url" placeholder="swagger.json or openapi.yaml URL">
          </div>
          <div class="col-12">
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="aa-public" checked>
              <label class="form-check-label" for="aa-public">Publicly accessible</label>
            </div>
          </div>
          <div class="col-12">
            <label class="form-label">NOTES</label>
            <textarea class="form-control" id="aa-notes" rows="3"></textarea>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-primary btn-sm" onclick="submitApiAsset()">Save Asset</button>
      </div>
    </div>
  </div>
</div>
```

---

## Step 4: Add JavaScript Functions

```javascript
// Project Details
let _projectDetailsModal = null;
let _currentProjectId = null;

async function viewProjectDetails(id) {
  try {
    const r = await _mfetch(`/api/projects/${id}`);
    const p = await r.json();
    _currentProjectId = id;

    // Update header
    document.getElementById('pd-project-name').textContent = p.name;
    document.getElementById('pd-project-full-name').textContent = p.name;
    document.getElementById('pd-project-description').textContent = p.description || 'No description';
    document.getElementById('pd-project-type').textContent = p.program_type || 'Private';
    document.getElementById('pd-project-type').className = 'badge ' + (p.program_type ? 'bg-info' : 'bg-secondary');

    const linkEl = document.getElementById('pd-project-link');
    if (p.program_url) {
      linkEl.href = p.program_url;
      linkEl.style.display = 'inline-block';
    } else {
      linkEl.style.display = 'none';
    }

    document.getElementById('pd-notes-content').textContent = p.notes || 'No notes yet. Click Edit to add notes.';

    // Load tabs
    await loadProjectDomains(id);
    await loadProjectMobileApps(id);
    await loadProjectApiAssets(id);

    if (!_projectDetailsModal) _projectDetailsModal = new bootstrap.Modal(document.getElementById('projectDetailsModal'));
    _projectDetailsModal.show();
  } catch(e) {
    showToast('Failed to load project details: ' + e.message, 'danger');
  }
}

async function loadProjectDomains(projectId) {
  try {
    const r = await _mfetch(`/api/projects/${projectId}`);
    const p = await r.json();
    const tbody = document.getElementById('pd-domains-body');
    tbody.innerHTML = '';

    if (!p.domains || p.domains.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No domains assigned</td></tr>';
      return;
    }

    p.domains.forEach(d => {
      const scopeLabels = {in_scope: 'In Scope', out_of_scope: 'Out of Scope', unknown: 'Unknown'};
      const scopeBadge = `<span class="badge bg-${d.scope_type === 'in_scope' ? 'success' : d.scope_type === 'out_of_scope' ? 'danger' : 'secondary'}">${scopeLabels[d.scope_type] || 'Unknown'}</span>`;

      tbody.innerHTML += `
        <tr>
          <td><a href="#" onclick="showDomainDetails(${d.id})">${escapeHtml(d.domain)}</a></td>
          <td>${scopeBadge}</td>
          <td>${d.subdomain_count || 0}</td>
          <td>
            <button class="btn btn-sm btn-outline-danger" onclick="unassignDomain(${d.id}, '${escapeHtml(d.domain).replace(/'/g, "\\'")}')">
              <i class="bi bi-x-lg"></i>
            </button>
          </td>
        </tr>
      `;
    });
  } catch(e) {
    console.error('project domains', e);
  }
}

async function loadProjectMobileApps(projectId) {
  try {
    const r = await _mfetch(`/api/projects/${projectId}/mobile-apps`);
    const apps = await r.json();
    const tbody = document.getElementById('pd-mobile-body');
    tbody.innerHTML = '';

    if (apps.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No mobile apps</td></tr>';
      return;
    }

    apps.forEach(app => {
      const platformBadge = app.platform === 'android'
        ? '<span class="badge bg-success">Android</span>'
        : '<span class="badge bg-info">iOS</span>';

      tbody.innerHTML += `
        <tr>
          <td>${escapeHtml(app.name)}</td>
          <td>${platformBadge}</td>
          <td><small class="text-muted">${escapeHtml(app.package_name || '-')}</small></td>
          <td>${app.is_active ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-secondary">Inactive</span>'}</td>
          <td>
            <button class="btn btn-sm btn-outline-primary" onclick="editMobileApp(${app.id})"><i class="bi bi-pencil"></i></button>
            <button class="btn btn-sm btn-outline-danger" onclick="deleteMobileApp(${app.id})"><i class="bi bi-trash"></i></button>
          </td>
        </tr>
      `;
    });
  } catch(e) {
    console.error('mobile apps', e);
  }
}

async function loadProjectApiAssets(projectId) {
  try {
    const r = await _mfetch(`/api/projects/${projectId}/api-assets`);
    const assets = await r.json();
    const tbody = document.getElementById('pd-api-body');
    tbody.innerHTML = '';

    if (assets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No API assets</td></tr>';
      return;
    }

    assets.forEach(asset => {
      const typeBadge = `<span class="badge bg-${asset.api_type === 'graphql' ? 'danger' : asset.api_type === 'rest' ? 'primary' : 'info'}">${asset.api_type.toUpperCase()}</span>`;

      tbody.innerHTML += `
        <tr>
          <td>${escapeHtml(asset.name)}</td>
          <td>${typeBadge}</td>
          <td><small class="text-muted">${escapeHtml(asset.base_url)}</small></td>
          <td><small>${escapeHtml(asset.authentication || 'None')}</small></td>
          <td>
            <button class="btn btn-sm btn-outline-primary" onclick="editApiAsset(${asset.id})"><i class="bi bi-pencil"></i></button>
            <button class="btn btn-sm btn-outline-danger" onclick="deleteApiAsset(${asset.id})"><i class="bi bi-trash"></i></button>
          </td>
        </tr>
      `;
    });
  } catch(e) {
    console.error('api assets', e);
  }
}

// Mobile App Management
let _mobileAppModal = null;
let _editingMobileAppId = null;

function showAddMobileAppModal() {
  _editingMobileAppId = null;
  document.getElementById('mobile-app-modal-title').innerHTML = '<i class="bi bi-phone"></i> Add Mobile App';
  document.getElementById('ma-name').value = '';
  document.getElementById('ma-platform').value = 'android';
  document.getElementById('ma-package').value = '';
  document.getElementById('ma-store-url').value = '';
  document.getElementById('ma-store-id').value = '';
  document.getElementById('ma-notes').value = '';
  if (!_mobileAppModal) _mobileAppModal = new bootstrap.Modal(document.getElementById('mobileAppModal'));
  _mobileAppModal.show();
}

async function editMobileApp(id) {
  // Load app details and show modal
  // TODO: Implement
}

async function submitMobileApp() {
  const name = document.getElementById('ma-name').value.trim();
  const platform = document.getElementById('ma-platform').value;
  const package = document.getElementById('ma-package').value.trim();
  const storeUrl = document.getElementById('ma-store-url').value.trim();
  const storeId = document.getElementById('ma-store-id').value.trim();
  const notes = document.getElementById('ma-notes').value.trim();

  if (!name) {
    showToast('App name is required', 'warning');
    return;
  }

  const data = { name, platform, package_name: package || null, app_store_url: storeUrl || null, store_id: storeId || null, notes: notes || null };

  try {
    const url = _editingMobileAppId ? `/api/projects/${_currentProjectId}/mobile-apps/${_editingMobileAppId}` : `/api/projects/${_currentProjectId}/mobile-apps`;
    const method = _editingMobileAppId ? 'PATCH' : 'POST';
    const r = await _mfetch(url, { method, body: JSON.stringify(data) });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    _mobileAppModal.hide();
    showToast('Mobile app saved', 'success');
    await loadProjectMobileApps(_currentProjectId);
  } catch(e) {
    showToast('Failed to save mobile app: ' + e.message, 'danger');
  }
}

async function deleteMobileApp(id) {
  if (!confirm('Delete this mobile app?')) return;
  try {
    const r = await _mfetch(`/api/mobile-apps/${id}`, { method: 'DELETE' });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    showToast('Mobile app deleted', 'success');
    await loadProjectMobileApps(_currentProjectId);
  } catch(e) {
    showToast('Failed to delete: ' + e.message, 'danger');
  }
}

// API Asset Management
let _apiAssetModal = null;
let _editingApiAssetId = null;

function showAddApiAssetModal() {
  _editingApiAssetId = null;
  document.getElementById('api-asset-modal-title').innerHTML = '<i class="bi bi-cloud"></i> Add API Asset';
  document.getElementById('aa-name').value = '';
  document.getElementById('aa-base-url').value = '';
  document.getElementById('aa-type').value = 'rest';
  document.getElementById('aa-auth').value = 'none';
  document.getElementById('aa-spec-url').value = '';
  document.getElementById('aa-public').checked = true;
  document.getElementById('aa-notes').value = '';
  if (!_apiAssetModal) _apiAssetModal = new bootstrap.Modal(document.getElementById('apiAssetModal'));
  _apiAssetModal.show();
}

async function editApiAsset(id) {
  // Load asset details and show modal
  // TODO: Implement
}

async function submitApiAsset() {
  const name = document.getElementById('aa-name').value.trim();
  const baseUrl = document.getElementById('aa-base-url').value.trim();
  const type = document.getElementById('aa-type').value;
  const auth = document.getElementById('aa-auth').value;
  const specUrl = document.getElementById('aa-spec-url').value.trim();
  const isPublic = document.getElementById('aa-public').checked;
  const notes = document.getElementById('aa-notes').value.trim();

  if (!name || !baseUrl) {
    showToast('Name and Base URL are required', 'warning');
    return;
  }

  const data = { name, base_url: baseUrl, api_type: type, authentication: auth, specification_url: specUrl || null, is_public: isPublic, notes: notes || null };

  try {
    const url = _editingApiAssetId ? `/api/api-assets/${_editingApiAssetId}` : `/api/projects/${_currentProjectId}/api-assets`;
    const method = _editingApiAssetId ? 'PATCH' : 'POST';
    const r = await _mfetch(url, { method, body: JSON.stringify(data) });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    _apiAssetModal.hide();
    showToast('API asset saved', 'success');
    await loadProjectApiAssets(_currentProjectId);
  } catch(e) {
    showToast('Failed to save API asset: ' + e.message, 'danger');
  }
}

async function deleteApiAsset(id) {
  if (!confirm('Delete this API asset?')) return;
  try {
    const r = await _mfetch(`/api/api-assets/${id}`, { method: 'DELETE' });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    showToast('API asset deleted', 'success');
    await loadProjectApiAssets(_currentProjectId);
  } catch(e) {
    showToast('Failed to delete: ' + e.message, 'danger');
  }
}
```

---

## Testing Checklist

- [ ] Project Details modal opens
- [ ] All tabs load correctly
- [ ] Mobile app can be added
- [ ] API asset can be added
- [ ] Items can be deleted
- [ ] Notes display correctly

---

**Status:** Ready to implement
**Estimated Time:** 2-3 hours
