# Projects Tab UI Implementation Instructions

> Step-by-step instructions for adding Projects tab to the dashboard

---

## Overview

Add a "Projects" tab to the dashboard that allows users to:
1. Create new projects (companies)
2. View all projects with asset counts
3. Edit project notes
4. Add mobile apps to projects
5. Add API assets to projects
6. Assign existing domains to projects

---

## Step 1: Add Projects Tab Navigation

**File:** `src/web/templates/dashboard.html`

**Location:** Line ~352 (after the Targets tab, before Profiles tab)

**Action:** Add this line to the nav-tabs:
```html
<li class="nav-item"><a class="nav-link" data-tab="projects" href="#" onclick="showTab('projects',this);return false;"><i class="bi bi-building"></i> Projects <span class="badge bg-secondary ms-1" id="tab-badge-projects">0</span></a></li>
```

---

## Step 2: Add Projects Tab Content Panel

**File:** `src/web/templates/dashboard.html`

**Location:** Find the tab-content div and add a new tab panel after the targets panel

**Template:**
```html
<div class="tab-pane fade" id="tab-projects" role="tabpanel">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h5 class="mb-0"><i class="bi bi-building me-2"></i>Projects / Companies</h5>
    <button class="btn btn-sm btn-primary" onclick="showCreateProjectModal()">
      <i class="bi bi-plus-lg me-1"></i>New Project
    </button>
  </div>

  <!-- Projects Table -->
  <div class="table-responsive">
    <table class="table table-sm table-hover" id="projects-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Domains</th>
          <th>Mobile Apps</th>
          <th>API Assets</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="projects-table-body">
        <!-- Projects will be loaded here -->
      </tbody>
    </table>
  </div>
</div>
```

---

## Step 3: Add Create Project Modal

**File:** `src/web/templates/dashboard.html`

**Location:** Near other modals (find the existing modals section)

**Template:**
```html
<!-- Create/Edit Project Modal -->
<div class="modal fade" id="projectModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="projectModalTitle">New Project</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <form id="projectForm">
          <input type="hidden" id="projectId">
          <div class="mb-3">
            <label class="form-label">Company/Project Name *</label>
            <input type="text" class="form-control form-control-sm" id="projectName" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Description</label>
            <textarea class="form-control form-control-sm" id="projectDescription" rows="2"></textarea>
          </div>
          <div class="row">
            <div class="col-md-6 mb-3">
              <label class="form-label">Program Type</label>
              <select class="form-select form-select-sm" id="projectProgramType">
                <option value="">Private</option>
                <option value="hackerone">HackerOne</option>
                <option value="bugcrowd">Bugcrowd</option>
                <option value="intigriti">Intigriti</option>
                <option value="synack">Synack</option>
                <option value="yeswehack">YesWeHack</option>
              </select>
            </div>
            <div class="col-md-6 mb-3">
              <label class="form-label">Program URL</label>
              <input type="url" class="form-control form-control-sm" id="projectProgramUrl" placeholder="https://">
            </div>
          </div>
          <div class="mb-3">
            <label class="form-label">Notes</label>
            <textarea class="form-control form-control-sm" id="projectNotes" rows="4" placeholder="Project notes, scope details, contacts..."></textarea>
          </div>
        </form>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-sm btn-primary" onclick="saveProject()">Save Project</button>
      </div>
    </div>
  </div>
</div>
```

---

## Step 4: Add JavaScript Functions

**File:** `src/web/templates/dashboard.html`

**Location:** In the <script> section, add these functions:

```javascript
// Projects Tab Functions

let projectModal;

function loadProjects() {
  _mfetch('/api/projects')
    .then(r => r.json())
    .then(projects => {
      const tbody = document.getElementById('projects-table-body');
      tbody.innerHTML = '';
      document.getElementById('tab-badge-projects').textContent = projects.length;

      projects.forEach(p => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>
            <div class="fw-bold">${escapeHtml(p.name)}</div>
            ${p.description ? `<small class="text-muted">${escapeHtml(p.description)}</small>` : ''}
          </td>
          <td>${p.program_type ? `<span class="badge bg-info">${escapeHtml(p.program_type)}</span>` : '<span class="text-muted">Private</span>'}</td>
          <td>${p.stats.domains}</td>
          <td>${p.stats.mobile_apps}</td>
          <td>${p.stats.api_assets}</td>
          <td>${p.is_active ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-secondary">Inactive</span>'}</td>
          <td>
            <div class="btn-group btn-group-sm">
              <button class="btn btn-outline-primary" onclick="editProject(${p.id})" title="Edit">
                <i class="bi bi-pencil"></i>
              </button>
              <button class="btn btn-outline-info" onclick="viewProjectDetails(${p.id})" title="Details">
                <i class="bi bi-list-ul"></i>
              </button>
              <button class="btn btn-outline-danger" onclick="deleteProject(${p.id}, '${escapeHtml(p.name)}')" title="Delete">
                <i class="bi bi-trash"></i>
              </button>
            </div>
          </td>
        `;
        tbody.appendChild(row);
      });
    })
    .catch(err => showToast('Failed to load projects: ' + err.message, 'danger'));
}

function showCreateProjectModal() {
  document.getElementById('projectModalTitle').textContent = 'New Project';
  document.getElementById('projectForm').reset();
  document.getElementById('projectId').value = '';
  if (!projectModal) projectModal = new bootstrap.Modal(document.getElementById('projectModal'));
  projectModal.show();
}

function editProject(id) {
  _mfetch(`/api/projects/${id}`)
    .then(r => r.json())
    .then(p => {
      document.getElementById('projectModalTitle').textContent = 'Edit Project';
      document.getElementById('projectId').value = p.id;
      document.getElementById('projectName').value = p.name;
      document.getElementById('projectDescription').value = p.description || '';
      document.getElementById('projectProgramType').value = p.program_type || '';
      document.getElementById('projectProgramUrl').value = p.program_url || '';
      document.getElementById('projectNotes').value = p.notes || '';
      if (!projectModal) projectModal = new bootstrap.Modal(document.getElementById('projectModal'));
      projectModal.show();
    })
    .catch(err => showToast('Failed to load project: ' + err.message, 'danger'));
}

function saveProject() {
  const id = document.getElementById('projectId').value;
  const data = {
    name: document.getElementById('projectName').value,
    description: document.getElementById('projectDescription').value,
    program_type: document.getElementById('projectProgramType').value,
    program_url: document.getElementById('projectProgramUrl').value,
    notes: document.getElementById('projectNotes').value,
  };

  if (!data.name.trim()) {
    showToast('Project name is required', 'warning');
    return;
  }

  const url = id ? `/api/projects/${id}` : '/api/projects';
  const method = id ? 'PATCH' : 'POST';

  _mfetch(url, {
    method: method,
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
  })
  .then(r => r.json())
  .then(() => {
    projectModal.hide();
    loadProjects();
    showToast('Project saved successfully', 'success');
  })
  .catch(err => showToast('Failed to save project: ' + err.message, 'danger'));
}

function deleteProject(id, name) {
  if (!confirm(`Delete project "${name}" and all its assets?\n\nThis will also delete all mobile apps and API assets associated with this project. Domains will NOT be deleted.`)) {
    return;
  }

  _mfetch(`/api/projects/${id}`, {method: 'DELETE'})
  .then(() => {
    loadProjects();
    showToast('Project deleted successfully', 'success');
  })
  .catch(err => showToast('Failed to delete project: ' + err.message, 'danger'));
}

function viewProjectDetails(id) {
  // Show project details with tabs for domains, mobile apps, API assets
  _mfetch(`/api/projects/${id}`)
    .then(r => r.json())
    .then(details => {
      // Create or update a details modal/view
      console.log(details);
      // TODO: Implement detailed view
    })
    .catch(err => showToast('Failed to load project details: ' + err.message, 'danger'));
}

// Add to showTab function
function showTab(name, el) {
  // ... existing code ...
  if (name === 'projects') {
    loadProjects();
  }
  // ... existing code ...
}
```

---

## Step 5: Update showTab Function

**File:** `src/web/templates/dashboard.html`

**Action:** Update the existing `showTab` function to include projects loading:

Find the showTab function and add the projects case:
```javascript
if (name === 'projects') {
  loadProjects();
}
```

---

## Testing Checklist

- [ ] Projects tab appears in navigation
- [ ] Clicking Projects tab shows empty state or list of projects
- [ ] New Project modal opens correctly
- [ ] Creating a project works and shows in the list
- [ ] Editing a project loads existing data
- [ ] Saving edits updates the project
- [ ] Deleting a project requires confirmation
- [ ] Delete confirmation message mentions assets will be deleted
- [ ] Badge count updates correctly

---

## Next Steps After This

1. Add Mobile Apps management UI (within project details)
2. Add API Assets management UI (within project details)
3. Add domain assignment to projects
4. Add notes quick-edit functionality

---

**Status:** Ready to implement
**Estimated Time:** 1-2 hours
