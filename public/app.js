const POLL_MS = 15000;
let currentFilter = 'all';
let currentUser = null;
let scanConfigsCache = null;
const deviceScanTimers = {}; // deviceId -> intervalId

const el = {
  alertList: document.getElementById('alertList'),
  lastUpdated: document.getElementById('lastUpdated'),
  countCritical: document.getElementById('countCritical'),
  countHigh: document.getElementById('countHigh'),
  countMedium: document.getElementById('countMedium'),
  refreshBtn: document.getElementById('refreshBtn'),
  healthDot: document.querySelector('.health .dot'),
  userChip: document.getElementById('userChip'),
  logoutBtn: document.getElementById('logoutBtn'),
  tabs: document.getElementById('tabs'),
  addDeviceBtn: document.getElementById('addDeviceBtn'),
  addDeviceFormWrap: document.getElementById('addDeviceFormWrap'),
  addDeviceForm: document.getElementById('addDeviceForm'),
  cancelAddDevice: document.getElementById('cancelAddDevice'),
  addDeviceWarnings: document.getElementById('addDeviceWarnings'),
  deviceList: document.getElementById('deviceList')
};

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function fmtTime(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleString();
}

// ---------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------
async function requireAuthOrRedirect() {
  try {
    const res = await fetch('/api/auth/me');
    const data = await res.json();
    if (!data.ok) throw new Error('not authenticated');
    currentUser = data.user;
  } catch (err) {
    window.location.href = '/login.html';
    throw err;
  }
}

function applyRoleVisibility() {
  const isAdmin = currentUser && currentUser.role === 'admin';
  document.querySelectorAll('[data-admin-only]').forEach((node) => {
    node.hidden = !isAdmin;
  });
  el.userChip.hidden = false;
  el.userChip.textContent = `${currentUser.username} (${currentUser.role})`;
}

el.logoutBtn.addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  window.location.href = '/login.html';
});

// ---------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------
el.tabs.addEventListener('click', (e) => {
  const btn = e.target.closest('.tab');
  if (!btn) return;
  const tabName = btn.dataset.tab;

  document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
  btn.classList.add('active');

  document.querySelectorAll('.panel').forEach((p) => {
    p.hidden = p.id !== `panel-${tabName}`;
  });

  if (tabName === 'devices') loadDevices();
});

// ---------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------
function renderAlerts(alerts) {
  const counts = { critical: 0, high: 0, medium: 0 };
  alerts.forEach((a) => {
    if (counts[a.severity] != null) counts[a.severity]++;
  });
  el.countCritical.textContent = counts.critical;
  el.countHigh.textContent = counts.high;
  el.countMedium.textContent = counts.medium;

  const filtered = currentFilter === 'all' ? alerts : alerts.filter((a) => a.severity === currentFilter);

  el.alertList.innerHTML = '';

  if (filtered.length === 0) {
    el.alertList.innerHTML = '<div class="empty-state">No alerts in this range. Good sign.</div>';
    return;
  }

  for (const a of filtered) {
    const card = document.createElement('div');
    card.className = `alert-card ${a.severity}`;
    card.innerHTML = `
      <div class="sev-badge ${a.severity}">${a.severity}</div>
      <div class="alert-main">
        <div class="alert-desc">${escapeHtml(a.description)}</div>
        <div class="alert-meta">
          <span>agent: ${escapeHtml(a.agent || 'n/a')}</span>
          <span>rule: ${escapeHtml(String(a.ruleId || ''))}</span>
          <span>${fmtTime(a.timestamp)}</span>
        </div>
      </div>
      <div class="alert-level">level ${a.level}</div>
    `;
    el.alertList.appendChild(card);
  }
}

async function loadAlerts() {
  try {
    const res = await fetch('/api/alerts');
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Unknown error');
    renderAlerts(data.alerts);
    el.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    el.healthDot.classList.add('ok');
    el.healthDot.classList.remove('err');
  } catch (err) {
    el.alertList.innerHTML = `<div class="empty-state">Couldn't load alerts: ${escapeHtml(err.message)}</div>`;
    el.healthDot.classList.add('err');
    el.healthDot.classList.remove('ok');
  }
}

document.getElementById('filters').addEventListener('click', (e) => {
  const btn = e.target.closest('.filter-chip');
  if (!btn) return;
  document.querySelectorAll('.filter-chip').forEach((c) => c.classList.remove('active'));
  btn.classList.add('active');
  currentFilter = btn.dataset.filter;
  loadAlerts();
});
el.refreshBtn.addEventListener('click', loadAlerts);

// ---------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------
async function getScanConfigs() {
  if (scanConfigsCache) return scanConfigsCache;
  const res = await fetch('/api/openvas/configs');
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || 'Could not load scan types');
  scanConfigsCache = data.configs;
  return scanConfigsCache;
}

function wazuhBadge(device) {
  if (device.wazuh && device.wazuh.registered) {
    return `<span class="badge badge-ok">Wazuh: registered</span>`;
  }
  if (device.wazuh && device.wazuh.error) {
    return `<span class="badge badge-err" title="${escapeHtml(device.wazuh.error)}">Wazuh: failed</span>`;
  }
  return `<span class="badge badge-muted">Wazuh: not registered</span>`;
}

function openvasBadge(device) {
  if (device.openvas && device.openvas.targetId) {
    return `<span class="badge badge-ok">OpenVAS: target ready</span>`;
  }
  if (device.openvas && device.openvas.error) {
    return `<span class="badge badge-err" title="${escapeHtml(device.openvas.error)}">OpenVAS: failed</span>`;
  }
  return `<span class="badge badge-muted">OpenVAS: no target</span>`;
}

async function renderDevices(devices) {
  const isAdmin = currentUser && currentUser.role === 'admin';
  el.deviceList.innerHTML = '';

  if (devices.length === 0) {
    el.deviceList.innerHTML = '<div class="empty-state">No devices yet. Add one to get started.</div>';
    return;
  }

  let configs = [];
  if (isAdmin) {
    try {
      configs = await getScanConfigs();
    } catch (err) {
      configs = [];
    }
  }

  for (const d of devices) {
    const card = document.createElement('div');
    card.className = 'device-card';
    card.dataset.deviceId = d.id;

    const scanOptions = configs
      .map((c) => `<option value="${escapeHtml(c.id)}">${escapeHtml(c.name)}</option>`)
      .join('');

    const keyNote =
      d.wazuh && d.wazuh.agentKey
        ? `<div class="agent-key-note">Enrollment key generated. Run the Wazuh agent installer on <strong>${escapeHtml(
            d.ip
          )}</strong> using agent id <code>${escapeHtml(d.wazuh.agentId)}</code> to finish connecting it.</div>`
        : '';

    card.innerHTML = `
      <div class="device-main">
        <div class="device-name">${escapeHtml(d.name)}</div>
        <div class="device-meta">
          <span>${escapeHtml(d.ip)}</span>
          ${d.os ? `<span>${escapeHtml(d.os)}</span>` : ''}
        </div>
        <div class="device-badges">
          ${wazuhBadge(d)}
          ${openvasBadge(d)}
        </div>
        ${keyNote}
        <div class="device-scan-status" data-role="scan-status">
          ${d.openvas && d.openvas.lastScanStatus ? `Last scan: ${escapeHtml(d.openvas.lastScanStatus)}` : ''}
        </div>
      </div>
      <div class="device-actions" ${isAdmin ? '' : 'hidden'}>
        <select class="scan-type-select" ${configs.length ? '' : 'disabled'}>
          ${configs.length ? scanOptions : '<option>No scan types available</option>'}
        </select>
        <button class="btn btn-primary btn-scan">▶ Scan</button>
        <button class="btn btn-ghost btn-delete">Delete</button>
      </div>
    `;

    el.deviceList.appendChild(card);

    if (isAdmin) {
      card.querySelector('.btn-scan').addEventListener('click', () => startDeviceScan(d.id, card));
      card.querySelector('.btn-delete').addEventListener('click', () => deleteDevice(d.id));
    }

    // Resume polling if a scan was already in flight.
    if (d.openvas && d.openvas.lastTaskId && !isScanTerminal(d.openvas.lastScanStatus)) {
      pollDeviceScan(d.id, card);
    }
  }
}

function isScanTerminal(status) {
  return !status || ['Done', 'Stopped', 'Interrupted', 'Task not found'].indexOf(status) !== -1;
}


const SEV_COLORS = {
  Critical: '#f85149',
  High: '#f0883e',
  Medium: '#d29922',
  Low: '#3fb950',
  Log: '#8b98a5'
};

function renderScanResult(card, data) {
  const box = card.querySelector('[data-role="scan-result"]');
  if (!box) return;
  if (!data || data.status !== 'Done' || !data.lastReportId) {
    box.innerHTML = '';
    return;
  }

  const label = data.severityLabel || 'Log';
  const score = data.severity != null ? data.severity : 'n/a';
  const c = data.counts || { hole: 0, warning: 0, info: 0, log: 0 };

  box.innerHTML = `
    <div class="scan-result-row">
      <span class="scan-sev" style="background:${SEV_COLORS[label] || SEV_COLORS.Log}">
        Severity: ${escapeHtml(label)} (${escapeHtml(String(score))})
      </span>
      <span class="scan-counts">High: ${c.hole} · Medium: ${c.warning} · Low: ${c.info} · Log: ${c.log}</span>
      ${
        data.reportUrl
          ? `<a href="${escapeHtml(data.reportUrl)}" target="_blank" rel="noopener">Open full report</a>`
          : ''
      }
    </div>
  `;
}

async function loadScanResult(id, card) {
  try {
    const res = await fetch(`/api/devices/${id}/scan/status`);
    const data = await res.json();
    if (data.ok && data.found) renderScanResult(card, data);
  } catch (err) {
    /* ignore, the result box just stays empty */
  }
}



async function loadDevices() {
  try {
    const res = await fetch('/api/devices');
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Unknown error');
    await renderDevices(data.devices);
  } catch (err) {
    el.deviceList.innerHTML = `<div class="empty-state">Couldn't load devices: ${escapeHtml(err.message)}</div>`;
  }
}

el.addDeviceBtn.addEventListener('click', () => {
  el.addDeviceFormWrap.hidden = !el.addDeviceFormWrap.hidden;
});
el.cancelAddDevice.addEventListener('click', () => {
  el.addDeviceFormWrap.hidden = true;
  el.addDeviceForm.reset();
});

el.addDeviceForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('devName').value.trim();
  const ip = document.getElementById('devIp').value.trim();
  const os = document.getElementById('devOs').value.trim();

  el.addDeviceWarnings.hidden = true;
  const submitBtn = el.addDeviceForm.querySelector('button[type="submit"]');
  submitBtn.disabled = true;

  try {
    const res = await fetch('/api/devices', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, ip, os })
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Unknown error');

    if (data.warnings && data.warnings.length) {
      el.addDeviceWarnings.hidden = false;
      el.addDeviceWarnings.innerHTML = data.warnings.map((w) => `<div>${escapeHtml(w)}</div>`).join('');
    } else {
      el.addDeviceFormWrap.hidden = true;
    }
    el.addDeviceForm.reset();
    loadDevices();
  } catch (err) {
    el.addDeviceWarnings.hidden = false;
    el.addDeviceWarnings.innerHTML = `<div>${escapeHtml(err.message)}</div>`;
  } finally {
    submitBtn.disabled = false;
  }
});

async function deleteDevice(id) {
  if (!confirm('Delete this device? This also removes its Wazuh agent entry and OpenVAS target.')) return;
  try {
    const res = await fetch(`/api/devices/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Unknown error');
    if (deviceScanTimers[id]) {
      clearInterval(deviceScanTimers[id]);
      delete deviceScanTimers[id];
    }
    loadDevices();
  } catch (err) {
    alert(`Couldn't delete device: ${err.message}`);
  }
}

async function startDeviceScan(id, card) {
  const select = card.querySelector('.scan-type-select');
  const configId = select && select.value;
  const statusEl = card.querySelector('[data-role="scan-status"]');
  const scanBtn = card.querySelector('.btn-scan');

  if (!configId) {
    statusEl.textContent = 'No scan type selected.';
    return;
  }

  scanBtn.disabled = true;
  statusEl.textContent = 'Starting scan…';

  try {
    const res = await fetch(`/api/devices/${id}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ configId })
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Unknown error');
    pollDeviceScan(id, card);
  } catch (err) {
    statusEl.textContent = `Error: ${err.message}`;
    scanBtn.disabled = false;
  }
}

function pollDeviceScan(id, card) {
  if (deviceScanTimers[id]) clearInterval(deviceScanTimers[id]);

  const statusEl = card.querySelector('[data-role="scan-status"]');
  const scanBtn = card.querySelector('.btn-scan');
  if (scanBtn) scanBtn.disabled = true;

  const tick = async () => {
    try {
      const res = await fetch(`/api/devices/${id}/scan/status`);
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Unknown error');

      if (!data.found) {
        statusEl.textContent = 'No scan found.';
        clearInterval(deviceScanTimers[id]);
        delete deviceScanTimers[id];
        if (scanBtn) scanBtn.disabled = false;
        return;
      }

      statusEl.textContent = `Last scan: ${data.status} (${data.progress != null ? data.progress : 0}%)`;

      if (isScanTerminal(data.status)) {
        clearInterval(deviceScanTimers[id]);
        delete deviceScanTimers[id];
        if (scanBtn) scanBtn.disabled = false;
        loadAlerts();
      }
    } catch (err) {
      statusEl.textContent = `Error: ${err.message}`;
      clearInterval(deviceScanTimers[id]);
      delete deviceScanTimers[id];
      if (scanBtn) scanBtn.disabled = false;
    }
  };

  deviceScanTimers[id] = setInterval(tick, 4000);
  tick();
}

// ---------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------
(async function init() {
  await requireAuthOrRedirect();
  applyRoleVisibility();
  loadAlerts();
  setInterval(loadAlerts, POLL_MS);
})();
