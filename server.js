require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const { WazuhClient } = require('./lib/wazuh');
const { WazuhManagerClient } = require('./lib/wazuhManager');
const { GvmClient } = require('./lib/gvm');
const { verifyPassword } = require('./lib/users');
const { listDevices, getDevice, addDeviceRecord, updateDevice, removeDevice } = require('./lib/devices');

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Clients ----
const wazuh = new WazuhClient({
  host: process.env.WAZUH_INDEXER_HOST,
  port: process.env.WAZUH_INDEXER_PORT,
  user: process.env.WAZUH_INDEXER_USER,
  pass: process.env.WAZUH_INDEXER_PASS,
  index: process.env.WAZUH_INDEXER_INDEX,
  tlsRejectUnauthorized: process.env.WAZUH_INDEXER_TLS_REJECT_UNAUTHORIZED !== 'false'
});

const wazuhManager = new WazuhManagerClient({
  host: process.env.WAZUH_API_HOST || process.env.WAZUH_INDEXER_HOST,
  port: process.env.WAZUH_API_PORT || 55000,
  user: process.env.WAZUH_API_USER,
  pass: process.env.WAZUH_API_PASS,
  tlsRejectUnauthorized: process.env.WAZUH_API_TLS_REJECT_UNAUTHORIZED !== 'false'
});

const gvm = new GvmClient({
  host: process.env.GVM_HOST,
  port: Number(process.env.GVM_PORT || 9390),
  user: process.env.GVM_USER,
  pass: process.env.GVM_PASS,
  tlsRejectUnauthorized: process.env.GVM_TLS_REJECT_UNAUTHORIZED !== 'false',
  useTls: process.env.GVM_USE_TLS !== 'false'
});

const MIN_LEVEL = Number(process.env.MIN_LEVEL || 7);
const ALERTS_LIMIT = Number(process.env.ALERTS_LIMIT || 100);

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-this-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
  })
);
app.use(express.static(path.join(__dirname, 'public')));

// ---- Auth helpers ----
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ ok: false, error: 'Not authenticated' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ ok: false, error: 'Not authenticated' });
  }
  if (req.session.user.role !== 'admin') {
    return res.status(403).json({ ok: false, error: 'Admin role required' });
  }
  next();
}

// ---- Auth routes ----
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ ok: false, error: 'Username and password are required' });
    }
    const user = await verifyPassword(username, password);
    if (!user) {
      return res.status(401).json({ ok: false, error: 'Invalid username or password' });
    }
    req.session.user = user;
    res.json({ ok: true, user });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  if (!req.session) return res.json({ ok: true });
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session || !req.session.user) return res.status(401).json({ ok: false });
  res.json({ ok: true, user: req.session.user });
});

// ---- Alerts ----
app.get('/api/alerts', requireAuth, async (req, res) => {
  try {
    const minLevel = Number(req.query.minLevel) || MIN_LEVEL;
    const alerts = await wazuh.getAlerts({ minLevel, limit: ALERTS_LIMIT });
    res.json({ ok: true, count: alerts.length, alerts });
  } catch (err) {
    console.error('[alerts] error:', err.message);
    res.status(502).json({ ok: false, error: err.message });
  }
});

// ---- Devices ----
// admin: add/delete devices and start scans. observer: view only.
app.get('/api/devices', requireAuth, (req, res) => {
  res.json({ ok: true, devices: listDevices() });
});

app.post('/api/devices', requireAdmin, async (req, res) => {
  const { name, ip, os } = req.body || {};
  if (!name || !ip) {
    return res.status(400).json({ ok: false, error: 'name and ip are required' });
  }

  const device = addDeviceRecord({ name, ip, os });
  const warnings = [];

  // Register the agent on the Wazuh manager. This only creates the agent
  // entry + enrollment key - the agent software still has to be
  // installed/enrolled on the device itself using that key.
  try {
    const agent = await wazuhManager.addAgent(name, ip);
    updateDevice(device.id, {
      wazuh: { agentId: agent.agentId, agentKey: agent.agentKey, registered: true, error: null }
    });
  } catch (err) {
    warnings.push(`Wazuh: ${err.message}`);
    updateDevice(device.id, {
      wazuh: { agentId: null, agentKey: null, registered: false, error: err.message }
    });
  }

  // Create the OpenVAS target. This part is fully automatic - no agent
  // needed, OpenVAS scans over the network.
  try {
    const target = await gvm.createTarget(name, ip);
    updateDevice(device.id, {
      openvas: { targetId: target.targetId, lastTaskId: null, lastScanStatus: null, error: null }
    });
  } catch (err) {
    warnings.push(`OpenVAS: ${err.message}`);
    updateDevice(device.id, {
      openvas: { targetId: null, lastTaskId: null, lastScanStatus: null, error: err.message }
    });
  }

  res.json({ ok: true, device: getDevice(device.id), warnings });
});

app.delete('/api/devices/:id', requireAdmin, async (req, res) => {
  const device = getDevice(req.params.id);
  if (!device) return res.status(404).json({ ok: false, error: 'Device not found' });

  const warnings = [];
  if (device.wazuh && device.wazuh.agentId) {
    try {
      await wazuhManager.removeAgent(device.wazuh.agentId);
    } catch (err) {
      warnings.push(`Wazuh: ${err.message}`);
    }
  }
  if (device.openvas && device.openvas.targetId) {
    try {
      await gvm.deleteTarget(device.openvas.targetId);
    } catch (err) {
      warnings.push(`OpenVAS: ${err.message}`);
    }
  }

  removeDevice(device.id);
  res.json({ ok: true, warnings });
});

// ---- OpenVAS scan types + per-device scanning ----
app.get('/api/openvas/configs', requireAuth, async (req, res) => {
  try {
    const configs = await gvm.getConfigs();
    res.json({ ok: true, configs });
  } catch (err) {
    console.error('[openvas/configs] error:', err.message);
    res.status(502).json({ ok: false, error: err.message });
  }
});

app.post('/api/devices/:id/scan', requireAdmin, async (req, res) => {
  try {
    const device = getDevice(req.params.id);
    if (!device) return res.status(404).json({ ok: false, error: 'Device not found' });

    const { configId } = req.body || {};
    if (!configId) return res.status(400).json({ ok: false, error: 'configId is required' });

    let targetId = device.openvas && device.openvas.targetId;
    if (!targetId) {
      const target = await gvm.createTarget(device.name, device.ip);
      targetId = target.targetId;
    }

    const taskName = `${device.name} - ${new Date().toISOString()}`;
    const task = await gvm.createTask(taskName, configId, targetId);
    await gvm.startTask(task.taskId);

    updateDevice(device.id, {
      openvas: Object.assign({}, device.openvas, {
        targetId,
        lastTaskId: task.taskId,
        lastScanStatus: 'Requested',
        error: null
      })
    });

    res.json({ ok: true, taskId: task.taskId });
  } catch (err) {
    console.error('[devices/scan] error:', err.message);
    res.status(502).json({ ok: false, error: err.message });
  }
});

app.get('/api/devices/:id/scan/status', requireAuth, async (req, res) => {
  try {
    const device = getDevice(req.params.id);
    if (!device) return res.status(404).json({ ok: false, error: 'Device not found' });

    const taskId = device.openvas && device.openvas.lastTaskId;
    if (!taskId) return res.json({ ok: true, found: false });

    const status = await gvm.getTaskStatus(taskId);
    if (status.found) {
      updateDevice(device.id, {
        openvas: Object.assign({}, device.openvas, { lastScanStatus: status.status })
      });
    }
    res.json(Object.assign({ ok: true }, status));
  } catch (err) {
    console.error('[devices/scan/status] error:', err.message);
    res.status(502).json({ ok: false, error: err.message });
  }
});

app.get('/api/health', async (req, res) => {
  const out = { wazuh: 'unknown' };
  try {
    await wazuh.ping();
    out.wazuh = 'ok';
  } catch (err) {
    out.wazuh = `error: ${err.message}`;
  }
  res.json(out);
});

app.listen(PORT, () => {
  console.log(`Dashboard running at http://localhost:${PORT}`);
});
