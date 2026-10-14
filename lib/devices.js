const path = require('path');
const { readJson, writeJson } = require('./jsonStore');
const { uuidv4 } = require('./idgen');

const DEVICES_FILE = path.join(__dirname, '..', 'data', 'devices.json');

function loadDevices() {
  return readJson(DEVICES_FILE, []);
}

function saveDevices(devices) {
  writeJson(DEVICES_FILE, devices);
}

function listDevices() {
  return loadDevices();
}

function getDevice(id) {
  return loadDevices().find((d) => d.id === id) || null;
}

function addDeviceRecord(data) {
  const devices = loadDevices();
  const device = {
    id: uuidv4(),
    name: data.name,
    ip: data.ip,
    os: data.os || '',
    createdAt: new Date().toISOString(),
    wazuh: { agentId: null, agentKey: null, registered: false, error: null },
    openvas: { targetId: null, lastTaskId: null, lastScanStatus: null, error: null }
  };
  devices.push(device);
  saveDevices(devices);
  return device;
}

function updateDevice(id, patch) {
  const devices = loadDevices();
  const idx = devices.findIndex((d) => d.id === id);
  if (idx === -1) return null;
  devices[idx] = Object.assign({}, devices[idx], patch);
  saveDevices(devices);
  return devices[idx];
}

function removeDevice(id) {
  const devices = loadDevices();
  const next = devices.filter((d) => d.id !== id);
  saveDevices(next);
  return next.length !== devices.length;
}

module.exports = { listDevices, getDevice, addDeviceRecord, updateDevice, removeDevice };
