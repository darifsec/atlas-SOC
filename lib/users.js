const path = require('path');
const bcrypt = require('bcryptjs');
const { readJson, writeJson } = require('./jsonStore');

const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');

function loadUsers() {
  return readJson(USERS_FILE, []);
}

function findByUsername(username) {
  const users = loadUsers();
  const needle = String(username || '').toLowerCase();
  return users.find((u) => u.username.toLowerCase() === needle) || null;
}

/**
 * Returns {username, role} on success, or null on bad credentials /
 * unknown user. Never returns the password hash.
 */
async function verifyPassword(username, password) {
  const user = findByUsername(username);
  if (!user) return null;
  const ok = await bcrypt.compare(password || '', user.passwordHash);
  return ok ? { username: user.username, role: user.role } : null;
}

async function createUser(username, password, role) {
  if (role !== 'admin' && role !== 'observer') {
    throw new Error('role must be "admin" or "observer"');
  }
  if (!username || !password) {
    throw new Error('username and password are required');
  }
  const users = loadUsers();
  if (findByUsername(username)) {
    throw new Error(`user "${username}" already exists`);
  }
  const passwordHash = await bcrypt.hash(password, 10);
  users.push({ username, passwordHash, role });
  writeJson(USERS_FILE, users);
}

function listUsernames() {
  return loadUsers().map((u) => ({ username: u.username, role: u.role }));
}

module.exports = { findByUsername, verifyPassword, createUser, listUsernames };
