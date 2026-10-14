#!/usr/bin/env node
// Adds a dashboard login (admin or observer).
//
// Interactive:   npm run create-user
// Non-interactive (e.g. scripting/Docker): CREATE_USER_NAME=admin
//   CREATE_USER_PASS=secret CREATE_USER_ROLE=admin npm run create-user
require('dotenv').config();
const readline = require('readline');
const { createUser } = require('../lib/users');

function ask(rl, question) {
  return new Promise((resolve) => rl.question(question, resolve));
}

async function main() {
  let username = process.env.CREATE_USER_NAME;
  let password = process.env.CREATE_USER_PASS;
  let role = process.env.CREATE_USER_ROLE;

  if (!username || !password) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    try {
      username = (await ask(rl, 'Username: ')).trim();
      password = (await ask(rl, 'Password: ')).trim();
      role = (await ask(rl, 'Role (admin/observer) [observer]: ')).trim().toLowerCase();
    } finally {
      rl.close();
    }
  }

  if (!role) role = 'observer';
  role = role.toLowerCase();
  if (role !== 'admin' && role !== 'observer') {
    throw new Error('Role must be "admin" or "observer"');
  }

  await createUser(username, password, role);
  console.log(`\nCreated user "${username}" with role "${role}".`);
  console.log('admin can add/delete devices and start scans.');
  console.log('observer can view alerts and devices only.');
}

main().catch((err) => {
  console.error('\nError:', err.message);
  process.exitCode = 1;
});
