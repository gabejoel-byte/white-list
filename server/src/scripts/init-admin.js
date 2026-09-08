'use strict';
// Create or reset the dashboard admin. Usage:
//   node src/scripts/init-admin.js <username> <password>
const db = require('../db');
const { hashSecret } = require('../lib/crypto');

const [, , username, password] = process.argv;
if (!username || !password) {
  console.error('usage: init-admin <username> <password>');
  process.exit(1);
}
const hash = hashSecret(password);
const existing = db.prepare('SELECT id FROM admins WHERE username = ?').get(username);
if (existing) {
  db.prepare('UPDATE admins SET pass_hash = ? WHERE id = ?').run(hash, existing.id);
  console.log(`updated admin "${username}"`);
} else {
  db.prepare('INSERT INTO admins (username, pass_hash) VALUES (?, ?)').run(username, hash);
  console.log(`created admin "${username}"`);
}
