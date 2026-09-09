'use strict';
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'whitelist.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id         INTEGER PRIMARY KEY,
  username   TEXT UNIQUE NOT NULL,
  pass_hash  TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

-- Reusable org enrollment keys (the string baked into an installer package).
CREATE TABLE IF NOT EXISTS enrollment_keys (
  id          INTEGER PRIMARY KEY,
  key         TEXT UNIQUE NOT NULL,
  label       TEXT,
  policy_id   INTEGER REFERENCES policies(id),   -- policy new devices inherit
  revoked     INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS policies (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL,
  version     INTEGER NOT NULL DEFAULT 1,
  body        TEXT NOT NULL,                      -- JSON policy shape
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
  id             TEXT PRIMARY KEY,               -- random device id
  machine_id     TEXT UNIQUE NOT NULL,           -- stable hw-derived id
  token_hash     TEXT NOT NULL,
  hostname       TEXT,
  os             TEXT,
  policy_id      INTEGER REFERENCES policies(id),
  policy_version INTEGER NOT NULL DEFAULT 0,     -- version the device last acked
  agent_version  TEXT,
  status         TEXT,                           -- JSON last reported status
  last_seen      TEXT,
  enrolled_at    TEXT NOT NULL DEFAULT (datetime('now')),
  revoked        INTEGER NOT NULL DEFAULT 0
);

-- Out-of-band commands queued for a device (unlock, uninstall, refresh).
CREATE TABLE IF NOT EXISTS commands (
  id          TEXT PRIMARY KEY,
  device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  type        TEXT NOT NULL,
  payload     TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  delivered   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY,
  device_id   TEXT REFERENCES devices(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  detail      TEXT,
  at          TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id, at);

-- iOS/iPadOS devices enrolled over Apple MDM.
CREATE TABLE IF NOT EXISTS ios_devices (
  udid        TEXT PRIMARY KEY,
  push_token  TEXT,
  push_magic  TEXT,
  topic       TEXT,
  policy_id   INTEGER REFERENCES policies(id),
  info        TEXT,                             -- JSON DeviceInformation
  last_seen   TEXT,
  enrolled_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Queued MDM commands per device (FIFO).
CREATE TABLE IF NOT EXISTS ios_commands (
  id           INTEGER PRIMARY KEY,
  udid         TEXT NOT NULL,
  command_uuid TEXT NOT NULL,
  request_type TEXT,
  payload      TEXT NOT NULL,                   -- command plist (XML)
  status       TEXT NOT NULL DEFAULT 'queued',  -- queued | sent | acknowledged
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ioscmd ON ios_commands(udid, status, id);
`);

// --- lightweight migrations for columns added after first release ---
const deviceCols = db.prepare('PRAGMA table_info(devices)').all().map((c) => c.name);
if (!deviceCols.includes('label')) db.exec('ALTER TABLE devices ADD COLUMN label TEXT');

module.exports = db;
