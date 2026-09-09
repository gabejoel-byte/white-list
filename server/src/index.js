'use strict';
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');

const db = require('./db'); // ensure schema
// Bootstrap the first admin from env on a fresh hosted deploy (no shell needed).
// Only acts when there are zero admins, so it never overwrites an existing one.
if (process.env.ADMIN_USER && process.env.ADMIN_PASS) {
  const count = db.prepare('SELECT COUNT(*) c FROM admins').get().c;
  if (count === 0) {
    const { hashSecret } = require('./lib/crypto');
    db.prepare('INSERT INTO admins (username, pass_hash) VALUES (?, ?)')
      .run(process.env.ADMIN_USER, hashSecret(process.env.ADMIN_PASS));
    console.log(`[whitelist-cloud] bootstrapped admin "${process.env.ADMIN_USER}" from env`);
  }
}
const agentRoutes = require('./routes/agent');
const adminRoutes = require('./routes/admin');
const mdmRoutes = require('./routes/mdm');

const app = express();
app.disable('x-powered-by');
// Behind a hosting provider's TLS-terminating proxy (Render/Railway/Fly/nginx):
// trust the first proxy hop so secure cookies and req.protocol work correctly.
app.set('trust proxy', 1);
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());

app.get('/healthz', (req, res) => res.json({ ok: true, ts: Date.now() }));

app.use('/api/v1', agentRoutes);   // desktop agent endpoints
app.use('/admin/api', adminRoutes); // dashboard endpoints
app.use('/mdm', mdmRoutes);         // Apple MDM device protocol

// Static dashboard.
app.use('/', express.static(path.join(__dirname, '..', 'public')));

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, HOST, () => {
  console.log(`[whitelist-cloud] listening on http://${HOST}:${PORT}`);
  console.log(`[whitelist-cloud] dashboard: http://localhost:${PORT}/`);
});
