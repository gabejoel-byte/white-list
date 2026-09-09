'use strict';
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');

require('./db'); // ensure schema
const agentRoutes = require('./routes/agent');
const adminRoutes = require('./routes/admin');
const mdmRoutes = require('./routes/mdm');

const app = express();
app.disable('x-powered-by');
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
