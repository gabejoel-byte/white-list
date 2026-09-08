'use strict';
// Thin HTTPS/HTTP client (stdlib only, no deps) for talking to the cloud.
const http = require('http');
const https = require('https');
const { URL } = require('url');

function request(base, method, pathname, { token, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(pathname, base);
    const lib = u.protocol === 'https:' ? https : http;
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const req = lib.request(u, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(data ? { 'content-length': data.length } : {}),
        ...(token ? { authorization: 'Bearer ' + token } : {}),
      },
      timeout: 15000,
    }, (res) => {
      let buf = '';
      res.on('data', (c) => (buf += c));
      res.on('end', () => {
        let json = {};
        try { json = buf ? JSON.parse(buf) : {}; } catch { /* leave {} */ }
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(json);
        else reject(Object.assign(new Error(json.error || 'http_' + res.statusCode), { status: res.statusCode, body: json }));
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    if (data) req.write(data);
    req.end();
  });
}

function makeClient(base) {
  return {
    enroll: (payload) => request(base, 'POST', '/api/v1/enroll', { body: payload }),
    heartbeat: (token, payload) => request(base, 'POST', '/api/v1/heartbeat', { token, body: payload }),
  };
}

module.exports = { makeClient };
