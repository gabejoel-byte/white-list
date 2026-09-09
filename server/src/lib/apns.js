'use strict';
// APNs push for MDM. To "wake" an enrolled device so it polls for commands, we
// send a push with body {"mdm":"<PushMagic>"} to the device's push token, over
// TLS with the MDM push certificate, topic = the cert's UID.
//
// Requires: APNS_CERT + APNS_KEY (PEM paths) from the Apple Push Certificates
// Portal MDM cert. Without them this no-ops (logs) so the rest of the MDM flow
// still works in development — the device will still pick up queued commands on
// its next natural check-in.
const fs = require('fs');
const http2 = require('http2');

function isConfigured() { return !!(process.env.APNS_CERT && process.env.APNS_KEY); }

function push(pushToken, pushMagic, topic) {
  if (!isConfigured()) {
    console.log('[apns] not configured — skipping wake (device will poll on next check-in)');
    return Promise.resolve({ sent: false, reason: 'apns_not_configured' });
  }
  return new Promise((resolve) => {
    let client;
    try {
      client = http2.connect('https://api.push.apple.com:443', {
        cert: fs.readFileSync(process.env.APNS_CERT),
        key: fs.readFileSync(process.env.APNS_KEY),
      });
    } catch (e) { return resolve({ sent: false, reason: e.message }); }
    const body = Buffer.from(JSON.stringify({ mdm: pushMagic }));
    const req = client.request({
      ':method': 'POST', ':path': `/3/device/${pushToken}`,
      'apns-topic': topic, 'apns-push-type': 'mdm', 'content-length': body.length,
    });
    let status = 0;
    req.on('response', (h) => { status = h[':status']; });
    req.on('error', (e) => { client.close(); resolve({ sent: false, reason: e.message }); });
    req.on('end', () => { client.close(); resolve({ sent: status === 200, status }); });
    req.write(body); req.end();
  });
}

module.exports = { isConfigured, push };
