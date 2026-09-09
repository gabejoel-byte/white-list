'use strict';
// Apple MDM scaffolding. A full MDM server also needs: an APNs certificate
// (Apple Push, obtained via an MDM vendor cert + push cert), an HTTPS endpoint
// serving the enrollment + check-in + command protocol, and SCEP/identity for
// signed enrollment. This module provides the pieces that are pure and testable
// — the enrollment profile and the MDM command plists — plus a documented APNs
// push entry point. See README.md for the Apple-account prerequisites.
const { build } = require('./plist');
const crypto = require('crypto');
const uuid = () => crypto.randomUUID().toUpperCase();

// The enrollment profile a device installs (via Apple Configurator / ABM for
// supervision, or user-initiated for BYOD) to hand management to our server.
function enrollmentProfile({ serverUrl, topic, organization = 'Whitelist Cloud', accessRights = 8191 }) {
  if (!serverUrl || !topic) throw new Error('serverUrl and topic (APNs) are required');
  return build({
    PayloadType: 'Configuration',
    PayloadVersion: 1,
    PayloadIdentifier: 'cloud.whitelist.enroll',
    PayloadUUID: uuid(),
    PayloadDisplayName: `${organization} Enrollment`,
    PayloadContent: [{
      PayloadType: 'com.apple.mdm',
      PayloadVersion: 1,
      PayloadIdentifier: 'cloud.whitelist.enroll.mdm',
      PayloadUUID: uuid(),
      ServerURL: `${serverUrl}/mdm/command`,
      CheckInURL: `${serverUrl}/mdm/checkin`,
      Topic: topic,                         // APNs push topic (from push cert)
      AccessRights: accessRights,           // 8191 = all rights
      CheckOutWhenRemoved: true,
      ServerCapabilities: ['com.apple.mdm.per-user-connections'],
      SignMessage: true,
    }],
  });
}

// MDM command builders (the plist the server returns to a device poll).
function installProfileCommand(mobileconfigXml) {
  return build({
    CommandUUID: uuid(),
    Command: { RequestType: 'InstallProfile', Payload: Buffer.from(mobileconfigXml, 'utf8') },
  });
}
function removeProfileCommand(identifier) {
  return build({ CommandUUID: uuid(), Command: { RequestType: 'RemoveProfile', Identifier: identifier } });
}
function deviceInformationCommand(queries = ['DeviceName', 'OSVersion', 'ProductName', 'UDID']) {
  return build({ CommandUUID: uuid(), Command: { RequestType: 'DeviceInformation', Queries: queries } });
}

// Wake a device so it polls for the queued command. Requires an APNs client
// (token/cert) — injected so this module has no network dependency itself.
async function pushWake(apnsClient, pushMagic, deviceToken) {
  if (!apnsClient) throw new Error('no APNs client configured (see README)');
  return apnsClient.send(deviceToken, { mdm: pushMagic });
}

module.exports = { enrollmentProfile, installProfileCommand, removeProfileCommand, deviceInformationCommand, pushWake };
