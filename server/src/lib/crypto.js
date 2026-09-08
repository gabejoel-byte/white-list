'use strict';
// Password / key hashing built only on Node's stdlib crypto (scrypt) so the
// server has no native-crypto dependency to compile. Format stored in the DB:
//   scrypt$<N>$<r>$<p>$<saltHex>$<hashHex>
const crypto = require('crypto');

const N = 16384, r = 8, p = 1, KEYLEN = 64;

function hashSecret(secret) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(secret, salt, KEYLEN, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${N}$${r}$${p}$${salt.toString('hex')}$${dk.toString('hex')}`;
}

function verifySecret(secret, stored) {
  try {
    const [scheme, n, rr, pp, saltHex, hashHex] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const dk = crypto.scryptSync(secret, salt, expected.length, {
      N: +n, r: +rr, p: +pp, maxmem: 64 * 1024 * 1024,
    });
    return crypto.timingSafeEqual(dk, expected);
  } catch {
    return false;
  }
}

// Fast, non-secret hash for the unlock key the agent checks offline. It only
// needs to stop a casual user reading the plaintext out of the local policy
// file; brute-force resistance is not the threat here (the real gate is the
// server issuing the unlock command).
function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

function token(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

module.exports = { hashSecret, verifySecret, sha256, token };
