const dns = require('node:dns/promises');
const { URL } = require('node:url');

const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^fe80:/i,
];

function isPrivateIp(ip) {
  return PRIVATE_RANGES.some((re) => re.test(ip));
}

/**
 * Validates a target URL and resolves it to catch SSRF-style abuse.
 * - Only http/https allowed
 * - Non-http schemes rejected
 * - Optional block of private/loopback/link-local ranges
 */
async function validateTarget(raw, { allowPrivate = true } = {}) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('INVALID_URL: target bukan URL yang valid');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('SCHEME_NOT_ALLOWED: hanya http/https yang didukung');
  }
  if (!url.hostname) {
    throw new Error('INVALID_URL: host kosong');
  }
  if (url.username || url.password) {
    throw new Error('CRED_IN_URL: jangan masukkan kredensial di URL');
  }

  let ips = [];
  try {
    ips = await dns.lookup(url.hostname, { all: true, verbatim: true });
  } catch {
    throw new Error('DNS_FAILED: tidak bisa resolve host');
  }

  const blocked = ips
    .map((r) => r.address)
    .filter((ip) => !allowPrivate && isPrivateIp(ip));

  if (blocked.length > 0) {
    throw new Error(
      `SSRF_BLOCKED: target resolve ke IP privat/lokal (${blocked.join(', ')}). ` +
        `Kalau ini lab/localhost lo, aktifkan "izinkan target lokal" di UI.`
    );
  }

  return { url, ips };
}

module.exports = { validateTarget, isPrivateIp };
