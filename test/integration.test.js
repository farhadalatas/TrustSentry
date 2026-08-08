const { spawn } = require('node:child_process');
const path = require('node:path');

const SERVER_DIR = path.join(__dirname, '..', 'server');
const MOCK = path.join(__dirname, 'mock-target.js');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const errors = [];
function check(cond, label) {
  if (cond) {
    console.log('  ok  -', label);
  } else {
    errors.push(label);
    console.error('FAIL -', label);
  }
}

async function waitHealthy(url, tries = 30) {
  for (let i = 0; i < tries; i++) {
    try { if ((await fetch(url)).ok) return; } catch {}
    await sleep(200);
  }
  throw new Error('target tidak sehat: ' + url);
}

const children = [];
function start(name, cmd, args, env) {
  const c = spawn(cmd, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'], cwd: __dirname });
  c.stdout.on('data', () => {});
  c.stderr.on('data', () => {});
  children.push(c);
  return c;
}
function cleanup() {
  for (const c of children) { try { c.kill('SIGKILL'); } catch {} }
}
process.on('exit', cleanup);

const BASE = 'http://localhost:44010';
const PORT_DIFF = 43001;
const PORT_SAME = 43002;

const AUTH_FLOWS = {
  email: 'test@lab.dev',
  login: { endpoint: '/api/auth/login', method: 'POST', body: { email: '<USER>', password: '<PASS>' }, successCodes: [200] },
  register: { endpoint: '/api/auth/register', method: 'POST', body: { email: '<USER>', password: '<PASS>', name: 'tester' }, successCodes: [201] },
  forgot: { endpoint: '/api/auth/forgot-password', method: 'POST', body: { email: '<USER>' }, successCodes: [200] },
  verifyOtp: { endpoint: '/api/auth/verify-email', method: 'POST', body: { email: '<USER>', otp: '<OTP>' }, successCodes: [200] },
  resend: { endpoint: '/api/auth/resend-otp', method: 'POST', body: { email: '<USER>' }, successCodes: [200] },
};

async function runScan(cfg) {
  const res = await fetch(`${BASE}/api/runs`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg),
  });
  const { runId } = await res.json();
  for (let i = 0; i < 80; i++) {
    await sleep(250);
    const j = await (await fetch(`${BASE}/api/runs/${runId}`)).json();
    if (j.finished) return j;
  }
  throw new Error('scan tidak selesai dalam batas waktu: ' + runId);
}

(async () => {
  start('mock-diff', 'node', [MOCK], { MOCK_PORT: String(PORT_DIFF), BEHAVIOUR: 'diff' });
  start('mock-same', 'node', [MOCK], { MOCK_PORT: String(PORT_SAME), BEHAVIOUR: 'same' });
  start('server', 'node', [path.join(SERVER_DIR, 'src/index.js')], { PORT: '44010' });
  await sleep(1200);
  await waitHealthy(`http://localhost:${PORT_DIFF}`);
  await waitHealthy(`http://localhost:${PORT_SAME}`);
  await waitHealthy(`${BASE}/api/health`);

  // ---- Skenario 1: target "diff" -> enumeration aktif, semua modul deteksi ----
  const algNoneToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.abc';
  const j = await runScan({
    authorized: true,
    target: `http://localhost:${PORT_DIFF}`,
    allowPrivate: true,
    modules: ['recon', 'bruteforce', 'otp', 'injection', 'session', 'fuzz', 'logic'],
    budget: { maxRequests: 260, minDelayMs: 0, sprayMax: 3, otpMax: 10, fuzzMax: 120 },
    auth: { ...AUTH_FLOWS },
    spray: ['123456', 'admin123', 'letmein'],
    jwt: { token: algNoneToken },
  });

  console.log('--- Findings (target diff) ---');
  j.findings.forEach((f) => console.log(`[${f.severity}] ${f.type} - ${f.title}`));
  const types = new Set(j.findings.map((f) => f.type));

  check(types.has('brute-enumeration'), 'enumeration terdeteksi pada target diff');
  check(types.has('otp-resend-no-cooldown'), 'otp resend cooldown terdeteksi');
  check(types.has('fuzz-discovered'), 'fuzz endpoint ditemukan');
  check(types.has('register-disposable-email'), 'disposable email terdeteksi');
  check(types.has('register-race-condition'), 'race condition terdeteksi');

  const algNone = j.findings.find((f) => f.type === 'jwt-alg-none');
  check(algNone && algNone.severity === 'CRITICAL', 'JWT alg:none severity CRITICAL (regresi severity)');

  // ---- Skenario 2: target "same" (respon identik) -> enumeration TIDAK boleh muncul ----
  const j3 = await runScan({
    authorized: true,
    target: `http://localhost:${PORT_SAME}`,
    allowPrivate: true,
    modules: ['bruteforce'],
    budget: { maxRequests: 50, minDelayMs: 0 },
    auth: {
      email: 'test@lab.dev',
      login: { endpoint: '/api/auth/login', method: 'POST', body: { email: '<USER>', password: '<PASS>' }, successCodes: [200] },
      forgot: { endpoint: '/api/auth/forgot-password', method: 'POST', body: { email: '<USER>' }, successCodes: [200] },
    },
  });
  const enums = j3.findings.filter((f) => f.type === 'brute-enumeration');
  check(enums.length === 0, 'target identik tidak men-flag enumeration (regresi false-positive)');

  // ---- Katalog & rekomendasi ----
  const cat = (await (await fetch(`${BASE}/api/catalog`)).json());
  check(cat.tools.length >= 30 && cat.categories.length >= 10, `katalog minimal (${cat.tools.length} tools)`);
  const rec = await (await fetch(`${BASE}/api/recommend?q=${encodeURIComponent('cari subdomain')}`)).json();
  check(rec.tools.some((t) => t.name === 'subfinder'), 'rekomendasi subdomain -> subfinder');

  // ---- Report menampilkan section coverage ----
  const html = await (await fetch(`${BASE}/api/runs/${j.runId}/report?format=html`)).text();
  check(html.includes('Cakupan Pengujian'), 'report memuat section coverage');

  // ---- JWT decode ----
  const dec = await (await fetch(`${BASE}/api/jwt/decode`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6IkFkbWluIn0.x' }),
  })).json();
  check(dec.header && dec.header.alg === 'HS256', 'jwt decode berfungsi');
  const bad = await fetch(`${BASE}/api/jwt/decode`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: 'not-a-jwt' }),
  });
  check(bad.status === 400, 'jwt decode menolak token invalid');

  children.forEach((c) => c.kill('SIGKILL'));
  if (errors.length) {
    console.error(`\n${errors.length} assertion GAGAL:`);
    errors.forEach((e) => console.error('  -', e));
    process.exit(1);
  }
  console.log('\nSemua assertions lulus. DONE');
})().catch((e) => {
  console.error('ITEST FAIL:', e.stack || e.message);
  children.forEach((c) => c.kill('SIGKILL'));
  process.exit(1);
});