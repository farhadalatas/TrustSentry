const { spawn } = require('node:child_process');
const path = require('node:path');

const SERVER_DIR = path.join(__dirname, '..', 'server');
const MOCK = path.join(__dirname, 'mock-target.js');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitHealthy(url, tries = 30) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) return true;
    } catch {}
    await sleep(200);
  }
  throw new Error('target tidak sehat: ' + url);
}

const children = [];
function start(name, cmd, args, env) {
  const c = spawn(cmd, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  const log = [];
  c.stdout.on('data', (d) => log.push(d.toString()));
  c.stderr.on('data', (d) => log.push(d.toString()));
  c.on('exit', () => {
    require('node:fs').writeFileSync(`/tmp/opencode/log-${name}.txt`, log.join(''));
  });
  children.push(c);
  return c;
}

(async () => {
  start('mock', 'node', [MOCK]);
  start('server', 'node', [path.join(SERVER_DIR, 'src/index.js')], { PORT: '4010' });
  await sleep(1200);
  await waitHealthy('http://localhost:3000');
  await waitHealthy('http://localhost:4010/api/health');

  const config = {
    authorized: true,
    target: 'http://localhost:3000',
    allowPrivate: true,
    modules: ['recon', 'bruteforce', 'otp', 'injection', 'session', 'fuzz', 'logic'],
    budget: { maxRequests: 260, minDelayMs: 0, sprayMax: 3, otpMax: 10, fuzzMax: 120 },
    auth: {
      email: 'test@lab.dev',
      login: { endpoint: '/api/auth/login', method: 'POST', body: { email: '<USER>', password: '<PASS>' }, successCodes: [200] },
      register: { endpoint: '/api/auth/register', method: 'POST', body: { email: '<USER>', password: '<PASS>', name: 'tester' }, successCodes: [201] },
      forgot: { endpoint: '/api/auth/forgot-password', method: 'POST', body: { email: '<USER>' }, successCodes: [200] },
      verifyOtp: { endpoint: '/api/auth/verify-email', method: 'POST', body: { email: '<USER>', otp: '<OTP>' }, successCodes: [200] },
      resend: { endpoint: '/api/auth/resend-otp', method: 'POST', body: { email: '<USER>' }, successCodes: [200] },
    },
    spray: ['123456', 'admin123', 'letmein'],
  };

  const runRes = await fetch('http://localhost:4010/api/runs', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config),
  });
  const { runId } = await runRes.json();
  console.log('runId:', runId);

  let j;
  for (let i = 0; i < 50; i++) {
    await sleep(300);
    const r = await fetch(`http://localhost:4010/api/runs/${runId}`);
    j = await r.json();
    if (j.finished) break;
  }
  console.log('requests:', j.requests, 'finished:', j.finished);
  console.log('summary:', JSON.stringify(j.summary));
  console.log('--- findings ---');
  for (const f of j.findings) {
    console.log(`[${f.severity}] ${f.type} - ${f.title}`);
  }

  // report endpoints
  const html = await fetch(`http://localhost:4010/api/runs/${runId}/report?format=html`);
  console.log('report html status:', html.status, 'len:', (await html.text()).length);

  // jwt decode
  const jwt = await fetch('http://localhost:4010/api/jwt/decode', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' }),
  });
  const jd = await jwt.json();
  console.log('jwt decoded alg:', jd.header && jd.header.alg);

  // history
  const hist = await fetch('http://localhost:4010/api/history');
  const hd = await hist.json();
  console.log('history runs:', hd.runs.length, 'latest:', hd.runs[0] && hd.runs[0].runId, 'risk:', hd.runs[0] && hd.runs[0].summary.riskScore);

  // catalog + recommend
  const cat = await fetch('http://localhost:4010/api/catalog').then((r) => r.json());
  console.log('catalog tools:', cat.tools.length, 'categories:', cat.categories.length);
  const rec = await fetch('http://localhost:4010/api/recommend?q=' + encodeURIComponent('cari subdomain')).then((r) => r.json());
  console.log('recommend subdomain:', rec.tools.map((t) => t.name).join(', '));

  // report HTML contains coverage section
  const html2 = await (await fetch(`http://localhost:4010/api/runs/${runId}/report?format=html`)).text();
  console.log('report has coverage section:', html2.includes('Cakupan Pengujian'));

  children.forEach((c) => c.kill('SIGKILL'));
  console.log('DONE');
})().catch((e) => {
  console.error('ITEST FAIL:', e.message);
  children.forEach((c) => c.kill('SIGKILL'));
  process.exit(1);
});