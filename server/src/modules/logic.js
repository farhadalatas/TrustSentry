const { SEV } = require('../lib/severity.js');
const { buildCall } = require('./bruteforce.js');

const DISPOSABLE_DOMAINS = [
  'mailinator.com', 'guerrillamail.com', 'sharklasers.com', 'temp-mail.org',
  '10minutemail.com', 'yopmail.com', 'trashmail.com', 'maildrop.cc',
  'mailnesia.com', 'getnada.com', 'dispostable.com', 'fakeinbox.com',
];

async function runLogic(ctx, cfg) {
  const auth = cfg.auth || {};
  ctx.emitEvent('module', { name: 'logic', label: 'Business Logic' });
  const startIdx = ctx.findings.length;

  if (auth.register) {
    const register = buildCall(ctx, auth.register);

    // 1) DISPOSABLE EMAIL - apakah registrasi menerima email sekali pakai.
    const disp = DISPOSABLE_DOMAINS[Math.floor(Math.random() * DISPOSABLE_DOMAINS.length)];
    const res = await register({ '<USER>': `abuse_${Date.now()}@${disp}`, '<PASS>': 'pass1234!' });
    if (isSuccess(auth.register, res)) {
      ctx.addFinding({
        type: 'register-disposable-email',
        severity: SEV.MEDIUM,
        title: `Registrasi menerima email sekali pakai (${disp})`,
        evidence: { domain: disp, status: res.status },
        recommendation: 'Blokir/validasi domain email sekali pakai + verifikasi email sebelum aktivasi penuh.',
      });
    } else {
      ctx.addFinding({
        type: 'register-disposable-email-ok',
        severity: SEV.INFO,
        title: 'Registrasi menolak email sekali pakai (atau tidak terverifikasi).',
      });
    }

    // 2) RACE CONDITION - dua registrasi paralel email sama; kalau keduanya sukses -> TOCTOU.
    const email = 'race_' + Date.now() + '@example.org';
    const [r1, r2] = await Promise.all([
      register({ '<USER>': email, '<PASS>': 'pass1234!' }),
      register({ '<USER>': email, '<PASS>': 'pass1234!' }),
    ]);
    const ok1 = isSuccess(auth.register, r1);
    const ok2 = isSuccess(auth.register, r2);
    ctx.emitEvent('progress', { note: `race register ${email}: [${r1.status}, ${r2.status}]` });
    if (ok1 && ok2) {
      ctx.addFinding({
        type: 'register-race-condition',
        severity: SEV.HIGH,
        title: 'Race condition pada register: dua akun dibuat dari email yang sama',
        evidence: { email, statuses: [r1.status, r2.status] },
        recommendation: 'Enforce unique constraint atomik (unique index) + handle conflict 409 di awal transaksi.',
      });
    } else {
      ctx.addFinding({
        type: 'register-race-ok',
        severity: SEV.INFO,
        title: 'Tidak ada race condition teramati (satu request ditolak).',
        evidence: { statuses: [r1.status, r2.status] },
      });
    }
  }

  return ctx.findings.slice(startIdx);
}

function isSuccess(flow, res) {
  return Array.isArray(flow.successCodes) ? flow.successCodes.includes(res.status) : res.ok;
}

module.exports = { runLogic };