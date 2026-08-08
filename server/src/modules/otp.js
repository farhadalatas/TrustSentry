const { SEV } = require('../lib/severity.js');
const { buildCall } = require('./bruteforce.js');
const { isSuccess } = require('../lib/success.js');

async function runOtp(ctx, cfg) {
  const auth = cfg.auth || {};
  const verify = auth.verifyOtp;
  const resend = auth.resend;
  ctx.emitEvent('module', { name: 'otp', label: 'OTP / 2FA' });

  const otpMax = (ctx.config.budget && ctx.config.budget.otpMax) || 200;

  if (verify) {
    const submit = buildCall(ctx, verify);

    // 1) OTP BRUTE (bounded) - scan 000000..0000xx for a successful code.
    let bruteHitAt = null;
    for (let i = 0; i < otpMax; i++) {
      const code = String(i).padStart(6, '0');
      const res = await submit({ '<USER>': auth.email, '<OTP>': code });
      if (isSuccess(verify, res)) {
        bruteHitAt = code;
        break;
      }
      if (res.status && [401, 403, 429].includes(res.status)) {
        ctx.addFinding({
          type: 'otp-rate-limited',
          severity: SEV.INFO,
          title: `Request OTP pada percobaan #${i} ditolak status ${res.status} (rate rampasan aktif).`,
          evidence: { attempt: i, code, status: res.status },
          recommendation: 'Rate limit OTP terdeteksi aktif - lanjutkan vektor bypass.',
        });
        break;
      }
    }
    if (bruteHitAt !== null) {
      ctx.addFinding({
        type: 'otp-brute-hit',
        severity: SEV.CRITICAL,
        title: `OTP berhasil ditebak: ${bruteHitAt}`,
        evidence: { code: bruteHitAt },
        recommendation: 'Wajib limit percobaan OTP + time-based lockout + backoff.',
      });
    } else {
      ctx.addFinding({
        type: 'otp-brute-ok',
        severity: SEV.INFO,
        title: `OTP tidak berhasil ditebak dalam ${otpMax} percobaan (limit aktif).`,
        recommendation: 'Tidak ada temuan; tetap cek bypass vektor di bawah.',
      });
    }

    // 2) OTP BYPASS vectors (type juggling / coercion / encoding abuse).
    const vectors = [
      { label: 'null / kosong', value: null },
      { label: 'array tunggal', value: ['000000'] },
      { label: 'string dengan spasi', value: ' 000000 ' },
      { label: 'string panjang', value: '0'.repeat(40) },
      { label: 'float eksponensial', value: '1e6' },
      { label: 'boolean true', value: true },
      { label: 'integer 0', value: 0 },
    ];
    const baseProbe = await submit({ '<USER>': auth.email, '<OTP>': '000000' });
    for (const v of vectors) {
      const res = await submit({ '<USER>': auth.email, '<OTP>': v });
      if (isSuccess(verify, res) && !isSuccess(verify, baseProbe)) {
        ctx.addFinding({
          type: 'otp-bypass-vector',
          severity: SEV.CRITICAL,
          title: `OTP bypass via vektor: ${v.label}`,
          evidence: { vector: v.label, value: JSON.stringify(v), status: res.status },
          recommendation: 'Validasi tipe OTP ketat (string numerik 6 digit) & tambah rate limit.',
        });
      }
    }
    ctx.emitEvent('progress', { note: 'OTP bypass vector scan selesai.' });

    // 3) Replay / expiry - gunakan OTP yang diketahui expired/used (isi oleh user).
    if (cfg.knownUsedOtp) {
      const res = await submit({ '<USER>': auth.email, '<OTP>': cfg.knownUsedOtp });
      if (isSuccess(verify, res)) {
        ctx.addFinding({
          type: 'otp-replay',
          severity: SEV.HIGH,
          title: 'OTP bekas/expired masih diterima (replay)',
          evidence: { code: cfg.knownUsedOtp, status: res.status },
          recommendation: 'Invalidasi kode setelah se-sukses dan enforce TTL.',
        });
      } else {
        ctx.addFinding({
          type: 'otp-replay-ok',
          severity: SEV.INFO,
          title: 'OTP bekas ditolak (anti-replay bekerja).',
        });
      }
    }

    // 4) Response/header leak scan.
    const leak = await submit({ '<USER>': auth.email, '<OTP>': '000000' });
    const big = (leak.body || '') + JSON.stringify(leak.headers || {});
    if (/\b\d{6}\b/.test(big)) {
      ctx.addFinding({
        type: 'otp-leak',
        severity: SEV.HIGH,
        title: 'Pola 6-digit (potensi OTP) terlihat di respon body/header.',
        evidence: { snippet: leak.body.slice(0, 200) },
        recommendation: 'Jangan pernah kembalikan OTP di respon API.',
      });
    }
  }

  // 5) RESEND abuse - spam resend, cek cooldown.
  if (resend) {
    const resendCall = buildCall(ctx, resend);
    let blocked = false;
    for (let i = 0; i < 3; i++) {
      const r = await resendCall({ '<USER>': auth.email });
      if (r.status === 429 || (r.status >= 400 && r.status < 500)) {
        blocked = true;
        ctx.emitEvent('progress', { note: `resend #${i + 1} diblokir (${r.status})` });
        break;
      }
    }
    if (!blocked) {
      ctx.addFinding({
        type: 'otp-resend-no-cooldown',
        severity: SEV.LOW,
        title: 'Resend OTP tidak enforce cooldown (bisa di-spam).',
        recommendation: 'Enforce cooldown resend dan rate limit per email+IP.',
      });
    }
  }
}

module.exports = { runOtp };