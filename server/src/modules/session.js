const { SEV } = require('../lib/severity.js');

function b64urlDecode(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
}

function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length < 3) return null;
  try {
    return {
      header: JSON.parse(b64urlDecode(parts[0])),
      payload: JSON.parse(b64urlDecode(parts[1])),
      signature: parts[2],
    };
  } catch {
    return null;
  }
}

function auditCookies(ctx, value) {
  const cookies = (value || '').split(';').filter((c) => c.includes('='));
  for (const raw of cookies) {
    const [name, ...rest] = raw.trim().split('=');
    const flags = rest.join('=').toLowerCase();
    const issues = [];
    if (!flags.includes('httponly')) issues.push('HttpOnly');
    if (!flags.includes('secure')) issues.push('Secure');
    const ss = /samesite=(\w+)/i.exec(flags);
    if (!ss) issues.push('SameSite');
    else if (!['none', 'strict', 'lax'].includes(ss[1].toLowerCase())) issues.push('SameSite=' + ss[1]);
    if (issues.length) {
      ctx.addFinding({
        type: 'cookie-flags',
        severity: issues.includes('Secure') ? SEV.HIGH : SEV.MEDIUM,
        title: `Cookie "${name}" kurang flag: ${issues.join(', ')}`,
        evidence: { cookie: name, missing: issues },
        recommendation: 'Set flag HttpOnly; Secure; SameSite=Lax/Strict.',
      });
    }
  }
}

async function runSession(ctx, cfg) {
  ctx.emitEvent('module', { name: 'session', label: 'Session & JWT' });

  // 1) Cookie analysis - ambil Set-Cookie dari respons login.
  if (cfg.auth && cfg.auth.login) {
    const { buildCall } = require('./bruteforce.js');
    const login = buildCall(ctx, cfg.auth.login);
    const res = await login({ '<USER>': cfg.auth.email, '<PASS>': 'wrongpass1!' });
    if (res.headers && res.headers['set-cookie']) {
      auditCookies(ctx, res.headers['set-cookie']);
      ctx.emitEvent('progress', { note: 'Cookie dari respons login dianalisis.' });
    } else {
      ctx.emitEvent('progress', { note: 'Tidak ada Set-Cookie di respons login.' });
    }
  }

  // 2) JWT decode + analisis keamanan.
  if (cfg.jwt && cfg.jwt.token) {
    const jwt = decodeJwt(cfg.jwt.token);
    if (!jwt) {
      ctx.addFinding({
        type: 'jwt-parse-failed',
        severity: SEV.INFO,
        title: 'Token tidak bisa di-parse sebagai JWT.',
      });
      return;
    }
    const checks = [];
    if (jwt.header.alg === 'none') {
      checks.push({ type: 'jwt-alg-none', severity: SEV.CRITICAL, title: 'JWT memakai "alg": "none" - bisa dipalsukan.' });
    }
    if (jwt.header.kid) {
      checks.push({ type: 'jwt-kid-unsafe', severity: SEV.MEDIUM, title: 'JWT punya "kid" - uji path traversal / key confusion.' });
    }
    if (!jwt.payload.exp) {
      checks.push({ type: 'jwt-no-exp', severity: SEV.MEDIUM, title: 'JWT tidak punya klaim "exp".' });
    } else if (Date.now() / 1000 > jwt.payload.exp) {
      checks.push({ type: 'jwt-expired', severity: SEV.INFO, title: 'JWT expired - host seharusnya menolak.' });
    }
    if (!jwt.payload.iss || !jwt.payload.aud) {
      checks.push({ type: 'jwt-missing-claims', severity: SEV.LOW, title: 'JWT kurang iss/aud (risiko token confusion).' });
    }
    for (const c of checks) {
      ctx.addFinding({
        type: c.type,
        severity: c.severity,
        title: c.title,
        evidence: { header: jwt.header, payload: jwt.payload },
        recommendation: 'Gunakan library JWT resmi, ikat iss/aud/exp, nonaktifkan alg:none.',
      });
    }
    ctx.emitEvent('progress', { note: `JWT payload: ${JSON.stringify(jwt.payload)}` });
  }
}

module.exports = { runSession, decodeJwt, auditCookies };