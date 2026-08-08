const { SEV } = require('../lib/severity.js');
const { applyTemplate, fingerprint } = require('../lib/template.js');
const { isSuccess } = require('../lib/success.js');

function resolveUrl(base, endpoint) {
  if (!endpoint) return base;
  if (endpoint.startsWith('http')) return endpoint;
  return new URL(endpoint, base).toString();
}

/** Build an HTTP callable that injects <USER>/<PASS>/<OTP> vars + extra headers. */
function buildCall(ctx, flow) {
  const method = (flow.method || 'POST').toUpperCase();
  const contentType = flow.contentType || 'application/json';
  const url = resolveUrl(ctx.target.url.origin, flow.endpoint);
  return async (vars, extra = {}) => {
    const body = applyTemplate(flow.body, vars);
    return ctx.http({
      url,
      method,
      headers: {
        'Content-Type': contentType,
        ...((ctx.cfg && ctx.cfg.headers) || {}),
        ...extra,
      },
      body:
        contentType === 'application/x-www-form-urlencoded'
          ? new URLSearchParams(body).toString()
          : JSON.stringify(body),
    });
  };
}

function pwdStrength(pw) {
  return pw.length < 8 || /^(password|admin|123456|qwerty|letmein|test123)$/i.test(pw)
    ? SEV.HIGH
    : SEV.MEDIUM;
}

async function runBruteforce(ctx, cfg) {
  const auth = cfg.auth || {};
  ctx.emitEvent('module', { name: 'bruteforce', label: 'Brute Force & Rate Limit' });
  const sprayMax = (ctx.config.budget && ctx.config.budget.sprayMax) || 15;
  let lockoutBypassFound = false;

// 1) USER ENUMERATION: bandingkan respon valid vs invalid email per flow.
  if (auth.forgot && auth.login) {
    const forgot = buildCall(ctx, auth.forgot);
    const login = buildCall(ctx, auth.login);
    const invalidEmail = 'nobody_' + Date.now() + '@example.org';
    for (const fn of [
      { name: 'forgot-password', call: forgot },
      { name: 'login', call: login },
    ]) {
      const invalidRes = await fn.call({ '<USER>': invalidEmail, '<PASS>': 'wrongpass1!' });
      const validRes = await fn.call({ '<USER>': auth.email, '<PASS>': 'wrongpass1!' });
      const fpi = fingerprint(invalidRes);
      const fpv = fingerprint(validRes);
      if (fpi === fpv) {
        ctx.emitEvent('progress', {
          note: `${fn.name}: respon email valid & invalid identik (tidak ada enumeration)`,
        });
        continue;
      }
      ctx.addFinding({
        type: 'brute-enumeration',
        severity: SEV.MEDIUM,
        title: `Enumeration user: ${fn.name} membedakan email valid/invalid`,
        evidence: { flow: fn.name, validFingerprint: fpv, invalidFingerprint: fpi },
        recommendation:
          'Seragamkan pesan, status, dan timing untuk email valid vs invalid.',
      });
    }
  }

  // 2) PASSWORD SPRAYING - bounded, common passwords vs one account.
  if (auth.login) {
    const login = buildCall(ctx, auth.login);
    const spray = (cfg.spray || []).slice(0, sprayMax);
    for (const pw of spray) {
      const res = await login({ '<USER>': auth.email, '<PASS>': pw });
      if (isSuccess(auth.login, res)) {
        ctx.addFinding({
          type: 'brute-spray-hit',
          severity: pwdStrength(pw),
          title: `Password spray berhasil: ${auth.email} : "${pw}"`,
          evidence: { status: res.status, body: res.body.slice(0, 300) },
          recommendation:
            'Terapkan password policy kuat dan rate limit berbasis akun.',
        });
      }
      ctx.emitEvent('progress', { note: `spray "${pw}" -> ${res.status}` });
    }
  }

  // 3) RATE-LIMIT BYPASS via spoofed proxy headers (small, bounded loop).
  if (auth.login) {
    const login = buildCall(ctx, auth.login);
    for (const [header, values] of Object.entries({
      'X-Forwarded-For': ['1.2.3.4', '203.0.113.5'],
      'X-Real-IP': ['203.0.113.6'],
      'X-Client-IP': ['203.0.113.7'],
    })) {
      for (const val of values) {
        const res = await login(
          { '<USER>': auth.email, '<PASS>': 'wrongpassXX!' },
          { [header]: val }
        );
        if (isSuccess(auth.login, res) && !lockoutBypassFound) {
          ctx.addFinding({
            type: 'rate-limit-bypass',
            severity: SEV.HIGH,
            title: `Rate limit dibypass via header ${header}: ${val}`,
            evidence: { header, value: val },
            recommendation: `Jangan percayai ${header} tanpa whitelist proxy; batasi per akun dan per IP.`,
          });
          lockoutBypassFound = true;
        }
      }
    }
  }

  // 4) TIMING ATTACK - bandingkan durasi login user valid vs invalid.
  //    (Side-channel untuk user enumeration via BCrypt/Argon2 hashing time.)
  if (auth.login) {
    const login = buildCall(ctx, auth.login);
    async function medianLatency(user, n = 5) {
      const times = [];
      for (let i = 0; i < n; i++) {
        const t0 = Date.now();
        await login({ '<USER>': user, '<PASS>': 'wrongpassXX!' });
        times.push(Date.now() - t0);
      }
      const s = times.sort((a, b) => a - b);
      return { median: s[Math.floor(s.length / 2)], samples: times };
    }
    const threshold = (ctx.config.timing && ctx.config.timing.thresholdMs) || 200;
    const valid = await medianLatency(auth.email, 5);
    const invalid = await medianLatency('ghost_' + Date.now() + '@example.org', 5);
    if (valid.median - invalid.median > threshold) {
      ctx.addFinding({
        type: 'timing-enumeration',
        severity: SEV.MEDIUM,
        title: `Timing attack: login user valid ~${valid.median}ms vs invalid ~${invalid.median}ms`,
        evidence: { validUserMedianMs: valid.median, invalidUserMedianMs: invalid.median, sample: { valid, invalid } },
        recommendation: 'Hash fake user juga (dummy verify) supaya durasi login seragam.',
      });
    } else {
      ctx.emitEvent('progress', { note: `timing valid~${valid.median}ms invalid~${invalid.median}ms (tidak signifikan)` });
    }
  }
}

module.exports = { runBruteforce, buildCall, applyTemplate, resolveUrl };