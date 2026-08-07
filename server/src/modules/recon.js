const { SEV } = require('../lib/severity.js');

const HEADER_POLICY = {
  'strict-transport-security': { sev: 'LOW', hint: 'Aktifkan HSTS untuk mencegah downgrade & cookie tanpa TLS' },
  'x-frame-options': { sev: 'LOW', hint: 'Tambahkan X-Frame-Options: DENY / SAMEORIGIN' },
  'x-content-type-options': { sev: 'LOW', hint: 'Set x-content-type-options: nosniff' },
  'content-security-policy': { sev: 'LOW', hint: 'Definisikan CSP' },
  'referrer-policy': { sev: 'INFO', hint: 'Set referrer-policy' },
  'permissions-policy': { sev: 'INFO', hint: 'Batasi fitur browser via permissions-policy' },
  'x-xss-protection': { sev: 'INFO', hint: 'Deprecated; gunakan CSP + sanitasi output' },
};

async function runRecon(ctx, cfg) {
  const { url } = ctx.target;
  const base = cfg.baseUrl || url.origin;

  ctx.emitEvent('module', { name: 'recon', label: 'Recon & Fingerprint' });

  // 1. header security audit
  const baseRes = await ctx.http({ url: base, method: 'GET' });
  const hdrs = baseRes.headers || {};
  for (const [name, policy] of Object.entries(HEADER_POLICY)) {
    if (!hdrs[name]) {
      ctx.addFinding({
        id: 'recon-missing-header',
        sev: policy.sev,
        title: `Header keamanan hilang: ${name}`,
        evidence: { header: name, responseHeaders: hdrs },
        recommendation: policy.hint,
      });
    } else {
      ctx.addFinding({
        id: 'recon-header-ok',
        sev: 'INFO',
        title: `Header ${name} ada`,
        evidence: { header: name, value: hdrs[name] },
      });
    }
  }

  // 2. framework fingerprint
  const fp = { poweredBy: hdrs['x-powered-by'], server: hdrs['server'] };
  const cookieHints = {
    laravel_session: 'Laravel/PHP',
    'connect.sid': 'Express/Node',
    nextauth: 'NextAuth',
    JSESSIONID: 'Java/Tomcat',
    'ASP.NET': 'ASP.NET',
    csrftoken: 'Django',
  };
  const setCookies = (hdrs['set-cookie'] || '');
  for (const [k, label] of Object.entries(cookieHints)) {
    if (setCookies.includes(k) || fp.poweredBy?.includes(label)) {
      fp.detected = label;
      break;
    }
  }
  if (fp.detected || fp.poweredBy || fp.server) {
    ctx.addFinding({
      id: 'recon-fingerprint',
      sev: 'INFO',
      title: `Fingerprint tekonologi: ${fp.detected || fp.poweredBy || fp.server}`,
      evidence: fp,
      recommendation: 'Sembunyikan server/X-Powered-By header di production',
    });
  }

  // 3. WAF detection via common payloads
  const probePayloads = {
    sqli: "' OR '1'='1",
    traversal: '../../../../etc/passwd',
    xss: '<script>alert(1)</script>',
  };
  for (const [name, payload] of Object.entries(probePayloads)) {
    const probeUrl = `${base}/?waf=${encodeURIComponent(payload)}`;
    const r = await ctx.http({ url: probeUrl, method: 'GET' });
    if (r.status === 403) {
      ctx.addFinding({
        id: 'recon-waf',
        sev: 'INFO',
        title: `Potensi WAF terdeteksi (${name} payload → 403)`,
        evidence: { payload, status: r.status },
      });
      break;
    }
  }

  return ctx.findings.filter((f) => f.type && f.type.startsWith('recon'));
}

module.exports = { runRecon };