const { SEV } = require('../lib/severity.js');

// Wordlist umum untuk path auth (ffuf-style). Sesuaikan dengan target.
const DEFAULT_WORDLIST = [
  '/', '/login', '/register', '/logout', '/signin', '/signup', '/forgot-password',
  '/reset-password', '/verify-email', '/api', '/api/v1', '/api/v2', '/api/auth',
  '/api/auth/login', '/api/auth/register', '/api/users', '/api/me', '/api/session',
  '/admin', '/admin/login', '/admin/dashboard', '/dashboard', '/profile', '/settings',
  '/api/otp', '/api/verify', '/api/resend', '/graphql', '/swagger', '/docs', '/health',
  '/robots.txt', '/sitemap.xml', '/.env', '/config.json', '/backup', '/users', '/account',
];

async function runFuzz(ctx, cfg) {
  const auth = cfg.auth || {};
  ctx.emitEvent('module', { name: 'fuzz', label: 'Endpoint Fuzzing' });
  const startIdx = ctx.findings.length;

  const base = ctx.target.url.origin;
  const wordlist = (cfg.wordlist || DEFAULT_WORDLIST).slice(0, (ctx.config.budget && ctx.config.budget.fuzzMax) || 80);

  // Baseline: status dari request GET ke root tanpa kata.
  const baseline = await ctx.http({ url: base + '/', method: 'GET' });
  ctx.emitEvent('progress', { note: `baseline GET / -> ${baseline.status}` });

  const found = [];
  for (const p of wordlist) {
    const res = await ctx.http({ url: new URL(p, base).toString(), method: 'GET' });
    if (res.status && res.status < 400 && res.status !== baseline.status) {
      found.push({ path: p, status: res.status, len: (res.body || '').length });
    }
  }

  if (found.length) {
    const sensitive = found.filter((f) => f.status === 200 && /(env|config|backup|swagger|docs|graphql)/i.test(f.path));
    ctx.addFinding({
      type: 'fuzz-discovered',
      severity: sensitive.length ? SEV.HIGH : SEV.MEDIUM,
      title: `${found.length} endpoint ditemukan via fuzzing${sensitive.length ? ' (termasuk file sensitif)' : ''}`,
      evidence: { endpoints: found, sensitive: sensitive.map((s) => s.path) },
      recommendation: 'Tutup endpoint internal/sensitif; lakukan authz check server-side di semua endpoint.',
    });
  } else {
    ctx.addFinding({
      type: 'fuzz-none',
      severity: SEV.INFO,
      title: `Tidak ada endpoint baru dari ${wordlist.length} path (semua ${baseline.status}).`,
    });
  }

  return ctx.findings.slice(startIdx);
}

module.exports = { runFuzz, DEFAULT_WORDLIST };