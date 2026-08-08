// Mock auth target untuk smoke/integration test.
// BEHAVIOUR=diff (default): forgot-password & login membedakan email valid/invalid (enumeration vuln).
// BEHAVIOUR=same: respon identik untuk kedua email (no enumeration).
const http = require('node:http');

const BEHAVIOUR = process.env.BEHAVIOUR || 'diff';
const PORT = process.env.MOCK_PORT || 3000;

http.createServer((req, res) => {
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    const send = (status, obj) => {
      res.writeHead(status, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=abc; Path=/; HttpOnly',
        'X-Powered-By': 'Express',
      });
      res.end(JSON.stringify(obj));
    };
    if (req.method === 'GET' && req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('mock target ok');
    }
    let parsed = {};
    try { parsed = JSON.parse(body || '{}'); } catch {}
    const email = parsed.email || '';

    if (req.url.startsWith('/api/auth/login')) {
      if (BEHAVIOUR === 'same') return send(401, { error: 'invalid credentials' });
      const ok = email === 'test@lab.dev';
      return ok ? send(200, { token: 'ok' }) : send(401, { error: 'invalid credentials' });
    }
    if (req.url === '/admin' || req.url === '/api/v1' || req.url === '/swagger') {
      return send(200, { hidden: true });
    }
    if (req.url.startsWith('/api/auth/register')) {
      return send(201, { id: 1 });
    }
    if (req.url.startsWith('/api/auth/forgot-password')) {
      if (BEHAVIOUR === 'same') return send(200, { ok: true });
      return email === 'test@lab.dev'
        ? send(200, { ok: true })
        : send(404, { error: 'no user' });
    }
    if (req.url.startsWith('/api/auth/verify-email')) {
      return parsed.otp === '000001'
        ? send(200, { verified: true })
        : send(400, { error: 'OTP_INVALID' });
    }
    if (req.url.startsWith('/api/auth/resend-otp')) {
      return send(200, { sent: true });
    }
    res.writeHead(404).end();
  });
}).listen(PORT, () => console.log(`mock target on :${PORT} (BEHAVIOUR=${BEHAVIOUR})`));