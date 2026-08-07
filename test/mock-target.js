// Temporary mock auth target to smoke-test the pentest tool.
const http = require('node:http');

const OK_CODES = { verifyOtp: ['000001'], login: ['rightpass'] };

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
    if (req.url.startsWith('/api/auth/login')) {
      const pw = parsed.password;
      return pw === '123456'
        ? send201(res, { token: 'ok' })
        : res.writeHead(401, { 'Content-Type': 'application/json' }) && res.end(JSON.stringify({ error: 'invalid credentials' }));
    }
    if (req.url === '/admin' || req.url === '/api/v1' || req.url === '/swagger') {
      return send200(res, { hidden: true });
    }
    if (req.url.startsWith('/api/auth/register')) {
      return send201(res, { id: 1 });
    }
    if (req.url.startsWith('/api/auth/forgot-password')) {
      // NOTE: differentiates valid vs invalid email -> enumeration vuln
      return parsed.email === 'test@lab.dev'
        ? send200(res, { ok: true })
        : res.writeHead(404, { 'Content-Type': 'application/json' }) && res.end(JSON.stringify({ error: 'no user' }));
    }
    if (req.url.startsWith('/api/auth/verify-email')) {
      return parsed.otp === '000001'
        ? send200(res, { verified: true })
        : send400(res, { error: 'OTP_INVALID' });
    }
    if (req.url.startsWith('/api/auth/resend-otp')) {
      return send200(res, { sent: true });
    }
    res.writeHead(404).end();
  });
}).listen(3000, () => console.log('mock target on :3000'));

function send200(res, o) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); }
function send201(res, o) { res.writeHead(201, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); }
function send400(res, o) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); }