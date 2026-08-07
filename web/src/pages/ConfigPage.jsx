import { useState } from 'react';

const MODULES = [
  { id: 'recon', label: 'Recon & Fingerprint', desc: 'Header audit, framework detect, WAF probe' },
  { id: 'bruteforce', label: 'Brute Force & Rate Limit', desc: 'Enumeration, spray, rate-limit bypass' },
  { id: 'otp', label: 'OTP / 2FA', desc: 'Brute bounded, bypass vektor, replay, resend' },
  { id: 'injection', label: 'Input & Injection', desc: 'SQLi, NoSQLi, header inject, XSS' },
  { id: 'session', label: 'Session & JWT', desc: 'Cookie flags, JWT decode & fuzz' },
  { id: 'fuzz', label: 'Endpoint Fuzzing', desc: 'Kotak path discovery (ffuf-style)' },
  { id: 'logic', label: 'Business Logic', desc: 'Disposable email, race condition, mass assignment' },
  { id: 'cli', label: 'CLI Tools (Kali)', desc: 'nmap, nuclei, nikto, sqlmap, hydra' },
];

const DEFAULT_AUTH = {
  email: 'test@lab.dev',
  login: { endpoint: '/api/auth/login', method: 'POST', body: { email: '<USER>', password: '<PASS>' }, successCodes: [200] },
  register: { endpoint: '/api/auth/register', method: 'POST', body: { email: '<USER>', password: '<PASS>', name: 'tester' }, successCodes: [201] },
  forgot: { endpoint: '/api/auth/forgot-password', method: 'POST', body: { email: '<USER>' }, successCodes: [200] },
  verifyOtp: { endpoint: '/api/auth/verify-email', method: 'POST', body: { email: '<USER>', otp: '<OTP>' }, successCodes: [200] },
  resend: { endpoint: '/api/auth/resend-otp', method: 'POST', body: { email: '<USER>' }, successCodes: [200] },
};

const AUTH_FLOWS = [
  { key: 'login', label: 'Login', body: '{"email": "<USER>", "password": "<PASS>"}' },
  { key: 'register', label: 'Register', body: '{"email": "<USER>", "password": "<PASS>", "name": "tester"}' },
  { key: 'forgot', label: 'Forgot Password', body: '{"email": "<USER>"}' },
  { key: 'verifyOtp', label: 'Verify OTP', body: '{"email": "<USER>", "otp": "<OTP>"}' },
  { key: 'resend', label: 'Resend OTP', body: '{"email": "<USER>"}' },
];

export default function ConfigPage({ config, onChange }) {
  const set = (patch) => onChange({ ...config, ...patch });

  return (
    <div className="card">
      <h2>Target & Otorisasi</h2>
      <label className="check">
        <input
          type="checkbox"
          checked={!!config.authorized}
          onChange={(e) => set({ authorized: e.target.checked })}
        />
        <b>Wajib:</b> Saya pemilik / memegang izin resmi untuk menguji target ini (authorized scope).
      </label>
      <label>Target URL</label>
      <input
        value={config.target || ''}
        onChange={(e) => set({ target: e.target.value })}
        placeholder="http://localhost:3000"
      />
      <label className="check">
        <input
          type="checkbox"
          checked={config.allowPrivate !== false}
          onChange={(e) => set({ allowPrivate: e.target.checked })}
        />
        Izinkan target lokal / IP privat (lab & localhost)
      </label>

      <h2>Module</h2>
      <div className="mods">
        {MODULES.map((m) => (
          <label key={m.id} className="mod">
            <input
              type="checkbox"
              checked={(config.modules || []).includes(m.id)}
              onChange={(e) => {
                const cur = config.modules || [];
                set({
                  modules: e.target.checked
                    ? [...cur, m.id]
                    : cur.filter((x) => x !== m.id),
                });
              }}
            />
            <div>
              <b>{m.label}</b>
              <small>{m.desc}</small>
            </div>
          </label>
        ))}
      </div>

      <h2>Budget & Rate</h2>
      <div className="grid">
        <label>Max requests (global)<input type="number" min="1" value={config.budget?.maxRequests || 200} onChange={(e) => set({ budget: { ...config.budget, maxRequests: +e.target.value } })} /></label>
        <label>Delay / request (ms)<input type="number" min="0" value={config.budget?.minDelayMs ?? 150} onChange={(e) => set({ budget: { ...config.budget, minDelayMs: +e.target.value } })} /></label>
        <label>Spray max<input type="number" value={config.budget?.sprayMax ?? 15} onChange={(e) => set({ budget: { ...config.budget, sprayMax: +e.target.value } })} /></label>
        <label>OTP brute (input count)<input type="number" value={config.budget?.otpMax ?? 200} onChange={(e) => set({ budget: { ...config.budget, otpMax: +e.target.value } })} /></label>
        <label>Fuzz paths (max)<input type="number" value={config.budget?.fuzzMax ?? 80} onChange={(e) => set({ budget: { ...config.budget, fuzzMax: +e.target.value } })} /></label>
      </div>

      <h2>Auth Flow & Akun Uji</h2>
      <label>Email akun uji</label>
      <input value={config.auth?.email ?? ''} onChange={(e) => set({ auth: { ...config.auth, email: e.target.value } })} />
      {AUTH_FLOWS.map((f) => (
        <FlowEditor
          key={f.key}
          title={f.label}
          flow={config.auth?.[f.key] || AUTH_FLOWS[f.key]}
          onChange={(flow) => set({ auth: { ...config.auth, [f.key]: flow } })}
          onRemove={() => {
            const a = { ...config.auth };
            delete a[f.key];
            set({ auth: a });
          }}
        />
      ))}

      <h2>Custom Headers (opsional, JSON)</h2>
      <p className="note">Dikirim di semua request. Contoh: <code>{'{"Authorization": "Bearer <token>"}'}</code></p>
      <textarea
        rows={3}
        value={config.headers ? JSON.stringify(config.headers, null, 2) : ''}
        onChange={(e) => {
          try { set({ headers: JSON.parse(e.target.value) }); }
          catch { /* biarkan, akan jadi invalid */ }
        }}
        placeholder={'{ "Authorization": "Bearer eyJ..." }'}
      />

      <h2>Wordlist Spray (1 per baris)</h2>
      <textarea
        rows={4}
        value={(config.spray || []).join('\n')}
        onChange={(e) => set({ spray: e.target.value.split('\n').filter(Boolean) })}
        placeholder={'admin123\npassword\nletmein'}
      />

      <h2>JWT Token (opsional, untuk modul session)</h2>
      <input
        value={config.jwt?.token ?? ''}
        onChange={(e) => set({ jwt: { token: e.target.value } })}
        placeholder="eyJhbGciOi..."
      />

      <h2>CLI Tool (opsional, modul cli)</h2>
      <label>Tool</label>
      <select
        value={config.cli?.toolName ?? 'nmap'}
        onChange={(e) => set({ cli: { ...config.cli, toolName: e.target.value } })}
      >
        <option value="nmap">nmap</option>
        <option value="nuclei">nuclei</option>
        <option value="nikto">nikto</option>
        <option value="sqlmap">sqlmap</option>
        <option value="hydra">hydra</option>
      </select>
      <label>Ports (nmap)</label>
      <input value={config.cli?.ports ?? '80,443,22,3000,8080'} onChange={(e) => set({ cli: { ...config.cli, ports: e.target.value } })} />
      <br/><br/>
      <button type="button" onClick={() => localStorage.setItem('pt-config', JSON.stringify(config))}>Simpan konfigurasi</button>
    </div>
  );
}

function FlowEditor({ title, flow, onChange }) {
  const update = (p) => onChange({ ...flow, ...p });
  return (
    <details className="flow">
      <summary>{title}</summary>
      <div className="grid">
        <label>Endpoint<input value={flow?.endpoint || ''} onChange={(e) => update({ endpoint: e.target.value })} /></label>
        <label>Method
          <select value={flow?.method || 'POST'} onChange={(e) => update({ method: e.target.value })}>
            <option>POST</option><option>GET</option><option>PUT</option><option>PATCH</option>
          </select>
        </label>
        <label>Content-Type
          <select value={flow?.contentType || 'application/json'} onChange={(e) => update({ contentType: e.target.value })}>
            <option value="application/json">application/json</option>
            <option value="application/x-www-form-urlencoded">form-urlencoded</option>
          </select>
        </label>
        <label>Success codes (comma) e.g. 200,201
          <input
            value={(flow?.successCodes || []).join(',')}
            onChange={(e) => update({ successCodes: e.target.value.split(',').map((s) => +s).filter((n) => !isNaN(n)) })}
          />
        </label>
        <label className="wide">Body (pakai &lt;USER&gt;, &lt;PASS&gt;, &lt;OTP&gt;)
          <textarea rows={2} value={typeof flow?.body === 'string' ? flow.body : JSON.stringify(flow?.body || {})}
            onChange={(e) => update({ body: tryParse(e.target.value) })} />
        </label>
      </div>
    </details>
  );
}

function tryParse(s) {
  try { return JSON.parse(s); } catch { return s; }
}