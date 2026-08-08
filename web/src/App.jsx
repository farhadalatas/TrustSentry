import { useEffect, useRef, useState } from 'react';
import ConfigPage from './pages/ConfigPage.jsx';
import ResultsPage from './pages/ResultsPage.jsx';
import JwtPage from './pages/JwtPage.jsx';
import CliPage from './pages/CliPage.jsx';
import ReportPage from './pages/ReportPage.jsx';
import HistoryPage from './pages/HistoryPage.jsx';
import CatalogPage from './pages/CatalogPage.jsx';
import { post, streamRun } from './lib/api.js';

const TABS = [
  { id: 'config', label: 'Target & Config' },
  { id: 'results', label: 'Hasil Live' },
  { id: 'catalog', label: 'Tool Catalog' },
  { id: 'jwt', label: 'JWT Tool' },
  { id: 'cli', label: 'CLI Tools' },
  { id: 'history', label: 'Riwayat' },
  { id: 'report', label: 'Report' },
];

function loadInitial() {
  const saved = localStorage.getItem('pt-config');
  return saved
    ? { ...JSON.parse(saved), modules: JSON.parse(saved).modules || [] }
    : {
        authorized: false,
        target: 'http://localhost:3000',
        allowPrivate: true,
        modules: ['recon', 'bruteforce', 'otp', 'injection', 'session', 'fuzz'],
        budget: { maxRequests: 200, minDelayMs: 150, sprayMax: 15, otpMax: 200, fuzzMax: 80 },
        auth: {
          email: 'test@lab.dev',
          login: { endpoint: '/api/auth/login', method: 'POST', body: { email: '<USER>', password: '<PASS>' }, successCodes: [200] },
          register: { endpoint: '/api/auth/register', method: 'POST', body: { email: '<USER>', password: '<PASS>', name: 'tester' }, successCodes: [201] },
          forgot: { endpoint: '/api/auth/forgot-password', method: 'POST', body: { email: '<USER>' }, successCodes: [200] },
          verifyOtp: { endpoint: '/api/auth/verify-email', method: 'POST', body: { email: '<USER>', otp: '<OTP>' }, successCodes: [200] },
          resend: { endpoint: '/api/auth/resend-otp', method: 'POST', body: { email: '<USER>' }, successCodes: [200] },
        },
        spray: ['admin123', 'password', 'letmein', '123456'],
      };
}

export default function App() {
  const [tab, setTab] = useState('config');
  const [config, setConfig] = useState(loadInitial);
  const [runId, setRunId] = useState(null);
  const [findings, setFindings] = useState([]);
  const [events, setEvents] = useState([]);
  const [requests, setRequests] = useState(0);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const closeRef = useRef(null);

  useEffect(() => () => closeRef.current && closeRef.current(), []);

  async function startRun(cfg = config) {
    setError('');
    setFindings([]);
    setEvents([]);
    setRequests(0);
    try {
      const { runId: id } = await post('/runs', cfg);
      setRunId(id);
      setRunning(true);
      closeRef.current = streamRun(id, {
        onEvent: (ev) => {
          setEvents((prev) => [...prev.slice(-199), ev]);
          if (ev.type === 'request') setRequests(ev.data.n);
          if (ev.type === 'finding') setFindings((prev) => [...prev, ev.data]);
          if (ev.type === 'done') { setRunning(false); closeRef.current && closeRef.current(); }
        },
      });
      setTab('results');
    } catch (e) {
      setError(e.message);
      setRunning(false);
    }
  }

  function stopRun() {
    if (runId) post(`/runs/${runId}/stop`).catch(() => {});
    closeRef.current && closeRef.current();
    setRunning(false);
  }

  return (
    <div className="app">
      <header>
        <h1>TrustSentry</h1>
        <nav>
          {TABS.map((t) => (
            <button
              key={t.id}
              className={tab === t.id ? 'active' : ''}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>

      {error && <div className="banner err">{error}</div>}
      {running && <div className="banner">Scan berjalan... runId: {runId}</div>}

      <main>
        {tab === 'config' && (
          <>
            <ConfigPage config={config} onChange={setConfig} />
            <div className="card">
              <button
                className="primary"
                disabled={running}
                onClick={() => startRun()}
              >
                {running ? 'Scan sedang berjalan...' : 'Jalankan Scan'}
              </button>
              {!config.authorized && (
                <p className="note">Centang konfirmasi otorisasi di atas sebelum menjalankan scan.</p>
              )}
            </div>
          </>
        )}
        {tab === 'results' && (
          <ResultsPage
            findings={findings}
            events={events}
            requests={requests}
            running={running}
            onStop={stopRun}
          />
        )}
        {tab === 'jwt' && <JwtPage />}
        {tab === 'cli' && <CliPage config={config} onRun={startRun} running={running} />}
        {tab === 'catalog' && <CatalogPage config={config} onRun={startRun} running={running} />}
        {tab === 'history' && <HistoryPage />}
        {tab === 'report' && <ReportPage runId={runId} findings={findings} />}
      </main>
    </div>
  );
}