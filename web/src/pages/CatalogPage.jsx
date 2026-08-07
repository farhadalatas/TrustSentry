import { useEffect, useState } from 'react';
import { API } from '../lib/api.js';

const RUNNABLE = ['nmap', 'nuclei', 'nikto', 'sqlmap', 'hydra'];

export default function CatalogPage({ config, onRun, running }) {
  const [data, setData] = useState(null);
  const [q, setQ] = useState('');
  const [recQ, setRecQ] = useState('');
  const [rec, setRec] = useState(null);

  useEffect(() => {
    fetch(`${API}/catalog`).then((r) => r.json()).then(setData).catch(() => setData({ categories: [], tools: [] }));
  }, []);

  function runTool(tool) {
    onRun(
      {
        ...config,
        modules: ['cli'],
        cli: { toolName: tool.name, ports: config.cli?.ports || '80,443,22,3000,8080', severity: 'high' },
      },
      tool.name
    );
  }

  async function recommend() {
    const r = await fetch(`${API}/recommend?q=${encodeURIComponent(recQ)}`).then((x) => x.json());
    setRec(r);
  }

  const filtered = data ? (q ? data.tools.filter((t) =>
    (`${t.name} ${t.desc} ${t.category} ${(t.tags || []).join(' ')}`).toLowerCase().includes(q.toLowerCase())
  ) : data.tools) : [];

  return (
    <div>
      <div className="card">
        <h2>Tool Catalog <span className="muted">({data ? data.tools.length : '...'} tools)</span></h2>
        <div className="grid">
          <label className="wide">Cari tool (nama/deskripsi/tag)</label>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="misal: sqlmap, xss, wordlist" />
        </div>
        {data && (
          <div className="kpis">
            {data.categories.map((c) => (
              <div key={c.id} className="kpi" style={{ borderTopColor: '#4f8cff' }}>
                <b>{c.label}</b>
                <span>{c.count}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h2>Rekomendasi (natural language)</h2>
        <div className="row wrap">
          <input value={recQ} onChange={(e) => setRecQ(e.target.value)}
            placeholder="ketik intent, misal: cari subdomain dari target" />
          <button onClick={recommend}>Rekomendasi</button>
        </div>
        {rec && (
          <p className="note">
            Intent: {rec.intent.length ? rec.intent.join(', ') : '(tidak cocok)'} → tools:{' '}
            {rec.tools.length ? rec.tools.map((t) => t.name).join(', ') : 'tidak ada'}
          </p>
        )}
      </div>

      <div className="card">
        <h2>{q ? `Hasil pencarian "${q}"` : 'Semua Tools'}</h2>
        <div className="mods">
          {filtered.map((t) => (
            <div key={t.name} className="mod" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <div className="row">
                <b>{t.name}</b>
                {t.installed ? (
                  <span className="sev-badge sev-INFO">installed</span>
                ) : (
                  <span className="sev-badge sev-LOW">not-installed</span>
                )}
              </div>
              <small>{t.desc} · <i>{t.category}</i></small>
              <small className="muted">{t.install}</small>
              {RUNNABLE.includes(t.name) ? (
                <button disabled={running || !config.authorized} onClick={() => runTool(t.name)}>
                  Run via tool
                </button>
              ) : (
                <span className="muted" style={{ fontSize: 11 }}>Auto-run nggak didukung — jalankan manual via perintah install di atas.</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}