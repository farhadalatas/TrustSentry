import { useEffect, useState } from 'react';
import { API } from '../lib/api.js';

export default function HistoryPage() {
  const [runs, setRuns] = useState(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    fetch(`${API}/history`).then((r) => r.json()).then((d) => setRuns(d.runs)).catch(() => setRuns([]));
  }, []);

  async function open(id) {
    const d = await fetch(`${API}/history/${id}`).then((r) => r.json());
    setSelected(d);
  }

  if (!runs) return <div className="card"><p className="muted">Memuat riwayat...</p></div>;

  return (
    <div className="card">
      <h2>Riwayat Scan</h2>
      {runs.length === 0 && <p className="muted">Belum ada run tersimpan.</p>}
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr><th style={th}>Target</th><th style={th}>Waktu</th><th style={th}>Requests</th><th style={th}>Risk</th><th style={th}></th></tr>
        </thead>
        <tbody>
          {runs.map((r) => (
            <tr key={r.runId}>
              <td style={td}><code>{r.target}</code></td>
              <td style={td}>{new Date(r.finishedAt).toLocaleString()}</td>
              <td style={td}>{r.requests}</td>
              <td style={td}>{(r.summary && r.summary.riskScore ? r.summary.riskScore : 0).toFixed(1)}</td>
              <td style={td}><button onClick={() => open(r.runId)}>Lihat</button></td>
            </tr>
          ))}
        </tbody>
      </table>

      {selected && (
        <div style={{ marginTop: 16 }}>
          <h3>Detail run <code>{selected.runId}</code></h3>
          <p className="muted">Target: {selected.target} &middot; requests: {selected.requests}</p>
          <pre>{JSON.stringify(selected.findings, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

const th = { textAlign: 'left', padding: 8, borderBottom: '1px solid #262b36', color: '#8b93a3', fontSize: 12 };
const td = { padding: 8, borderBottom: '1px solid #262b36' };