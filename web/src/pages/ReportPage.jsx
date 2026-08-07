import { useState } from 'react';
import { API } from '../lib/api.js';

export default function ReportPage({ runId, findings }) {
  const [data, setData] = useState(null);

  async function load() {
    const res = await fetch(`${API}/runs/${runId}`);
    setData(await res.json());
  }

  if (!findings || findings.length === 0) {
    return (
      <div className="card">
        <h2>Report</h2>
        <p className="muted">Belum ada run selesai. Jalankan scan dulu.</p>
      </div>
    );
  }

  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const riskScore = findings.reduce((acc, f) => acc + ({ CRITICAL: 9, HIGH: 7.5, MEDIUM: 5, LOW: 3, INFO: 0.5 }[f.severity] || 0), 0);

  return (
    <div className="card">
      <div className="row">
        <h2>Report Pentest</h2>
        <span>
          <a className="btn" href={`${API}/runs/${runId}/report?format=html`} target="_blank" rel="noreferrer">Export HTML</a>{' '}
          <a className="btn" href={`${API}/runs/${runId}/report`} target="_blank" rel="noreferrer">Export JSON</a>
        </span>
      </div>
      <p>Run: <code>{runId}</code> &middot; Total temuan: <b>{findings.length}</b> &middot; Risk score: <b>{riskScore.toFixed(1)}</b></p>
      <div className="kpis">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => (
          <div key={s} className="kpi"><b>{s}</b><span>{counts[s] || 0}</span></div>
        ))}
      </div>
      <p className="note">Untuk hasil lengkap + summary server-side, klik tombol export di atas.</p>
    </div>
  );
}