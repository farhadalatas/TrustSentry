import { API } from '../lib/api.js';
import { buildPdf } from '../lib/reportPdf.js';

export default function ReportPage({ runId, findings }) {
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
  const riskScore = findings.reduce(
    (acc, f) => acc + ({ CRITICAL: 9, HIGH: 7.5, MEDIUM: 5, LOW: 3, INFO: 0.5 }[f.severity] || 0),
    0
  );

  function downloadPdf() {
    let target = '—';
    try {
      target = JSON.parse(localStorage.getItem('pt-config') || '{}').target || '—';
    } catch {}
    const doc = buildPdf({
      findings,
      target,
      date: new Date().toISOString(),
      runId,
    });
    doc.save(`pentest-report-${runId || 'final'}.pdf`);
  }

  return (
    <div className="card">
      <div className="row wrap">
        <h2>Report Pentest</h2>
        <span className="btn-row">
          <button className="primary" onClick={downloadPdf}>Export PDF</button>
          <a className="btn" href={`${API}/runs/${runId}/report?format=html`} target="_blank" rel="noreferrer">Export HTML</a>
          <a className="btn" href={`${API}/runs/${runId}/report`} target="_blank" rel="noreferrer">Export JSON</a>
        </span>
      </div>
      <p className="muted">
        Run: <code>{runId}</code> &middot; Total temuan: <b>{findings.length}</b> &middot; Risk score:{' '}
        <b>{riskScore.toFixed(1)}</b>
      </p>
      <div className="kpis">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => (
          <div key={s} className="kpi">
            <b>{s}</b>
            <span>{counts[s] || 0}</span>
          </div>
        ))}
      </div>
      <div className="table-wrap">
        <table className="report-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Severity</th>
              <th>Temuan</th>
              <th>Rekomendasi</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={i}>
                <td>{i + 1}</td>
                <td>
                  <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
                </td>
                <td>{f.title}</td>
                <td>{f.recommendation || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
