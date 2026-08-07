const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_COLOR = { CRITICAL: '#b91c1c', HIGH: '#dc2626', MEDIUM: '#d97706', LOW: '#ca8a04', INFO: '#2563eb' };

export default function ResultsPage({ findings, events, requests, running, onStop }) {
  const sorted = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );
  return (
    <div className="card">
      <div className="row">
        <h2>Hasil Live</h2>
        <span className="muted">requests: {requests}</span>
        {running && <button type="button" onClick={onStop}>Stop</button>}
      </div>

      <div className="kpis">
        {SEV_ORDER.map((s) => {
          const n = findings.filter((f) => f.severity === s).length;
          return (
            <div key={s} className="kpi" style={{ borderTopColor: SEV_COLOR[s] }}>
              <b style={{ color: SEV_COLOR[s] }}>{s}</b>
              <span>{n}</span>
            </div>
          );
        })}
      </div>

      <div className="findings">
        {sorted.length === 0 && <p className="muted">Belum ada temuan. Jalankan scan dari tab Target.</p>}
        {sorted.map((f, i) => (
          <div key={i} className="finding" style={{ borderLeftColor: SEV_COLOR[f.severity] }}>
            <span className="sev" style={{ background: SEV_COLOR[f.severity] }}>{f.severity}</span>
            <div>
              <b>{f.title}</b>
              {f.recommendation && <p className="rec">Rekomendasi: {f.recommendation}</p>}
              {f.evidence && (
                <pre>{typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2)}</pre>
              )}
            </div>
          </div>
        ))}
      </div>

      <h3>Log Aktivitas</h3>
      <div className="log">
        {events.map((e, i) => (
          <div key={i} className={`log-line ${e.type}`}>
            <span className="muted">{new Date(e.ts).toLocaleTimeString()}</span>
            <b>[{e.type}]</b> {e.data && (e.data.label || e.data.note || e.data.message || JSON.stringify(e.data))}
          </div>
        ))}
      </div>
    </div>
  );
}