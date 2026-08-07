const { SEV, SEV_SCORE } = require('../lib/severity.js');
const { NOT_TESTED_CATEGORIES } = require('./catalog.js');

function summarize(findings) {
  const counts = {};
  for (const s of Object.values(SEV)) counts[s] = 0;
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  let riskScore = 0;
  for (const f of findings) riskScore += SEV_SCORE[f.severity] || 0;
  return { counts, riskScore, total: findings.length };
}

function toJson(findings, meta) {
  const s = summarize(findings);
  return {
    meta,
    summary: s,
    findings: findings.map((f) => ({
      severity: f.severity,
      title: f.title,
      evidence: f.evidence,
      recommendation: f.recommendation,
    })),
  };
}

function renderHtml(findings, meta) {
  const s = summarize(findings);
  const sevOrder = [SEV.CRITICAL, SEV.HIGH, SEV.MEDIUM, SEV.LOW, SEV.INFO];
  const sevColor = { CRITICAL: '#b91c1c', HIGH: '#dc2626', MEDIUM: '#d97706', LOW: '#ca8a04', INFO: '#2563eb' };
  const rows = findings
    .slice()
    .sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity))
    .map((f) => `
      <tr>
        <td><span style="color:${sevColor[f.severity]}">${f.severity}</span></td>
        <td>${escapeHtml(f.title)}</td>
        <td><pre>${escapeHtml(JSON.stringify(f.evidence || {}, null, 2))}</pre></td>
        <td>${escapeHtml(f.recommendation || '')}</td>
      </tr>`)
    .join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Pentest Report - Auth Workflow</title>
<style>body{font-family:system-ui;margin:2rem;max-width:1000px}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #d1d5db;padding:8px;text-align:left;vertical-align:top}th{background:#f3f4f6}
pre{background:#f9fafb;padding:8px;margin:0;white-space:pre-wrap}
.badge{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px}</style></head><body>
<h1>Auth Workflow Pentest Report</h1>
<p>Target: <b>${escapeHtml((meta && meta.target) || '-')}</b> &middot; ${(meta && meta.date) || ''}</p>
<h2>Ringkasan</h2>
<p>Total temuan: <b>${s.total}</b> &middot; Risk score: <b>${s.riskScore.toFixed(1)}</b></p>
<p>${sevOrder.map((sv) => `<span class="badge" style="background:${sevColor[sv]}">${sv}: ${s.counts[sv] || 0}</span>`).join(' ')}</p>
<table><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Rekomendasi</th></tr>${rows}</table>
<h2>Cakupan Pengujian (Not Tested / Out of Scope)</h2>
<p>Kategori berikut <b>tidak diuji</b> dan berada di luar scope engagement ini:</p>
<ul>${NOT_TESTED_CATEGORIES.map((c) => `<li>${escapeHtml(c)} — tidak diuji</li>`).join('')}</ul>
<p>Catatan: semua pengujian dilakukan terhadap target yang disetujui/dimiliki (authorized scope).</p>
</body></html>`;
}

function escapeHtml(s) {
  return s == null ? '' : String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

module.exports = { summarize, renderReport: toJson, renderHtml };