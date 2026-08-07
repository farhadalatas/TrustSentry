import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

const SEV_COLOR = {
  CRITICAL: [185, 28, 28],
  HIGH: [220, 38, 38],
  MEDIUM: [217, 119, 6],
  LOW: [202, 138, 4],
  INFO: [37, 99, 235],
};
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_SCORE = { CRITICAL: 9, HIGH: 7.5, MEDIUM: 5, LOW: 3, INFO: 0.5 };

export function buildPdf({ findings, target, date, runId, requests }) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const W = doc.internal.pageSize.getWidth();
  const M = 40;

  // ---- Header band ----
  doc.setFillColor(15, 17, 21);
  doc.rect(0, 0, W, 90, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.text('Auth Pentest Report', M, 40);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(180, 186, 199);
  doc.text(`Target   : ${target}`, M, 58);
  doc.text(`Tanggal  : ${new Date(date).toLocaleString('id-ID')}`, M, 72);

  // ---- Risk summary ----
  const counts = {};
  for (const s of SEV_ORDER) counts[s] = 0;
  let riskScore = 0;
  for (const f of findings || []) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    riskScore += SEV_SCORE[f.severity] || 0;
  }

  let y = 118;
  doc.setTextColor(15, 17, 21);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Ringkasan Risiko', M, y);
  y += 8;
  autoTable(doc, {
    startY: y,
    margin: { left: M, right: M },
    head: [['Total Temuan', 'Risk Score', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']],
    body: [[String(findings.length), riskScore.toFixed(1), counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW, counts.INFO]],
    headStyles: { fillColor: [23, 26, 33], fontSize: 8 },
    bodyStyles: { fontSize: 10, halign: 'center' },
    theme: 'grid',
  });
  y = doc.lastAutoTable.finalY + 24;

  // ---- Findings table ----
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Daftar Temuan', M, y);
  y += 8;

  const rows = [...findings]
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    .map((f, i) => [
      i + 1,
      f.severity,
      f.title || '',
      f.recommendation || '',
    ]);

  autoTable(doc, {
    startY: y,
    margin: { left: M, right: M },
    head: [['#', 'Severity', 'Temuan', 'Rekomendasi']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [37, 47, 62], fontSize: 8 },
    bodyStyles: { fontSize: 7.5 },
    columnStyles: {
      0: { cellWidth: 22, halign: 'center' },
      1: { cellWidth: 62, halign: 'center' },
      2: { cellWidth: 200 },
      3: { cellWidth: 'auto' },
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 1) {
        const sev = data.cell.raw;
        const rgb = SEV_COLOR[sev] || [100, 116, 139];
        data.cell.styles.fillColor = rgb;
        data.cell.styles.textColor = [255, 255, 255];
        data.cell.styles.fontStyle = 'bold';
      }
    },
  });

  // ---- Evidence appendix ----
  let ey = doc.lastAutoTable.finalY + 24;
  const serious = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  if (serious.length) {
    if (ey + serious.length * 80 > doc.internal.pageSize.getHeight() - 40) {
      doc.addPage();
      ey = 40;
    }
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('Lampiran - Bukti Temuan Kritis', M, ey);
    ey += 10;
    for (const f of serious) {
      const lines = [
        `[${f.severity}] ${f.title}`,
        `Rekomendasi: ${f.recommendation || '-'}`,
        `Evidence   : ${truncate(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence || {}), 180)}`,
      ];
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      lines.forEach((ln) => {
        doc.text(ln, M, ey);
        ey += 14;
      });
      ey += 6;
    }
  }

  // ---- Footer ----
  const pageCount = doc.getNumberOfPages();
  for (let p = 1; p <= pageCount; p++) {
    doc.setPage(p);
    doc.setFontSize(7);
    doc.setTextColor(140, 148, 160);
    doc.setFont('helvetica', 'normal');
    doc.text(
      `Auth Pentest Report - ${target}  |  Halaman ${p} / ${pageCount}`,
      M,
      doc.internal.pageSize.getHeight() - 20
    );
  }

  return doc;
}

function truncate(s, n) {
  const str = String(s || '');
  return str.length > n ? str.slice(0, n) + '...' : str;
}
