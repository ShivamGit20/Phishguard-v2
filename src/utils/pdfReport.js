// PDF report generator using jsPDF

import { jsPDF } from 'jspdf';

export function generateReport(threatResult, headerResult, urlResult, contentResult, attachmentResult) {
  const doc = new jsPDF();
  const margin = 20;
  let y = margin;

  // Title
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 150, 200);
  doc.text('PhishGuard v2 — Analysis Report', margin, y);
  y += 12;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(120, 120, 120);
  doc.text(`Generated: ${new Date().toLocaleString()}`, margin, y);
  y += 10;

  // Divider
  doc.setDrawColor(0, 150, 200);
  doc.setLineWidth(0.5);
  doc.line(margin, y, 190, y);
  y += 10;

  // Threat Score
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  const scoreColor = threatResult.level === 'critical' ? [255, 59, 92] : threatResult.level === 'high' ? [255, 107, 107] : threatResult.level === 'medium' ? [255, 171, 0] : [0, 230, 118];
  doc.setTextColor(...scoreColor);
  doc.text(`Threat Score: ${threatResult.score}/100 — ${threatResult.label}`, margin, y);
  y += 10;

  doc.setFontSize(10);
  doc.setTextColor(60, 60, 60);
  doc.text(`Total Findings: ${threatResult.totalFindings} (${threatResult.criticalCount} critical, ${threatResult.highCount} high, ${threatResult.mediumCount} medium, ${threatResult.lowCount} low)`, margin, y);
  y += 8;

  // Subject
  if (headerResult?.subject) {
    doc.text(`Subject: ${headerResult.subject}`, margin, y);
    y += 6;
  }
  if (headerResult?.from) {
    doc.text(`From: ${headerResult.from}`, margin, y);
    y += 6;
  }
  y += 6;

  // Findings
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('Findings', margin, y);
  y += 8;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');

  for (const f of threatResult.allFindings) {
    if (y > 270) { doc.addPage(); y = margin; }

    const sevLabel = `[${f.severity.toUpperCase()}]`;
    const sevColors = { critical: [255, 59, 92], high: [255, 107, 107], medium: [255, 171, 0], low: [0, 200, 100] };
    doc.setTextColor(...(sevColors[f.severity] || [0, 0, 0]));
    doc.setFont('helvetica', 'bold');
    doc.text(`${sevLabel} ${f.title}`, margin, y);
    y += 5;

    doc.setTextColor(80, 80, 80);
    doc.setFont('helvetica', 'normal');
    const lines = doc.splitTextToSize(f.description, 170);
    doc.text(lines, margin, y);
    y += lines.length * 4.5 + 4;
  }

  doc.save('phishguard-report.pdf');
}
