/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Server-side PDF report builder using PDFKit.
 *
 * A clean, branded deliverable: a dark Audit Forge cover (mirroring the web /
 * OG-card identity), then clean white interior pages with a robust,
 * non-overlapping finding renderer and an auditforge.org footer on every page.
 */

import PDFDocument from 'pdfkit';
import { AuditReport, ConsensusFinding, Severity } from '../types/finding';

// ── palette ─────────────────────────────────────────────────────────────
const BRAND = {
  dark:    '#0A0C0F',   // cover background
  green:   '#3BDDA4',   // brand mint (on dark)
  greenDk: '#0B8B5F',   // brand green (on white — legible)
  ink:     '#181A1D',
  muted:   '#6B7280',
  faint:   '#9AA0A8',
  line:    '#E5E7EB',
  tintBg:  '#F7FAF9',
  onDark:  '#EEF0F2',
  onDarkMuted: '#8B929C',
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#DC2626',
  high:     '#EA580C',
  medium:   '#D97706',
  low:      '#0891B2',
  info:     '#6B7280',
};

/** Score → tier (matches the web report + OG card). */
function tier(score: number): { color: string; label: string } {
  if (score >= 85) return { color: BRAND.green, label: 'LOW RISK' };
  if (score >= 70) return { color: '#86D45A', label: 'HARDENING ADVISED' };
  if (score >= 50) return { color: '#F4A52A', label: 'ELEVATED RISK' };
  return { color: '#F36A6E', label: 'HIGH RISK' };
}

function contractName(report: AuditReport): string {
  const s = (report.source || {}) as { contractName?: string; label?: string };
  let raw = (s.contractName || s.label || '').replace(/^github:/i, '');
  if (!raw || /^paste/i.test(raw) || raw === 'pasted-source') return 'Submitted contract';
  if (raw.includes('/')) raw = raw.split('/').filter(Boolean).pop() || raw;
  return raw.length > 42 ? raw.slice(0, 41) + '…' : raw;
}

const PAGE = { w: 612, h: 792, m: 56 };           // LETTER
const CONTENT_W = PAGE.w - PAGE.m * 2;

export function buildPdf(report: AuditReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'LETTER',
      margins: { top: PAGE.m, bottom: PAGE.m + 24, left: PAGE.m, right: PAGE.m },
      bufferPages: true,
      info: {
        Title: `Audit Forge Report — ${contractName(report)}`,
        Author: 'Audit Forge',
        Subject: 'Smart Contract Security Audit',
        CreationDate: new Date(report.createdAt),
      },
    });

    const chunks: Buffer[] = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    drawCover(doc, report);
    drawSummary(doc, report);
    if (report.aiBrief) drawBrief(doc, report);
    drawFindings(doc, report);
    drawAppendix(doc, report);
    drawFooters(doc);   // page numbers + auditforge.org on every non-cover page

    doc.end();
  });
}

// ── COVER (dark, branded) ─────────────────────────────────────────────────
function drawCover(doc: PDFKit.PDFDocument, report: AuditReport) {
  const t = tier(report.score);
  // The cover is entirely absolute-positioned; drop the bottom margin so the
  // bottom band (drawn below the content margin) doesn't trigger blank pages.
  doc.page.margins.bottom = 0;
  doc.rect(0, 0, PAGE.w, PAGE.h).fill(BRAND.dark);
  // top accent
  doc.rect(0, 0, PAGE.w, 6).fill(t.color);

  // wordmark: diamond + text
  const lx = PAGE.m, ly = 64;
  doc.save();
  doc.lineWidth(1.6).strokeColor(t.color)
     .moveTo(lx + 13, ly).lineTo(lx + 26, ly + 13).lineTo(lx + 13, ly + 26).lineTo(lx, ly + 13).closePath().stroke();
  doc.lineWidth(1.3).strokeColor(t.color)
     .moveTo(lx + 13, ly + 6).lineTo(lx + 20, ly + 13).lineTo(lx + 13, ly + 20).lineTo(lx + 6, ly + 13).closePath().stroke();
  doc.restore();
  doc.fillColor(BRAND.onDark).font('Helvetica-Bold').fontSize(17)
     .text('AUDIT FORGE', lx + 40, ly + 1, { characterSpacing: 3 });
  doc.fillColor(BRAND.onDarkMuted).font('Helvetica').fontSize(8)
     .text('MULTI-ENGINE AUDIT CONSOLE', lx + 40, ly + 22, { characterSpacing: 2 });
  doc.fillColor(BRAND.onDarkMuted).font('Helvetica').fontSize(10)
     .text('auditforge.org', PAGE.w - PAGE.m - 120, ly + 6, { width: 120, align: 'right', characterSpacing: 1 });

  // eyebrow + contract name
  doc.fillColor(t.color).font('Helvetica-Bold').fontSize(11)
     .text('SMART-CONTRACT SECURITY AUDIT', PAGE.m, 188, { characterSpacing: 3 });
  doc.fillColor(BRAND.onDark).font('Helvetica-Bold').fontSize(34)
     .text(contractName(report), PAGE.m, 212, { width: CONTENT_W });
  doc.fillColor(BRAND.onDarkMuted).font('Helvetica').fontSize(10)
     .text(report.source.label, PAGE.m, doc.y + 4, { width: CONTENT_W });

  // score block
  const sy = 320;
  doc.fillColor(t.color).font('Helvetica-Bold').fontSize(96)
     .text(String(report.score), PAGE.m, sy, { lineBreak: false });
  const scoreW = doc.widthOfString(String(report.score));
  doc.fillColor(BRAND.onDarkMuted).font('Helvetica').fontSize(18)
     .text('/ 100', PAGE.m + scoreW + 12, sy + 52, { lineBreak: false });
  doc.fillColor(t.color).font('Helvetica-Bold').fontSize(13)
     .text(`${report.grade}   ·   ${t.label}`, PAGE.m, sy + 108, { characterSpacing: 1 });

  // meter
  const my = sy + 134, mw = CONTENT_W;
  doc.roundedRect(PAGE.m, my, mw, 6, 3).fill('#20262E');
  doc.roundedRect(PAGE.m, my, Math.max(6, mw * Math.min(100, report.score) / 100), 6, 3).fill(t.color);

  // stats grid
  const counts = countBySeverity(report.consensusFindings);
  const stats: Array<[string, string]> = [
    ['ENGINES RUN', `${report.toolsRun.length} / 6`],
    ['CONSENSUS FINDINGS', String(report.consensusFindings.length)],
    ['CRITICAL / HIGH', `${counts.critical} / ${counts.high}`],
    ['RAW FINDINGS', String((report.rawFindings || []).length)],
    ['LINES OF CODE', String(report.contract?.lines ?? '—')],
    ['SCAN TIME', `${(report.durationMs / 1000).toFixed(1)}s`],
  ];
  const gy = my + 56, colW = CONTENT_W / 3;
  stats.forEach(([k, v], i) => {
    const cx = PAGE.m + (i % 3) * colW;
    const cyy = gy + Math.floor(i / 3) * 62;
    doc.fillColor(BRAND.onDarkMuted).font('Helvetica').fontSize(8)
       .text(k, cx, cyy, { characterSpacing: 1.5, width: colW - 10 });
    doc.fillColor(BRAND.onDark).font('Helvetica-Bold').fontSize(20)
       .text(v, cx, cyy + 13, { width: colW - 10 });
  });

  // bottom band
  doc.lineWidth(0.5).strokeColor('#222831')
     .moveTo(PAGE.m, PAGE.h - 92).lineTo(PAGE.w - PAGE.m, PAGE.h - 92).stroke();
  doc.fillColor(BRAND.onDarkMuted).font('Helvetica').fontSize(8)
     .text(`Report ID  ${report.id}`, PAGE.m, PAGE.h - 78, { width: CONTENT_W });
  doc.fillColor(BRAND.onDarkMuted).font('Helvetica').fontSize(8)
     .text(`Generated  ${new Date(report.createdAt).toUTCString()}`, PAGE.m, PAGE.h - 64, { width: CONTENT_W });
  doc.fillColor(BRAND.faint).font('Helvetica-Oblique').fontSize(7.5)
     .text('Automated first-pass analysis — not a substitute for a professional manual audit.',
       PAGE.m, PAGE.h - 46, { width: CONTENT_W });
}

// ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
function drawSummary(doc: PDFKit.PDFDocument, report: AuditReport) {
  doc.addPage();
  sectionHeader(doc, 'Executive summary');

  const counts = countBySeverity(report.consensusFindings);
  const multi = report.consensusFindings.filter(c => c.toolCount >= 2).length;
  doc.fillColor(BRAND.ink).font('Helvetica').fontSize(10.5).text(
    `Audit Forge analyzed ${report.contract?.lines ?? 'the submitted'} lines of Solidity with ${report.toolsRun.length} independent engines (${report.toolsRun.join(', ')}). ` +
    `After cross-engine consensus clustering, ${report.consensusFindings.length} distinct issues were identified — ${multi} of which were independently confirmed by two or more engines.`,
    { width: CONTENT_W, lineGap: 2, paragraphGap: 12 }
  );

  // severity table
  const top = doc.y + 4;
  const cols = [PAGE.m, PAGE.m + 200, PAGE.m + 300, PAGE.m + 410];
  doc.fillColor(BRAND.muted).font('Helvetica-Bold').fontSize(8.5)
     .text('SEVERITY', cols[0], top, { characterSpacing: 1, lineBreak: false })
     .text('TOTAL', cols[1], top, { characterSpacing: 1, lineBreak: false })
     .text('MULTI-ENGINE', cols[2], top, { characterSpacing: 1, lineBreak: false })
     .text('WEIGHT', cols[3], top, { characterSpacing: 1, lineBreak: false });
  doc.lineWidth(0.7).strokeColor(BRAND.line).moveTo(PAGE.m, top + 14).lineTo(PAGE.w - PAGE.m, top + 14).stroke();

  let y = top + 22;
  (['critical', 'high', 'medium', 'low', 'info'] as Severity[]).forEach(sev => {
    if (counts[sev] === 0) return;
    const m = report.consensusFindings.filter(c => c.severity === sev && c.toolCount >= 2).length;
    doc.roundedRect(cols[0], y + 1, 9, 9, 2).fill(SEVERITY_COLORS[sev]);
    doc.fillColor(BRAND.ink).font('Helvetica-Bold').fontSize(10).text(sev.toUpperCase(), cols[0] + 16, y, { lineBreak: false });
    doc.font('Helvetica').fillColor(BRAND.ink)
       .text(String(counts[sev]), cols[1], y, { lineBreak: false })
       .text(String(m), cols[2], y, { lineBreak: false })
       .text(m >= 1 ? 'confirmed' : 'single-engine', cols[3], y, { lineBreak: false });
    y += 22;
  });
  doc.y = y + 10;

  // confidence note
  doc.roundedRect(PAGE.m, doc.y, CONTENT_W, 0.1, 0); // anchor
  doc.fillColor(BRAND.muted).font('Helvetica-Oblique').fontSize(9).text(
    'Confidence signal: a finding flagged by several independent engines is far more likely to be real than one raised by a single tool. ' +
    'Single-engine findings — especially style/lint rules and findings inside audited library dependencies — frequently include false positives and should be triaged before acting.',
    PAGE.m, doc.y + 6, { width: CONTENT_W, lineGap: 2 }
  );

  if (report.toolErrors && report.toolErrors.length > 0) {
    doc.moveDown(0.8);
    doc.fillColor('#EA580C').font('Helvetica-Bold').fontSize(9.5).text('Engine errors', { lineBreak: false });
    doc.font('Helvetica').fillColor(BRAND.muted).fontSize(9);
    for (const e of report.toolErrors) doc.text(`•  ${e.tool}: ${e.error}`, { width: CONTENT_W });
  }
}

// ── AI BRIEF ──────────────────────────────────────────────────────────────
function drawBrief(doc: PDFKit.PDFDocument, report: AuditReport) {
  doc.addPage();
  sectionHeader(doc, "Auditor's brief");
  doc.fillColor(BRAND.muted).font('Helvetica-Oblique').fontSize(8.5)
     .text('AI-generated synthesis of the engine output. Review against the findings below.', { width: CONTENT_W });
  doc.moveDown(0.6);
  doc.fillColor(BRAND.ink).font('Helvetica').fontSize(10.5)
     .text(report.aiBrief || '', { width: CONTENT_W, lineGap: 2.5, paragraphGap: 8 });
}

// ── FINDINGS ──────────────────────────────────────────────────────────────
function drawFindings(doc: PDFKit.PDFDocument, report: AuditReport) {
  doc.addPage();
  sectionHeader(doc, `Findings (${report.consensusFindings.length})`);

  if (report.consensusFindings.length === 0) {
    doc.fillColor(BRAND.muted).font('Helvetica').fontSize(11)
       .text('No issues were identified by consensus across the engines that ran.', { width: CONTENT_W });
    return;
  }

  // ordered by severity, confirmed-first
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const findings = [...report.consensusFindings].sort((a, b) =>
    (order[a.severity] - order[b.severity]) || (b.toolCount - a.toolCount));

  findings.forEach((f, i) => drawFinding(doc, f, i + 1));
}

function drawFinding(doc: PDFKit.PDFDocument, f: ConsensusFinding, n: number) {
  // Page-break if there isn't room for at least the header + a couple of lines.
  if (doc.y > PAGE.h - PAGE.m - 96) doc.addPage();

  const color = SEVERITY_COLORS[f.severity];
  const y0 = doc.y;

  // severity chip (fixed box) + title (flowing to its right)
  const chipW = 62, chipH = 16;
  doc.roundedRect(PAGE.m, y0, chipW, chipH, 3).fill(color);
  doc.fillColor('#fff').font('Helvetica-Bold').fontSize(8)
     .text(f.severity.toUpperCase(), PAGE.m, y0 + 4.5, { width: chipW, align: 'center', lineBreak: false });

  const titleX = PAGE.m + chipW + 12, titleW = CONTENT_W - chipW - 12;
  doc.fillColor(BRAND.ink).font('Helvetica-Bold').fontSize(12);
  const titleH = doc.heightOfString(`${n}. ${f.title}`, { width: titleW });
  doc.text(`${n}. ${f.title}`, titleX, y0, { width: titleW });

  // move below the taller of chip / title, then flow the rest
  doc.x = PAGE.m;
  doc.y = y0 + Math.max(chipH, titleH) + 5;

  // meta line
  const loc = f.location ? `${f.location.file}:${f.location.startLine}` : '—';
  const meta = `${loc}    ·    ${f.tools.join(' + ')} (${f.toolCount} engine${f.toolCount === 1 ? '' : 's'})` +
    `    ·    confidence ${f.consensusConfidence}${f.swcId ? '    ·    ' + f.swcId : ''}`;
  doc.fillColor(BRAND.muted).font('Helvetica').fontSize(8.5).text(meta, PAGE.m, doc.y, { width: CONTENT_W });

  // description
  doc.moveDown(0.35);
  doc.fillColor('#33373D').font('Helvetica').fontSize(9.5)
     .text(f.description || '', PAGE.m, doc.y, { width: CONTENT_W, lineGap: 1.5, paragraphGap: 3 });

  if (f.severityDisagreement && f.severityDisagreement.notes) {
    doc.fillColor('#7747D2').font('Helvetica-Oblique').fontSize(8.5)
       .text(`Severity disagreement: ${f.severityDisagreement.notes}`, PAGE.m, doc.y + 1, { width: CONTENT_W });
  }

  if (f.recommendation) {
    doc.moveDown(0.25);
    doc.fillColor(BRAND.greenDk).font('Helvetica-Bold').fontSize(8)
       .text('RECOMMENDATION', PAGE.m, doc.y, { characterSpacing: 1, lineBreak: false });
    doc.fillColor('#33373D').font('Helvetica').fontSize(9.5)
       .text(f.recommendation, PAGE.m, doc.y + 1, { width: CONTENT_W, lineGap: 1.5 });
  }

  // divider
  doc.moveDown(0.7);
  doc.lineWidth(0.5).strokeColor(BRAND.line).moveTo(PAGE.m, doc.y).lineTo(PAGE.w - PAGE.m, doc.y).stroke();
  doc.moveDown(0.8);
}

// ── APPENDIX ──────────────────────────────────────────────────────────────
function drawAppendix(doc: PDFKit.PDFDocument, report: AuditReport) {
  doc.addPage();
  sectionHeader(doc, 'Appendix A — Engines');
  doc.fillColor(BRAND.ink).font('Courier').fontSize(9.5);
  const versions = [
    'slither   0.10.4   (Trail of Bits · static analysis)',
    'mythril   0.24.8   (Consensys · symbolic execution)',
    'aderyn    0.5.5    (Cyfrin · AST analysis)',
    'semgrep   1.85     (p/smart-contracts ruleset)',
    'solhint   5.0.5    (linting / style)',
    'echidna   2.2.4    (Trail of Bits · property fuzzing, opt-in)',
  ];
  versions.forEach(v => doc.text(v, { width: CONTENT_W }));

  doc.moveDown(1.2);
  sectionHeader(doc, 'Appendix B — Methodology');
  doc.fillColor(BRAND.ink).font('Helvetica').fontSize(10).text(
    'Each engine ran in an isolated, network-disabled, resource-capped Docker sandbox. The contract was analyzed statically and symbolically in isolation — no deployment-time or runtime context was simulated. ' +
    'Findings from each engine were normalized to a common schema (SWC IDs as the cross-reference taxonomy) and clustered by category, file, and line proximity (±3 lines). A finding\'s "engine count" indicates how many independent engines agreed; the 0–100 score is a severity-weighted roll-up that gives more weight to multi-engine consensus.',
    { width: CONTENT_W, lineGap: 2, paragraphGap: 8 }
  );

  doc.moveDown(1.5);
  doc.lineWidth(0.5).strokeColor(BRAND.line).moveTo(PAGE.m, doc.y).lineTo(PAGE.w - PAGE.m, doc.y).stroke();
  doc.moveDown(0.6);
  doc.fillColor(BRAND.muted).font('Helvetica-Oblique').fontSize(8).text(
    'DISCLAIMER  ·  This report is produced by automated analysis and AI synthesis. It automates the first pass and is not a substitute for a professional manual audit; a high score is not a guarantee of safety. ' +
    'Automated engines produce false positives — particularly single-engine, style/lint, and library-dependency findings. Audit Forge makes no warranty as to completeness, accuracy, or fitness for purpose. ' +
    'Deploying to a public blockchain is irreversible; engage a qualified auditor for any contract handling user funds.',
    { width: CONTENT_W, lineGap: 2 }
  );
}

// ── shared ────────────────────────────────────────────────────────────────
function sectionHeader(doc: PDFKit.PDFDocument, text: string) {
  if (doc.y > PAGE.h - PAGE.m - 60) doc.addPage();
  doc.fillColor(BRAND.greenDk).font('Helvetica-Bold').fontSize(13)
     .text(text, PAGE.m, doc.y, { width: CONTENT_W });
  doc.lineWidth(1.5).strokeColor(BRAND.greenDk)
     .moveTo(PAGE.m, doc.y + 3).lineTo(PAGE.m + 46, doc.y + 3).stroke();
  doc.moveDown(0.9);
}

/** Footer (page numbers + auditforge.org) on every page except the cover. */
function drawFooters(doc: PDFKit.PDFDocument) {
  const range = doc.bufferedPageRange();
  const total = range.count;
  for (let i = 1; i < total; i++) {            // skip cover (page 0)
    doc.switchToPage(range.start + i);
    doc.page.margins.bottom = 0;               // footer sits below the content margin — don't spawn a page
    const y = PAGE.h - 40;
    doc.lineWidth(0.5).strokeColor(BRAND.line).moveTo(PAGE.m, y).lineTo(PAGE.w - PAGE.m, y).stroke();
    doc.fillColor(BRAND.greenDk).font('Helvetica-Bold').fontSize(8)
       .text('AUDIT FORGE', PAGE.m, y + 6, { characterSpacing: 1.5, lineBreak: false });
    doc.fillColor(BRAND.muted).font('Helvetica').fontSize(8)
       .text('auditforge.org', PAGE.m, y + 6, { width: CONTENT_W, align: 'center', lineBreak: false });
    doc.fillColor(BRAND.muted).font('Helvetica').fontSize(8)
       .text(`Page ${i} of ${total - 1}`, PAGE.m, y + 6, { width: CONTENT_W, align: 'right', lineBreak: false });
  }
}

function countBySeverity(findings: ConsensusFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}
