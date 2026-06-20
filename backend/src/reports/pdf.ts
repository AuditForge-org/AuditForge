/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Server-side PDF report builder using PDFKit.
 *
 * Layout philosophy: looks like a real audit firm's deliverable, not a
 * generated dump. Cover page, executive summary, findings detail, appendix
 * with raw tool outputs.
 */

import PDFDocument from 'pdfkit';
import { AuditReport, ConsensusFinding, Severity } from '../types/finding';

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#2563eb',
  low:      '#9333ea',
  info:     '#6b7280',
};

export function buildPdf(report: AuditReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'LETTER',
      margins: { top: 60, bottom: 60, left: 60, right: 60 },
      info: {
        Title: `Forensiq Audit Report ${report.id}`,
        Author: 'Forensiq',
        Subject: 'Smart Contract Security Audit',
        CreationDate: new Date(report.createdAt),
      },
    });

    const chunks: Buffer[] = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // ─── COVER PAGE ────────────────────────────────────────────────────
    doc.rect(0, 0, doc.page.width, 8).fill('#f5a623');
    doc.fillColor('#111').fontSize(36).font('Helvetica-Bold')
       .text('FORENSIQ', 60, 80);
    doc.fontSize(10).font('Helvetica').fillColor('#666')
       .text('SMART CONTRACT AUDIT REPORT', 60, 124, { characterSpacing: 3 });

    doc.moveTo(60, 160).lineTo(doc.page.width - 60, 160).strokeColor('#ddd').stroke();

    // Score block
    doc.fontSize(72).font('Helvetica-Bold').fillColor('#111')
       .text(String(report.score), 60, 200);
    doc.fontSize(14).font('Helvetica').fillColor('#666')
       .text('/ 100', 60 + doc.widthOfString(String(report.score)) + 8, 240);
    doc.fontSize(16).font('Helvetica-Bold').fillColor('#111')
       .text(report.grade, 60, 300);

    // Source
    doc.fontSize(10).font('Helvetica').fillColor('#666')
       .text('SOURCE', 60, 360, { characterSpacing: 2 })
       .fontSize(12).font('Helvetica-Bold').fillColor('#111')
       .text(report.source.label, 60, 376);

    doc.fontSize(10).font('Helvetica').fillColor('#666')
       .text('TOOLS RUN', 60, 410, { characterSpacing: 2 })
       .fontSize(12).font('Helvetica-Bold').fillColor('#111')
       .text(report.toolsRun.join(', ').toUpperCase(), 60, 426);

    doc.fontSize(10).font('Helvetica').fillColor('#666')
       .text('CONSENSUS FINDINGS', 60, 460, { characterSpacing: 2 })
       .fontSize(12).font('Helvetica-Bold').fillColor('#111')
       .text(String(report.consensusFindings.length), 60, 476);

    doc.fontSize(10).font('Helvetica').fillColor('#666')
       .text('SCAN DURATION', 60, 510, { characterSpacing: 2 })
       .fontSize(12).font('Helvetica-Bold').fillColor('#111')
       .text(`${(report.durationMs / 1000).toFixed(1)}s`, 60, 526);

    // Footer on cover
    doc.fontSize(8).font('Helvetica').fillColor('#999')
       .text(
         `Report ID: ${report.id}    Generated: ${new Date(report.createdAt).toUTCString()}`,
         60, doc.page.height - 80
       );

    // ─── EXECUTIVE SUMMARY ─────────────────────────────────────────────
    doc.addPage();
    sectionHeader(doc, 'EXECUTIVE SUMMARY');

    const counts = countBySeverity(report.consensusFindings);
    doc.fontSize(11).font('Helvetica').fillColor('#333').text(
      `This report analyzed ${report.contract.lines} lines of Solidity using ${report.toolsRun.length} independent audit engines (${report.toolsRun.join(', ')}). After cross-tool consensus clustering, ${report.consensusFindings.length} distinct issues were identified.`,
      { paragraphGap: 12 }
    );

    // Severity table
    const tableTop = doc.y + 8;
    const colX = [60, 200, 320, 440];
    doc.fontSize(9).font('Helvetica-Bold').fillColor('#666')
       .text('SEVERITY', colX[0], tableTop, { characterSpacing: 1 })
       .text('COUNT', colX[1], tableTop, { characterSpacing: 1 })
       .text('TOOL CONSENSUS', colX[2], tableTop, { characterSpacing: 1 });
    doc.moveTo(60, tableTop + 14).lineTo(doc.page.width - 60, tableTop + 14).strokeColor('#ddd').stroke();

    let rowY = tableTop + 22;
    for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as Severity[]) {
      if (counts[sev] === 0) continue;
      doc.rect(colX[0] - 4, rowY - 2, 8, 8).fill(SEVERITY_COLORS[sev]);
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#111')
         .text(sev.toUpperCase(), colX[0] + 10, rowY);
      doc.font('Helvetica').text(String(counts[sev]), colX[1], rowY);
      const multiTool = report.consensusFindings
        .filter(c => c.severity === sev && c.toolCount >= 2).length;
      doc.text(`${multiTool} multi-tool / ${counts[sev]} total`, colX[2], rowY);
      rowY += 22;
    }

    doc.y = rowY + 16;

    // Tool errors
    if (report.toolErrors.length > 0) {
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#ea580c')
         .text('Tool errors:', { paragraphGap: 4 });
      doc.font('Helvetica').fillColor('#555').fontSize(9);
      for (const e of report.toolErrors) {
        doc.text(`• ${e.tool}: ${e.error}`);
      }
      doc.moveDown();
    }

    // ─── AI BRIEF ──────────────────────────────────────────────────────
    if (report.aiBrief) {
      doc.addPage();
      sectionHeader(doc, "AUDITOR'S BRIEF (AI)");
      doc.fontSize(10).font('Helvetica').fillColor('#333').text(report.aiBrief, {
        paragraphGap: 10,
        lineGap: 2,
      });
    }

    // ─── FINDINGS ─────────────────────────────────────────────────────
    doc.addPage();
    sectionHeader(doc, `CONSENSUS FINDINGS (${report.consensusFindings.length})`);

    if (report.consensusFindings.length === 0) {
      doc.fontSize(11).font('Helvetica').fillColor('#666')
         .text('No issues were identified by consensus across the tools that ran.');
    }

    for (let i = 0; i < report.consensusFindings.length; i++) {
      const f = report.consensusFindings[i];
      if (doc.y > doc.page.height - 180) doc.addPage();

      // Severity bar
      const color = SEVERITY_COLORS[f.severity];
      doc.rect(60, doc.y, 60, 16).fill(color);
      doc.fillColor('#fff').fontSize(8).font('Helvetica-Bold')
         .text(f.severity.toUpperCase(), 60, doc.y - 11, { width: 60, align: 'center' });

      doc.fontSize(13).font('Helvetica-Bold').fillColor('#111')
         .text(`${i + 1}. ${f.title}`, 130, doc.y - 16, { width: doc.page.width - 190 });

      // Meta line
      doc.fontSize(9).font('Helvetica').fillColor('#666')
         .text(
           `${f.location.file}:${f.location.startLine}    ${f.tools.join(' + ')} (${f.toolCount} tool${f.toolCount === 1 ? '' : 's'})    confidence: ${f.consensusConfidence}${f.swcId ? '    ' + f.swcId : ''}`,
           60, doc.y + 4
         );

      doc.moveDown(0.5);
      doc.fontSize(10).font('Helvetica').fillColor('#222')
         .text(f.description, { paragraphGap: 6, lineGap: 1 });

      if (f.severityDisagreement) {
        doc.fontSize(9).font('Helvetica-Oblique').fillColor('#9333ea')
           .text(`⚠ ${f.severityDisagreement.notes}`, { paragraphGap: 4 });
      }

      if (f.recommendation) {
        doc.fontSize(9).font('Helvetica-Bold').fillColor('#666')
           .text('RECOMMENDATION', { characterSpacing: 1, paragraphGap: 2 });
        doc.font('Helvetica').fillColor('#333')
           .text(f.recommendation, { paragraphGap: 8 });
      }

      doc.moveTo(60, doc.y + 4).lineTo(doc.page.width - 60, doc.y + 4)
         .strokeColor('#eee').stroke();
      doc.moveDown(1);
    }

    // ─── APPENDIX ─────────────────────────────────────────────────────
    doc.addPage();
    sectionHeader(doc, 'APPENDIX A — TOOL VERSIONS');
    doc.fontSize(10).font('Courier').fillColor('#333');
    doc.text('slither   0.10.4');
    doc.text('mythril   0.24.8');
    doc.text('aderyn    0.5.5');
    doc.text('semgrep   1.85 (p/smart-contracts ruleset)');
    doc.text('solhint   5.0.5');
    doc.moveDown();

    sectionHeader(doc, 'APPENDIX B — METHODOLOGY');
    doc.fontSize(10).font('Helvetica').fillColor('#333').text(
      `Each tool was executed in an isolated Docker container with no network access. The contract was analyzed in isolation; no deployment-time or runtime context was simulated. Findings from each tool were normalized to a common schema (using SWC IDs as the cross-reference taxonomy) and clustered by category, file, and line proximity (±3 lines). Consensus findings reported here are those where one or more tools detected an issue; the trust signal "tool count" indicates how many independent engines agreed.`,
      { paragraphGap: 8, lineGap: 2 }
    );

    // Disclaimer
    doc.moveDown(2);
    doc.fontSize(8).font('Helvetica-Oblique').fillColor('#888').text(
      `DISCLAIMER: This report is generated by automated analysis and AI synthesis. It is not a substitute for a manual audit by a qualified security firm. Forensiq makes no warranty, express or implied, regarding the completeness, accuracy, or fitness for purpose of this report. Deploying smart contracts to a public blockchain is irreversible; consider engaging a professional auditor for any contract handling user funds or critical operations.`,
      { lineGap: 2 }
    );

    doc.end();
  });
}

function sectionHeader(doc: PDFKit.PDFDocument, text: string) {
  doc.fontSize(11).font('Helvetica-Bold').fillColor('#f5a623')
     .text(text, { characterSpacing: 2 });
  doc.moveTo(60, doc.y + 2).lineTo(doc.page.width - 60, doc.y + 2)
     .strokeColor('#f5a623').lineWidth(1).stroke();
  doc.moveDown(0.8);
}

function countBySeverity(findings: ConsensusFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}
