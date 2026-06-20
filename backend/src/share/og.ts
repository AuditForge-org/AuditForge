// SPDX-License-Identifier: AGPL-3.0-or-later
/* ===========================================================================
   Audit Forge — share surfaces.

   Two server-rendered endpoints power organic growth:

   1. An embeddable SVG score badge (shields.io style) that projects paste into
      their README / docs. GitHub renders SVG badges, so every embed becomes a
      durable, crawlable backlink to a verified report.

   2. An OG/Twitter-card shell at /r/:id. The SPA is hash-routed, so social
      crawlers (which run no JS and never see the #fragment) would otherwise
      unfurl every shared report with the generic site card. This route returns
      a tiny HTML document carrying per-report meta, then bounces humans to the
      real app.

   No rasterizer dependency — the badge is a hand-built SVG string; the OG image
   is the site's static branded cover.
   =========================================================================== */

import { existsSync } from 'fs';
import { Resvg } from '@resvg/resvg-js';
import type { AuditReport } from '../types/finding';

function escapeXml(s: string): string {
  return String(s).replace(/[<>&"']/g, (c) =>
    ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c] as string));
}

/** Human-facing contract name for a report, with paste fallbacks scrubbed and
    long github/path labels collapsed to their `.sol` basename. */
export function contractName(report: AuditReport): string {
  const s = (report.source || {}) as { contractName?: string; label?: string };
  let raw = (s.contractName || s.label || '').replace(/^github:/i, '');
  if (!raw || /^paste/i.test(raw) || raw === 'pasted-source') return 'This contract';
  // Collapse a repo/path to its last segment (the contract file).
  if (raw.includes('/')) raw = raw.split('/').filter(Boolean).pop() || raw;
  return raw.length > 30 ? raw.slice(0, 29) + '…' : raw;
}

function severityCounts(report: AuditReport): { critical: number; high: number } {
  let critical = 0, high = 0;
  for (const f of report.consensusFindings || []) {
    if (f.severity === 'critical') critical++;
    else if (f.severity === 'high') high++;
  }
  return { critical, high };
}

/** Badge right-segment colour, keyed to the same tiers the report UI uses. */
function scoreColor(score: number): string {
  if (score >= 85) return '#16a34a'; // green  — low risk
  if (score >= 70) return '#65a30d'; // lime
  if (score >= 50) return '#d97706'; // amber  — hardening needed
  return '#dc2626';                  // red    — high risk
}

/** Approx text width for the SVG badge layout (Verdana 11px ≈ 6.5px/char). */
function textWidth(s: string): number {
  return Math.round(s.length * 6.6) + 12;
}

function badge(label: string, value: string, color: string): string {
  const lw = textWidth(label), vw = textWidth(value), h = 20, total = lw + vw;
  const lx = lw / 2, vx = lw + vw / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="${h}" role="img" aria-label="${escapeXml(label)}: ${escapeXml(value)}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".12"/><stop offset="1" stop-opacity=".12"/></linearGradient>
  <clipPath id="r"><rect width="${total}" height="${h}" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="${h}" fill="#2b3038"/>
    <rect x="${lw}" width="${vw}" height="${h}" fill="${color}"/>
    <rect width="${total}" height="${h}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${lx}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(label)}</text>
    <text x="${lx}" y="14">${escapeXml(label)}</text>
    <text x="${vx}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(value)}</text>
    <text x="${vx}" y="14">${escapeXml(value)}</text>
  </g>
</svg>`;
}

/** Score badge for a completed report. */
export function renderBadgeSvg(report: AuditReport): string {
  return badge('audit forge', `${report.score}/100`, scoreColor(report.score));
}

/** Neutral badge when a report id is unknown. */
export function notFoundBadgeSvg(): string {
  return badge('audit forge', 'no report', '#6b7280');
}

/* ── Per-report OG card (1200×630 PNG) ──────────────────────────────────
   Hand-built SVG rasterized with resvg-js (no headless browser). Fonts come
   from the image's apt-installed Inter + JetBrains Mono. Each shared report
   unfurls with its own score/grade/findings baked in. */

function cardTierColor(score: number): string {
  if (score >= 85) return '#3BDDA4'; // green
  if (score >= 70) return '#86D45A'; // lime
  if (score >= 50) return '#F4A52A'; // amber
  return '#F36A6E';                  // red
}
function cardTierLabel(score: number): string {
  if (score >= 85) return 'LOW RISK';
  if (score >= 70) return 'HARDENING ADVISED';
  if (score >= 50) return 'ELEVATED RISK';
  return 'HIGH RISK';
}
function sevCounts4(report: AuditReport): { critical: number; high: number; medium: number; low: number } {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of report.consensusFindings || []) {
    if (f.severity === 'critical') c.critical++;
    else if (f.severity === 'high') c.high++;
    else if (f.severity === 'medium') c.medium++;
    else if (f.severity === 'low') c.low++;
  }
  return c;
}

export function renderOgCardSvg(report: AuditReport): string {
  const score = Math.max(0, Math.min(100, report.score));
  const color = cardTierColor(score);
  const name0 = contractName(report);
  // Shrink the display font until the name fits the left column (~720px) so it
  // can never collide with the score ring.
  const name = name0.length > 26 ? name0.slice(0, 25) + '…' : name0;
  let nameFont = 72;
  while (name.length * nameFont * 0.56 > 720 && nameFont > 42) nameFont -= 4;
  const engines = (report.toolsRun || []).length;
  const c = sevCounts4(report);
  const src =
    report.source && report.source.chain ? report.source.chain.toUpperCase()
    : report.source && report.source.type === 'github' ? 'GITHUB REPO'
    : 'SOLIDITY SOURCE';

  const cx = 980, cy = 318, r = 150, sw = 22;
  const circ = 2 * Math.PI * r;
  const arc = (circ * score) / 100;
  const numSize = score >= 100 ? 104 : 150;
  const numY = cy + numSize * 0.34;

  const sev: Array<[string, number, string]> = [
    ['critical', c.critical, '#F36A6E'],
    ['high', c.high, '#FF9A4C'],
    ['medium', c.medium, '#FFC15E'],
    ['low', c.low, '#7CC4A0'],
  ];
  const sevX0 = 70, sevGap = 150, sevY = 492;
  const sevSvg = sev.map(([lbl, n, col], i) => {
    const x = sevX0 + i * sevGap;
    return `<text x="${x}" y="${sevY}" font-family="Inter" font-weight="700" font-size="46" fill="${col}">${n}</text>` +
      `<text x="${x + 2}" y="${sevY + 27}" font-family="JetBrains Mono" font-size="13" letter-spacing="2" fill="#7b828c">${lbl.toUpperCase()}</text>`;
  }).join('');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
<defs><radialGradient id="glow" cx="0.86" cy="0" r="0.95">
  <stop offset="0" stop-color="${color}" stop-opacity="0.22"/>
  <stop offset="0.6" stop-color="${color}" stop-opacity="0"/>
</radialGradient></defs>
<rect width="1200" height="630" fill="#0a0c0f"/>
<rect width="1200" height="630" fill="url(#glow)"/>
<g transform="translate(70,52)">
  <path d="M16 2 L29 16 L16 30 L3 16 Z" fill="none" stroke="${color}" stroke-width="1.8"/>
  <path d="M16 9 L23 16 L16 23 L9 16 Z" fill="${color}" fill-opacity="0.18" stroke="${color}" stroke-width="1.5"/>
  <text x="46" y="15" font-family="JetBrains Mono" font-weight="600" font-size="20" letter-spacing="5" fill="#eef0f2">AUDIT FORGE</text>
  <text x="46" y="33" font-family="JetBrains Mono" font-size="11" letter-spacing="3" fill="#6e7580">MULTI-ENGINE AUDIT CONSOLE</text>
</g>
<text x="1130" y="74" text-anchor="end" font-family="JetBrains Mono" font-size="15" letter-spacing="2" fill="#8b929c">auditforge.org</text>
<text x="70" y="214" font-family="JetBrains Mono" font-size="15" letter-spacing="4" fill="${color}">${escapeXml(src)} · SECURITY AUDIT</text>
<text x="68" y="300" font-family="Inter" font-weight="700" font-size="${nameFont}" fill="#f3f5f7">${escapeXml(name)}</text>
<text x="70" y="360" font-family="JetBrains Mono" font-size="17" letter-spacing="1" fill="#aeb4bd">${engines} / 6 engines · consensus-reconciled · SWC-mapped</text>
${sevSvg}
<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#20262e" stroke-width="${sw}"/>
<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${color}" stroke-width="${sw}" stroke-linecap="round" stroke-dasharray="${arc.toFixed(1)} ${circ.toFixed(1)}" transform="rotate(-90 ${cx} ${cy})"/>
<text x="${cx}" y="${numY.toFixed(0)}" text-anchor="middle" font-family="Inter" font-weight="700" font-size="${numSize}" fill="${color}">${score}</text>
<text x="${cx}" y="${cy + 96}" text-anchor="middle" font-family="JetBrains Mono" font-size="16" letter-spacing="3" fill="#9aa0a8">/ 100</text>
<text x="${cx}" y="${cy + 188}" text-anchor="middle" font-family="JetBrains Mono" font-weight="500" font-size="17" letter-spacing="3" fill="${color}">${escapeXml(cardTierLabel(score))}</text>
</svg>`;
}

// resvg-js `loadSystemFonts` does not pick up the apt-installed fonts in this
// image, so load the exact files explicitly (Inter for display, JetBrains Mono
// for labels). Filtered to those present so a missing weight can't break render.
const OG_FONT_FILES = [
  '/usr/share/fonts/opentype/inter/Inter-Regular.otf',
  '/usr/share/fonts/opentype/inter/Inter-Medium.otf',
  '/usr/share/fonts/opentype/inter/Inter-SemiBold.otf',
  '/usr/share/fonts/opentype/inter/Inter-Bold.otf',
  '/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf',
  '/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Medium.ttf',
  '/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-SemiBold.ttf',
].filter(existsSync);

/** Rasterize the per-report OG card to a PNG buffer. */
export function renderOgPng(report: AuditReport): Buffer {
  const resvg = new Resvg(renderOgCardSvg(report), {
    fitTo: { mode: 'width', value: 1200 },
    background: '#0a0c0f',
    font: { loadSystemFonts: false, defaultFontFamily: 'Inter', fontFiles: OG_FONT_FILES },
  });
  return Buffer.from(resvg.render().asPng());
}

/**
 * OG/Twitter-card shell for /r/:id. Crawlers read the meta; humans are bounced
 * to the hash-routed report. `report` may be null (unknown id) — then we serve
 * the generic site card and redirect home.
 */
export function renderOgShell(report: AuditReport | null, id: string, origin: string): string {
  // Escaped because `origin` can fall back to the (untrusted) Host header.
  // PUBLIC_URL is set in prod so this is normally a constant, but escape anyway.
  const cover = escapeXml(`${origin}/og-cover.png`);
  if (!report) {
    return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Audit Forge — Multi-Engine Smart Contract Security Audit</title>
<meta name="description" content="Six independent security engines, one reconciled verdict. Audit any Solidity contract free.">
<meta property="og:title" content="Audit Forge — Multi-Engine Smart Contract Audit">
<meta property="og:description" content="Six independent security engines, one reconciled verdict. Audit any Solidity contract free.">
<meta property="og:image" content="${cover}"><meta name="twitter:card" content="summary_large_image">
<script>location.replace('/#/scan');</script></head>
<body><p><a href="/#/scan">Audit Forge — run a free scan →</a></p></body></html>`;
  }

  const name = contractName(report);
  const { critical, high } = severityCounts(report);
  const engines = (report.toolsRun || []).length;
  const title = `${name} — ${report.score}/100 on Audit Forge`;
  const desc = `${name} scored ${report.score}/100 across ${engines} security engines on Audit Forge — ${critical} critical, ${high} high findings reconciled by consensus. Free multi-engine smart-contract audit.`;
  const url = `${origin}/r/${encodeURIComponent(id)}`;
  const hashUrl = `/#/report/${encodeURIComponent(id)}`;
  // Per-report card (score baked in). Falls back to the static cover if rasterizing fails.
  const card = escapeXml(`${origin}/og/${encodeURIComponent(id)}.png`);

  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeXml(title)}</title>
<meta name="description" content="${escapeXml(desc)}">
<link rel="canonical" href="${escapeXml(url)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Audit Forge">
<meta property="og:title" content="${escapeXml(name)} scored ${report.score}/100 on Audit Forge">
<meta property="og:description" content="${escapeXml(desc)}">
<meta property="og:url" content="${escapeXml(url)}">
<meta property="og:image" content="${card}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escapeXml(title)}">
<meta name="twitter:description" content="${escapeXml(desc)}">
<meta name="twitter:image" content="${card}">
<script>location.replace(${JSON.stringify(hashUrl)});</script>
</head>
<body style="font-family:system-ui,sans-serif;background:#0b0d10;color:#eef0f2;padding:40px">
<p>Audit Forge report for <b>${escapeXml(name)}</b> — security score <b>${report.score}/100</b>.</p>
<p><a href="${escapeXml(hashUrl)}" style="color:#62a0f7">View the full report →</a></p>
</body></html>`;
}
