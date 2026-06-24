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
import type { RegistryEntry } from '../registry/store';

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

function sevCountsAll(report: AuditReport): Record<string, number> {
  const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of report.consensusFindings || []) if (f.severity in c) c[f.severity]++;
  return c;
}

const RP_TOPBAR = `<header class="topbar"><div class="wrap"><a href="/" class="brand"><span class="mark"><svg viewBox="0 0 32 32" fill="none"><path d="M16 2 L29 16 L16 30 L3 16 Z" stroke="currentColor" stroke-width="1.6"></path><path d="M16 9 L23 16 L16 23 L9 16 Z" fill="currentColor" fill-opacity="0.16" stroke="currentColor" stroke-width="1.4"></path></svg></span><span class="name">AUDIT FORGE<small>MULTI-ENGINE AUDIT CONSOLE</small></span></a><nav class="nav"><a href="/#/scan">Scan</a><a href="/#/engines">Engines</a><a href="/registry">Registry</a></nav></div></header>`;
const RP_FOOTER = `<footer class="footer"><div class="wrap"><div class="footer-base"><span>Audit Forge automates the first pass — it is <b>not</b> a substitute for a professional manual audit. Provided without warranty.</span><span class="legal-links"><a href="/#/terms">Terms</a> · <a href="/#/privacy">Privacy</a> · <a href="/#/engines">Engines</a></span></div></div></footer>`;
const RP_CSS = `.rp{max-width:880px;margin:0 auto;padding:48px 28px 60px}.rp-crumb{font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3);margin-bottom:14px}.rp-crumb a{color:var(--amber)}.rp h1{font-family:var(--sans);font-weight:700;letter-spacing:-.02em;font-size:clamp(30px,4vw,44px);margin:0 0 6px;color:var(--ink)}.rp-src{font-family:var(--mono);font-size:12.5px;color:var(--ink-3);margin:0 0 24px;overflow-wrap:anywhere}.rp-score{display:flex;align-items:baseline;gap:18px;margin:0 0 22px;flex-wrap:wrap}.rp-num{font-family:var(--sans);font-weight:700;font-size:64px;line-height:1;color:var(--tc)}.rp-num small{font-size:20px;color:var(--ink-4);font-weight:500}.rp-grade{font-family:var(--mono);font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--tc)}.rp-strip{display:grid;grid-template-columns:repeat(5,1fr);border:1px solid var(--line-2);border-radius:12px;overflow:hidden;margin-bottom:30px}.rp-strip>div{padding:14px;text-align:center;border-right:1px solid var(--line)}.rp-strip>div:last-child{border-right:0}.rp-strip .n{display:block;font-family:var(--sans);font-weight:700;font-size:24px;color:var(--ink)}.rp-strip .l{font-family:var(--mono);font-size:9px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-3)}.rp h2{font-family:var(--sans);font-weight:700;font-size:22px;margin:34px 0 14px;color:var(--ink)}.rp-brief p{color:var(--ink-2);font-size:15px;line-height:1.7}.rp-f{border:1px solid var(--line-2);border-radius:12px;padding:16px 18px;margin-bottom:12px;background:var(--panel)}.rp-fh{display:flex;align-items:center;gap:12px}.rp-fh h3{margin:0;font-size:15px;font-weight:600;color:var(--ink)}.rp-sev{font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:.06em;padding:3px 8px;border-radius:5px;color:#fff;flex-shrink:0}.rp-sev.s-critical{background:#dc2626}.rp-sev.s-high{background:#ea580c}.rp-sev.s-medium{background:#d97706}.rp-sev.s-low{background:#0891b2}.rp-sev.s-info{background:#6b7280}.rp-m{font-family:var(--mono);font-size:11px;color:var(--ink-3);margin:6px 0 0}.rp-f p{color:var(--ink-2);font-size:13.5px;line-height:1.6;margin:8px 0 0}.rp-cta{margin:34px 0 18px;display:flex;gap:12px;flex-wrap:wrap}.rp-disc{color:var(--ink-3);font-size:12px}.rp-disc a{color:var(--amber)}@media(max-width:560px){.rp-strip{grid-template-columns:repeat(2,1fr)}}`;

/**
 * Server-rendered report page for /r/:id — a REAL, crawlable HTML page (not a
 * redirect shell). Indexed only when the report has been published to the
 * registry, so private shared reports stay out of search.
 */
export function renderOgShell(
  report: AuditReport | null,
  id: string,
  origin: string,
  published = false,
): string {
  const css = `<link rel="stylesheet" href="${escapeXml(origin)}/auditforge.css?v=20260621b"><link rel="stylesheet" href="${escapeXml(origin)}/auditforge-pages.css?v=20260621b"><style>${RP_CSS}</style>`;
  const head = (title: string, desc: string, robots: string, extra = '') =>
    `<!DOCTYPE html><html lang="en" data-theme="dark" data-accent="emerald" data-headline="sans"><head>` +
    `<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">` +
    `<title>${escapeXml(title)}</title><meta name="description" content="${escapeXml(desc)}">` +
    `<meta name="robots" content="${robots}"><meta name="theme-color" content="#07080A">${extra}${css}</head>`;

  if (!report) {
    return head('Report not found — Audit Forge', 'This audit report could not be found.', 'noindex,follow') +
      `<body>${RP_TOPBAR}<main class="rp"><h1>Report not found</h1><p class="rp-disc">This report doesn't exist or has expired. <a href="/#/scan">Run a new free scan →</a></p></main>${RP_FOOTER}</body></html>`;
  }

  const name = contractName(report);
  const counts = sevCountsAll(report);
  const engines = (report.toolsRun || []).length;
  const t = { color: cardTierColor(report.score), label: cardTierLabel(report.score) };
  const title = `${name} — ${report.score}/100 Smart Contract Audit | Audit Forge`;
  const desc = `${name} scored ${report.score}/100 across ${engines} security engines on Audit Forge — ${counts.critical} critical, ${counts.high} high findings reconciled by consensus. Free multi-engine smart-contract audit report.`;
  const url = `${origin}/r/${encodeURIComponent(id)}`;
  const hashUrl = `/#/report/${encodeURIComponent(id)}`;
  const card = escapeXml(`${origin}/og/${encodeURIComponent(id)}.png`);

  const og =
    `<link rel="canonical" href="${escapeXml(url)}">` +
    `<meta property="og:type" content="website"><meta property="og:site_name" content="Audit Forge">` +
    `<meta property="og:title" content="${escapeXml(name)} scored ${report.score}/100 on Audit Forge">` +
    `<meta property="og:description" content="${escapeXml(desc)}"><meta property="og:url" content="${escapeXml(url)}">` +
    `<meta property="og:image" content="${card}"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">` +
    `<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="${escapeXml(title)}"><meta name="twitter:description" content="${escapeXml(desc)}"><meta name="twitter:image" content="${card}">`;

  const findingHtml = (report.consensusFindings || []).map(f => {
    const sev = String(f.severity || 'info');
    const loc = f.location ? `${f.location.file}:${f.location.startLine}` : '';
    const d = escapeXml(String(f.description || '').replace(/\s+/g, ' ').trim().slice(0, 480));
    return `<article class="rp-f"><div class="rp-fh"><span class="rp-sev s-${sev}">${sev.toUpperCase()}</span><h3>${escapeXml(f.title || 'Finding')}</h3></div>` +
      `<div class="rp-m">${escapeXml(loc)}${f.swcId ? ' · ' + escapeXml(f.swcId) : ''} · ${f.toolCount} engine${f.toolCount === 1 ? '' : 's'}</div>${d ? `<p>${d}</p>` : ''}</article>`;
  }).join('');

  const strip = ['critical', 'high', 'medium', 'low', 'info']
    .map(s => `<div><span class="n">${counts[s]}</span><span class="l">${s}</span></div>`).join('');

  return head(title, desc, published ? 'index,follow' : 'noindex,follow', og) +
`<body>${RP_TOPBAR}
<main class="rp">
  <div class="rp-crumb"><a href="/#/registry">Registry</a> / Report</div>
  <h1>${escapeXml(name)}</h1>
  <p class="rp-src">${escapeXml(report.source.label)} · ${engines} engines · audited by Audit Forge</p>
  <div class="rp-score" style="--tc:${t.color}"><div class="rp-num">${report.score}<small>/100</small></div><div class="rp-grade">${escapeXml(report.grade)} · ${escapeXml(t.label)}</div></div>
  <div class="rp-strip">${strip}</div>
  ${report.aiBrief ? `<section class="rp-brief"><h2>Summary</h2><p>${escapeXml(String(report.aiBrief).replace(/\s+/g, ' ').trim().slice(0, 1400))}</p></section>` : ''}
  <section><h2>${(report.consensusFindings || []).length} findings</h2>${findingHtml || '<p class="rp-disc">No consensus findings were identified.</p>'}</section>
  <p class="rp-cta"><a class="btn btn-primary" href="${escapeXml(hashUrl)}">Open the interactive report →</a><a class="btn btn-ghost" href="/#/scan">Audit your own contract</a></p>
  <p class="rp-disc">Automated multi-engine analysis by <a href="/">Audit Forge</a> — a free, open-source smart-contract security scanner. Not a substitute for a professional manual audit.</p>
</main>${RP_FOOTER}</body></html>`;
}

const RG_CSS = `.rg{max-width:920px;margin:0 auto;padding:48px 28px 60px}.rg h1{font-family:var(--sans);font-weight:700;letter-spacing:-.02em;font-size:clamp(30px,4vw,44px);margin:0 0 10px;color:var(--ink)}.rg-lead{color:var(--ink-2);font-size:15.5px;line-height:1.7;max-width:72ch;margin:0 0 6px}.rg-tools{display:flex;gap:16px;align-items:center;margin:18px 0 26px;font-family:var(--mono);font-size:12px;color:var(--ink-3)}.rg-tools a{color:var(--amber)}.rg-list{display:flex;flex-direction:column;gap:10px}.rg-row{display:flex;align-items:center;gap:18px;padding:15px 18px;border:1px solid var(--line-2);border-radius:12px;background:var(--panel);text-decoration:none;transition:border-color .15s}.rg-row:hover{border-color:var(--amber)}.rg-score{display:flex;flex-direction:column;align-items:center;min-width:52px}.rg-num{font-family:var(--sans);font-weight:700;font-size:28px;line-height:1;color:var(--tc)}.rg-grade{font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--tc);margin-top:2px}.rg-main{flex:1;min-width:0}.rg-name{font-family:var(--sans);font-weight:600;font-size:15.5px;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.rg-meta{font-family:var(--mono);font-size:11.5px;color:var(--ink-3);margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.rg-sev{display:flex;gap:6px;flex-shrink:0}.rg-c{font-family:var(--mono);font-size:10px;font-weight:600;padding:4px 8px;border-radius:5px;white-space:nowrap}.rg-c.crit{background:rgba(220,38,38,.16);color:#f87171}.rg-c.high{background:rgba(234,88,12,.16);color:#fb923c}.rg-c.ok{background:rgba(59,221,164,.14);color:var(--amber)}.rg-empty{border:1px dashed var(--line-2);border-radius:14px;padding:52px 28px;text-align:center;color:var(--ink-2);font-size:15px;line-height:1.7}.rg-empty a{color:var(--amber)}@media(max-width:560px){.rg-sev{display:none}}`;

function shortAddr(a?: string): string {
  if (!a) return '';
  return a.length > 12 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

/**
 * Server-rendered, crawlable registry list at /registry. Lists published audits
 * (each links to its crawlable /r/:id page). Indexed; the interactive filter/sort
 * view stays at the SPA hash route /#/registry.
 */
export function renderRegistryPage(entries: RegistryEntry[], total: number, origin: string): string {
  const title = 'Smart Contract Audit Registry — Published Security Reports | Audit Forge';
  const desc = `Browse ${total} published smart-contract security audit${total === 1 ? '' : 's'} on Audit Forge — each scored 0–100 by six independent engines and reconciled by consensus. Free, open-source, verifiable.`;
  const url = `${origin}/registry`;

  const css = `<link rel="stylesheet" href="${escapeXml(origin)}/auditforge.css?v=20260621b"><link rel="stylesheet" href="${escapeXml(origin)}/auditforge-pages.css?v=20260621b"><style>${RG_CSS}</style>`;

  const ld = JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'CollectionPage',
    name: 'Audit Forge Registry',
    description: 'Published smart-contract security audits.',
    url,
    mainEntity: {
      '@type': 'ItemList',
      numberOfItems: total,
      itemListElement: entries.slice(0, 50).map((e, i) => ({
        '@type': 'ListItem',
        position: i + 1,
        url: `${origin}/r/${encodeURIComponent(e.reportId)}`,
        name: e.contractName || 'Smart contract audit',
      })),
    },
  }).replace(/</g, '\\u003c');

  const rows = entries.map(e => {
    const color = cardTierColor(e.score);
    const name = escapeXml(e.contractName || 'Contract');
    const chain = e.chain ? escapeXml(e.chain) : (e.repo ? 'repo' : 'source');
    const loc = e.address ? escapeXml(shortAddr(e.address)) : (e.repo ? escapeXml(e.repo) : '');
    const meta = [chain, loc, `${e.findingsCount} finding${e.findingsCount === 1 ? '' : 's'}`, e.verifiedSource ? '✓ verified source' : '']
      .filter(Boolean).join(' · ');
    const sev = e.criticalCount ? `<span class="rg-c crit">${e.criticalCount} critical</span>` : '';
    const hi = e.highCount ? `<span class="rg-c high">${e.highCount} high</span>` : '';
    const clean = (!e.criticalCount && !e.highCount) ? `<span class="rg-c ok">no crit/high</span>` : '';
    return `<a class="rg-row" href="/r/${encodeURIComponent(e.reportId)}" style="--tc:${color}">` +
      `<div class="rg-score"><span class="rg-num">${e.score}</span><span class="rg-grade">${escapeXml(e.grade)}</span></div>` +
      `<div class="rg-main"><div class="rg-name">${name}</div><div class="rg-meta">${meta}</div></div>` +
      `<div class="rg-sev">${sev}${hi}${clean}</div></a>`;
  }).join('');

  const body = entries.length
    ? `<div class="rg-list">${rows}</div>`
    : `<div class="rg-empty">No audits have been published to the registry yet.<br>Run a free audit, then publish it to appear here. <a href="/#/scan">Audit a contract →</a></div>`;

  return `<!DOCTYPE html><html lang="en" data-theme="dark" data-accent="emerald" data-headline="sans"><head>` +
    `<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">` +
    `<title>${escapeXml(title)}</title><meta name="description" content="${escapeXml(desc)}">` +
    `<meta name="robots" content="index,follow"><meta name="theme-color" content="#07080A">` +
    `<link rel="canonical" href="${escapeXml(url)}">` +
    `<meta property="og:type" content="website"><meta property="og:site_name" content="Audit Forge">` +
    `<meta property="og:title" content="Smart Contract Audit Registry — Audit Forge"><meta property="og:description" content="${escapeXml(desc)}">` +
    `<meta property="og:url" content="${escapeXml(url)}"><meta property="og:image" content="${escapeXml(origin)}/og-cover.png">` +
    `<meta name="twitter:card" content="summary_large_image"><meta name="twitter:image" content="${escapeXml(origin)}/og-cover.png">` +
    `<script type="application/ld+json">${ld}</script>${css}</head>` +
    `<body>${RP_TOPBAR}<main class="rg">` +
    `<h1>Audit Registry</h1>` +
    `<p class="rg-lead">Public smart-contract security audits run on Audit Forge — each scored 0–100 across six independent engines and reconciled by consensus. Click any entry for the full report.</p>` +
    `<div class="rg-tools"><span>${total} published audit${total === 1 ? '' : 's'}</span><a href="/#/registry">Filter &amp; sort interactively →</a><a href="/#/scan">Run an audit</a></div>` +
    body +
    `</main>${RP_FOOTER}</body></html>`;
}
