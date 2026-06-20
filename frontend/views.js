// SPDX-License-Identifier: AGPL-3.0-or-later
/* ===========================================================================
   AUDIT FORGE — View renderers (SPA).
   Each Views.<name>(el, params) renders the new Audit Forge markup into `el`
   and wires it to the backend via window.API. The router (app.js) calls the
   matching renderer, then AFUI.hydrate(el) to wire presentational behaviors.
   =========================================================================== */

window.Views = (function () {
  const $  = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, m =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
  }

  function toast(msg, isError = false) {
    const t = document.getElementById('toast');
    if (!t) return;
    t.textContent = msg;
    t.classList.toggle('error', !!isError);
    t.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => t.classList.remove('show'), 2400);
  }

  function relTime(iso) {
    if (!iso) return '—';
    const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.round(s / 60) + 'm ago';
    if (s < 86400) return Math.round(s / 3600) + 'h ago';
    return Math.round(s / 86400) + 'd ago';
  }

  // ── severity / score mapping ──────────────────────────────────────
  const SEV_TAG = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };
  const TOOL_COLOR = {
    slither: 'var(--c-static)', aderyn: 'var(--c-static)', mythril: 'var(--c-symbolic)',
    semgrep: 'var(--c-pattern)', solhint: 'var(--c-linter)', echidna: 'var(--c-fuzzing)',
  };
  const ENGINE_META = [
    ['Slither', 'slither', 'Static', 'var(--c-static)'],
    ['Aderyn', 'aderyn', 'AST', 'var(--c-static)'],
    ['Mythril', 'mythril', 'Symbolic', 'var(--c-symbolic)'],
    ['Semgrep', 'semgrep', 'Pattern', 'var(--c-pattern)'],
    ['Solhint', 'solhint', 'Linter', 'var(--c-linter)'],
    ['Echidna', 'echidna', 'Fuzzing', 'var(--c-fuzzing)'],
  ];
  function riskTier(score) {
    if (score >= 85) return { color: 'var(--c-linter)', label: 'Low risk', grad: 'var(--c-linter), var(--c-static)' };
    if (score >= 70) return { color: 'var(--sev-low)',  label: 'Some hardening needed', grad: 'var(--sev-low), var(--c-linter)' };
    if (score >= 50) return { color: 'var(--sev-high)', label: 'Elevated risk — review before deploy', grad: 'var(--sev-high), var(--sev-low)' };
    return { color: 'var(--sev-crit)', label: 'High risk — do not deploy', grad: 'var(--sev-crit), var(--sev-high)' };
  }
  function regScoreClass(score) { return score >= 80 ? 's-good' : score >= 60 ? 's-mid' : 's-bad'; }

  // ── social sharing + embeddable backlink badge ────────────────────
  const SHARE_ICONS = {
    x: '<path d="M3 3l7.55 9.78L3.3 21H6l5.4-6.27L16.2 21H21l-7.93-10.27L20.4 3h-2.7l-4.97 5.77L8 3H3z" fill="currentColor"/>',
    telegram: '<path d="M21.9 4.3 2.95 11.6c-.97.38-.96 1.78.02 2.13l4.7 1.5 1.78 5.4c.24.74 1.2.92 1.7.3l2.5-2.96 4.78 3.5c.6.45 1.47.13 1.64-.6L23.5 5.6c.2-.92-.7-1.65-1.6-1.3z" fill="currentColor"/><path d="M9.6 16.3 9.4 19c-.34 0-.49-.15-.66-.33l-1.6-1.55 4.6-4.16 5.27-4.6c.23-.2-.05-.32-.35-.12L9.9 13.2" fill="#fff" opacity=".55"/>',
    farcaster: '<path d="M5 4h14v3.1h-2.3V20h-3.1v-6.7c0-1-.86-1.8-1.6-1.8s-1.6.8-1.6 1.8V20H7.3V7.1H5z" fill="currentColor"/>',
    linkedin: '<path d="M4.6 3.4a2 2 0 1 0 .01 4.01A2 2 0 0 0 4.6 3.4zM3.1 9h3v12h-3zM9 9h2.87v1.64h.04c.4-.76 1.38-1.56 2.84-1.56 3.04 0 3.6 2 3.6 4.6V21h-3v-4.97c0-1.18-.02-2.7-1.65-2.7-1.65 0-1.9 1.29-1.9 2.62V21H9z" fill="currentColor"/>',
    reddit: '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="13.6" r="7.4"/><path d="M9.2 16.1c1.7 1.1 4 1.1 5.7 0" stroke-linecap="round"/><path d="M12.2 6.2 13.3 3l3.1.8"/></g><circle cx="9.1" cy="13" r="1.05" fill="currentColor"/><circle cx="15" cy="13" r="1.05" fill="currentColor"/><circle cx="16.4" cy="3.8" r="1.35" fill="currentColor"/>',
  };
  function buildShare(r, counts, enginesRun, name) {
    const url    = API.shareUrl(r.id);
    const report = API.reportUrl(r.id);
    const badge  = API.badgeUrl(r.id);
    const crit = counts.critical || 0, high = counts.high || 0;
    const text  = `🛡️ ${name} scored ${r.score}/100 on Audit Forge — ${enginesRun} security engines run, ${crit} critical / ${high} high findings reconciled by consensus. Audit your Solidity contract free:`;
    const title = `${name} — ${r.score}/100 on Audit Forge`;
    const t = encodeURIComponent(text), u = encodeURIComponent(url);
    return {
      url, report, badge, text, title,
      md:   `[![Audit Forge: ${r.score}/100](${badge})](${report})`,
      html: `<a href="${report}"><img src="${badge}" alt="Audit Forge security score: ${r.score}/100" height="20"></a>`,
      links: {
        x:         `https://twitter.com/intent/tweet?text=${t}&url=${u}&hashtags=smartcontracts,web3security,solidity`,
        telegram:  `https://t.me/share/url?url=${u}&text=${t}`,
        farcaster: `https://farcaster.xyz/~/compose?text=${t}&embeds[]=${u}`,
        linkedin:  `https://www.linkedin.com/sharing/share-offsite/?url=${u}`,
        reddit:    `https://www.reddit.com/submit?url=${u}&title=${encodeURIComponent(title)}`,
      },
    };
  }
  function shareBtns(sh, size) {
    const order = [['x', 'Share on X'], ['telegram', 'Share on Telegram'], ['farcaster', 'Cast on Farcaster'], ['linkedin', 'Share on LinkedIn'], ['reddit', 'Post to Reddit']];
    return order.map(([k, lbl]) =>
      `<a class="sbtn s-${k}${size === 'lg' ? ' lg' : ''}" href="${sh.links[k]}" target="_blank" rel="noopener noreferrer" aria-label="${lbl}" title="${lbl}"><svg viewBox="0 0 24 24" aria-hidden="true">${SHARE_ICONS[k]}</svg></a>`
    ).join('');
  }
  function pips(n) {
    let h = '';
    for (let i = 0; i < 6; i++) h += i < n ? '<i class="on"></i>' : '<i></i>';
    return h;
  }
  const loading = (label) => `<section class="page-section"><div class="wrap"><div class="af-loading"><span class="spinner"></span>${escapeHtml(label || 'Loading…')}</div></div></section>`;
  const errBox = (msg) => `<section class="page-section"><div class="wrap"><div class="af-empty"><span class="ico">✕</span>${escapeHtml(msg)}</div></div></section>`;

  // ════════════════════════════════════════════════════════════════
  // SCAN  (home / audit console + marketing)
  // ════════════════════════════════════════════════════════════════
  function scan(root) {
    let cancelWatch = null;
    const ts = { token: '', widgetId: null };  // Cloudflare Turnstile state

    root.innerHTML = `
<section class="hero">
  <div class="wrap">
    <div class="hero-top">
      <div class="hero-left reveal">
        <span class="eyebrow">Multi-engine smart-contract audit</span>
        <h1>Audit <span class="amber">any contract.</span><br><span class="line2">Before it audits you.</span></h1>
        <p class="lede">Audit Forge runs <b>six industry-standard engines</b> against your Solidity in parallel — static analysis, symbolic execution and property fuzzing — then cross-references every finding so you can trust what surfaces. Free, instant, and open source — no sign-up needed to start.</p>
        <div class="hero-ctas">
          <a href="#console" class="btn btn-primary">Run an audit →</a>
          <a href="#consensus" class="btn btn-ghost">How consensus works</a>
        </div>
        <div class="hero-proof">
          <span class="lbl">Powered by</span>
          <div class="engines">
            <span style="--dot:var(--c-static)">Slither</span>
            <span style="--dot:var(--c-symbolic)">Mythril</span>
            <span style="--dot:var(--c-static)">Aderyn</span>
            <span style="--dot:var(--c-pattern)">Semgrep</span>
            <span style="--dot:var(--c-linter)">Solhint</span>
            <span style="--dot:var(--c-fuzzing)">Echidna</span>
          </div>
        </div>
      </div>
      <aside class="hero-right reveal">
        <div class="term">
          <div class="term-bar">
            <span class="dots"><i></i><i></i><i></i></span>
            <span class="ttl">live audit · 0x7a3f…c9e2</span>
            <span class="rec"><i></i>live</span>
          </div>
          <div class="term-body" id="termBody">
            <div class="cmd"><span class="ps">$</span> auditforge scan --engines all</div>
            <div class="tline" data-dur="900"><span class="eng">slither</span><span class="meth" style="color:var(--c-static)">static</span><span class="fill">··············································</span><span class="res" data-final="<span class='ok'>✓</span> 2.1s · 3 findings"></span></div>
            <div class="tline" data-dur="700"><span class="eng">aderyn</span><span class="meth" style="color:var(--c-static)">ast</span><span class="fill">··············································</span><span class="res" data-final="<span class='ok'>✓</span> 1.4s · 1 finding"></span></div>
            <div class="tline" data-dur="1700"><span class="eng">mythril</span><span class="meth" style="color:var(--c-symbolic)">symbolic</span><span class="fill">··············································</span><span class="res" data-final="<span class='ok'>✓</span> 8.7s · 2 findings"></span></div>
            <div class="tline" data-dur="600"><span class="eng">semgrep</span><span class="meth" style="color:var(--c-pattern)">pattern</span><span class="fill">··············································</span><span class="res" data-final="<span class='ok'>✓</span> 0.9s · 0 findings"></span></div>
            <div class="tline" data-dur="500"><span class="eng">solhint</span><span class="meth" style="color:var(--c-linter)">linter</span><span class="fill">··············································</span><span class="res" data-final="<span class='ok'>✓</span> 0.6s · 4 findings"></span></div>
            <div class="tline" data-dur="400"><span class="eng">echidna</span><span class="meth" style="color:var(--c-fuzzing)">fuzzing</span><span class="fill">··············································</span><span class="res" data-final="<span class='skip'>— opt-in</span>"></span></div>
            <div class="term-sum">
              <div class="row1">consensus → <b>SWC-107</b> confirmed by 3/6 engines</div>
              <div class="score"><span class="n">87</span><span class="meter"><i></i></span><span class="tag">low risk</span></div>
            </div>
          </div>
        </div>
        <div class="hero-stats">
          <div><div class="n">6</div><div class="l">Engines</div></div>
          <div><div class="n">3</div><div class="l">Methods</div></div>
          <div><div class="n">AI</div><div class="l">Brief</div></div>
        </div>
      </aside>
    </div>

    <div class="console reveal" id="console">
      <div class="console-bar">
        <span class="dots"><i></i><i></i><i></i></span>
        <span class="ttl">audit forge · new audit</span>
        <span class="secure"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" stroke="currentColor" stroke-width="1.5"></path></svg> Sandboxed · network-disabled</span>
      </div>
      <div class="tabs" role="tablist">
        <button class="tab active" data-tab="paste" role="tab">Code paste</button>
        <button class="tab" data-tab="address" role="tab">Contract address</button>
        <button class="tab" data-tab="github" role="tab">GitHub repo</button>
      </div>
      <div class="console-body">
        <div class="tab-pane active" data-pane="paste">
          <label class="field-label">Solidity source code</label>
          <div class="editor">
            <div class="gutter" id="gutter"></div>
            <pre class="code" id="code" contenteditable="true" spellcheck="false"><span class="cm">// SPDX-License-Identifier: MIT</span>
<span class="kw">pragma</span> solidity ^0.8.8;

<span class="kw">contract</span> <span class="ty">YourContract</span> { ... }</pre>
          </div>
          <p class="console-hint">Paste a complete contract or a flattened bundle. Best results when imports are inlined.</p>
        </div>
        <div class="tab-pane" data-pane="address">
          <label class="field-label">Verified contract address</label>
          <div class="input-line">
            <span class="pfx">0x</span>
            <input type="text" id="af-addr" placeholder="d8dA6BF26964aF9D7eEd9e03E53415D37aA96045">
            <select class="net" id="af-chain" style="cursor:pointer">
              <option value="ethereum">Ethereum</option>
              <option value="base">Base</option>
              <option value="arbitrum">Arbitrum</option>
              <option value="optimism">Optimism</option>
              <option value="polygon">Polygon</option>
              <option value="bsc">BNB Chain</option>
              <option value="ethw">EthereumPoW</option>
            </select>
          </div>
          <p class="console-hint">We pull verified source from the explorer. Requires the chain's API key configured on the server.</p>
        </div>
        <div class="tab-pane" data-pane="github">
          <label class="field-label">Public repository</label>
          <div class="input-line">
            <span class="pfx">github.com /</span>
            <input type="text" id="af-repo" placeholder="org/protocol">
            <input type="text" id="af-ref" class="net" value="main" style="width:88px;text-align:center" title="branch / ref">
          </div>
          <div class="input-line" style="margin-top:10px">
            <span class="pfx">/</span>
            <input type="text" id="af-path" placeholder="contracts/Vault.sol  (path to the .sol entry file)">
          </div>
          <p class="console-hint">Point at the entry contract. The backend fetches it via raw.githubusercontent.com.</p>
        </div>
      </div>
      <div class="console-foot">
        <label class="toggle" id="echidna"><span class="sw"></span><span class="lbl">Enable Echidna fuzzing <em>(slower · ~6 min · finds counterexamples)</em></span></label>
        <div class="actions">
          <button class="btn btn-ghost" id="loadSample">Load vulnerable sample</button>
          <button class="btn btn-primary" id="af-run">Run audit →</button>
        </div>
      </div>
      <div class="af-ts" id="af-turnstile"></div>
      <p class="console-disclosure">Engines run in isolated, network-disabled sandboxes. To generate the plain-English brief, your findings and a portion of the submitted source are sent to a third-party AI provider (Groq). Paste audits aren't stored unless you publish them. See our <a href="#/privacy">Privacy Policy</a>.</p>
    </div>
    <div id="af-progress"></div>
  </div>
</section>

<section class="section section-rule" id="pipeline">
  <div class="wrap">
    <div class="section-head reveal">
      <span class="eyebrow"><span class="idx">01</span>The pipeline</span>
      <h2>From source to verdict <em>in one pass</em></h2>
      <p>No toolchain to install, no config files. Submit a contract and Audit Forge orchestrates the rest.</p>
    </div>
    <div class="pipeline-grid reveal">
      <div class="step"><div class="num">01</div><h3>Submit</h3><p>Paste Solidity, point at a verified contract address, or link a GitHub repo.</p><svg class="arrow" viewBox="0 0 24 24" fill="none"><path d="M5 12h13M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.6"></path></svg></div>
      <div class="step"><div class="num">02</div><h3>Fan-out to 6 engines</h3><p>Each tool runs in an isolated, network-disabled sandbox — in parallel.</p><div class="chips"><span class="chip">Slither</span><span class="chip">Aderyn</span><span class="chip">Mythril</span><span class="chip">Semgrep</span><span class="chip">Solhint</span><span class="chip">Echidna</span></div><svg class="arrow" viewBox="0 0 24 24" fill="none"><path d="M5 12h13M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.6"></path></svg></div>
      <div class="step"><div class="num">03</div><h3>Consensus</h3><p>Findings cluster by SWC id; confidence scales with how many engines agree.</p><svg class="arrow" viewBox="0 0 24 24" fill="none"><path d="M5 12h13M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.6"></path></svg></div>
      <div class="step"><div class="num">04</div><h3>Scored report</h3><p>A 0–100 score, ranked findings, an AI brief and a shareable PDF.</p><div class="verdict">87<small>/ 100 · low risk</small></div></div>
    </div>
  </div>
</section>

<section class="section section-rule" id="engines">
  <div class="wrap">
    <div class="section-head reveal">
      <span class="eyebrow"><span class="idx">02</span>The engines</span>
      <h2>Six tools the professionals <em>already trust</em></h2>
      <p>Audit Forge doesn't reinvent detection — it orchestrates the best open-source analyzers in the industry and reconciles their output into one verdict.</p>
    </div>
    <div class="engines-grid">
      <article class="ecard reveal" style="--glow:rgba(108,168,255,0.12);--mc:var(--c-static)"><div class="top"><span class="eico" style="color:var(--c-static)"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3 L20 8 V16 L12 21 L4 16 V8 Z" stroke="currentColor" stroke-width="1.5"></path><path d="M12 8 L16 10.5 V14 L12 16.5 L8 14 V10.5 Z" fill="currentColor" fill-opacity="0.2"></path></svg></span><div><h3>Slither <span class="method m-static">Static</span></h3><p class="vendor">By Trail of Bits</p></div></div><p>90+ hardened detectors for reentrancy, access-control gaps, and unsafe low-level calls.</p></article>
      <article class="ecard reveal" style="--glow:rgba(108,168,255,0.12);--mc:var(--c-static)"><div class="top"><span class="eico" style="color:var(--c-static)"><svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="6" r="2.4" stroke="currentColor" stroke-width="1.5"></circle><circle cx="6" cy="17" r="2.4" stroke="currentColor" stroke-width="1.5"></circle><circle cx="18" cy="17" r="2.4" stroke="currentColor" stroke-width="1.5"></circle><path d="M11 8 L7 15 M13 8 L17 15" stroke="currentColor" stroke-width="1.3"></path></svg></span><div><h3>Aderyn <span class="method m-ast">AST</span></h3><p class="vendor">By Cyfrin</p></div></div><p>Rust-speed abstract-syntax analysis tuned for modern Solidity and Foundry layouts.</p></article>
      <article class="ecard reveal" style="--glow:rgba(195,155,255,0.12);--mc:var(--c-symbolic)"><div class="top"><span class="eico" style="color:var(--c-symbolic)"><svg viewBox="0 0 24 24" fill="none"><path d="M5 5 L19 19 M19 5 L5 19" stroke="currentColor" stroke-width="1.5"></path><circle cx="12" cy="12" r="3.2" stroke="currentColor" stroke-width="1.5" class="ic-knockout"></circle></svg></span><div><h3>Mythril <span class="method m-symbolic">Symbolic</span></h3><p class="vendor">By Consensys</p></div></div><p>Symbolic execution with an SMT solver — proves whether a dangerous path is actually reachable.</p></article>
      <article class="ecard reveal" style="--glow:rgba(244,165,42,0.12);--mc:var(--c-pattern)"><div class="top"><span class="eico" style="color:var(--c-pattern)"><svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="7.5" stroke="currentColor" stroke-width="1.5"></circle><circle cx="12" cy="12" r="2.6" fill="currentColor"></circle></svg></span><div><h3>Semgrep <span class="method m-pattern">Pattern</span></h3><p class="vendor">By Semgrep Inc.</p></div></div><p>The community smart-contract ruleset, matching known-dangerous code shapes by structure.</p></article>
      <article class="ecard reveal" style="--glow:rgba(108,240,194,0.12);--mc:var(--c-linter)"><div class="top"><span class="eico" style="color:var(--c-linter)"><svg viewBox="0 0 24 24" fill="none"><path d="M6 7h12M6 12h12M6 17h7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"></path></svg></span><div><h3>Solhint <span class="method m-linter">Linter</span></h3><p class="vendor">By Protofire</p></div></div><p>Security and best-practice linting that reliably catches the fundamentals others skip.</p></article>
      <article class="ecard reveal" style="--glow:rgba(243,106,110,0.12);--mc:var(--c-fuzzing)"><div class="top"><span class="eico" style="color:var(--c-fuzzing)"><svg viewBox="0 0 24 24" fill="none"><path d="M12 4 L14 9.2 L19.5 9.2 L15.2 12.8 L17 18.5 L12 15 L7 18.5 L8.8 12.8 L4.5 9.2 L10 9.2 Z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"></path></svg></span><div><h3>Echidna <span class="method m-fuzzing">Fuzzing</span></h3><p class="vendor">By Trail of Bits</p></div></div><p>Generates adversarial transaction sequences to break your invariants with a real counterexample. Opt-in.</p></article>
    </div>
  </div>
</section>

<section class="section section-rule" id="consensus">
  <div class="wrap">
    <div class="consensus">
      <div class="copy reveal">
        <span class="eyebrow"><span class="idx">03</span>The difference</span>
        <h2>One tool flags it.<br>Three tools agree.</h2>
        <p>Any single analyzer is noisy. Audit Forge maps every finding to its SWC category and clusters matches across all six engines. When independent tools converge on the same issue, the signal is real — and we surface exactly how many agreed, on every finding.</p>
        <div class="bullets">
          <div class="bullet"><span class="bi"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12l4 4 10-10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path></svg></span><span><b>SWC-mapped</b> — findings normalized to the Smart Contract Weakness registry.</span></div>
          <div class="bullet"><span class="bi"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12l4 4 10-10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path></svg></span><span><b>Confidence-weighted</b> — 3/6 engines agreeing outranks 1/6 flagging.</span></div>
          <div class="bullet"><span class="bi"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12l4 4 10-10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path></svg></span><span><b>Honest by design</b> — single-tool hints are labeled hints, never verdicts.</span></div>
        </div>
      </div>
      <div class="diagram reveal">
        <svg viewBox="0 0 520 320" fill="none" id="consensusSvg">
          <g stroke-linecap="round">
            <path d="M70 50 C 220 50, 260 150, 400 150" class="cline agree" stroke-width="1.6"></path>
            <path d="M70 100 C 220 100, 260 150, 400 150" class="cline agree" stroke-width="1.6"></path>
            <path d="M70 150 C 220 150, 260 150, 400 150" class="cline agree" stroke-width="1.6"></path>
            <path d="M70 200 C 220 200, 260 150, 400 150" class="cline faint" stroke-width="1.4" stroke-dasharray="4 5"></path>
            <path d="M70 250 C 220 250, 260 150, 400 150" class="cline faint" stroke-width="1.4" stroke-dasharray="4 5"></path>
            <path d="M70 300 C 220 300, 260 150, 400 150" class="cline faint" stroke-width="1.4" stroke-dasharray="4 5"></path>
          </g>
          <g font-family="JetBrains Mono" font-size="9" letter-spacing="0.5">
            <g class="node agree"><circle class="ndot" cx="70" cy="50" r="13" stroke-width="1.4"></circle><text class="ntag" x="70" y="53" text-anchor="middle">SL</text></g>
            <g class="node agree"><circle class="ndot" cx="70" cy="100" r="13" stroke-width="1.4"></circle><text class="ntag" x="70" y="103" text-anchor="middle">MY</text></g>
            <g class="node agree"><circle class="ndot" cx="70" cy="150" r="13" stroke-width="1.4"></circle><text class="ntag" x="70" y="153" text-anchor="middle">AD</text></g>
            <g class="node faint"><circle class="ndot" cx="70" cy="200" r="13" stroke-width="1.4"></circle><text class="ntag" x="70" y="203" text-anchor="middle">SG</text></g>
            <g class="node faint"><circle class="ndot" cx="70" cy="250" r="13" stroke-width="1.4"></circle><text class="ntag" x="70" y="253" text-anchor="middle">SH</text></g>
            <g class="node faint"><circle class="ndot" cx="70" cy="300" r="13" stroke-width="1.4"></circle><text class="ntag" x="70" y="303" text-anchor="middle">EC</text></g>
          </g>
          <g class="finding">
            <circle class="ffill" cx="400" cy="150" r="44" stroke-width="1.6"></circle>
            <circle class="fring" cx="400" cy="150" r="60" fill="none" stroke-width="1"></circle>
            <text class="fid" x="400" y="146" font-family="JetBrains Mono" font-size="15" font-weight="600" text-anchor="middle">SWC-107</text>
            <text class="fsub" x="400" y="162" font-family="JetBrains Mono" font-size="8.5" letter-spacing="1.5" text-anchor="middle">REENTRANCY</text>
          </g>
        </svg>
        <p class="caption"><b>3 / 6 engines</b> independently flagged this → high confidence</p>
      </div>
    </div>
  </div>
</section>

<section class="section" style="padding-top:0">
  <div class="wrap">
    <div class="statsbar reveal">
      <div><div class="n" data-count="6">0</div><div class="l">Analysis engines</div></div>
      <div><div class="n" data-count="3">0</div><div class="l">Static · Symbolic · Fuzzing</div></div>
      <div><div class="n" data-count="60" data-prefix="&lt;" data-suffix="s">&lt;0s</div><div class="l">Typical scan</div></div>
      <div><div class="n">AGPL</div><div class="l">100% open source</div></div>
    </div>
  </div>
</section>

<section class="section section-rule" id="faq">
  <div class="wrap">
    <div class="section-head reveal"><span class="eyebrow"><span class="idx">04</span>FAQ</span><h2>Questions, answered <em>straight</em></h2></div>
    <div class="faq-list reveal">
      <div class="faq-item"><button class="faq-q"><span class="qn">01</span><span class="qt">Is Audit Forge a replacement for a professional audit?</span><span class="ic"></span></button><div class="faq-a"><div class="inner">No — and we say so plainly. Audit Forge automates the first pass: it surfaces the issues automated tooling can find, fast, before you spend on a manual engagement. A human auditor still catches business-logic flaws, economic attacks and design errors that no static tool can reason about.</div></div></div>
      <div class="faq-item"><button class="faq-q"><span class="qn">02</span><span class="qt">What does the 0–100 score mean?</span><span class="ic"></span></button><div class="faq-a"><div class="inner">It's a weighted roll-up of every reconciled finding — severity times consensus. A high score means few issues and broad engine agreement that the contract is clean; it is a signal, not a guarantee.</div></div></div>
      <div class="faq-item"><button class="faq-q"><span class="qn">03</span><span class="qt">Which networks can I scan by contract address?</span><span class="ic"></span></button><div class="faq-a"><div class="inner">Any chain with a verified-source explorer: Ethereum, Base, Arbitrum, Optimism, Polygon, BNB Chain and EthereumPoW. We pull verified source directly from the explorer and run the full engine suite.</div></div></div>
      <div class="faq-item"><button class="faq-q"><span class="qn">04</span><span class="qt">What is "consensus" and why does it matter?</span><span class="ic"></span></button><div class="faq-a"><div class="inner">Every engine reports differently and produces false positives. We normalize each finding to its SWC category and count how many independent tools flagged it. Agreement across tools that work in completely different ways is the strongest signal that a finding is real.</div></div></div>
      <div class="faq-item"><button class="faq-q"><span class="qn">05</span><span class="qt">Is my code private?</span><span class="ic"></span></button><div class="faq-a"><div class="inner">The six analysis engines run in an isolated, network-disabled sandbox and never send your code anywhere. To write the plain-English <b>AI brief</b>, however, your source is sent to a third-party LLM provider (Groq) — this happens automatically on every scan. Reports stay private to you unless you choose to publish one to the public registry.</div></div></div>
      <div class="faq-item"><button class="faq-q"><span class="qn">06</span><span class="qt">How long does a scan take?</span><span class="ic"></span></button><div class="faq-a"><div class="inner">Most scans finish in under 60 seconds. Enabling Echidna property fuzzing adds a few minutes because it executes thousands of adversarial transaction sequences against your invariants.</div></div></div>
      <div class="faq-item"><button class="faq-q"><span class="qn">07</span><span class="qt">What can automated analysis <em>not</em> catch?</span><span class="ic"></span></button><div class="faq-a"><div class="inner">Anything that requires understanding intent: flawed incentive design, oracle and governance manipulation, cross-contract economic attacks, and bugs that only exist relative to your spec. Treat Audit Forge as triage, not a seal of approval.</div></div></div>
      <div class="faq-item"><button class="faq-q"><span class="qn">08</span><span class="qt">Is it free and open source?</span><span class="ic"></span></button><div class="faq-a"><div class="inner">The scanner is free — run a quick scan with no account, or sign in (also free) to raise your daily limit. Audit Forge is released under AGPL-3.0, and every engine it orchestrates is open source — you can read exactly how a verdict was reached.</div></div></div>
    </div>
  </div>
</section>

<section class="section" id="cta" style="padding-top:0">
  <div class="wrap">
    <div class="cta-band reveal">
      <span class="watermark"><svg viewBox="0 0 32 32" fill="none"><path d="M16 2 L29 16 L16 30 L3 16 Z" stroke="currentColor" stroke-width="0.8"></path><path d="M16 9 L23 16 L16 23 L9 16 Z" stroke="currentColor" stroke-width="0.6"></path></svg></span>
      <span class="mono-label">No sign-up to start · No credit card · Under 60 seconds</span>
      <h2>Run your first <span class="amber">audit</span> now</h2>
      <p>It takes one paste and a few seconds.</p>
      <div class="row"><a href="#console" class="btn btn-primary">Start a scan ↑</a><a href="#engines" class="btn btn-ghost">See the engines</a></div>
    </div>
  </div>
</section>`;

    // ── progress UI ───────────────────────────────────────────────
    function progressUI(id) {
      return `<div class="console" style="margin-top:20px">
        <div class="console-bar"><span class="dots"><i></i><i></i><i></i></span><span class="ttl">running audit${id ? ' · ' + escapeHtml(id.slice(0, 8)) : ''}</span><span class="rec"><i></i>live</span></div>
        <div style="padding:22px 26px">
          <div id="af-pstage" style="font-family:var(--mono);font-size:12px;letter-spacing:0.14em;text-transform:uppercase;color:var(--ink-2)">submitting…</div>
          <div style="margin:14px 0;height:8px;background:var(--panel-3);border:1px solid var(--line);border-radius:99px;overflow:hidden"><i id="af-pbar" style="display:block;height:100%;width:0%;background:linear-gradient(90deg,var(--amber-2),var(--amber));transition:width .45s var(--ease)"></i></div>
          <div id="af-plog" style="font-family:var(--mono);font-size:12px;line-height:1.95;color:var(--ink-3);max-height:220px;overflow:auto"></div>
        </div>
      </div>`;
    }

    const resetTurnstile = () => {
      try { if (window.turnstile && ts.widgetId != null) window.turnstile.reset(ts.widgetId); } catch (e) {}
      ts.token = '';
    };
    function submit(source, enableFuzzing) {
      // If Turnstile is active, require a token before spending an audit slot.
      if ((window.AF_CONFIG || {}).turnstileSiteKey && !ts.token) {
        return toast('Please complete the verification check below the form.', true);
      }
      const prog = $('#af-progress', root);
      prog.innerHTML = progressUI(null);
      const pstage = () => $('#af-pstage', root), pbar = () => $('#af-pbar', root), plog = () => $('#af-plog', root);
      const clog = (msg, cls) => {
        const c = { ok: 'var(--green)', err: 'var(--red)' }[cls] || 'var(--ink-4)';
        const line = document.createElement('div');
        line.innerHTML = `<span style="color:${c}">›</span> ${escapeHtml(msg)}`;
        plog().appendChild(line); plog().scrollTop = plog().scrollHeight;
      };
      clog('submitting ' + source.type + ' audit…');
      prog.scrollIntoView({ behavior: 'smooth', block: 'center' });
      API.submitAudit(source, { enableFuzzing, turnstileToken: ts.token }).then(({ id }) => {
        resetTurnstile();  // token is single-use — refresh for the next submit
        clog('queued · ' + id, 'ok');
        if (cancelWatch) cancelWatch();
        cancelWatch = API.watchAudit(id, (data) => {
          if (data.status === 'complete') {
            clog('scan complete → opening report', 'ok');
            if (pbar()) pbar().style.width = '100%';
            setTimeout(() => { window.location.hash = '#/report/' + id; }, 550);
          } else if (data.status === 'failed') {
            if (pstage()) pstage().textContent = 'failed';
            clog('failed: ' + (data.failedReason || data.error || 'unknown'), 'err');
          } else {
            const st = (data.progress && data.progress.stage) || data.status || 'working';
            const pct = (data.progress && data.progress.progress) || 0;
            if (pstage()) pstage().textContent = st;
            if (pbar()) pbar().style.width = pct + '%';
            clog(st + ' · ' + pct + '%');
          }
        });
      }).catch(e => {
        resetTurnstile();  // refresh the (now-spent) token so a retry can re-verify
        const friendly = /missing api key|could not resolve source|not verified/i.test(e.message || '')
          ? 'Could not fetch that contract’s source on this instance — paste the source or link a GitHub repo instead.'
          : e.message;
        clog(friendly, 'err'); toast(friendly, true);
      });
    }

    $('#af-run', root).addEventListener('click', () => {
      const activeTab = (($('.tabs .tab.active', root) || {}).dataset || {}).tab || 'paste';
      const enableFuzzing = !!($('#echidna', root) && $('#echidna', root).classList.contains('on'));
      if (activeTab === 'paste') {
        const code = ($('#code', root).textContent || '').trim();
        if (code.length < 20) return toast('Paste a contract first', true);
        submit({ type: 'paste', code }, enableFuzzing);
      } else if (activeTab === 'address') {
        const addr = ($('#af-addr', root).value || '').trim();
        if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) return toast('Enter a valid 0x… address', true);
        submit({ type: 'address', address: addr, chain: $('#af-chain', root).value }, enableFuzzing);
      } else {
        const repo = ($('#af-repo', root).value || '').trim().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
        if (!repo) return toast('Enter a repository (org/repo)', true);
        submit({ type: 'github', repo, path: ($('#af-path', root).value || '').trim() || undefined, ref: ($('#af-ref', root).value || '').trim() || undefined }, enableFuzzing);
      }
    });

    // Render the Cloudflare Turnstile widget when configured (sitekey from /api/config).
    function mountTurnstile() {
      const key = (window.AF_CONFIG || {}).turnstileSiteKey;
      const el = $('#af-turnstile', root);
      if (!key || !el) return;
      const render = () => {
        if (!window.turnstile || ts.widgetId != null) return;
        try {
          ts.widgetId = window.turnstile.render(el, {
            sitekey: key, theme: 'auto',
            callback: (t) => { ts.token = t; },
            'expired-callback': () => { ts.token = ''; },
            'error-callback': () => { ts.token = ''; },
          });
        } catch (e) {}
      };
      if (window.turnstile) return render();
      if (!document.getElementById('cf-turnstile-js')) {
        const s = document.createElement('script');
        s.id = 'cf-turnstile-js';
        s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
        s.async = true; s.defer = true; s.onload = render;
        document.head.appendChild(s);
      } else {
        const iv = setInterval(() => { if (window.turnstile) { clearInterval(iv); render(); } }, 200);
        setTimeout(() => clearInterval(iv), 6000);
      }
    }
    mountTurnstile();

    return () => {
      if (cancelWatch) cancelWatch();
      try { if (window.turnstile && ts.widgetId != null) window.turnstile.remove(ts.widgetId); } catch (e) {}
    };
  }

  // ════════════════════════════════════════════════════════════════
  // REPORT
  // ════════════════════════════════════════════════════════════════
  async function report(root, params) {
    const id = params.id;
    root.innerHTML = loading('Loading report ' + id + '…');
    let data;
    try { data = await API.getAudit(id); }
    catch (e) { root.innerHTML = errBox('Could not load report: ' + e.message); return; }

    if (data.status !== 'complete') {
      root.innerHTML = `<section class="page-section"><div class="wrap"><div class="af-empty"><span class="ico">⧖</span>Audit in progress (${escapeHtml(data.status)})…<br><a href="#/scan">← New scan</a></div></div></section>`;
      setTimeout(() => report(root, params), 3000);
      return;
    }
    renderReport(root, data.report);
  }

  function renderReport(root, r) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    (r.consensusFindings || []).forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const tier = riskTier(r.score);
    const toolsRun = r.toolsRun || [];
    const toolErrors = (r.toolErrors || []).map(e => e.tool);
    const rawTotal = (r.rawFindings || []).length;

    const sevCell = (n, color, label) =>
      `<div${n === 0 ? ' class="zero"' : ''}><div class="n"${n > 0 ? ` style="color:${color}"` : ''}>${n}</div><div class="l">${label}</div></div>`;

    const findingHtml = (f, i) => {
      const sev = SEV_TAG[f.severity] || 'info';
      const n = f.toolCount || (f.tools ? f.tools.length : 1) || 1;
      const isHint = n < 2;
      const ct = isHint ? '1/6 · hint' : `${n}/6 ${n >= 3 ? 'confirmed' : 'agreed'}`;
      const chips = (f.tools || []).map(t => `<span class="chip" style="color:${TOOL_COLOR[t] || 'var(--ink-2)'}">${escapeHtml(t)}${f.detectorId ? ' · ' + escapeHtml(f.detectorId) : ''}</span>`).join('');
      const snippet = f.location && f.location.snippet ? `<pre class="snippet">${escapeHtml(f.location.snippet)}</pre>` : '';
      const loc = f.location ? `${escapeHtml(f.location.file || 'source')}:${f.location.startLine || 0}` : '';
      return `<article class="finding${i === 0 ? ' open' : ''}">
        <button class="f-head">
          <span class="sev-tag ${sev}">${escapeHtml((f.severity || 'info').replace(/^\w/, c => c.toUpperCase()))}</span>
          <span class="swc">${escapeHtml(f.swcId || 'HINT')}</span>
          <span class="t">${escapeHtml(f.title || 'Finding')}</span>
          <span class="f-cons${isHint ? ' hint' : ''}"><span class="pips">${pips(n)}</span><span class="ct">${ct}</span></span>
          <svg class="chev" viewBox="0 0 24 24" fill="none"><path d="M9 6l6 6-6 6" stroke="currentColor" stroke-width="1.8"></path></svg>
        </button>
        <div class="f-body">
          <p>${escapeHtml(f.description || '')}</p>
          ${loc ? `<p style="font-family:var(--mono);font-size:12px;color:var(--ink-3)">${loc}</p>` : ''}
          ${snippet}
          ${chips ? `<div class="f-engines">${chips}</div>` : ''}
          ${f.recommendation ? `<div class="f-rec"><span class="k">Recommended fix</span><p>${escapeHtml(f.recommendation)}</p></div>` : ''}
        </div>
      </article>`;
    };

    const engineRows = ENGINE_META.map(([name, key, method, color]) => {
      let status;
      if (toolsRun.includes(key)) status = '<span class="st-ok">✓ completed</span>';
      else if (toolErrors.includes(key)) status = '<span class="st-skip" style="color:var(--sev-high)">failed</span>';
      else status = '<span class="st-skip">skipped · opt-in</span>';
      return `<div class="et-row"><span class="e">${name}</span><span class="meth" style="color:${color}">${method}</span><span>—</span><span>—</span>${status}</div>`;
    }).join('');

    // share / growth payload
    let cname = ((r.source && r.source.contractName) || (r.source && r.source.label) || '').replace(/^github:/i, '');
    if (!cname || /^paste/i.test(cname) || cname === 'pasted-source') cname = 'This contract';
    else if (cname.indexOf('/') !== -1) cname = cname.split('/').filter(Boolean).pop() || cname;
    const sh = buildShare(r, counts, toolsRun.length, cname);

    root.innerHTML = `
<section class="page-section" style="padding-top:56px">
  <div class="wrap">
    <div class="report-head reveal">
      <div class="report-id">
        <div class="crumb"><a href="#/registry">Registry</a> <span>/</span> <span>Report ${escapeHtml(String(r.id).slice(0, 13).toUpperCase())}</span></div>
        <h1>${escapeHtml((r.contract && r.contract.contractName) || (r.source && r.source.contractName) || (r.source && r.source.label) || 'Contract')}</h1>
        <div class="meta-grid">
          <div><span class="k">Source</span><span class="v">${escapeHtml((r.source && r.source.label) || 'paste')}</span></div>
          <div><span class="k">Network</span><span class="v">${escapeHtml((r.source && r.source.chain) || (r.source && r.source.type) || '—')}</span></div>
          <div><span class="k">Audited</span><span class="v">${escapeHtml(new Date(r.createdAt || Date.now()).toISOString().slice(0, 16).replace('T', ' '))} UTC</span></div>
          <div><span class="k">Engines run</span><span class="v"><span class="ok">${toolsRun.length} / 6</span> · ${((r.durationMs || 0) / 1000).toFixed(1)}s total</span></div>
          <div><span class="k">Lines</span><span class="v">${(r.contract && r.contract.lines) || '—'}</span></div>
          <div><span class="k">Reconciled / raw</span><span class="v">${(r.consensusFindings || []).length} from ${rawTotal} reports</span></div>
        </div>
      </div>
      <div class="score-card">
        <span class="k">Audit Forge score</span>
        <div class="big"><span class="n" style="color:${tier.color}">${r.score}</span><small>/ 100</small></div>
        <div class="meter"><i style="width:${r.score}%;background:linear-gradient(90deg, ${tier.grad})"></i></div>
        <span class="tag" style="color:${tier.color}">${escapeHtml(tier.label)}</span>
        <div class="actions">
          <a href="${API.pdfUrl(r.id)}" target="_blank" class="btn btn-primary" style="padding:11px 18px">Download PDF</a>
          <button class="btn btn-ghost" id="af-copy" style="padding:11px 18px">Copy link</button>
        </div>
        <div class="share-row">
          <span class="sr-lbl">Share score</span>
          <div class="sbtns">${shareBtns(sh)}</div>
        </div>
      </div>
    </div>

    <div class="sevstrip reveal">
      ${sevCell(counts.critical, 'var(--sev-crit)', 'Critical')}
      ${sevCell(counts.high, 'var(--sev-high)', 'High')}
      ${sevCell(counts.medium, 'var(--sev-med)', 'Medium')}
      ${sevCell(counts.low, 'var(--sev-low)', 'Low')}
      ${sevCell(counts.info, 'var(--sev-info)', 'Informational')}
    </div>

    <div class="share-embed reveal">
      <div class="se-head">
        <span class="eyebrow"><span class="idx">★</span>Show your score</span>
        <h2>Put this audit on your repo <em>&amp; socials</em></h2>
        <p>A badge for your README and docs — backed by this verified report — plus one-tap sharing to X, Telegram, Farcaster and more. Every embed links back here.</p>
      </div>
      <div class="se-grid">
        <div class="se-card se-badge">
          <span class="se-lbl">Embeddable badge</span>
          <a href="${sh.report}" class="badge-live-wrap" target="_blank" rel="noopener noreferrer">
            <img class="badge-live" src="${sh.badge}" alt="Audit Forge: ${r.score}/100" height="22"
                 onerror="this.style.display='none';this.nextElementSibling.style.display='inline-flex'">
            <span class="badge-css" style="display:none"><span class="bl">audit&nbsp;forge</span><span class="br" style="background:${tier.color}">${r.score}/100</span></span>
          </a>
          <div class="snip">
            <div class="snip-row"><span class="snip-k">MD</span><code id="snip-md" title="${escapeHtml(sh.md)}">${escapeHtml(sh.md)}</code><button class="snip-copy" id="af-copy-md" aria-label="Copy Markdown badge snippet">Copy</button></div>
            <div class="snip-row"><span class="snip-k">HTML</span><code id="snip-html" title="${escapeHtml(sh.html)}">${escapeHtml(sh.html)}</code><button class="snip-copy" id="af-copy-html" aria-label="Copy HTML badge snippet">Copy</button></div>
          </div>
        </div>
        <div class="se-card se-share">
          <span class="se-lbl">Share the result</span>
          <div class="sbtns lg">${shareBtns(sh, 'lg')}</div>
          <button class="btn btn-ghost" id="af-copy2" style="margin-top:16px;width:100%;justify-content:center">Copy report link</button>
        </div>
      </div>
    </div>

    ${r.aiBrief ? `<div class="ai-brief reveal"><span class="k">AI brief</span><p>${escapeHtml(r.aiBrief)}</p></div>` : ''}

    <div class="section-head reveal" style="margin-bottom:28px">
      <span class="eyebrow"><span class="idx">01</span>Findings</span>
      <h2>${(r.consensusFindings || []).length} reconciled findings <em>from ${rawTotal} raw reports</em></h2>
      <p>Findings are clustered by SWC category across all six engines. Consensus pips show how many independent tools flagged each issue.</p>
    </div>
    <div class="findings reveal">
      ${(r.consensusFindings || []).length ? r.consensusFindings.map(findingHtml).join('') : '<div class="af-empty"><span class="ico">✓</span>No consensus findings. The AI brief above may carry additional observations.</div>'}
    </div>

    <div class="section-head reveal" style="margin:64px 0 28px">
      <span class="eyebrow"><span class="idx">02</span>Engine breakdown</span>
      <h2>What each engine <em>reported</em></h2>
    </div>
    <div class="engine-table reveal">
      <div class="et-head"><span>Engine</span><span>Method</span><span>Runtime</span><span>Raw findings</span><span>Status</span></div>
      ${engineRows}
    </div>

    <div style="margin-top:48px"><a class="btn btn-ghost" href="#/scan">← New scan</a></div>
  </div>
</section>`;

    const copyTo = (sel, val, msg) => {
      const b = $(sel, root);
      if (b) b.addEventListener('click', () => {
        try { navigator.clipboard.writeText(val); toast(msg); }
        catch (e) { toast('Copy failed', true); }
      });
    };
    copyTo('#af-copy',      sh.report, 'Report link copied');
    copyTo('#af-copy2',     sh.report, 'Report link copied');
    copyTo('#af-copy-md',   sh.md,     'Markdown copied — paste into your README');
    copyTo('#af-copy-html', sh.html,   'HTML snippet copied');
  }

  // ════════════════════════════════════════════════════════════════
  // REGISTRY
  // ════════════════════════════════════════════════════════════════
  async function registry(root) {
    const filters = { chain: '', sort: 'published_desc', search: '' };

    root.innerHTML = `
<section class="page-hero">
  <div class="wrap"><div class="grid">
    <div class="reveal">
      <span class="eyebrow">Public registry</span>
      <h1><em>Public</em> <span class="amber">audit registry.</span></h1>
      <p class="lede">Browse contracts audited and published to Audit Forge. Filter by chain, score, or severity. Each entry preserves its full history; republishing supersedes but never deletes.</p>
    </div>
    <div class="page-stats reveal" id="reg-stats"></div>
  </div></div>
</section>
<section class="page-section">
  <div class="wrap">
    <div class="toolbar reveal">
      <div class="control"><label>Chain</label><select id="reg-chain"><option value="">All chains</option><option value="ethereum">Ethereum</option><option value="base">Base</option><option value="arbitrum">Arbitrum</option><option value="optimism">Optimism</option><option value="polygon">Polygon</option><option value="bsc">BNB Chain</option><option value="ethw">EthereumPoW</option></select></div>
      <div class="control"><label>Sort</label><select id="reg-sort"><option value="published_desc">Newest first</option><option value="score_desc">Highest score</option><option value="score_asc">Lowest score</option><option value="critical_desc">Most critical</option></select></div>
      <div class="control grow"><label>Search</label><input type="text" id="reg-search" placeholder="name, address, repo …"></div>
    </div>
    <div class="reg-list reveal">
      <div class="reg-head"><span>Contract</span><span>Chain</span><span>Findings</span><span>Engines</span><span>Score</span><span>Published</span><span></span></div>
      <div id="reg-rows"></div>
    </div>
  </div>
</section>`;

    const rowsEl = $('#reg-rows', root);
    const regRow = (e) => {
      const sc = regScoreClass(e.score);
      const name = escapeHtml(e.contractName || 'Unnamed contract');
      const sub = escapeHtml(e.address ? (e.address.slice(0, 6) + '…' + e.address.slice(-4)) : (e.repo || 'paste-source'));
      const chain = e.chain ? escapeHtml(e.chain.replace(/^\w/, c => c.toUpperCase())) : 'Offchain';
      let sev = '';
      if (e.criticalCount) sev += `<span class="sc-crit">${e.criticalCount} crit</span>`;
      if (e.highCount) sev += `<span class="sc-high">${e.highCount} high</span>`;
      if (!sev) sev = (e.findingsCount ? `<span class="sc-low">${e.findingsCount} total</span>` : '<span class="none">clean</span>');
      const date = e.publishedAt ? escapeHtml(new Date(e.publishedAt).toISOString().slice(0, 10)) : '—';
      return `<div class="reg-row">
        <a class="cover" href="#/report/${escapeHtml(e.reportId)}" aria-label="Open report"></a>
        <span class="nm">${name}<small>${sub}</small></span>
        <span><span class="chain-chip">${chain}</span></span>
        <span class="sevcounts">${sev}</span>
        <span class="eng">6 / 6</span>
        <span class="score-pill ${sc}">${e.score}<small>/100</small></span>
        <span class="date">${date}</span>
        <svg class="go" width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M9 6l6 6-6 6" stroke="currentColor" stroke-width="1.8"></path></svg>
      </div>`;
    };

    async function load() {
      rowsEl.innerHTML = `<div class="af-loading"><span class="spinner"></span>Loading registry…</div>`;
      try {
        const data = await API.getLeaderboard(filters);
        const entries = data.entries || [];
        rowsEl.innerHTML = entries.length
          ? entries.map(regRow).join('')
          : `<div class="af-empty"><span class="ico">∅</span>No published audits match. Be the first to <a href="#/scan">run &amp; publish one</a>.</div>`;
      } catch (e) {
        rowsEl.innerHTML = `<div class="af-empty"><span class="ico">✕</span>Could not load registry: ${escapeHtml(e.message)}</div>`;
      }
    }
    API.getChainStats().then(({ chains }) => {
      const statsEl = $('#reg-stats', root); if (!statsEl || !chains) return;
      const total = chains.reduce((a, c) => a + (c.entries || 0), 0);
      const crit = chains.reduce((a, c) => a + (c.criticalCount || 0), 0);
      statsEl.innerHTML = `<div><div class="n">${total}</div><div class="l">Entries</div></div><div><div class="n">${chains.length}</div><div class="l">Chains</div></div><div><div class="n">${crit}</div><div class="l">Critical</div></div>`;
    }).catch(() => {});

    $('#reg-chain', root).addEventListener('change', e => { filters.chain = e.target.value; load(); });
    $('#reg-sort', root).addEventListener('change', e => { filters.sort = e.target.value; load(); });
    let st; $('#reg-search', root).addEventListener('input', e => { clearTimeout(st); st = setTimeout(() => { filters.search = e.target.value.trim(); load(); }, 300); });
    load();
  }

  // ════════════════════════════════════════════════════════════════
  // WATCH
  // ════════════════════════════════════════════════════════════════
  async function watch(root) {
    root.innerHTML = `
<section class="page-hero">
  <div class="wrap"><div class="grid">
    <div class="reveal">
      <span class="eyebrow">Continuous monitoring</span>
      <h1>Keep watch on what <span class="amber">you've shipped.</span></h1>
      <p class="lede">An audit is a snapshot; detection moves on. Watch re-audits your repositories on every push so a regression never ships silently — and tells you the moment a score moves.</p>
    </div>
    <div class="page-stats reveal" id="watch-stats"><div><div class="n">—</div><div class="l">Watched</div></div><div><div class="n">6</div><div class="l">Engines</div></div><div><div class="n">PR</div><div class="l">Checks</div></div></div>
  </div></div>
</section>
<section class="page-section">
  <div class="wrap">
    <div class="watch-add reveal">
      <div class="input-line"><span class="pfx">github.com /</span><input type="text" id="watch-repo" placeholder="org/protocol  — repository to watch"><input type="text" id="watch-branch" class="net" value="main" style="width:90px;text-align:center"></div>
      <button class="btn btn-primary" id="watch-add-btn">Watch repository →</button>
    </div>
    <div id="watch-body"></div>
  </div>
</section>
<section class="section section-rule" style="padding-top:80px">
  <div class="wrap">
    <div class="section-head reveal"><span class="eyebrow"><span class="idx">01</span>How it works</span><h2>Audits that <em>don't go stale</em></h2><p>Watch keeps your last verdict honest against a moving target.</p></div>
    <div class="pipeline-grid reveal" style="grid-template-columns:repeat(3,1fr)">
      <div class="step"><div class="num">01</div><h3>Baseline</h3><p>Add a repository. Audit Forge runs the full six-engine pass and records the verdict as your baseline.</p><svg class="arrow" viewBox="0 0 24 24" fill="none"><path d="M5 12h13M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.6"></path></svg></div>
      <div class="step"><div class="num">02</div><h3>Detect change</h3><p>Every push that touches Solidity triggers a scoped re-audit of the changed contracts.</p><svg class="arrow" viewBox="0 0 24 24" fill="none"><path d="M5 12h13M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.6"></path></svg></div>
      <div class="step"><div class="num">03</div><h3>Re-audit &amp; alert</h3><p>The result is diffed against baseline. Score moved? You get the finding-level diff via check-run, email or Slack.</p><div class="verdict">▼ 3<small>score moved · alert sent</small></div></div>
    </div>
  </div>
</section>`;

    const body = $('#watch-body', root);
    body.innerHTML = `<div class="af-loading"><span class="spinner"></span>Loading watched projects…</div>`;
    let projects = null;
    try { const d = await API.listWatchedProjects(); projects = d.projects || []; }
    catch (e) {
      body.innerHTML = `<div class="af-empty" style="padding:60px 36px"><span class="ico">⊘</span>Sign in with GitHub to save watched repositories and receive alerts.<br><br><button class="btn btn-primary" id="watch-signin">Sign in with GitHub</button></div>`;
      const b = $('#watch-signin', root); if (b) b.addEventListener('click', () => API.login('#/watch'));
      return;
    }

    const ws = $('#watch-stats', root);
    if (ws) ws.innerHTML = `<div><div class="n">${projects.length}</div><div class="l">Watched</div></div><div><div class="n">6</div><div class="l">Engines</div></div><div><div class="n">24h</div><div class="l">Re-scan</div></div>`;

    if (!projects.length) {
      body.innerHTML = `<div class="af-empty"><span class="ico">⊕</span>No repositories watched yet. Add one above to start continuous auditing.</div>`;
    } else {
      body.innerHTML = `<div class="reg-list reveal" style="margin-top:18px"><div class="watch-head"><span>Repository</span><span>Branch</span><span>Min severity</span><span>Status</span><span>Created</span><span></span></div>${projects.map(p => `
        <div class="watch-row">
          <span class="nm">${escapeHtml(p.repo)}</span>
          <span><span class="chain-chip">${escapeHtml(p.branch || 'main')}</span></span>
          <span class="score-pill s-mid">${escapeHtml((p.minSeverity || 'medium').toUpperCase())}</span>
          <span class="drift${p.enabled ? '' : ' alert'}">${p.enabled ? 'Active — auditing on push' : 'Paused'}</span>
          <span class="last">${relTime(p.createdAt)}</span>
          <a class="btn-mini" href="#/runs/${escapeHtml(p.id)}">Runs</a>
        </div>`).join('')}</div>`;
    }

    const addBtn = $('#watch-add-btn', root);
    if (addBtn) addBtn.addEventListener('click', async () => {
      const repo = ($('#watch-repo', root).value || '').trim().replace(/^https?:\/\/github\.com\//, '');
      if (!repo) return toast('Enter a repository (org/repo)', true);
      try {
        await API.createWatchedProject({ repo, branch: ($('#watch-branch', root).value || 'main').trim(), minSeverity: 'medium' });
        toast('Repository added'); watch(root);
      } catch (e) { toast(e.message, true); }
    });
  }

  // ════════════════════════════════════════════════════════════════
  // RUNS  (project history)
  // ════════════════════════════════════════════════════════════════
  async function runs(root, params) {
    root.innerHTML = loading('Loading runs…');
    let project, runsData;
    try {
      project = (await API.getWatchedProject(params.id)).project;
      runsData = await API.listProjectRuns(params.id);
    } catch (e) { root.innerHTML = errBox('Could not load runs: ' + e.message); return; }

    const rows = (runsData.runs || []).map(rn => `
      <div class="watch-row">
        <span class="nm">${escapeHtml((rn.commitMessage || 'no message').split('\n')[0].slice(0, 70))}<small>${escapeHtml((rn.commitSha || '').slice(0, 8))}${rn.committer ? ' · ' + escapeHtml(rn.committer) : ''}</small></span>
        <span><span class="chain-chip">${escapeHtml(rn.status)}</span></span>
        <span class="score-pill ${rn.scoreDelta > 0 ? 's-good' : rn.scoreDelta < 0 ? 's-bad' : 's-mid'}">${rn.scoreDelta != null ? (rn.scoreDelta > 0 ? '▲ ' : rn.scoreDelta < 0 ? '▼ ' : '·') + Math.abs(rn.scoreDelta) : '—'}</span>
        <span class="drift">${rn.findingsDelta != null ? (rn.findingsDelta > 0 ? '+' : '') + rn.findingsDelta + ' findings' : '—'}</span>
        <span class="last">${relTime(rn.createdAt)}</span>
        ${rn.auditId ? `<a class="btn-mini" href="#/report/${escapeHtml(rn.auditId)}">View</a>` : '<span></span>'}
      </div>`).join('');

    root.innerHTML = `
<section class="page-hero"><div class="wrap"><div class="grid">
  <div class="reveal"><span class="eyebrow">Continuous monitoring</span><h1>${escapeHtml(project.repo)} <span class="amber">· runs</span></h1><p class="lede">${(runsData.runs || []).length} run(s) on @${escapeHtml(project.branch || 'main')}.</p></div>
</div></div></section>
<section class="page-section"><div class="wrap">
  <div class="reg-list reveal"><div class="watch-head"><span>Commit</span><span>Status</span><span>Score Δ</span><span>Findings Δ</span><span>When</span><span></span></div>
  ${rows || '<div class="af-empty"><span class="ico">∅</span>No runs yet. Push to the repo to trigger one.</div>'}</div>
  <div style="margin-top:40px"><a class="btn btn-ghost" href="#/watch">← Back to watch</a></div>
</div></section>`;
  }

  // ════════════════════════════════════════════════════════════════
  // INSTALL APP
  // ════════════════════════════════════════════════════════════════
  function install(root) {
    const installUrl = 'https://github.com/apps/forensiq/installations/new';
    root.innerHTML = `
<section class="page-hero">
  <div class="wrap"><div class="grid">
    <div class="reveal">
      <span class="eyebrow">GitHub App</span>
      <h1>Every pull request, <span class="amber">audited.</span></h1>
      <p class="lede">Install the Audit Forge app on your repository and every PR that touches Solidity gets the full six-engine pass — posted as a check, with findings annotated on the diff.</p>
      <div class="hero-ctas"><a href="${installUrl}" target="_blank" rel="noopener" class="btn btn-primary">Install on GitHub →</a><a href="#/scan" class="btn btn-ghost">Try a manual scan</a></div>
    </div>
    <div class="page-stats reveal"><div><div class="n">6</div><div class="l">Engines per PR</div></div><div><div class="n">&lt;60s</div><div class="l">Typical check</div></div><div><div class="n">$0</div><div class="l">Public repos</div></div></div>
  </div></div>
</section>
<section class="page-section">
  <div class="wrap"><div class="install-grid">
    <div class="copy reveal">
      <span class="eyebrow"><span class="idx">01</span>In your workflow</span>
      <h2 class="display-2">Findings land where <em>you review code</em></h2>
      <p style="color:var(--ink-2);font-size:15.5px;line-height:1.7;margin:0 0 28px;max-width:46ch">No dashboard to remember. The check fails when consensus findings cross your severity threshold, and each finding is annotated on the exact lines that triggered it — with the engine count that confirmed it.</p>
      <div class="bullets">
        <div class="bullet"><span class="bi"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12l4 4 10-10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path></svg></span><span><b>Diff-aware</b> — only contracts changed in the PR are scanned.</span></div>
        <div class="bullet"><span class="bi"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12l4 4 10-10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path></svg></span><span><b>Threshold you control</b> — fail on critical only, or on any consensus finding.</span></div>
        <div class="bullet"><span class="bi"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12l4 4 10-10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path></svg></span><span><b>Foundry &amp; Hardhat</b> — dependency graphs resolved automatically.</span></div>
      </div>
    </div>
    <div class="ghcard reveal">
      <div class="gh-top"><svg viewBox="0 0 24 24" fill="none"><path d="M7 8l-4 4 4 4M17 8l4 4-4 4M14 4l-4 16" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"></path></svg><span class="t">feat: add withdraw queue<small>protocol/contracts · #142 · 3 files changed</small></span><span class="pr">checks 2/3</span></div>
      <div class="gh-check"><span class="st ok"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12l4 4 10-10" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"></path></svg></span><div class="body"><span class="name">ci / build &amp; test</span><div class="sub">Successful in 1m 42s</div></div></div>
      <div class="gh-check"><span class="st ok"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12l4 4 10-10" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"></path></svg></span><div class="body"><span class="name">ci / lint</span><div class="sub">Successful in 38s</div></div></div>
      <div class="gh-check"><span class="st warn"><svg viewBox="0 0 24 24" fill="none"><path d="M12 7v6M12 16.5v.5" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"></path></svg></span><div class="body"><span class="name">audit-forge / scan</span><div class="sub"><b>1 high finding</b> · SWC-107 reentrancy in WithdrawQueue.sol:87 — confirmed by 3/6 engines · score 64/100</div></div><a class="details" href="#/scan">Details →</a></div>
    </div>
  </div></div>
</section>
<section class="section section-rule" style="padding-top:80px">
  <div class="wrap">
    <div class="section-head reveal"><span class="eyebrow"><span class="idx">02</span>Setup</span><h2>Installed in <em>two minutes</em></h2></div>
    <div class="pipeline-grid reveal" style="grid-template-columns:repeat(3,1fr)">
      <div class="step"><div class="num">01</div><h3>Install the app</h3><p>One click from the GitHub Marketplace. Read-only access to code; write access only to checks and PR comments.</p><svg class="arrow" viewBox="0 0 24 24" fill="none"><path d="M5 12h13M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.6"></path></svg></div>
      <div class="step"><div class="num">02</div><h3>Pick repositories</h3><p>Enable it for your whole org or just the contracts repo. Add an optional auditforge.yml to tune thresholds.</p><svg class="arrow" viewBox="0 0 24 24" fill="none"><path d="M5 12h13M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.6"></path></svg></div>
      <div class="step"><div class="num">03</div><h3>Open a PR</h3><p>Any PR touching .sol files gets scanned. Findings annotate the diff; the check gates the merge.</p><div class="verdict">✓<small>check posted · merge gated</small></div></div>
    </div>
  </div>
</section>
<section class="section" id="cta" style="padding-top:0">
  <div class="wrap"><div class="cta-band reveal">
    <span class="watermark"><svg viewBox="0 0 32 32" fill="none"><path d="M16 2 L29 16 L16 30 L3 16 Z" stroke="currentColor" stroke-width="0.8"></path><path d="M16 9 L23 16 L16 23 L9 16 Z" stroke="currentColor" stroke-width="0.6"></path></svg></span>
    <span class="mono-label">Free for public repositories</span>
    <h2>Gate every merge on a <span class="amber">verdict</span></h2>
    <p>Install once. Every contract change gets six opinions before it ships.</p>
    <div class="row"><a href="${installUrl}" target="_blank" rel="noopener" class="btn btn-primary">Install on GitHub →</a><a href="#/scan" class="btn btn-ghost">Try a manual scan first</a></div>
  </div></div>
</section>`;
  }

  // ════════════════════════════════════════════════════════════════
  // LEGAL — Terms of Service & Privacy Policy
  // ════════════════════════════════════════════════════════════════
  const LEGAL_UPDATED = 'June 12, 2026';

  function legalShell(crumbLabel, title, lede, bodyHtml) {
    return `
<section class="page-section legal" style="padding-top:60px">
  <div class="wrap">
    <div class="legal-head reveal">
      <div class="crumb"><a href="#/scan">Home</a> <span>/</span> <span>${escapeHtml(crumbLabel)}</span></div>
      <h1>${escapeHtml(title)}</h1>
      <p class="updated">Last updated ${escapeHtml(LEGAL_UPDATED)}</p>
      <p class="lede">${lede}</p>
    </div>
    <div class="legal-body reveal">${bodyHtml}</div>
    <div style="margin-top:48px"><a class="btn btn-ghost" href="#/scan">← Back to Audit Forge</a></div>
  </div>
</section>`;
  }
  const sec = (h, ...ps) => `<section><h2>${h}</h2>${ps.join('')}</section>`;
  const p = (t) => `<p>${t}</p>`;
  const ul = (...items) => `<ul>${items.map(i => `<li>${i}</li>`).join('')}</ul>`;

  function terms(root) {
    const body =
      sec('1. Acceptance of these terms',
        p(`Audit Forge ("Audit Forge", "we", "us") provides an automated, multi-engine smart-contract analysis service at auditforge.org (the "Service"). By submitting a contract, address, or repository, or otherwise using the Service, you agree to these Terms of Service. If you do not agree, do not use the Service.`)) +
      sec('2. What the Service is — and is not',
        p(`Audit Forge runs your Solidity source through several independent open-source security engines (Slither, Mythril, Aderyn, Semgrep, Solhint and, optionally, Echidna), reconciles their findings by consensus, and produces a score, a findings list, and an AI-generated brief.`),
        p(`<strong>The Service automates a first pass only. It is not a professional manual audit, a guarantee of security, financial advice, or a recommendation to deploy, buy, sell, or interact with any contract.</strong> A high score does not mean a contract is safe. Always obtain an independent, professional manual audit before deploying or trusting a contract with funds.`)) +
      sec('3. No warranty',
        p(`The Service is provided <strong>"as is" and "as available", without warranties of any kind</strong>, whether express or implied, including but not limited to merchantability, fitness for a particular purpose, accuracy, completeness, and non-infringement. We do not warrant that findings are complete or correct, that the Service will be uninterrupted, or that defects will be corrected.`)) +
      sec('4. Limitation of liability',
        p(`To the maximum extent permitted by law, Audit Forge and its contributors shall not be liable for any indirect, incidental, special, consequential, or exemplary damages, or for any loss of funds, profits, data, or goodwill, arising from your use of (or inability to use) the Service or reliance on its output — even if advised of the possibility of such damages.`)) +
      sec('5. Acceptable use',
        p('You agree not to:'),
        ul(
          'Submit code, repositories, or data that you do not have the right to share or analyze;',
          'Use the Service to facilitate illegal activity, or to develop or refine malware or exploits for unlawful purposes;',
          'Attempt to disrupt, overload, circumvent rate limits, or gain unauthorized access to the Service or its infrastructure;',
          'Resell or rebrand the Service in violation of its license (see section 8).')) +
      sec('6. Rate limits & fair use',
        p(`The Service is free and shared. We apply per-client rate limits and size limits, and may queue, throttle, or refuse requests to keep it available for everyone. Anonymous submissions have lower limits than signed-in accounts.`)) +
      sec('7. Third-party engines & AI processing',
        p(`Analysis engines are third-party open-source tools, each under its own license. To generate the plain-English brief, your reconciled findings and a portion of the submitted source are sent to a third-party AI provider for processing. For address-mode audits, we fetch verified source from public block explorers; for repository audits, from GitHub. See the <a href="#/privacy">Privacy Policy</a> for details.`)) +
      sec('8. Open source & intellectual property',
        p(`Audit Forge is licensed under <strong>AGPL-3.0-or-later</strong>. You retain all rights to the code you submit; we claim no ownership of it. You are responsible for ensuring you have the rights to submit it.`)) +
      sec('9. Changes',
        p(`We may update these terms as the Service evolves. Material changes will be reflected by the "Last updated" date above. Continued use after a change constitutes acceptance.`)) +
      sec('10. Contact',
        p(`Questions about these terms can be raised through the public source repository linked in the site footer.`));
    root.innerHTML = legalShell('Terms', 'Terms of Service',
      'Plain-English terms for a free, automated smart-contract analysis tool. The short version: it is a helpful first pass, not a substitute for a professional audit, and it comes with no warranty.',
      body);
  }

  function privacy(root) {
    const body =
      sec('1. Overview',
        p(`This policy explains what Audit Forge collects when you use auditforge.org, why, and who it is shared with. We aim to collect as little as possible.`)) +
      sec('2. What we collect',
        ul(
          '<strong>Submitted content</strong> — the Solidity source you paste, the contract address you enter, or the GitHub repository/path you link, plus scan options.',
          '<strong>Network/technical data</strong> — your IP address and basic request metadata, used for rate-limiting, abuse prevention, and operational logging.',
          '<strong>Account data (only if you sign in)</strong> — your GitHub username, avatar, and email, via GitHub OAuth, plus a session cookie to keep you signed in.',
          '<strong>Cookies</strong> — a single session cookie when signed in. We do not use advertising or cross-site tracking cookies.')) +
      sec('3. How we use it',
        ul(
          'To run the requested analysis and produce your report;',
          'To generate the AI brief (see section 4);',
          'To enforce rate limits and protect the Service from abuse;',
          'To operate, debug, and improve the Service.')) +
      sec('4. Third-party processors',
        p('To deliver the Service we share the minimum necessary data with:'),
        ul(
          '<strong>AI brief provider (Groq)</strong> — your reconciled findings and a portion of the submitted source are sent to generate the plain-English brief. If you consider your source sensitive, audit it privately rather than through this hosted Service.',
          '<strong>Block explorers</strong> (Etherscan, BscScan and equivalents) — only the contract address, when you audit by address, to fetch verified source.',
          '<strong>GitHub</strong> — only the repository and path, when you audit a repo, to fetch source; and for OAuth login if you sign in.',
          '<strong>Hosting</strong> — the Service runs on a dedicated server (Hetzner); data is processed there.')) +
      sec('5. Data retention',
        ul(
          '<strong>Paste audits are not persisted</strong> unless you explicitly publish the report to the public registry.',
          'Published reports (and reports you generate while signed in) are stored so they remain accessible at their share link and in the registry.',
          'Operational logs containing IP/request metadata are short-lived and used only for security and debugging.')) +
      sec('6. Security',
        p(`Each analysis engine runs in an isolated, network-disabled, resource-capped sandbox. Traffic is served over TLS. No system is perfectly secure, but we apply industry-standard safeguards.`)) +
      sec('7. Your choices',
        p(`You can use the Service anonymously (no account). If you sign in, you can sign out at any time. To request removal of a published report, contact us via the repository linked in the footer.`)) +
      sec('8. Children',
        p(`The Service is not directed to children under 13, and we do not knowingly collect their data.`)) +
      sec('9. Changes',
        p(`We may update this policy; the "Last updated" date above reflects the latest version.`)) +
      sec('10. Contact',
        p(`Privacy questions can be raised through the public source repository linked in the site footer.`));
    root.innerHTML = legalShell('Privacy', 'Privacy Policy',
      'What Audit Forge collects, why, and who it is shared with. The short version: as little as possible — and your pasted code is not stored unless you publish it.',
      body);
  }

  return { scan, report, registry, watch, runs, install, terms, privacy, toast };
})();
