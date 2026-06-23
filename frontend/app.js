// SPDX-License-Identifier: AGPL-3.0-or-later
/* ===========================================================================
   AUDIT FORGE — App router + auth bootstrap.
   Hash-based routing (no build step). On hashchange we resolve the route,
   render the matching Views.<name>(), then AFUI.hydrate() to wire behaviors.
   =========================================================================== */

(function () {
  const VIEW_EL = document.getElementById('view');

  const ROUTES = [
    { match: /^\/?$/,                view: 'scan' },
    { match: /^\/scan$/,             view: 'scan' },
    { match: /^\/report\/([\w-]+)$/, view: 'report',   params: m => ({ id: m[1] }) },
    { match: /^\/registry$/,         view: 'registry' },
    { match: /^\/engines$/,          view: 'engines' },
    { match: /^\/watch$/,            view: 'watch' },
    { match: /^\/runs\/([\w-]+)$/,   view: 'runs',     params: m => ({ id: m[1] }) },
    { match: /^\/install$/,          view: 'install' },
    { match: /^\/terms$/,            view: 'terms' },
    { match: /^\/privacy$/,          view: 'privacy' },
  ];

  let cleanupCurrentView = null;

  function resolve() {
    const hash = window.location.hash.replace(/^#/, '') || '/scan';
    for (const r of ROUTES) {
      const m = r.match.exec(hash);
      if (m) return { view: r.view, params: r.params ? r.params(m) : {} };
    }
    return { view: 'scan', params: {} };
  }

  function highlightActiveNav() {
    const hash = window.location.hash.replace(/^#/, '');
    document.querySelectorAll('.nav a[data-route]').forEach(a => {
      const route = a.getAttribute('data-route');
      a.classList.toggle('active', hash === route || (route === '/scan' && (hash === '' || hash === '/')));
    });
  }

  async function navigate() {
    if (cleanupCurrentView) { try { cleanupCurrentView(); } catch {} cleanupCurrentView = null; }

    const { view, params } = resolve();
    highlightActiveNav();

    const handler = Views[view];
    if (!handler) { VIEW_EL.innerHTML = '<section class="page-section"><div class="wrap"><div class="af-empty">Unknown route</div></div></section>'; return; }

    try {
      const cleanup = await handler(VIEW_EL, params);
      if (typeof cleanup === 'function') cleanupCurrentView = cleanup;
      if (window.AFUI && AFUI.hydrate) AFUI.hydrate(VIEW_EL);
      window.scrollTo(0, 0);
    } catch (e) {
      console.error('[route] handler error:', e);
      VIEW_EL.innerHTML = '<section class="page-section"><div class="wrap"><div class="af-empty"><span class="ico">✕</span>Failed to render: ' + (e && e.message ? e.message : e) + '</div></div></section>';
    }
  }

  // ─── User pill (top-right) ─────────────────────────────────────────
  function renderUserPill(user) {
    const pill = document.getElementById('user-pill');
    if (!pill) return;
    if (!user) {
      pill.className = '';
      // Show "Sign in" only when GitHub OAuth is actually configured (per /api/config),
      // so the button never appears as a dead end.
      if (window.AF_CONFIG && window.AF_CONFIG.authEnabled) {
        pill.innerHTML = '<button class="signin-btn" id="signin-btn">Sign in</button>';
        const b = document.getElementById('signin-btn');
        if (b) b.addEventListener('click', () => API.login());
      } else {
        pill.innerHTML = '';
      }
      return;
    }
    pill.className = 'user-pill';
    pill.innerHTML =
      (user.avatarUrl ? `<img src="${user.avatarUrl}" alt="">` : '') +
      `<span class="uname">${user.githubUsername || 'account'}</span>` +
      `<div class="umenu"><a href="#/watch">My watch</a><button id="pill-logout">Sign out</button></div>`;
    pill.addEventListener('click', (e) => { if (e.target.id === 'pill-logout') return; pill.classList.toggle('open'); });
    const lo = document.getElementById('pill-logout');
    if (lo) lo.addEventListener('click', async (e) => {
      e.stopPropagation(); pill.classList.remove('open');
      await API.logout(); Views.toast('Signed out'); navigate();
    });
    document.addEventListener('click', (e) => { if (!pill.contains(e.target)) pill.classList.remove('open'); });
  }
  API.onAuthChange(renderUserPill);

  // ─── API health indicator (.api-pill) ──────────────────────────────
  async function pingApi() {
    const el = document.getElementById('api-status');
    if (!el) return;
    try {
      await API.health();
      el.classList.remove('down');
      el.innerHTML = '<span class="dot"></span>API operational';
    } catch {
      el.classList.add('down');
      el.innerHTML = '<span class="dot"></span>API offline';
    }
  }

  // ─── Theme toggle ──────────────────────────────────────────────────
  function syncThemeMeta(t) {
    const mc = document.querySelector('meta[name="theme-color"]');
    if (mc) mc.setAttribute('content', t === 'dark' ? '#07080A' : '#F3EFE6');
  }
  function initThemeToggle() {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    const cur0 = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    btn.setAttribute('aria-pressed', String(cur0 === 'dark'));
    syncThemeMeta(cur0);
    btn.addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
      const next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      btn.setAttribute('aria-pressed', String(next === 'dark'));
      syncThemeMeta(next);
      try { localStorage.setItem('af-theme', next); } catch (e) {}
      // Drop a stale ?theme= override so the manual choice sticks on reload.
      try {
        const u = new URL(location.href);
        if (u.searchParams.has('theme')) {
          u.searchParams.delete('theme');
          history.replaceState(null, '', u.pathname + u.search + u.hash);
        }
      } catch (e) {}
    });
  }

  // Share links use real paths (/r/:id) so social crawlers can unfurl them.
  // The SPA itself is hash-routed, so on boot we translate a real report path
  // into the hash route and clean up the URL bar.
  function adoptRealPath() {
    const m = window.location.pathname.match(/^\/(?:r|report)\/([\w-]+)\/?$/);
    if (m) { history.replaceState(null, '', '/#/report/' + m[1]); }
  }

  // ─── Boot ──────────────────────────────────────────────────────────
  window.addEventListener('hashchange', navigate);
  window.addEventListener('load', async () => {
    initThemeToggle();
    adoptRealPath();
    // Load public config first so the user pill knows whether to offer "Sign in".
    try { window.AF_CONFIG = await API.getConfig(); }
    catch { window.AF_CONFIG = { authEnabled: false, turnstileSiteKey: null }; }
    await API.refreshMe().catch(() => {});
    if (!window.location.hash) window.location.hash = '#/scan';
    else navigate();
    pingApi();
    setInterval(pingApi, 30000);
  });
})();
