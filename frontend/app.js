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

  // ─── Sign-in provider chooser ──────────────────────────────────────
  // If both GitHub and Google are configured, present a small chooser modal.
  // If only one provider is live, go straight to it (no needless extra click).
  function showSignin(returnTo) {
    const cfg = window.AF_CONFIG || {};
    if (!cfg.googleAuthEnabled) { API.login(returnTo); return; }
    if (!cfg.authEnabled) { API.loginGoogle(returnTo); return; }
    const old = document.getElementById('af-signin-ov');
    if (old) old.remove();
    const ov = document.createElement('div');
    ov.id = 'af-signin-ov';
    ov.className = 'af-modal-ov';
    ov.innerHTML =
      '<div class="af-modal" role="dialog" aria-modal="true" aria-label="Sign in to Audit Forge">' +
        '<button class="af-modal-x" aria-label="Close">&times;</button>' +
        '<h3>Sign in to Audit Forge</h3>' +
        '<p>Publish audits to the public registry and unlock higher daily limits. Free, either way.</p>' +
        '<button class="af-prov" data-prov="github">' +
          '<svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"></path></svg>' +
          '<span>Continue with GitHub</span></button>' +
        '<button class="af-prov" data-prov="google">' +
          '<svg viewBox="0 0 18 18" width="18" height="18" aria-hidden="true"><path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62Z"></path><path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.33A9 9 0 0 0 9 18Z"></path><path fill="#FBBC05" d="M3.97 10.72a5.4 5.4 0 0 1 0-3.44V4.95H.96a9 9 0 0 0 0 8.1l3.01-2.33Z"></path><path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.58C13.46.89 11.43 0 9 0A9 9 0 0 0 .96 4.95l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58Z"></path></svg>' +
          '<span>Continue with Google</span></button>' +
        '<p class="af-modal-fine">We use your account only to identify you. See our <a href="/privacy/">Privacy Policy</a>.</p>' +
      '</div>';
    document.body.appendChild(ov);
    const close = () => { ov.remove(); document.removeEventListener('keydown', onEsc); };
    function onEsc(e) { if (e.key === 'Escape') close(); }
    ov.addEventListener('click', (e) => { if (e.target === ov) close(); });
    ov.querySelector('.af-modal-x').addEventListener('click', close);
    ov.querySelector('[data-prov="github"]').addEventListener('click', () => API.login(returnTo));
    ov.querySelector('[data-prov="google"]').addEventListener('click', () => API.loginGoogle(returnTo));
    document.addEventListener('keydown', onEsc);
  }
  // Let other modules (e.g. the watch view) open the same chooser.
  window.AF_signin = showSignin;

  // ─── User pill (top-right) ─────────────────────────────────────────
  function renderUserPill(user) {
    const pill = document.getElementById('user-pill');
    if (!pill) return;
    if (!user) {
      pill.className = '';
      // Show "Sign in" only when at least one OAuth provider is configured
      // (per /api/config), so the button never appears as a dead end.
      if (window.AF_CONFIG && (window.AF_CONFIG.authEnabled || window.AF_CONFIG.googleAuthEnabled)) {
        pill.innerHTML = '<button class="signin-btn" id="signin-btn">Sign in</button>';
        const b = document.getElementById('signin-btn');
        if (b) b.addEventListener('click', () => showSignin());
      } else {
        pill.innerHTML = '';
      }
      return;
    }
    pill.className = 'user-pill';
    pill.innerHTML =
      (user.avatarUrl ? `<img src="${user.avatarUrl}" alt="">` : '') +
      `<span class="uname">${user.name || user.githubUsername || 'account'}</span>` +
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
    catch { window.AF_CONFIG = { authEnabled: false, googleAuthEnabled: false, turnstileSiteKey: null }; }
    await API.refreshMe().catch(() => {});
    if (!window.location.hash) window.location.hash = '#/scan';
    else navigate();
    pingApi();
    setInterval(pingApi, 30000);
  });
})();
