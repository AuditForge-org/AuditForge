// SPDX-License-Identifier: AGPL-3.0-or-later
/* ===========================================================================
   FORENSIQ — API client
   Single source of truth for talking to the backend. Every view uses this.
   =========================================================================== */

window.API = (function () {
  // Default to relative URLs (same-origin); override via ?api= for local dev
  const params = new URLSearchParams(window.location.search);
  const BASE = params.get('api') || (
    window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'http://localhost:3000'
      : ''
  );

  // Current authenticated user, populated by refreshMe(). null = not logged in,
  // undefined = haven't checked yet.
  let currentUser = undefined;
  const subscribers = new Set();

  function onAuthChange(fn) {
    subscribers.add(fn);
    if (currentUser !== undefined) fn(currentUser);
    return () => subscribers.delete(fn);
  }
  function setUser(u) {
    currentUser = u;
    for (const fn of subscribers) try { fn(u); } catch {}
  }
  function getUser() { return currentUser; }

  async function request(path, opts = {}) {
    const url = BASE + path;
    const headers = {
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    };
    const res = await fetch(url, {
      ...opts,
      headers,
      // Cookies for session auth — required for cross-origin in dev
      credentials: 'include',
    });
    if (res.status === 204) return null;
    const ct = res.headers.get('content-type') || '';
    if (!res.ok) {
      let detail = '';
      try {
        detail = ct.includes('json') ? JSON.stringify(await res.json()) : await res.text();
      } catch { detail = res.statusText; }
      const err = new Error(`${res.status}: ${detail.slice(0, 200)}`);
      err.status = res.status;
      // 401 → user is logged out
      if (res.status === 401) setUser(null);
      throw err;
    }
    if (ct.includes('json')) return res.json();
    return res.text();
  }

  // ─── Auth ───────────────────────────────────────────────────────────

  /** Fetch the current user. Updates the cached state. */
  async function refreshMe() {
    try {
      const { user } = await request('/api/auth/me');
      setUser(user);
      return user;
    } catch (e) {
      if (e.status === 401 || e.status === 503) { setUser(null); return null; }
      throw e;
    }
  }

  /** Start the OAuth flow. Browser navigates away — no return value. */
  function login(returnTo) {
    const url = BASE + '/api/auth/github/login?returnTo=' +
      encodeURIComponent(returnTo || window.location.hash || '#/scan');
    window.location.href = url;
  }

  /** End the current session. */
  async function logout() {
    try { await request('/api/auth/logout', { method: 'POST' }); }
    finally { setUser(null); }
  }

  // ─── Health / public config ─────────────────────────────────────────
  async function health() { return request('/api/health'); }
  /** Public client config: { authEnabled, turnstileSiteKey } */
  async function getConfig() { return request('/api/config'); }

  // ─── Audits ─────────────────────────────────────────────────────────

  /**
   * Submit an audit.
   * @param {object} source     { type: 'paste'|'address'|'github', ... }
   * @param {object} [opts]     { tools, solcVersion, enableFuzzing }
   * @returns {Promise<{id: string, status: string, pollUrl: string}>}
   */
  async function submitAudit(source, opts = {}) {
    return request('/api/audits', {
      method: 'POST',
      body: JSON.stringify({ source, ...opts }),
    });
  }

  /** Poll for status or completed report */
  async function getAudit(id) { return request(`/api/audits/${id}`); }

  /**
   * Subscribe to job progress. Polls every 2s until 'complete' or 'failed'.
   * Calls onUpdate({status, progress, report?}) on every poll.
   * Returns a cancel function.
   */
  function watchAudit(id, onUpdate) {
    let cancelled = false;
    let timer = null;
    async function tick() {
      if (cancelled) return;
      try {
        const data = await getAudit(id);
        onUpdate(data);
        if (data.status === 'complete' || data.status === 'failed') return;
      } catch (e) {
        onUpdate({ status: 'failed', error: e.message });
        return;
      }
      timer = setTimeout(tick, 2000);
    }
    tick();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }

  function pdfUrl(id) { return `${BASE}/api/audits/${id}/pdf`; }
  // Real-path URLs (not hash) so social crawlers can fetch per-report OG meta.
  function reportUrl(id) { return `${window.location.origin}/r/${id}`; }
  function shareUrl(id) { return reportUrl(id); }
  function badgeUrl(id) { return `${window.location.origin}/badge/${id}.svg`; }

  // ─── Watch (continuous-audit projects) ──────────────────────────────

  async function listWatchedProjects() {
    return request('/api/watch');
  }
  async function createWatchedProject(payload) {
    return request('/api/watch', { method: 'POST', body: JSON.stringify(payload) });
  }
  async function getWatchedProject(id) {
    return request(`/api/watch/${id}`);
  }
  async function deleteWatchedProject(id) {
    return request(`/api/watch/${id}`, { method: 'DELETE' });
  }
  async function listProjectRuns(id) {
    return request(`/api/watch/${id}/runs`);
  }

  // ─── Registry ───────────────────────────────────────────────────────

  /** Public — no auth needed */
  async function getLeaderboard(filters = {}) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(filters)) {
      if (v != null && v !== '') qs.set(k, v);
    }
    return request(`/api/registry?${qs.toString()}`);
  }
  async function getChainStats() {
    return request('/api/registry/chains');
  }
  async function getContractHistory(chain, address) {
    return request(`/api/registry/contract/${chain}/${address}`);
  }
  async function publishReport(reportId, opts = {}) {
    return request(`/api/registry/publish/${reportId}`, {
      method: 'POST',
      body: JSON.stringify(opts),
    });
  }

  return {
    BASE,
    // Auth
    refreshMe, login, logout, getUser, onAuthChange,
    health, getConfig,
    submitAudit, getAudit, watchAudit, pdfUrl, shareUrl, reportUrl, badgeUrl,
    listWatchedProjects, createWatchedProject, getWatchedProject,
    deleteWatchedProject, listProjectRuns,
    getLeaderboard, getChainStats, getContractHistory, publishReport,
  };
})();
