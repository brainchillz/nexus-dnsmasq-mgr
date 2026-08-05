function onUnauthorized() { showLogin(); throw new Error('Session expired — please sign in'); }

const API = {
  async get(path) {
    const r = await fetch(path);
    if (r.status === 401) onUnauthorized();
    if (!r.ok) {
      let j = null; try { j = await r.json(); } catch (e) {}
      throw new Error((j && j.error) || ('HTTP ' + r.status));
    }
    return r.json();
  },
  async post(path, data) {
    const r = await fetch(path, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data)
    });
    if (r.status === 401) onUnauthorized();
    const j = await r.json();
    if (!r.ok && !j.success) {
      const e = new Error(j.error || JSON.stringify(j));
      e.body = j;  // structured details (e.g. DHCP conflict server list)
      throw e;
    }
    return j;
  },
  async delete(path) {
    const r = await fetch(path, { method: 'DELETE' });
    if (r.status === 401) onUnauthorized();
    const j = await r.json();
    if (!j.success) throw new Error(j.error || 'Command failed');
    return j;
  }
};

function $(id) { return document.getElementById(id); }
function showPage(id) { document.querySelectorAll('.nav-list a').forEach(a => a.classList.toggle('active', a.dataset.page === id)); renderPage(id); }
function escapeHtml(s) { const d = document.createElement('div'); d.textContent = (s == null ? '' : s); return d.innerHTML; }
// Escape a value for safe use as a single-quoted JS string inside a
// double-quoted HTML attribute (e.g. onclick="fn('VALUE')").
function jsArg(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')
    .replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

let isAuthed = false;
let currentUser = '';
let currentRole = 'admin';

// ─── Modal ──────────────────────────────────────────────
function openModal(title, html, opts) {
  $('modal-title').textContent = title;
  $('modal-body').innerHTML = html;
  $('modal-content').classList.toggle('wide', !!(opts && opts.wide));
  $('modal-overlay').style.display = 'flex';
}
let modalLocked = false;  // forced modals (first-run password change) can't be dismissed
function closeModal() {
  if (modalLocked) return;
  $('modal-overlay').style.display = 'none';
}
$('modal-overlay').addEventListener('click', e => { if (e.target === $('modal-overlay')) closeModal(); });

// ─── Navigation ─────────────────────────────────────────
document.querySelectorAll('.nav-list a').forEach(a => {
  a.addEventListener('click', e => { e.preventDefault(); showPage(a.dataset.page); });
});

async function renderPage(page) {
  $('page-content').innerHTML = '<div class="loading">Loading...</div>';
  const content = document.querySelector('.content');
  if (content) content.scrollTop = 0;
  window.scrollTo(0, 0);
  try {
    if (typeof window['page_' + page] === 'function') await window['page_' + page]();
    else $('page-content').innerHTML = '<h2>Page not found</h2>';
  } catch (e) {
    $('page-content').innerHTML = `<div class="error">Error: ${escapeHtml(e.message)}</div>`;
  }
}

// ─── Theme (light / dark) ───────────────────────────────
function applyThemeLabel() {
  const light = document.documentElement.classList.contains('theme-light');
  const el = $('theme-label');
  if (el) el.textContent = light ? 'Dark theme' : 'Light theme';
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', light ? '#ffffff' : '#1c1e22');
}
function toggleTheme(e) {
  if (e) e.preventDefault();
  const light = document.documentElement.classList.toggle('theme-light');
  try { localStorage.setItem('theme', light ? 'light' : 'dark'); } catch (err) {}
  applyThemeLabel();
}

// ─── Shared helpers ─────────────────────────────────────
// Inline stroke icon from the symbol set in index.html.
function icon(name, cls) {
  return `<svg class="ico ${cls || ''}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

function fmtTs(sec) {
  if (!sec) return '-';
  try { return new Date(sec * 1000).toLocaleString(); } catch (e) { return '-'; }
}

function fmtDur(sec) {
  if (sec == null) return '-';
  sec = Math.max(0, Math.round(sec));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m ${sec % 60}s`;
}

// Render a usage bar; colour shifts green -> yellow -> red as it fills.
function usageBar(pct) {
  pct = Math.max(0, Math.min(100, Math.round(pct)));
  const cls = pct >= 90 ? 'red' : pct >= 70 ? 'yellow' : 'green';
  return `<div class="usage-bar"><div class="usage-bar-fill ${cls}" style="width:${pct}%"></div><span class="usage-bar-label">${pct}%</span></div>`;
}

// Toggle switch (same markup/CSS as the Nexus Modules page).
function switchHtml(checked, onchange, disabled) {
  return `<label class="switch"><input type="checkbox" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''} onchange="${onchange}"><span class="slider"></span></label>`;
}

function enabledBadge(on) {
  return `<span class="status-badge ${on ? 'green' : 'gray'}">${on ? 'enabled' : 'disabled'}</span>`;
}

// Minimal inline-SVG sparkline from [[ts,value],...] — no chart lib (no build step).
function sparkline(points, opts) {
  opts = opts || {};
  const w = opts.w || 140, h = opts.h || 26, pad = 2;
  const pts = (points || []).filter(p => p && p[1] != null);
  if (pts.length < 2) return '<span class="help" style="font-size:.78em">collecting…</span>';
  const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  let y0 = Math.min(...ys), y1 = Math.max(...ys);
  if (y1 === y0) y1 = y0 + 1;
  const sx = t => pad + (x1 === x0 ? 0 : (t - x0) / (x1 - x0)) * (w - 2 * pad);
  const sy = v => (h - pad) - (v - y0) / (y1 - y0) * (h - 2 * pad);
  const d = pts.map((p, i) => (i ? 'L' : 'M') + sx(p[0]).toFixed(1) + ' ' + sy(p[1]).toFixed(1)).join(' ');
  return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><path d="${d}" fill="none" stroke="var(--primary,#c1550f)" stroke-width="1.5"/></svg>`;
}

// Surface the apply pipeline's service outcome after a successful save.
function notifyApply(r) {
  if (r && r.service_ok === false) {
    alert('Saved, but dnsmasq did not come back cleanly: ' + (r.service_detail || 'check the logs on the Config page.'));
  }
}

// Mirror lock: pages call lockedBanner() and disable their toolbars when the
// section is managed by a mirror source.
let mirrorStatus = { locked: [], sources: {} };
async function refreshMirrorStatus() {
  try { mirrorStatus = await API.get('/api/mirror/status'); }
  catch (e) { mirrorStatus = { locked: [], sources: {} }; }
  return mirrorStatus;
}
function sectionLocked(section) { return (mirrorStatus.locked || []).includes(section); }
function isSecondaryNode() { return Object.keys(mirrorStatus.sources || {}).length > 0; }
// Reflect secondary/replica status in the sidebar subtitle (visible on every page).
function applyRoleSubtitle() {
  const sub = document.querySelector('.sidebar-header .subtitle');
  if (!sub) return;
  if (isSecondaryNode()) {
    const src = Object.keys(mirrorStatus.sources || {}).join(', ');
    sub.innerHTML = icon('lock', 'ico-sm') + ' secondary &middot; synced from ' + escapeHtml(src);
    sub.style.color = 'var(--primary)';
  } else {
    sub.textContent = 'dnsmasq management';
    sub.style.color = '';
  }
}
function lockedBanner(section) {
  if (!sectionLocked(section)) return '';
  let src = '';
  for (const [name, s] of Object.entries(mirrorStatus.sources || {})) {
    if ((s.sections || []).includes(section)) { src = name; break; }
  }
  return `<div class="alert alert-info">${icon('lock', 'ico-sm')} This section is mirrored from <strong>${escapeHtml(src)}</strong> and is read-only on this node.
    <a href="#" onclick="showPage('peers');return false">Manage mirroring</a></div>`;
}

// ─── Overview page ──────────────────────────────────────
async function toggleFeature(key, enabled, force) {
  try {
    const r = await API.post('/api/settings/toggles', { [key]: enabled, force: !!force });
    notifyApply(r);
    if (r.probe_note) console.warn('DHCP probe note:', r.probe_note);
  } catch (e) {
    // Probe-and-warn: a foreign DHCP server answered our DISCOVER.
    if (e.body && e.body.conflict) {
      const list = (e.body.servers || []).map(s => `${s.server} (offered ${s.offer_ip})`).join(', ');
      if (confirm(`⚠ Another DHCP server is already active on this network:\n\n    ${list}\n\nRunning two DHCP servers on the same LAN causes address conflicts.\nEnable DHCP here anyway?`)) {
        return toggleFeature(key, enabled, true);
      }
    } else {
      alert(e.message);
    }
  }
  page_overview();
}

async function overviewRestart() {
  if (!confirm('Restart dnsmasq now?')) return;
  try { await API.post('/api/dnsmasq/restart', {}); } catch (e) { alert(e.message); }
  page_overview();
}

async function page_overview() {
  const [st, cur, peers] = await Promise.all([
    API.get('/api/dnsmasq/status'),
    API.get('/api/stats/current').catch(() => null),
    currentRole === 'admin' ? API.get('/api/peers').catch(() => null) : null,
    refreshMirrorStatus(),   // keep the secondary/primary role indicators current
  ]);
  const dns = (cur && cur.dns) || null;
  const dhcp = (cur && cur.dhcp) || { active_leases: 0, pools: [] };
  const peerList = (peers && peers.peers) || [];
  const peerOk = peerList.filter(p => p.last_status === 'ok').length;
  const admin = currentRole === 'admin';
  // This node is a SECONDARY when it is receiving mirrored config from a
  // source — its DNS/DHCP pages are locked read-only.
  const sources = Object.entries(mirrorStatus.sources || {});
  const isSecondary = sources.length > 0;
  const srcNames = sources.map(([n]) => n).join(', ');
  const lastRecv = sources.reduce((m, [, s]) => Math.max(m, s.last_received || 0), 0);

  const statusCard = `
    <div class="card">
      <div class="card-head"><span class="status-dot ${st.running ? 'green' : 'red'}"></span>dnsmasq</div>
      <div class="card-value" style="font-size:1.4em">${st.running ? 'running' : 'stopped'}</div>
      <div class="card-sub">${st.version ? 'v' + escapeHtml(st.version) + ' · ' : ''}${escapeHtml(st.mode)} mode${st.pid ? ' · pid ' + st.pid : ''}</div>
      ${admin ? `<div class="toolbar" style="margin-top:8px"><button class="btn btn-sm btn-outline" onclick="overviewRestart()">Restart</button></div>` : ''}
    </div>`;

  // Encrypted upstream is configured on the Settings page, not toggled here —
  // enabling it needs a provider/mode choice; this row is a status readout.
  const enc = st.encdns || {};
  const encRow = enc.enabled
    ? `<span class="status-badge ${enc.running ? 'green' : 'red'}">${enc.running ? 'active' : 'DOWN'}</span>`
    : `<span class="status-badge gray">off</span>`;
  const togglesCard = `
    <div class="card">
      <div class="card-head">Features</div>
      <div style="display:flex;flex-direction:column;gap:10px;margin-top:6px">
        <div style="display:flex;justify-content:space-between;align-items:center"><span>DNS server</span>${switchHtml(st.dns_enabled, "toggleFeature('dns_enabled', this.checked)", !admin)}</div>
        <div style="display:flex;justify-content:space-between;align-items:center"><span>DHCP server</span>${switchHtml(st.dhcp_enabled, "toggleFeature('dhcp_enabled', this.checked)", !admin)}</div>
        <div style="display:flex;justify-content:space-between;align-items:center${admin ? ';cursor:pointer" onclick="showPage(\'settings\')' : ''}" title="Encrypted DNS upstream (dnscrypt-proxy) — configured in Settings"><span>Encrypted DNS</span>${encRow}</div>
      </div>
    </div>`;

  const dnsCard = dns ? `
    <div class="card card-link" onclick="showPage('stats')">
      <div class="card-head">DNS cache</div>
      <div class="card-value">${dns.hit_ratio != null ? dns.hit_ratio : '-'}<span class="card-unit">% hit</span></div>
      <div class="card-sub">${dns.cachesize} slots · ${dns.hits} hits / ${dns.misses} misses</div>
      <div id="spark-dns"></div>
    </div>` : `
    <div class="card">
      <div class="card-head">DNS cache</div>
      <div class="card-value" style="font-size:1.1em">${st.dns_enabled ? 'unreachable' : 'DNS disabled'}</div>
      <div class="card-sub">${st.dns_enabled ? 'no answer from 127.0.0.1:53' : 'enable DNS to serve names'}</div>
    </div>`;

  const leaseCard = `
    <div class="card card-link" onclick="showPage('dhcp')">
      <div class="card-head">DHCP leases</div>
      <div class="card-value">${dhcp.active_leases}<span class="card-unit">active</span></div>
      <div class="card-sub">${dhcp.pools.length ? dhcp.pools.map(p => `${escapeHtml(p.tag)}: ${p.used}/${p.size}`).join(' · ') : (st.dhcp_enabled ? 'no pools defined' : 'DHCP disabled')}</div>
      <div id="spark-leases"></div>
    </div>`;

  // Mirroring card is role-aware: a secondary shows what it's synced FROM (not
  // "0 peers"); a primary/standalone shows the mirrors it pushes to.
  let peerCard = '';
  if (admin && isSecondary) {
    peerCard = `
    <div class="card card-link" onclick="showPage('peers')" style="border-color:var(--primary)">
      <div class="card-head">Mirroring</div>
      <div class="card-value" style="font-size:1.3em">${icon('lock')} Secondary</div>
      <div class="card-sub">synced from <strong>${escapeHtml(srcNames)}</strong></div>
      <div class="card-sub">${(mirrorStatus.locked || []).length} section(s) read-only${lastRecv ? ' &middot; last ' + fmtTs(lastRecv) : ''}</div>
    </div>`;
  } else if (admin) {
    peerCard = `
    <div class="card card-link" onclick="showPage('peers')">
      <div class="card-head">Mirroring</div>
      <div class="card-value">${peerList.length}<span class="card-unit">${peerList.length ? 'mirror' + (peerList.length === 1 ? '' : 's') : 'peers'}</span></div>
      <div class="card-sub">${peerList.length ? `${peerOk}/${peerList.length} in sync` : 'primary &middot; no mirrors configured'}</div>
    </div>`;
  }

  const pools = dhcp.pools.length ? `
    <h3>Pool utilization</h3>
    <div class="cards">${dhcp.pools.map(p => `
      <div class="card">
        <div class="card-head">${escapeHtml(p.tag)}</div>
        <div class="card-value">${p.used}<span class="card-unit">/ ${p.size}</span></div>
        ${usageBar(p.pct)}
        <div class="card-sub">${escapeHtml(p.start)} – ${escapeHtml(p.end)}</div>
      </div>`).join('')}</div>` : '';

  const secondaryBanner = isSecondary ? `<div class="alert alert-info">${icon('lock', 'ico-sm')} <strong>Secondary node.</strong>
    DNS is managed on <strong>${escapeHtml(srcNames)}</strong> and mirrored here read-only — make changes on the primary, not here.</div>` : '';

  $('page-content').innerHTML = `
    <h2>Overview</h2>
    ${secondaryBanner}
    ${st.running ? '' : '<div class="alert alert-warning"><strong>dnsmasq is not running.</strong> Check the Config page for validation errors, or restart it.</div>'}
    <div class="cards">${statusCard}${togglesCard}${dnsCard}${leaseCard}${peerCard}</div>
    ${pools}`;

  fillOverviewSparks();
}

async function fillOverviewSparks() {
  for (const [id, metric] of [['spark-dns', 'dns_hits'], ['spark-leases', 'dhcp_leases']]) {
    const el = document.getElementById(id);
    if (!el) continue;
    try { const h = await API.get(`/api/history?metric=${metric}&since=86400`); el.innerHTML = sparkline(h.points); }
    catch (e) {}
  }
}

// ─── Authentication ─────────────────────────────────────
function showLogin() {
  isAuthed = false;
  document.querySelector('.sidebar').style.display = 'none';
  document.querySelector('.content').style.display = 'none';
  modalLocked = false;
  closeModal();
  $('login-screen').style.display = 'flex';
  $('login-pass').value = '';
  $('login-user').focus();
}

async function showApp(user, fqdn, role, mustChange) {
  isAuthed = true;
  currentRole = role || 'admin';
  $('login-screen').style.display = 'none';
  document.querySelector('.sidebar').style.display = '';
  document.querySelector('.content').style.display = '';
  document.body.classList.toggle('readonly', currentRole !== 'admin');
  currentUser = user || '';
  if (fqdn) $('sidebar-title').textContent = fqdn;
  $('account-user').textContent = user ? `Signed in as ${user}${currentRole !== 'admin' ? ' · read-only' : ''}` : '';
  await refreshMirrorStatus();
  // Always-visible role cue in the sidebar so a secondary is obvious on every
  // page the moment you log in — not just the Overview.
  applyRoleSubtitle();
  showPage('overview');
  if (mustChange) forcePasswordChange();
}

// First-run: force the bootstrap admin to set a real password before anything else.
function forcePasswordChange() {
  modalLocked = true;
  openModal('Set a new password to continue', `
    <div class="alert alert-warning">This account is still using its initial setup password. Choose a new one to continue.</div>
    <div class="form-group"><label>Current password</label><input id="cp-old" type="password" class="form-control" autocomplete="current-password"></div>
    <div class="form-group"><label>New password</label><input id="cp-new" type="password" class="form-control" autocomplete="new-password"></div>
    <div class="form-group"><label>Confirm new password</label><input id="cp-confirm" type="password" class="form-control" autocomplete="new-password"></div>
    <p class="help">Must be at least 8 characters.</p>
    <button class="btn" onclick="doChangePassword(true)">Set Password</button>`);
}

async function doLogin(e) {
  e.preventDefault();
  const errEl = $('login-error');
  errEl.style.display = 'none';
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: $('login-user').value.trim(), password: $('login-pass').value })
    });
    const j = await r.json();
    if (!r.ok || !j.success) {
      errEl.textContent = j.error || 'Login failed';
      errEl.style.display = 'block';
      return;
    }
    showApp(j.user, j.fqdn, j.role, j.must_change);
  } catch (err) {
    errEl.textContent = 'Login failed';
    errEl.style.display = 'block';
  }
}

async function doLogout(e) {
  if (e) e.preventDefault();
  try { await fetch('/api/logout', { method: 'POST' }); } catch (err) {}
  showLogin();
}

function changePassword(e) {
  if (e) e.preventDefault();
  openModal('Change Password', `
    <div class="form-group"><label>Current password</label><input id="cp-old" type="password" class="form-control" autocomplete="current-password"></div>
    <div class="form-group"><label>New password</label><input id="cp-new" type="password" class="form-control" autocomplete="new-password"></div>
    <div class="form-group"><label>Confirm new password</label><input id="cp-confirm" type="password" class="form-control" autocomplete="new-password"></div>
    <p class="help">Must be at least 8 characters.</p>
    <button class="btn" onclick="doChangePassword()">Update Password</button>
  `);
}

async function doChangePassword(forced) {
  const oldp = $('cp-old').value, newp = $('cp-new').value, confirmp = $('cp-confirm').value;
  if (newp !== confirmp) { alert('New passwords do not match'); return; }
  try {
    await API.post('/api/account/password', { old_password: oldp, new_password: newp });
    modalLocked = false;
    closeModal();
    alert('Password updated.');
    if (forced) showPage('overview');
  } catch (err) { alert(err.message); }
}

async function checkAuth() {
  try {
    const r = await fetch('/api/me');
    if (!r.ok) { showLogin(); return; }
    const j = await r.json();
    showApp(j.user, j.fqdn, j.role, j.must_change);
  } catch (err) { showLogin(); }
}

applyThemeLabel();
checkAuth();

// Auto-refresh the overview every 30s while it's open and no modal is up.
setInterval(async () => {
  if (!isAuthed) return;
  const active = document.querySelector('.nav-list a.active');
  if (active && active.dataset.page === 'overview' && $('modal-overlay').style.display === 'none') {
    try { await page_overview(); } catch (e) {}
  }
}, 30000);
