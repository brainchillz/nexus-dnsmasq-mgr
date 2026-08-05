// Query Log page: live view over dnsmasq's log-queries output. Polls every
// 5 s while the page is open (paused via the button or when a modal is up).

let _qlTimer = null;
let _qlPaused = false;

async function page_querylog() {
  if (_qlTimer) { clearInterval(_qlTimer); _qlTimer = null; }
  _qlPaused = false;
  $('page-content').innerHTML = `
    <h2>Query Log</h2>
    <div id="ql-status"></div>
    <div id="ql-body"></div>`;
  await qlRefresh();
  _qlTimer = setInterval(() => {
    const active = document.querySelector('.nav-list a.active');
    if (!active || active.dataset.page !== 'querylog') { clearInterval(_qlTimer); _qlTimer = null; return; }
    if (!_qlPaused && $('modal-overlay').style.display === 'none') qlRefresh();
  }, 5000);
}

function qlTogglePause() {
  _qlPaused = !_qlPaused;
  const b = $('ql-pause');
  if (b) b.textContent = _qlPaused ? 'Resume' : 'Pause';
}

async function qlEnableLogging() {
  try {
    const r = await API.post('/api/settings', { log_queries: true });
    notifyApply(r);
    qlRefresh();
  } catch (e) { alert(e.message); }
}

function _qlTopTable(title, pairs, valueHead) {
  if (!pairs || !pairs.length) return '';
  const rows = pairs.map(([k, n]) =>
    `<tr><td><code>${escapeHtml(k)}</code></td><td style="text-align:right">${n}</td></tr>`).join('');
  return `<div class="card"><div class="card-head">${title}</div>
    <table class="table"><thead><tr><th></th><th style="text-align:right">${valueHead || 'queries'}</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

const QL_STATUS_BADGE = {
  blocked: 'red', nxdomain: 'yellow', answered: 'green',
  forwarded: 'gray', pending: 'gray',
};

async function qlRefresh() {
  let r;
  try { r = await API.get('/api/querylog'); }
  catch (e) { $('ql-status').innerHTML = `<div class="error">Error: ${escapeHtml(e.message)}</div>`; return; }

  if (!r.enabled) {
    $('ql-status').innerHTML = `<div class="alert alert-info">
      <strong>Query logging is off.</strong> dnsmasq only logs queries with <code>log-queries</code> enabled —
      counters on the Statistics page still work without it.
      ${currentRole === 'admin' ? `<div class="toolbar" style="margin-top:8px">
        <button class="btn btn-sm" onclick="qlEnableLogging()">Enable query logging</button></div>`
        : 'Ask an administrator to enable it in Settings.'}</div>`;
    $('ql-body').innerHTML = '';
    return;
  }

  $('ql-status').innerHTML = `<div class="toolbar">
    <span class="help">${r.queries} queries in the last ${r.window_lines} log lines
      (${escapeHtml(r.mode)} log) · ${r.blocked} blocked · ${r.nxdomain} NXDOMAIN · refreshes every 5 s</span>
    <button id="ql-pause" class="btn btn-sm btn-outline" onclick="qlTogglePause()">${_qlPaused ? 'Resume' : 'Pause'}</button>
  </div>`;

  const tops = `
    <div class="cards">
      ${_qlTopTable('Top domains', r.top_domains)}
      ${_qlTopTable('Top clients', r.top_clients)}
      ${_qlTopTable('Blocked hits', r.top_blocked, 'hits')}
      ${_qlTopTable('Answered by upstream', r.upstreams, 'forwards')}
    </div>`;

  const entries = (r.entries || []).slice().reverse();
  const rows = entries.map(en => {
    const ans = (en.answers || []).map(a =>
      `${escapeHtml(a.value)} <span class="help">(${escapeHtml(a.source)})</span>`).join('<br>');
    return `<tr>
      <td class="help" style="white-space:nowrap">${escapeHtml(en.time || '')}</td>
      <td><span class="badge-type">${escapeHtml(en.qtype)}</span></td>
      <td><code>${escapeHtml(en.name)}</code></td>
      <td>${escapeHtml(en.client)}</td>
      <td><span class="status-badge ${QL_STATUS_BADGE[en.status] || 'gray'}">${escapeHtml(en.status)}</span></td>
      <td>${ans || (en.upstreams && en.upstreams.length ? '→ ' + escapeHtml(en.upstreams.join(', ')) : '')}</td>
    </tr>`;
  }).join('');

  $('ql-body').innerHTML = `${tops}
    <h3 style="margin-top:18px">Recent queries <span class="help">(newest first)</span></h3>
    <table class="table"><thead><tr><th>Time</th><th>Type</th><th>Name</th><th>Client</th><th>Status</th><th>Answer</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="6">No queries parsed from the current log window yet.</td></tr>`}</tbody></table>`;
}
