// Lookup page: ask the running dnsmasq for a name and show where every answer
// actually comes from (managed record, /etc/hosts, foreign conf, lease,
// blocklist, upstream). Also renders the shadowing audit banner used here and
// on the DNS page.

const LOOKUP_KIND_LABEL = {
  host: ['Managed host record', 'green'],
  override: ['Managed override', 'green'],
  cname: ['Managed CNAME', 'green'],
  blocklist: ['Blocklist', 'green'],
  forward: ['Managed forward', 'green'],
  lease: ['DHCP lease', 'gray'],
  upstream: ['Upstream / cache', 'gray'],
  'encrypted-upstream': ['Encrypted upstream', 'green'],
  'etc-hosts': ['/etc/hosts', 'yellow'],
  'foreign-conf': ['Foreign conf', 'yellow'],
};

async function page_lookup() {
  $('page-content').innerHTML = `
    <h2>Lookup</h2>
    <p class="help">Query this server's dnsmasq for a name and see where each answer comes from —
      including sources outside this app (the system <code>/etc/hosts</code>, other dnsmasq config files, DHCP leases).</p>
    <div id="lookup-audit"></div>
    <form class="toolbar" onsubmit="lookupGo(event)" style="max-width:560px">
      <input id="lk-name" class="form-control" placeholder="nas.lan" autocomplete="off" spellcheck="false" style="flex:1">
      <button class="btn" type="submit">${icon('search', 'ico-sm')} Look up</button>
    </form>
    <div id="lk-result"></div>`;
  $('lk-name').focus();
  renderAuditBanner('lookup-audit');
}

async function lookupGo(e) {
  if (e) e.preventDefault();
  const name = $('lk-name').value.trim();
  if (!name) return;
  const out = $('lk-result');
  out.innerHTML = '<div class="loading">Querying dnsmasq…</div>';
  let r;
  try {
    r = await API.get('/api/lookup?name=' + encodeURIComponent(name));
  } catch (err) {
    out.innerHTML = `<div class="alert alert-warning"><strong>Lookup failed:</strong> ${escapeHtml(err.message)}</div>`;
    return;
  }

  const warnings = (r.warnings || []).map(w =>
    `<div class="alert alert-warning">${icon('warn', 'ico-sm')} ${escapeHtml(w)}</div>`).join('');

  let body;
  if (!r.answers.length) {
    body = `<div class="card" style="max-width:560px"><div class="card-head">${escapeHtml(r.name)}</div>
      <div class="card-value" style="font-size:1.1em">${r.nxdomain ? 'NXDOMAIN' : 'no A/AAAA records'}</div>
      <div class="card-sub">${r.nxdomain ? 'the server says this name does not exist' : 'the name exists but has no address records'}</div></div>`;
  } else {
    const rows = r.answers.map(a => {
      const [label, color] = LOOKUP_KIND_LABEL[a.source.kind] || [a.source.kind, 'gray'];
      return `<tr>
        <td><span class="badge-type">${escapeHtml(a.type)}</span></td>
        <td><code>${escapeHtml(a.name)}</code></td>
        <td><code>${escapeHtml(a.value)}</code></td>
        <td>${a.ttl}</td>
        <td><span class="status-badge ${color}">${escapeHtml(label)}</span>
            ${a.source.warn ? ` <span class="status-badge red">not managed by me</span>` : ''}
            <div class="help" style="margin-top:2px">${escapeHtml(a.source.detail)}</div></td>
      </tr>`;
    }).join('');
    body = `<table class="table"><thead><tr><th>Type</th><th>Name</th><th>Answer</th><th>TTL</th><th>Source</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }
  out.innerHTML = `${warnings}${body}
    ${r.no_hosts ? '' : `<p class="help">dnsmasq is reading the system <code>/etc/hosts</code> (default). You can turn that off
      with “Ignore the system /etc/hosts” in Settings so only managed records are served.</p>`}`;
}

// Shared shadowing-audit banner (Lookup page + DNS Overrides page).
async function renderAuditBanner(elId) {
  const el = document.getElementById(elId);
  if (!el) return;
  let a;
  try { a = await API.get('/api/lookup/audit'); } catch (e) { return; }
  if (!a.conflicts || !a.conflicts.length) { el.innerHTML = ''; return; }
  const items = a.conflicts.slice(0, 6).map(c => {
    if (c.kind === 'etc-hosts')
      return `<li><code>${escapeHtml(c.name)}</code> is also defined in <code>${escapeHtml(c.file)}</code> line ${c.line}
        as <code>${escapeHtml(c.ip)}</code> (managed record says <code>${escapeHtml(c.expected)}</code>)</li>`;
    if (c.kind === 'etc-hosts-loopback')
      return `<li><code>${escapeHtml(c.name)}</code> resolves to <code>${escapeHtml(c.ip)}</code>
        via <code>${escapeHtml(c.file)}</code> line ${c.line} — clients are being sent to
        <em>themselves</em> for this name</li>`;
    return `<li><code>${escapeHtml(c.file)}</code> line ${c.line}: <code>${escapeHtml(c.text || '')}</code></li>`;
  }).join('');
  el.innerHTML = `<div class="alert alert-warning">${icon('warn', 'ico-sm')}
    <strong>${a.conflicts.length} name(s) are shadowed by config outside this app.</strong>
    dnsmasq may answer with values the UI does not show.
    <ul style="margin:6px 0 0 18px">${items}</ul>
    ${a.conflicts.length > 6 ? `<div class="help">…and ${a.conflicts.length - 6} more.</div>` : ''}
    <a href="#" onclick="showPage('lookup');return false">Diagnose with Lookup</a></div>`;
}
