// DHCP page: ranges, static leases, options, live leases.
let _dhcpData = null;
let _dhcpLeases = [];
let _dhcpLastEvent = 0;
let _dhcpTimer = null;

const DHCP_OPTION_PRESETS = [
  ['option:router', 'Default gateway (3)'],
  ['option:dns-server', 'DNS servers (6)'],
  ['option:ntp-server', 'NTP servers (42)'],
  ['option:domain-name', 'Domain name (15)'],
  ['option:domain-search', 'Domain search list (119)'],
  ['option:tftp-server', 'TFTP server name (66)'],
  ['option:bootfile-name', 'Boot file name (67)'],
  ['option:classless-static-route', 'Static routes (121)'],
];

async function page_dhcp() {
  await refreshMirrorStatus();
  const [d, st, leases, ev] = await Promise.all([
    API.get('/api/dhcp'),
    API.get('/api/dnsmasq/status'),
    API.get('/api/dhcp/leases').catch(() => ({ leases: [] })),
    API.get('/api/dhcp/events').catch(() => null),
  ]);
  _dhcpData = d;
  _dhcpLeases = leases.leases || [];
  _dhcpLastEvent = leases.last_event_ts || 0;
  const locked = sectionLocked('dhcp');
  const can = currentRole === 'admin' && !locked;

  const rangeRows = d.ranges.map(r => `<tr>
    <td>${r.tag ? `<span class="badge-type">${escapeHtml(r.tag)}</span>` : (r.interface ? `<code>${escapeHtml(r.interface)}</code>` : '-')}</td>
    <td><code>${escapeHtml(r.start)} – ${escapeHtml(r.end)}</code></td>
    <td>${escapeHtml(r.netmask || 'auto')}</td>
    <td>${escapeHtml(r.lease)}</td>
    <td>${enabledBadge(r.enabled)}</td>
    <td>${escapeHtml(r.comment || '')}</td>
    <td class="row-actions">${can ? `
      <button class="btn btn-sm btn-outline" onclick="dhcpRangeModal('${jsArg(r.id)}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="dhcpDelete('ranges','${jsArg(r.id)}','${jsArg(r.start)}')">Delete</button>` : ''}
    </td></tr>`).join('');

  const staticRows = d.static_leases.map(s => `<tr data-row>
    <td><code>${escapeHtml(s.mac)}</code></td>
    <td>${escapeHtml(s.ip)}</td>
    <td>${escapeHtml(s.hostname || '-')}</td>
    <td>${s.tag ? `<span class="badge-type">${escapeHtml(s.tag)}</span>` : '-'}</td>
    <td>${enabledBadge(s.enabled)}</td>
    <td class="row-actions">${can ? `
      <button class="btn btn-sm btn-outline" onclick="dhcpStaticModal('${jsArg(s.id)}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="dhcpDelete('static_leases','${jsArg(s.id)}','${jsArg(s.mac)}')">Delete</button>` : ''}
    </td></tr>`).join('');

  const optRows = d.options.map(o => `<tr>
    <td>${o.tag ? `<span class="badge-type">${escapeHtml(o.tag)}</span>` : '<span class="help">all</span>'}</td>
    <td><code>${escapeHtml(o.option)}</code></td>
    <td>${escapeHtml(o.value || '-')}</td>
    <td>${enabledBadge(o.enabled)}</td>
    <td class="row-actions">${can ? `
      <button class="btn btn-sm btn-outline" onclick="dhcpOptModal('${jsArg(o.id)}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="dhcpDelete('options','${jsArg(o.id)}','${jsArg(o.option)}')">Delete</button>` : ''}
    </td></tr>`).join('');

  const leaseRows = (leases.leases || []).map(l => `<tr data-row>
    <td><code>${escapeHtml(l.mac)}</code></td>
    <td>${escapeHtml(l.ip)}</td>
    <td>${escapeHtml(l.hostname || '-')}</td>
    <td class="help">${escapeHtml(l.vendor || '')}</td>
    <td>${l.expiry ? fmtDur(l.expires_in) : 'infinite'}</td>
    <td>${l.static ? '<span class="status-badge green">static</span>' : '<span class="status-badge gray">dynamic</span>'}</td>
    <td class="row-actions">${can && !l.static ? `<button class="btn btn-sm" onclick="dhcpReserve('${jsArg(l.mac)}','${jsArg(l.ip)}','${jsArg(l.hostname || '')}')">Reserve</button>` : ''}
      ${can ? `<button class="btn btn-sm btn-outline" title="Send a DHCPRELEASE for this lease (the client keeps the address until it renews)" onclick="dhcpRelease('${jsArg(l.mac)}','${jsArg(l.ip)}')">Release</button>` : ''}</td>
    </tr>`).join('');

  const evRows = ev && ev.events && ev.events.length ? ev.events.slice(0, 12).map(e => `<tr>
    <td class="help" style="white-space:nowrap">${fmtTs(e.ts)}</td>
    <td><span class="badge-type">${escapeHtml(e.action === 'old' ? 'renew' : e.action === 'del' ? 'expire' : 'new')}</span></td>
    <td><code>${escapeHtml(e.mac)}</code></td><td>${escapeHtml(e.ip)}</td>
    <td>${escapeHtml(e.hostname || '-')}</td><td class="help">${escapeHtml(e.vendor || '')}</td></tr>`).join('') : '';
  const evNote = !ev ? '' : !ev.enabled ? '<span class="help">lease events are off (Settings → “Report lease events”)</span>'
    : !ev.listening ? '<span class="status-badge yellow">listener not running</span>'
    : !ev.active ? '<span class="help">reported live once DHCP is enabled</span>'
    : `<span class="status-badge green">live</span> <span class="help">dnsmasq reports every lease change to the app on 127.0.0.1:${ev.port}</span>`;

  $('page-content').innerHTML = `
    <h2>DHCP</h2>
    ${st.dhcp_enabled ? '' : `<div class="alert alert-info">DHCP is currently <strong>disabled</strong>. Configuration is kept but not served.
      ${currentRole === 'admin' ? '<a href="#" onclick="toggleFeature(\'dhcp_enabled\', true);return false">Enable DHCP</a>' : ''}</div>`}
    ${lockedBanner('dhcp')}
    <h3>Pools / Ranges</h3>
    ${can ? `<div class="toolbar"><button class="btn btn-sm" onclick="dhcpRangeModal()">+ Add range</button></div>` : ''}
    <table class="table"><thead><tr><th>Tag / Interface</th><th>Range</th><th>Netmask</th><th>Lease</th><th>State</th><th>Comment</th><th></th></tr></thead>
      <tbody>${rangeRows || '<tr><td colspan="7">No DHCP ranges — add one to serve leases</td></tr>'}</tbody></table>

    <h3 style="margin-top:24px">Static Leases</h3>
    <div class="toolbar">${can ? `<button class="btn btn-sm" onclick="dhcpStaticModal()">+ Add static lease</button>` : ''}
      <button class="btn btn-sm btn-outline" onclick="dhcpExport('static')">${icon('ul', 'ico-sm')} CSV</button>
      ${filterBox('dh-static-filter', 'dh-static-table', 'dh-static-count', 'filter MAC / IP / hostname…')}</div>
    <table class="table" id="dh-static-table"><thead><tr><th>MAC</th><th>IP</th><th>Hostname</th><th>Tag</th><th>State</th><th></th></tr></thead>
      <tbody>${staticRows || '<tr><td colspan="6">No static leases</td></tr>'}</tbody></table>

    <h3 style="margin-top:24px">Options</h3>
    ${can ? `<div class="toolbar"><button class="btn btn-sm" onclick="dhcpOptModal()">+ Add option</button></div>` : ''}
    <table class="table"><thead><tr><th>Tag</th><th>Option</th><th>Value</th><th>State</th><th></th></tr></thead>
      <tbody>${optRows || '<tr><td colspan="5">No options — dnsmasq defaults apply (gateway/DNS = this host)</td></tr>'}</tbody></table>

    <h3 style="margin-top:24px">Live Leases <span class="help">(${(leases.leases || []).length} active)</span></h3>
    <div class="toolbar">
      <button class="btn btn-sm btn-outline" onclick="dhcpExport('leases')">${icon('ul', 'ico-sm')} CSV</button>
      ${filterBox('dh-lease-filter', 'dh-lease-table', 'dh-lease-count', 'filter MAC / IP / hostname / vendor…')}
      ${evNote}
    </div>
    <table class="table" id="dh-lease-table"><thead><tr><th>MAC</th><th>IP</th><th>Hostname</th><th>Vendor</th><th>Expires</th><th>Type</th><th></th></tr></thead>
      <tbody>${leaseRows || '<tr><td colspan="7">No active leases</td></tr>'}</tbody></table>
    ${evRows ? `<h3 style="margin-top:24px">Recent lease events</h3>
    <table class="table"><thead><tr><th>When</th><th>Event</th><th>MAC</th><th>IP</th><th>Hostname</th><th>Vendor</th></tr></thead>
      <tbody>${evRows}</tbody></table>` : ''}`;
  tableFilter('dh-static-filter', 'dh-static-table', 'dh-static-count');
  tableFilter('dh-lease-filter', 'dh-lease-table', 'dh-lease-count');
  // Re-render when a lease event has arrived since this render (cheap poll of
  // the leases endpoint; only while the page is open and no modal is up).
  if (_dhcpTimer) clearInterval(_dhcpTimer);
  _dhcpTimer = setInterval(async () => {
    const active = document.querySelector('.nav-list a.active');
    if (!active || active.dataset.page !== 'dhcp') { clearInterval(_dhcpTimer); _dhcpTimer = null; return; }
    if ($('modal-overlay').style.display !== 'none') return;
    if ($('dh-lease-filter') && $('dh-lease-filter').value) return;   // don't yank a filtered view
    try {
      const r = await API.get('/api/dhcp/leases');
      if ((r.last_event_ts || 0) !== _dhcpLastEvent || (r.count || 0) !== _dhcpLeases.length) page_dhcp();
    } catch (e) {}
  }, 5000);
}

function dhcpExport(kind) {
  const stamp = new Date().toISOString().slice(0, 10);
  if (kind === 'static') {
    downloadCsv(`dnsmaq-static-leases-${stamp}.csv`, ['mac', 'ip', 'hostname', 'tag', 'enabled', 'comment', 'id'],
      (_dhcpData.static_leases || []).map(s => [s.mac, s.ip, s.hostname || '', s.tag || '', s.enabled === false ? 'no' : 'yes', s.comment || '', s.id]));
    return;
  }
  downloadCsv(`dnsmaq-leases-${stamp}.csv`, ['mac', 'ip', 'hostname', 'vendor', 'expires_at', 'static', 'client_id'],
    _dhcpLeases.map(l => [l.mac, l.ip, l.hostname || '', l.vendor || '',
      l.expiry ? new Date(l.expiry * 1000).toISOString() : 'infinite', l.static ? 'yes' : 'no', l.client_id || '']));
}

async function dhcpRelease(mac, ip) {
  if (!confirm(`Release the lease for ${mac} at ${ip}?\n\nThe pool slot is freed now; the device keeps using the address until it renews.`)) return;
  try {
    await API.post('/api/dhcp/leases/release', { mac, ip });
    page_dhcp();
  } catch (e) { alert(e.message); }
}

function _drec(coll, id) { return (_dhcpData[coll] || []).find(r => r.id === id) || {}; }

function _dhcpFormCommon(r) {
  return `
    <div class="form-group"><label>Comment</label><input id="dh-comment" class="form-control" value="${escapeHtml(r.comment || '')}"></div>
    <label class="checkitem" style="padding-left:0"><input id="dh-enabled" type="checkbox" ${r.enabled !== false ? 'checked' : ''}> Enabled</label>`;
}

function dhcpRangeModal(id) {
  const r = id ? _drec('ranges', id) : {};
  openModal(id ? 'Edit DHCP range' : 'Add DHCP range', `
    <div class="form-group"><label>Start address</label><input id="dh-start" class="form-control" value="${escapeHtml(r.start || '')}" placeholder="10.0.0.100"></div>
    <div class="form-group"><label>End address</label><input id="dh-end" class="form-control" value="${escapeHtml(r.end || '')}" placeholder="10.0.0.199"></div>
    <div class="form-group"><label>Netmask (optional)</label><input id="dh-netmask" class="form-control" value="${escapeHtml(r.netmask || '')}" placeholder="255.255.255.0"></div>
    <div class="form-group"><label>Lease time</label><input id="dh-lease" class="form-control" value="${escapeHtml(r.lease || '12h')}" placeholder="12h / 90m / infinite"></div>
    <div class="form-group"><label>Tag (optional — for tagged options/boot)</label><input id="dh-tag" class="form-control" value="${escapeHtml(r.tag || '')}"></div>
    <div class="form-group"><label>Interface (optional — serve this range only on one NIC; cannot combine with a tag)</label><input id="dh-iface" class="form-control" value="${escapeHtml(r.interface || '')}" placeholder="eth0"></div>
    ${_dhcpFormCommon(r)}
    <button class="btn" onclick="dhcpSave('ranges','${jsArg(id || '')}',{start:$('dh-start').value.trim(),end:$('dh-end').value.trim(),netmask:$('dh-netmask').value.trim(),lease:$('dh-lease').value.trim(),tag:$('dh-tag').value.trim(),interface:$('dh-iface').value.trim()})">${id ? 'Save' : 'Add'}</button>`);
}

function dhcpStaticModal(id, preset) {
  const r = id ? _drec('static_leases', id) : (preset || {});
  openModal(id ? 'Edit static lease' : 'Add static lease', `
    <div class="form-group"><label>MAC address</label><input id="dh-mac" class="form-control" value="${escapeHtml(r.mac || '')}" placeholder="aa:bb:cc:dd:ee:ff"></div>
    <div class="form-group"><label>IPv4 address</label><input id="dh-ip" class="form-control" value="${escapeHtml(r.ip || '')}"></div>
    <div class="form-group"><label>Hostname (optional)</label><input id="dh-hostname" class="form-control" value="${escapeHtml(r.hostname || '')}"></div>
    <div class="form-group"><label>Tag (optional)</label><input id="dh-tag" class="form-control" value="${escapeHtml(r.tag || '')}"></div>
    ${_dhcpFormCommon(r)}
    <button class="btn" onclick="dhcpSave('static_leases','${jsArg(id || '')}',{mac:$('dh-mac').value.trim(),ip:$('dh-ip').value.trim(),hostname:$('dh-hostname').value.trim(),tag:$('dh-tag').value.trim()})">${id ? 'Save' : 'Add'}</button>`);
}

function dhcpOptModal(id) {
  const r = id ? _drec('options', id) : {};
  const presets = DHCP_OPTION_PRESETS.map(([v, l]) =>
    `<option value="${escapeHtml(v)}" ${r.option === v ? 'selected' : ''}>${escapeHtml(l)}</option>`).join('');
  openModal(id ? 'Edit DHCP option' : 'Add DHCP option', `
    <div class="form-group"><label>Common options</label>
      <select class="form-control" onchange="if(this.value)$('dh-option').value=this.value">
        <option value="">— pick or type below —</option>${presets}</select></div>
    <div class="form-group"><label>Option (number or option:name)</label><input id="dh-option" class="form-control" value="${escapeHtml(r.option || '')}" placeholder="option:router"></div>
    <div class="form-group"><label>Value</label><input id="dh-value" class="form-control" value="${escapeHtml(r.value || '')}" placeholder="10.0.0.1"></div>
    <div class="form-group"><label>Tag (optional — only for clients in a tagged range)</label><input id="dh-tag" class="form-control" value="${escapeHtml(r.tag || '')}"></div>
    ${_dhcpFormCommon(r)}
    <button class="btn" onclick="dhcpSave('options','${jsArg(id || '')}',{option:$('dh-option').value.trim(),value:$('dh-value').value.trim(),tag:$('dh-tag').value.trim()})">${id ? 'Save' : 'Add'}</button>`);
}

async function dhcpSave(coll, id, fields) {
  fields.comment = $('dh-comment').value;
  fields.enabled = $('dh-enabled').checked;
  try {
    const r = await API.post('/api/dhcp/' + coll + (id ? '/' + encodeURIComponent(id) : ''), fields);
    notifyApply(r);
    closeModal();
    page_dhcp();
  } catch (e) { alert(e.message); }
}

async function dhcpDelete(coll, id, name) {
  if (!confirm(`Delete "${name}"?`)) return;
  try {
    const r = await API.delete(`/api/dhcp/${coll}/${encodeURIComponent(id)}`);
    notifyApply(r);
    page_dhcp();
  } catch (e) { alert(e.message); }
}

function dhcpReserve(mac, ip, hostname) {
  dhcpStaticModal(null, { mac, ip, hostname });
}
