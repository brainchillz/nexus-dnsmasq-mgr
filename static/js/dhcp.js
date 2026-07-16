// DHCP page: ranges, static leases, options, live leases.
let _dhcpData = null;

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
  const [d, st, leases] = await Promise.all([
    API.get('/api/dhcp'),
    API.get('/api/dnsmasq/status'),
    API.get('/api/dhcp/leases').catch(() => ({ leases: [] })),
  ]);
  _dhcpData = d;
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

  const staticRows = d.static_leases.map(s => `<tr>
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

  const leaseRows = (leases.leases || []).map(l => `<tr>
    <td><code>${escapeHtml(l.mac)}</code></td>
    <td>${escapeHtml(l.ip)}</td>
    <td>${escapeHtml(l.hostname || '-')}</td>
    <td>${l.expiry ? fmtDur(l.expires_in) : 'infinite'}</td>
    <td>${l.static ? '<span class="status-badge green">static</span>' : '<span class="status-badge gray">dynamic</span>'}</td>
    <td class="row-actions">${can && !l.static ? `<button class="btn btn-sm" onclick="dhcpReserve('${jsArg(l.mac)}','${jsArg(l.ip)}','${jsArg(l.hostname || '')}')">Reserve</button>` : ''}</td>
    </tr>`).join('');

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
    ${can ? `<div class="toolbar"><button class="btn btn-sm" onclick="dhcpStaticModal()">+ Add static lease</button></div>` : ''}
    <table class="table"><thead><tr><th>MAC</th><th>IP</th><th>Hostname</th><th>Tag</th><th>State</th><th></th></tr></thead>
      <tbody>${staticRows || '<tr><td colspan="6">No static leases</td></tr>'}</tbody></table>

    <h3 style="margin-top:24px">Options</h3>
    ${can ? `<div class="toolbar"><button class="btn btn-sm" onclick="dhcpOptModal()">+ Add option</button></div>` : ''}
    <table class="table"><thead><tr><th>Tag</th><th>Option</th><th>Value</th><th>State</th><th></th></tr></thead>
      <tbody>${optRows || '<tr><td colspan="5">No options — dnsmasq defaults apply (gateway/DNS = this host)</td></tr>'}</tbody></table>

    <h3 style="margin-top:24px">Live Leases <span class="help">(${(leases.leases || []).length} active)</span></h3>
    <table class="table"><thead><tr><th>MAC</th><th>IP</th><th>Hostname</th><th>Expires</th><th>Type</th><th></th></tr></thead>
      <tbody>${leaseRows || '<tr><td colspan="6">No active leases</td></tr>'}</tbody></table>`;
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
