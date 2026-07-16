// DNS Overrides page: host records, CNAMEs, domain overrides, domain forwards,
// upstream servers.
let _dnsData = null;

async function page_dns() {
  await refreshMirrorStatus();
  const [d, s] = await Promise.all([API.get('/api/dns'), API.get('/api/settings')]);
  _dnsData = d;
  const hostsLocked = sectionLocked('hosts'), dnsLocked = sectionLocked('dns');
  const admin = currentRole === 'admin';
  const canHosts = admin && !hostsLocked, canDns = admin && !dnsLocked;

  const hostRows = d.hosts.map(h => `<tr>
    <td><code>${escapeHtml(h.name)}</code></td>
    <td>${escapeHtml(h.a || '-')}</td>
    <td>${escapeHtml(h.aaaa || '-')}</td>
    <td>${enabledBadge(h.enabled)}</td>
    <td>${escapeHtml(h.comment || '')}</td>
    <td class="row-actions">${canHosts ? `
      <button class="btn btn-sm btn-outline" onclick="dnsHostModal('${jsArg(h.id)}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="dnsDelete('hosts','${jsArg(h.id)}','${jsArg(h.name)}')">Delete</button>` : ''}
    </td></tr>`).join('');

  const cnameRows = d.cnames.map(c => `<tr>
    <td><code>${escapeHtml(c.alias)}</code></td><td><code>${escapeHtml(c.target)}</code></td>
    <td>${enabledBadge(c.enabled)}</td><td>${escapeHtml(c.comment || '')}</td>
    <td class="row-actions">${canDns ? `
      <button class="btn btn-sm btn-outline" onclick="dnsCnameModal('${jsArg(c.id)}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="dnsDelete('cnames','${jsArg(c.id)}','${jsArg(c.alias)}')">Delete</button>` : ''}
    </td></tr>`).join('');

  const addrRows = d.addresses.map(a => `<tr>
    <td><code>${escapeHtml(a.domain)}</code></td><td>${escapeHtml(a.ip)}</td>
    <td>${enabledBadge(a.enabled)}</td><td>${escapeHtml(a.comment || '')}</td>
    <td class="row-actions">${canDns ? `
      <button class="btn btn-sm btn-outline" onclick="dnsAddrModal('${jsArg(a.id)}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="dnsDelete('addresses','${jsArg(a.id)}','${jsArg(a.domain)}')">Delete</button>` : ''}
    </td></tr>`).join('');

  const fwdRows = d.forwards.map(f => `<tr>
    <td><code>${escapeHtml(f.domain)}</code></td><td>${escapeHtml(f.upstream)}</td>
    <td>${enabledBadge(f.enabled)}</td><td>${escapeHtml(f.comment || '')}</td>
    <td class="row-actions">${canDns ? `
      <button class="btn btn-sm btn-outline" onclick="dnsFwdModal('${jsArg(f.id)}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="dnsDelete('forwards','${jsArg(f.id)}','${jsArg(f.domain)}')">Delete</button>` : ''}
    </td></tr>`).join('');

  $('page-content').innerHTML = `
    <h2>DNS Overrides</h2>
    ${lockedBanner('hosts')}${lockedBanner('dns')}
    <h3>Host Records <span class="help">(the dnsmasq hosts file: name &rarr; A/AAAA)</span></h3>
    ${canHosts ? `<div class="toolbar">
      <button class="btn btn-sm" onclick="dnsHostModal()">+ Add host record</button>
      <button class="btn btn-sm btn-outline" onclick="dnsImportModal()">&#8681; Import hosts file</button>
    </div>` : ''}
    <table class="table"><thead><tr><th>Name</th><th>A (IPv4)</th><th>AAAA (IPv6)</th><th>State</th><th>Comment</th><th></th></tr></thead>
      <tbody>${hostRows || '<tr><td colspan="6">No host records</td></tr>'}</tbody></table>

    <h3 style="margin-top:24px">CNAMEs</h3>
    ${canDns ? `<div class="toolbar"><button class="btn btn-sm" onclick="dnsCnameModal()">+ Add CNAME</button></div>` : ''}
    <table class="table"><thead><tr><th>Alias</th><th>Target</th><th>State</th><th>Comment</th><th></th></tr></thead>
      <tbody>${cnameRows || '<tr><td colspan="5">No CNAMEs</td></tr>'}</tbody></table>
    <p class="help">CNAME targets must be names dnsmasq itself knows (host records or DHCP leases).</p>

    <h3 style="margin-top:24px">Domain Overrides <span class="help">(address=/domain/ip — whole domain &rarr; one IP; also handy for blocking with 0.0.0.0)</span></h3>
    ${canDns ? `<div class="toolbar"><button class="btn btn-sm" onclick="dnsAddrModal()">+ Add domain override</button></div>` : ''}
    <table class="table"><thead><tr><th>Domain</th><th>IP</th><th>State</th><th>Comment</th><th></th></tr></thead>
      <tbody>${addrRows || '<tr><td colspan="5">No domain overrides</td></tr>'}</tbody></table>

    <h3 style="margin-top:24px">Domain Forwards <span class="help">(server=/domain/upstream — send a domain to a specific resolver)</span></h3>
    ${canDns ? `<div class="toolbar"><button class="btn btn-sm" onclick="dnsFwdModal()">+ Add forward</button></div>` : ''}
    <table class="table"><thead><tr><th>Domain</th><th>Upstream</th><th>State</th><th>Comment</th><th></th></tr></thead>
      <tbody>${fwdRows || '<tr><td colspan="5">No domain forwards</td></tr>'}</tbody></table>

    <h3 style="margin-top:24px">Upstream Servers</h3>
    <div class="form-group" style="max-width:480px">
      <label>Default resolvers (one per line, IP or IP#port)</label>
      <textarea id="dns-upstreams" class="form-control" rows="3" ${canDns ? '' : 'disabled'}>${escapeHtml((s.upstreams || []).join('\n'))}</textarea>
    </div>
    ${canDns ? `<button class="btn" onclick="dnsSaveUpstreams()">Save upstreams</button>` : ''}`;
}

function _rec(coll, id) { return (_dnsData[coll] || []).find(r => r.id === id) || {}; }

function _dnsFormCommon(r) {
  return `
    <div class="form-group"><label>Comment</label><input id="dm-comment" class="form-control" value="${escapeHtml(r.comment || '')}"></div>
    <label class="checkitem" style="padding-left:0"><input id="dm-enabled" type="checkbox" ${r.enabled !== false ? 'checked' : ''}> Enabled</label>`;
}

function dnsHostModal(id) {
  const r = id ? _rec('hosts', id) : {};
  openModal(id ? 'Edit host record' : 'Add host record', `
    <div class="form-group"><label>Hostname (bare name or FQDN)</label><input id="dm-name" class="form-control" value="${escapeHtml(r.name || '')}" placeholder="nas or nas.lan"></div>
    <div class="form-group"><label>IPv4 address (A)</label><input id="dm-a" class="form-control" value="${escapeHtml(r.a || '')}" placeholder="10.0.0.5"></div>
    <div class="form-group"><label>IPv6 address (AAAA)</label><input id="dm-aaaa" class="form-control" value="${escapeHtml(r.aaaa || '')}" placeholder="optional"></div>
    ${_dnsFormCommon(r)}
    <button class="btn" onclick="dnsSave('hosts','${jsArg(id || '')}',{name:$('dm-name').value.trim(),a:$('dm-a').value.trim(),aaaa:$('dm-aaaa').value.trim()})">${id ? 'Save' : 'Add'}</button>`);
}

function dnsCnameModal(id) {
  const r = id ? _rec('cnames', id) : {};
  openModal(id ? 'Edit CNAME' : 'Add CNAME', `
    <div class="form-group"><label>Alias</label><input id="dm-alias" class="form-control" value="${escapeHtml(r.alias || '')}" placeholder="www.lan"></div>
    <div class="form-group"><label>Target</label><input id="dm-target" class="form-control" value="${escapeHtml(r.target || '')}" placeholder="nas.lan"></div>
    ${_dnsFormCommon(r)}
    <button class="btn" onclick="dnsSave('cnames','${jsArg(id || '')}',{alias:$('dm-alias').value.trim(),target:$('dm-target').value.trim()})">${id ? 'Save' : 'Add'}</button>`);
}

function dnsAddrModal(id) {
  const r = id ? _rec('addresses', id) : {};
  openModal(id ? 'Edit domain override' : 'Add domain override', `
    <div class="form-group"><label>Domain</label><input id="dm-domain" class="form-control" value="${escapeHtml(r.domain || '')}" placeholder="ads.example.com"></div>
    <div class="form-group"><label>IP (use 0.0.0.0 to block)</label><input id="dm-ip" class="form-control" value="${escapeHtml(r.ip || '')}"></div>
    ${_dnsFormCommon(r)}
    <button class="btn" onclick="dnsSave('addresses','${jsArg(id || '')}',{domain:$('dm-domain').value.trim(),ip:$('dm-ip').value.trim()})">${id ? 'Save' : 'Add'}</button>`);
}

function dnsFwdModal(id) {
  const r = id ? _rec('forwards', id) : {};
  openModal(id ? 'Edit domain forward' : 'Add domain forward', `
    <div class="form-group"><label>Domain</label><input id="dm-domain" class="form-control" value="${escapeHtml(r.domain || '')}" placeholder="corp.example.com"></div>
    <div class="form-group"><label>Upstream resolver (IP or IP#port)</label><input id="dm-upstream" class="form-control" value="${escapeHtml(r.upstream || '')}" placeholder="10.1.1.1"></div>
    ${_dnsFormCommon(r)}
    <button class="btn" onclick="dnsSave('forwards','${jsArg(id || '')}',{domain:$('dm-domain').value.trim(),upstream:$('dm-upstream').value.trim()})">${id ? 'Save' : 'Add'}</button>`);
}

async function dnsSave(coll, id, fields) {
  fields.comment = $('dm-comment').value;
  fields.enabled = $('dm-enabled').checked;
  try {
    const r = await API.post('/api/dns/' + coll + (id ? '/' + encodeURIComponent(id) : ''), fields);
    notifyApply(r);
    closeModal();
    page_dns();
  } catch (e) { alert(e.message); }
}

async function dnsDelete(coll, id, name) {
  if (!confirm(`Delete "${name}"?`)) return;
  try {
    const r = await API.delete(`/api/dns/${coll}/${encodeURIComponent(id)}`);
    notifyApply(r);
    page_dns();
  } catch (e) { alert(e.message); }
}

// ─── Hosts-file import ──────────────────────────────────
function dnsImportModal() {
  openModal('Import hosts file', `
    <p class="help">Paste (or pick a file with) standard unix hosts-file lines:
      <code>IP&nbsp;name&nbsp;[alias&nbsp;…]</code>, <code>#</code> comments ignored.
      IPv4 becomes A records, IPv6 becomes AAAA.</p>
    <div class="form-group">
      <input type="file" id="di-file" class="form-control" accept=".txt,.hosts,text/plain"
             onchange="dnsImportReadFile(this)">
    </div>
    <div class="form-group">
      <textarea id="di-text" class="form-control" rows="10" spellcheck="false"
        placeholder="10.0.0.5   nas nas.lan&#10;10.0.0.6   printer&#10;fd00::5    nas.lan"></textarea>
    </div>
    <label class="checkitem" style="padding-left:0"><input id="di-skip" type="checkbox" checked>
      Skip boilerplate entries (localhost, ip6-allnodes, …)</label>
    <label class="checkitem" style="padding-left:0"><input id="di-replace" type="checkbox">
      Replace ALL existing host records (unchecked = merge by name)</label>
    <div class="toolbar" style="margin-top:10px">
      <button class="btn" onclick="dnsImportGo()">Import</button>
    </div>
    <div id="di-result"></div>`, { wide: true });
}

function dnsImportReadFile(input) {
  const f = input.files && input.files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = () => { $('di-text').value = reader.result; };
  reader.readAsText(f);
}

async function dnsImportGo() {
  const text = $('di-text').value;
  if (!text.trim()) { alert('Paste or choose a hosts file first'); return; }
  const replace = $('di-replace').checked;
  if (replace && !confirm('Replace ALL existing host records with the imported list?')) return;
  $('di-result').innerHTML = '<p class="help">Importing…</p>';
  try {
    const r = await API.post('/api/dns/import', {
      text, skip_boilerplate: $('di-skip').checked, replace,
    });
    notifyApply(r);
    $('di-result').innerHTML = `<div class="health-ok">✓ Imported: ${r.added} added, ${r.updated} updated,
      ${r.unchanged} unchanged${r.skipped ? `, ${r.skipped} boilerplate skipped` : ''}${r.invalid ? `, ${r.invalid} invalid line(s) ignored` : ''}
      · applied via ${r.action}</div>
      <div class="toolbar" style="margin-top:8px"><button class="btn btn-sm" onclick="closeModal(); page_dns();">Done</button></div>`;
  } catch (e) {
    $('di-result').innerHTML = `<div class="alert alert-warning"><strong>Import failed:</strong> ${escapeHtml(e.message)}</div>`;
  }
}

async function dnsSaveUpstreams() {
  const ups = $('dns-upstreams').value.split('\n').map(x => x.trim()).filter(Boolean);
  try {
    const r = await API.post('/api/settings', { upstreams: ups });
    notifyApply(r);
    page_dns();
  } catch (e) { alert(e.message); }
}
