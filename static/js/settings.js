// Settings page: global DNS/network, TLS certificate, users & tokens, service.
async function page_settings() {
  if (currentRole !== 'admin') {
    $('page-content').innerHTML = '<h2>Settings</h2><div class="alert alert-warning">Administrator access required.</div>';
    return;
  }
  const [s, tlsInfo, users, tokens] = await Promise.all([
    API.get('/api/settings'),
    API.get('/api/tls/info').catch(() => ({ present: false })),
    API.get('/api/users').catch(() => []),
    API.get('/api/tokens').catch(() => []),
  ]);

  const flag = (id, label, val, help) => `
    <label class="checkitem" style="padding-left:0" title="${escapeHtml(help || '')}">
      <input id="${id}" type="checkbox" ${val ? 'checked' : ''}> ${label}</label>`;

  const userRows = users.map(u => `<tr>
    <td>${escapeHtml(u.username)}</td>
    <td><span class="badge-type">${escapeHtml(u.role)}</span></td>
    <td class="row-actions">
      <button class="btn btn-sm btn-outline" onclick="userSetRole('${jsArg(u.username)}','${u.role === 'admin' ? 'readonly' : 'admin'}')">Make ${u.role === 'admin' ? 'read-only' : 'admin'}</button>
      <button class="btn btn-sm btn-outline" onclick="userPassModal('${jsArg(u.username)}')">Set password</button>
      <button class="btn btn-sm btn-danger" onclick="userDelete('${jsArg(u.username)}')">Delete</button>
    </td></tr>`).join('');

  const tokenRows = tokens.map(t => `<tr>
    <td>${escapeHtml(t.name)}</td>
    <td><span class="badge-type">${escapeHtml(t.role)}</span></td>
    <td>${escapeHtml(t.created || '-')}</td>
    <td>${escapeHtml(t.last_used || 'never')}</td>
    <td class="row-actions"><button class="btn btn-sm btn-danger" onclick="tokenDelete('${jsArg(t.id)}','${jsArg(t.name)}')">Revoke</button></td>
    </tr>`).join('');

  $('page-content').innerHTML = `
    <h2>Settings</h2>

    <h3>DNS &amp; Network</h3>
    <div class="card" style="max-width:640px">
      <div class="form-group"><label>Local domain</label>
        <input id="st-domain" class="form-control" value="${escapeHtml(s.domain || '')}" placeholder="lan"></div>
      <div class="form-group"><label>Listen interfaces (one per line, empty = all)</label>
        <textarea id="st-ifaces" class="form-control" rows="2">${escapeHtml((s.interfaces || []).join('\n'))}</textarea></div>
      <div class="form-group"><label>Extra listen addresses (one per line)</label>
        <textarea id="st-addrs" class="form-control" rows="2">${escapeHtml((s.listen_addresses || []).join('\n'))}</textarea></div>
      <div class="form-group"><label>Cache size (entries)</label>
        <input id="st-cache" class="form-control" type="number" value="${s.cache_size}"></div>
      ${flag('st-expand', 'Expand hosts (append local domain to bare names)', s.expand_hosts)}
      ${flag('st-bind', 'Bind interfaces (bind only the listed interfaces — needed to coexist with other resolvers)', s.bind_interfaces)}
      ${flag('st-noresolv', 'Ignore /etc/resolv.conf (use only the upstreams configured here)', s.no_resolv)}
      ${flag('st-domneed', 'Domain needed (never forward bare names upstream)', s.domain_needed)}
      ${flag('st-bogus', 'Bogus-priv (never forward private-range reverse lookups)', s.bogus_priv)}
      ${flag('st-dnssec', 'DNSSEC validation', s.dnssec)}
      ${flag('st-auth', 'DHCP authoritative (this is the only DHCP server on the LAN)', s.dhcp_authoritative)}
      ${flag('st-logq', 'Log DNS queries (verbose — feeds the Query Log page)', s.log_queries)}
      ${flag('st-logd', 'Log DHCP transactions', s.log_dhcp)}
      ${flag('st-nohosts', 'Ignore the system /etc/hosts (no-hosts — serve only managed host records)', s.no_hosts,
             'By default dnsmasq also answers from the /etc/hosts of this machine, which this app does not manage. Stray entries there can shadow managed records — the Lookup page can diagnose that.')}
      <div class="toolbar" style="margin-top:10px"><button class="btn" onclick="stSave()">Save &amp; Apply</button></div>
    </div>

    <h3 style="margin-top:24px">TLS Certificate (web UI)</h3>
    <div class="card" style="max-width:640px">
      ${tlsInfo.present ? `
        <p>${tlsInfo.self_signed ? '<span class="status-badge yellow">self-signed</span>' : '<span class="status-badge green">custom</span>'}</p>
        <table class="table">
          <tr><td>Subject</td><td><code>${escapeHtml(tlsInfo.subject || '-')}</code></td></tr>
          <tr><td>Issuer</td><td><code>${escapeHtml(tlsInfo.issuer || '-')}</code></td></tr>
          <tr><td>Expires</td><td>${escapeHtml(tlsInfo.expires || '-')}</td></tr>
        </table>` : '<p class="help">No certificate present (TLS may be disabled).</p>'}
      <div class="form-group"><label>Certificate (PEM)</label>
        <textarea id="tls-cert" class="form-control" rows="4" placeholder="-----BEGIN CERTIFICATE-----" spellcheck="false"></textarea></div>
      <div class="form-group"><label>Private key (PEM)</label>
        <textarea id="tls-key" class="form-control" rows="4" placeholder="-----BEGIN PRIVATE KEY-----" spellcheck="false"></textarea></div>
      <div class="toolbar">
        <button class="btn" onclick="tlsUploadCert()">Upload certificate</button>
        <button class="btn btn-outline" onclick="tlsRegenerate()">Regenerate self-signed</button>
      </div>
      <p class="help">Uploads are validated (PEM parse + key/cert match) before replacing anything.
        Restart the DNSMAQ-MGR service afterwards to serve the new certificate.</p>
    </div>

    <h3 style="margin-top:24px">Users</h3>
    <div class="toolbar"><button class="btn btn-sm" onclick="userCreateModal()">+ Add user</button></div>
    <table class="table"><thead><tr><th>Username</th><th>Role</th><th></th></tr></thead>
      <tbody>${userRows || '<tr><td colspan="3">No users</td></tr>'}</tbody></table>

    <h3 style="margin-top:24px">API Tokens</h3>
    <div class="toolbar"><button class="btn btn-sm" onclick="tokenCreateModal()">+ Create token</button></div>
    <table class="table"><thead><tr><th>Name</th><th>Role</th><th>Created</th><th>Last used</th><th></th></tr></thead>
      <tbody>${tokenRows || '<tr><td colspan="5">No API tokens</td></tr>'}</tbody></table>
    <p class="help">Tokens authenticate automation (<code>Authorization: Bearer dm_…</code>). Read-only tokens can GET everything; admin tokens can change config.</p>

    <h3 style="margin-top:24px">Backup &amp; Restore</h3>
    <div class="card" style="max-width:640px">
      <p class="help">One JSON file with the full configuration — DNS, DHCP, netboot, blocklist subscriptions and
        mirroring peers. Handy for bare-metal &harr; Docker migrations. Blocklist domain data is not included;
        lists are re-fetched from their URLs after a restore.</p>
      <label class="checkitem" style="padding-left:0"><input id="bk-accounts" type="checkbox">
        Include user accounts &amp; API tokens (password/token hashes)</label>
      <div class="toolbar" style="margin-top:8px">
        <button class="btn" onclick="backupDownload()">${icon('dl', 'ico-sm')} Download backup</button>
        <button class="btn btn-outline" onclick="restoreModal()">${icon('ul', 'ico-sm')} Restore from backup…</button>
      </div>
    </div>`;
}

// ─── Backup & restore ───────────────────────────────────
function backupDownload() {
  window.location = '/api/backup?include_accounts=' + ($('bk-accounts').checked ? '1' : '0');
}

function restoreModal() {
  openModal('Restore from backup', `
    <div class="alert alert-warning"><strong>This replaces the configuration on this node</strong> with the
      backup's contents and applies it (gated by <code>dnsmasq --test</code> — an invalid backup changes nothing).</div>
    <div class="form-group"><input type="file" id="rs-file" class="form-control" accept=".json,application/json"></div>
    <label class="checkitem" style="padding-left:0"><input id="rs-accounts" type="checkbox">
      Also restore user accounts &amp; API tokens (if present in the backup — may sign you out)</label>
    <div class="toolbar" style="margin-top:10px"><button class="btn" onclick="restoreGo(this)">Restore</button></div>
    <div id="rs-result"></div>`);
}

async function restoreGo(btn) {
  const f = $('rs-file').files && $('rs-file').files[0];
  if (!f) { alert('Choose a backup file first'); return; }
  if (!confirm('Replace the configuration on this node with the backup?')) return;
  let backup;
  try { backup = JSON.parse(await f.text()); }
  catch (e) { alert('Not a valid JSON file'); return; }
  btn.disabled = true;
  $('rs-result').innerHTML = '<p class="help">Restoring…</p>';
  try {
    const r = await API.post('/api/backup/restore', {
      backup, include_accounts: $('rs-accounts').checked,
    });
    notifyApply(r);
    $('rs-result').innerHTML = `<div class="health-ok">✓ Restored: ${r.restored.join(', ')}
      ${r.accounts_restored ? ' · accounts replaced' : ''}
      ${r.blocklists_refreshing ? ' · blocklists re-fetching in the background' : ''}
      · applied via ${r.action}</div>
      <div class="toolbar" style="margin-top:8px"><button class="btn btn-sm" onclick="closeModal(); page_settings();">Done</button></div>`;
  } catch (e) {
    $('rs-result').innerHTML = `<div class="alert alert-warning"><strong>Restore failed:</strong> ${escapeHtml(e.message)}</div>`;
  } finally { btn.disabled = false; }
}

async function stSave() {
  const body = {
    domain: $('st-domain').value.trim(),
    interfaces: $('st-ifaces').value.split('\n').map(x => x.trim()).filter(Boolean),
    listen_addresses: $('st-addrs').value.split('\n').map(x => x.trim()).filter(Boolean),
    cache_size: parseInt($('st-cache').value) || 0,
    expand_hosts: $('st-expand').checked,
    bind_interfaces: $('st-bind').checked,
    no_resolv: $('st-noresolv').checked,
    domain_needed: $('st-domneed').checked,
    bogus_priv: $('st-bogus').checked,
    dnssec: $('st-dnssec').checked,
    dhcp_authoritative: $('st-auth').checked,
    log_queries: $('st-logq').checked,
    log_dhcp: $('st-logd').checked,
    no_hosts: $('st-nohosts').checked,
  };
  try {
    const r = await API.post('/api/settings', body);
    notifyApply(r);
    alert('Settings applied.');
    page_settings();
  } catch (e) { alert(e.message); }
}

// ─── TLS ────────────────────────────────────────────────
async function tlsUploadCert() {
  const cert = $('tls-cert').value.trim();
  const key = $('tls-key').value.trim();
  if (!cert || !key) { alert('Paste both the certificate and the private key'); return; }
  try {
    const r = await API.post('/api/tls/cert', { cert, key });
    if (r.success) alert('Certificate saved. Restart the DNSMAQ-MGR service to apply it.');
    page_settings();
  } catch (e) { alert(e.message); }
}

async function tlsRegenerate() {
  if (!confirm('Generate a new self-signed certificate? This replaces the current one.')) return;
  try {
    const r = await API.post('/api/tls/regenerate', {});
    if (r.success) alert('New self-signed certificate generated. Restart the DNSMAQ-MGR service to apply it.');
    page_settings();
  } catch (e) { alert(e.message); }
}

// ─── Users ──────────────────────────────────────────────
function userCreateModal() {
  openModal('Add user', `
    <div class="form-group"><label>Username</label><input id="nu-name" class="form-control" autocomplete="off"></div>
    <div class="form-group"><label>Password</label><input id="nu-pass" type="password" class="form-control" autocomplete="new-password"></div>
    <div class="form-group"><label>Role</label>
      <select id="nu-role" class="form-control">
        <option value="readonly">Read-only</option>
        <option value="admin">Administrator</option>
      </select></div>
    <button class="btn" onclick="userDoCreate()">Create user</button>`);
}

async function userDoCreate() {
  const username = $('nu-name').value.trim(), password = $('nu-pass').value, role = $('nu-role').value;
  if (!username || !password) { alert('Username and password required'); return; }
  try {
    await API.post('/api/users', { username, password, role });
    closeModal(); page_settings();
  } catch (e) { alert(e.message); }
}

async function userSetRole(username, role) {
  if (!confirm(`Change ${username} to ${role}?`)) return;
  try { await API.post(`/api/users/${encodeURIComponent(username)}/role`, { role }); page_settings(); }
  catch (e) { alert(e.message); }
}

function userPassModal(username) {
  openModal(`Set password: ${username}`, `
    <div class="form-group"><label>New password</label><input id="up-pass" type="password" class="form-control" autocomplete="new-password"></div>
    <button class="btn" onclick="userDoPassword('${jsArg(username)}')">Set password</button>`);
}

async function userDoPassword(username) {
  const password = $('up-pass').value;
  if (!password) { alert('Password required'); return; }
  try {
    await API.post(`/api/users/${encodeURIComponent(username)}/password`, { password });
    closeModal(); alert('Password updated.');
  } catch (e) { alert(e.message); }
}

async function userDelete(username) {
  if (!confirm(`Delete user "${username}"?`)) return;
  try { await API.delete(`/api/users/${encodeURIComponent(username)}`); page_settings(); }
  catch (e) { alert(e.message); }
}

// ─── API tokens ─────────────────────────────────────────
function tokenCreateModal() {
  openModal('Create API token', `
    <div class="form-group"><label>Name</label><input id="tk-name" class="form-control" autocomplete="off" placeholder="ansible"></div>
    <div class="form-group"><label>Role</label>
      <select id="tk-role" class="form-control">
        <option value="readonly">Read-only</option>
        <option value="admin">Administrator</option>
      </select></div>
    <button class="btn" onclick="tokenDoCreate()">Create token</button>`);
}

async function tokenDoCreate() {
  const name = $('tk-name').value.trim();
  const role = $('tk-role').value;
  if (!name) { alert('Name required'); return; }
  try {
    const r = await API.post('/api/tokens', { name, role });
    openModal('Token created — copy it now', `
      <div class="alert alert-warning"><strong>This is shown only once.</strong> Store it somewhere safe;
        it can't be retrieved again (only revoked).</div>
      <div class="form-group"><label>Token for <strong>${escapeHtml(r.name)}</strong> (${escapeHtml(r.role)})</label>
        <textarea class="form-control" rows="2" readonly onclick="this.select()">${escapeHtml(r.token)}</textarea></div>
      <button class="btn" onclick="closeModal(); page_settings();">Done</button>`);
  } catch (e) { alert(e.message); }
}

async function tokenDelete(id, name) {
  if (!confirm(`Revoke API token "${name}"? Any script using it will stop working.`)) return;
  try { await API.delete(`/api/tokens/${encodeURIComponent(id)}`); page_settings(); }
  catch (e) { alert(e.message); }
}
