// Blocklists page: subscribed blocklist URLs, per-list enable/disable,
// entry counts, refresh state, manual refresh.

let _blData = null;

const BL_PRESETS = [
  ['StevenBlack (ads + malware)', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'],
  ['hagezi Multi Normal', 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt'],
];

async function page_blocklists() {
  const b = await API.get('/api/blocklists');
  _blData = b;
  const admin = currentRole === 'admin';

  const rows = (b.lists || []).map(l => {
    const status = !l.last_status ? '<span class="status-badge gray">never fetched</span>'
      : l.last_status === 'ok' ? '<span class="status-badge green">ok</span>'
      : `<span class="status-badge red" title="${escapeHtml(l.last_status)}">error</span>`;
    return `<tr>
      <td><strong>${escapeHtml(l.name)}</strong><div class="help" style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(l.url)}</div></td>
      <td>${switchHtml(l.enabled, `blToggle('${jsArg(l.id)}', this.checked)`, !admin)}</td>
      <td>${l.entries ? l.entries.toLocaleString() : '-'}</td>
      <td>every ${l.refresh_hours}h</td>
      <td>${status}<div class="help">${l.last_fetch ? fmtTs(l.last_fetch) : ''}</div></td>
      <td class="row-actions">${admin ? `
        <button class="btn btn-sm btn-outline" onclick="blRefresh('${jsArg(l.id)}', this)">Refresh</button>
        <button class="btn btn-sm btn-outline" onclick="blModal('${jsArg(l.id)}')">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="blDelete('${jsArg(l.id)}','${jsArg(l.name)}')">Delete</button>` : ''}
      </td></tr>`;
  }).join('');

  $('page-content').innerHTML = `
    <h2>Blocklists</h2>
    <p class="help">Subscribed lists are fetched on a schedule and rendered as
      <code>address=/domain/0.0.0.0</code> blocks, each in its own config file — a broken download can
      never take out the rest of the configuration. Lists refresh automatically with the 5-minute stats tick.</p>
    ${admin ? `<div class="toolbar"><button class="btn btn-sm" onclick="blModal()">+ Subscribe to a list</button></div>` : ''}
    <table class="table"><thead><tr><th>List</th><th>Enabled</th><th>Entries</th><th>Refresh</th><th>Last fetch</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6">No blocklists subscribed</td></tr>'}</tbody></table>`;
}

function blModal(id) {
  const r = id ? (_blData.lists || []).find(x => x.id === id) || {} : {};
  const presets = BL_PRESETS.map(([n, u]) =>
    `<button class="btn btn-sm btn-outline" type="button" onclick="$('bl-name').value='${jsArg(n)}';$('bl-url').value='${jsArg(u)}'">${escapeHtml(n)}</button>`).join(' ');
  openModal(id ? 'Edit blocklist' : 'Subscribe to a blocklist', `
    ${id ? '' : `<div class="toolbar" style="margin-bottom:8px">${presets}</div>`}
    <div class="form-group"><label>Name</label><input id="bl-name" class="form-control" value="${escapeHtml(r.name || '')}" placeholder="StevenBlack"></div>
    <div class="form-group"><label>List URL</label><input id="bl-url" class="form-control" value="${escapeHtml(r.url || '')}" placeholder="https://…" spellcheck="false"></div>
    <div class="form-group"><label>Refresh interval (hours)</label><input id="bl-hours" class="form-control" type="number" min="1" max="720" value="${r.refresh_hours || 24}"></div>
    <label class="checkitem" style="padding-left:0"><input id="bl-enabled" type="checkbox" ${r.enabled !== false ? 'checked' : ''}> Enabled</label>
    <p class="help">Accepted formats: hosts files (<code>0.0.0.0 domain</code>), plain domain lists,
      dnsmasq <code>address=</code> lines and adblock <code>||domain^</code> lines.</p>
    <div class="toolbar"><button class="btn" onclick="blSave('${jsArg(id || '')}', this)">${id ? 'Save' : 'Subscribe & fetch'}</button></div>
    <div id="bl-result"></div>`);
}

async function blSave(id, btn) {
  const body = {
    name: $('bl-name').value.trim(),
    url: $('bl-url').value.trim(),
    refresh_hours: parseInt($('bl-hours').value) || 24,
    enabled: $('bl-enabled').checked,
  };
  btn.disabled = true;
  $('bl-result').innerHTML = '<p class="help">Saving…' + (id ? '' : ' (first fetch may take a few seconds)') + '</p>';
  try {
    const r = await API.post('/api/blocklists' + (id ? '/' + encodeURIComponent(id) : ''), body);
    notifyApply(r);
    if (r.fetch_ok === false) {
      $('bl-result').innerHTML = `<div class="alert alert-warning"><strong>Saved, but the fetch failed:</strong>
        ${escapeHtml(r.fetch_detail)}<br>It will be retried automatically; the config is unchanged until a fetch succeeds.</div>
        <div class="toolbar" style="margin-top:8px"><button class="btn btn-sm" onclick="closeModal(); page_blocklists();">Close</button></div>`;
      return;
    }
    closeModal();
    page_blocklists();
  } catch (e) {
    $('bl-result').innerHTML = `<div class="alert alert-warning">${escapeHtml(e.message)}</div>`;
  } finally { btn.disabled = false; }
}

async function blToggle(id, enabled) {
  try {
    const r = await API.post('/api/blocklists/' + encodeURIComponent(id), { enabled });
    notifyApply(r);
  } catch (e) { alert(e.message); }
  page_blocklists();
}

async function blRefresh(id, btn) {
  btn.disabled = true; btn.textContent = 'Fetching…';
  try {
    const r = await API.post('/api/blocklists/' + encodeURIComponent(id) + '/refresh', {});
    notifyApply(r);
  } catch (e) { alert(e.message); }
  page_blocklists();
}

async function blDelete(id, name) {
  if (!confirm(`Unsubscribe from "${name}"? Its blocks are removed from the config.`)) return;
  try {
    const r = await API.delete('/api/blocklists/' + encodeURIComponent(id));
    notifyApply(r);
  } catch (e) { alert(e.message); }
  page_blocklists();
}
