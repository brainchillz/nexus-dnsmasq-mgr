// Mirroring page: this node's receive settings + push peers.
let _peerData = null;

const PEER_SECTIONS = [
  ['hosts', 'Host records'],
  ['dns', 'DNS (CNAMEs, overrides, forwards, upstreams)'],
  ['dhcp', 'DHCP (ranges, static leases, options)'],
  ['netboot', 'Network boot'],
];
const PEER_SECTION_LABEL = Object.fromEntries(PEER_SECTIONS);

async function page_peers() {
  const [ms, ps] = await Promise.all([refreshMirrorStatus(), API.get('/api/peers')]);
  _peerData = ps;

  const sources = Object.entries(ms.sources || {});
  const sourceRows = sources.map(([name, s]) => `<tr>
    <td><code>${escapeHtml(name)}</code></td>
    <td>${(s.sections || []).map(x => `<span class="badge-type">${escapeHtml(PEER_SECTION_LABEL[x] || x)}</span>`).join(' ')}</td>
    <td>${fmtTs(s.last_received)}</td>
    <td>serial ${s.serial}</td>
    <td class="row-actions"><button class="btn btn-sm btn-warning" onclick="peerDetach('${jsArg(name)}')">Detach</button></td>
    </tr>`).join('');

  const peerRows = (ps.peers || []).map(p => {
    const ok = p.last_status === 'ok';
    return `<tr>
    <td>${escapeHtml(p.name)}</td>
    <td><code>${escapeHtml(p.url)}</code></td>
    <td>${(p.sections || []).map(x => `<span class="badge-type">${escapeHtml(x)}</span>`).join(' ')}</td>
    <td>${fmtTs(p.last_sync)}</td>
    <td><span class="status-badge ${p.last_status ? (ok ? 'green' : 'red') : 'gray'}" title="${escapeHtml(p.last_status || '')}">${ok ? 'in sync' : (p.last_status ? 'error' : 'never')}</span>
        ${!p.enabled ? '<span class="status-badge gray">paused</span>' : ''}</td>
    <td class="row-actions">
      <button class="btn btn-sm" onclick="peerSync('${jsArg(p.id)}')">Sync now</button>
      <button class="btn btn-sm btn-outline" onclick="peerModal('${jsArg(p.id)}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="peerDelete('${jsArg(p.id)}','${jsArg(p.name)}')">Delete</button>
    </td></tr>`;
  }).join('');

  const errDetail = (ps.peers || []).filter(p => p.last_status && p.last_status !== 'ok')
    .map(p => `<div class="alert alert-warning"><strong>${escapeHtml(p.name)}:</strong> ${escapeHtml(p.last_status)}</div>`).join('');

  $('page-content').innerHTML = `
    <h2>Mirroring</h2>
    <div class="cards">
      <div class="card">
        <div class="card-head">This node as a mirror target</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin:8px 0">
          <span>Accept mirrored config</span>${switchHtml(ms.accept, 'peerAcceptToggle(this.checked)')}</div>
        <div class="card-sub">${ms.has_token ? 'Mirror token is set.' : 'No mirror token yet — generate one, then paste it into the primary\'s peer entry.'}</div>
        <div class="toolbar" style="margin-top:8px">
          <button class="btn btn-sm" onclick="peerGenToken()">${ms.has_token ? 'Rotate token' : 'Generate token'}</button>
        </div>
      </div>
      <div class="card">
        <div class="card-head">How it works</div>
        <div class="card-sub" style="margin-top:6px">The primary pushes selected sections to each peer over HTTPS on every change
          (and via Sync now). Mirrored sections become <strong>read-only</strong> on the receiving node so the two sides can't drift;
          detach a section there to take back local control.</div>
      </div>
    </div>

    ${sources.length ? `<h3>Mirrored from</h3>
    <table class="table"><thead><tr><th>Source</th><th>Sections (locked here)</th><th>Last received</th><th></th><th></th></tr></thead>
      <tbody>${sourceRows}</tbody></table>` : ''}

    <h3 style="margin-top:24px">Push Peers</h3>
    <div class="toolbar"><button class="btn btn-sm" onclick="peerModal()">+ Add peer</button></div>
    ${errDetail}
    <table class="table"><thead><tr><th>Name</th><th>URL</th><th>Sections</th><th>Last sync</th><th>Status</th><th></th></tr></thead>
      <tbody>${peerRows || '<tr><td colspan="6">No peers — add one to mirror this node\'s config to another DNSMAQ-MGR instance</td></tr>'}</tbody></table>`;
}

async function peerAcceptToggle(on) {
  try { await API.post('/api/mirror/accept', { enabled: on }); }
  catch (e) { alert(e.message); }
  page_peers();
}

async function peerGenToken() {
  if (!confirm('Generate a new mirror token? Any primary using the old token will stop syncing to this node.')) { page_peers(); return; }
  try {
    const r = await API.post('/api/mirror/token', {});
    openModal('Mirror token — copy it now', `
      <div class="alert alert-warning"><strong>This is shown only once.</strong> Paste it into the peer entry on the PRIMARY node.</div>
      <div class="form-group"><textarea class="form-control" rows="2" readonly onclick="this.select()">${escapeHtml(r.token)}</textarea></div>
      <button class="btn" onclick="closeModal(); page_peers();">Done</button>`);
  } catch (e) { alert(e.message); }
}

async function peerDetach(name) {
  if (!confirm(`Detach from "${name}"? Its sections become editable here until the next push re-locks them.`)) return;
  try { await API.post(`/api/mirror/sources/${encodeURIComponent(name)}/detach`, {}); }
  catch (e) { alert(e.message); }
  page_peers();
}

function peerModal(id) {
  const p = id ? (_peerData.peers.find(x => x.id === id) || {}) : {};
  const secs = p.sections || ['hosts', 'dns'];
  const checks = PEER_SECTIONS.map(([v, l]) =>
    `<label class="checkitem"><input type="checkbox" class="peer-sec" value="${v}" ${secs.includes(v) ? 'checked' : ''}> ${escapeHtml(l)}</label>`).join('');
  const verify = p.verify || 'system';
  const isFp = verify.startsWith('fingerprint:');
  openModal(id ? 'Edit peer' : 'Add peer', `
    <div class="form-group"><label>Name</label><input id="pe-name" class="form-control" value="${escapeHtml(p.name || '')}" placeholder="branch-dns"></div>
    <div class="form-group"><label>URL</label><input id="pe-url" class="form-control" value="${escapeHtml(p.url || '')}" placeholder="https://10.9.9.2:8443"></div>
    <div class="form-group"><label>Peer mirror token ${id ? '(leave blank to keep current)' : '(generate it on the peer\'s Mirroring page)'}</label>
      <input id="pe-token" class="form-control" autocomplete="off" placeholder="dmm_…"></div>
    <div class="form-group"><label>Sections to mirror</label><div class="checklist">${checks}</div></div>
    <div class="form-group"><label>TLS verification</label>
      <select id="pe-verify" class="form-control" onchange="$('pe-fp-row').style.display = this.value === 'fingerprint' ? '' : 'none'">
        <option value="system" ${verify === 'system' ? 'selected' : ''}>System CAs (proper certificate)</option>
        <option value="fingerprint" ${isFp ? 'selected' : ''}>Pin certificate fingerprint (self-signed peers)</option>
        <option value="insecure" ${verify === 'insecure' ? 'selected' : ''}>No verification (not recommended)</option>
      </select></div>
    <div class="form-group" id="pe-fp-row" style="${isFp ? '' : 'display:none'}">
      <label>SHA-256 fingerprint</label>
      <input id="pe-fp" class="form-control" value="${escapeHtml(isFp ? verify.slice(12) : '')}" placeholder="64 hex chars">
      <div class="toolbar" style="margin-top:6px"><button class="btn btn-sm btn-outline" onclick="peerFetchFp()">Fetch from peer</button></div>
    </div>
    <label class="checkitem" style="padding-left:0"><input id="pe-enabled" type="checkbox" ${p.enabled !== false ? 'checked' : ''}> Enabled (push automatically on every change)</label>
    <button class="btn" onclick="peerSave('${jsArg(id || '')}')">${id ? 'Save' : 'Add peer'}</button>`);
}

async function peerFetchFp() {
  const url = $('pe-url').value.trim();
  if (!url) { alert('Enter the peer URL first'); return; }
  try {
    const r = await API.post('/api/peers/fetch-fingerprint', { url });
    $('pe-fp').value = r.fingerprint;
  } catch (e) { alert(e.message); }
}

async function peerSave(id) {
  let verify = $('pe-verify').value;
  if (verify === 'fingerprint') {
    const fp = $('pe-fp').value.trim().toLowerCase().replace(/[^0-9a-f]/g, '');
    if (fp.length !== 64) { alert('Fingerprint must be 64 hex characters (use Fetch from peer)'); return; }
    verify = 'fingerprint:' + fp;
  }
  const fields = {
    name: $('pe-name').value.trim(),
    url: $('pe-url').value.trim(),
    token: $('pe-token').value.trim(),
    sections: Array.from(document.querySelectorAll('.peer-sec:checked')).map(c => c.value),
    verify,
    enabled: $('pe-enabled').checked,
  };
  try {
    await API.post('/api/peers' + (id ? '/' + encodeURIComponent(id) : ''), fields);
    closeModal();
    page_peers();
  } catch (e) { alert(e.message); }
}

async function peerSync(id) {
  try {
    await API.post(`/api/peers/${encodeURIComponent(id)}/sync`, {});
  } catch (e) { alert(e.message); }
  page_peers();
}

async function peerDelete(id, name) {
  if (!confirm(`Delete peer "${name}"? This node will stop pushing to it (its config stays as-is).`)) return;
  try { await API.delete(`/api/peers/${encodeURIComponent(id)}`); }
  catch (e) { alert(e.message); }
  page_peers();
}
