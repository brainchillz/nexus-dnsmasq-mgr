// Config page: read-only rendered files, extra options, validate.
let _cfgFiles = {};
let _cfgActive = null;

async function page_config() {
  const [cfg, s] = await Promise.all([API.get('/api/dnsmasq/config'), API.get('/api/settings')]);
  _cfgFiles = cfg.files || {};
  const names = Object.keys(_cfgFiles);
  if (!_cfgActive || !names.includes(_cfgActive)) _cfgActive = names[0];
  const admin = currentRole === 'admin';

  $('page-content').innerHTML = `
    <h2>Config</h2>
    <p class="help">Rendered dnsmasq configuration (source of truth is this app — files under
      <code>${escapeHtml(cfg.render_dir)}</code> are regenerated on every change).</p>
    <div class="toolbar" id="cfg-tabs">${names.map(n =>
      `<button class="btn btn-sm ${n === _cfgActive ? '' : 'btn-outline'}" onclick="cfgShow('${jsArg(n)}')">${escapeHtml(n)}</button>`).join(' ')}</div>
    <pre class="raw-output" id="cfg-view" style="max-height:420px;overflow:auto"></pre>

    <h3 style="margin-top:24px">Extra Options <span class="help">(raw dnsmasq directives the UI doesn't cover — rendered into 90-extra.conf)</span></h3>
    <div class="form-group">
      <textarea id="cfg-extra" class="form-control" rows="6" spellcheck="false" ${admin ? '' : 'disabled'}
        placeholder="# one dnsmasq option per line, e.g.&#10;dhcp-option=option:tftp-server,10.0.0.5">${escapeHtml(s.extra_options || '')}</textarea>
    </div>
    ${admin ? `<div class="toolbar">
      <button class="btn" onclick="cfgSaveExtra()">Save &amp; Apply</button>
      <button class="btn btn-outline" onclick="cfgValidate()">Validate current config</button>
      <button class="btn btn-outline btn-warning" onclick="cfgForceApply()">Force re-render + restart</button>
    </div>` : ''}
    <div id="cfg-result"></div>`;
  cfgShow(_cfgActive);
}

function cfgShow(name) {
  _cfgActive = name;
  const view = $('cfg-view');
  if (view) view.textContent = _cfgFiles[name] || '';
  document.querySelectorAll('#cfg-tabs .btn').forEach(b => {
    b.classList.toggle('btn-outline', b.textContent !== name);
  });
}

async function cfgSaveExtra() {
  try {
    const r = await API.post('/api/settings', { extra_options: $('cfg-extra').value });
    notifyApply(r);
    page_config();
  } catch (e) {
    $('cfg-result').innerHTML = `<div class="alert alert-warning"><strong>Rejected:</strong> ${escapeHtml(e.message)}</div>`;
  }
}

async function cfgValidate() {
  $('cfg-result').innerHTML = '<p class="help">Validating…</p>';
  try {
    const r = await API.post('/api/dnsmasq/validate', {});
    $('cfg-result').innerHTML = r.valid
      ? `<div class="health-ok">✓ ${escapeHtml(r.output)}${r.pending_action !== 'none' ? ` · pending ${escapeHtml(r.pending_action)} (${r.pending_files.length} file(s) differ on disk)` : ''}</div>`
      : `<div class="alert alert-warning"><strong>Invalid:</strong> ${escapeHtml(r.output)}</div>`;
  } catch (e) { $('cfg-result').innerHTML = `<div class="alert alert-warning">${escapeHtml(e.message)}</div>`; }
}

async function cfgForceApply() {
  if (!confirm('Re-render every config file and restart dnsmasq?')) return;
  try {
    const r = await API.post('/api/dnsmasq/apply', {});
    notifyApply(r);
    page_config();
  } catch (e) { alert(e.message); }
}
