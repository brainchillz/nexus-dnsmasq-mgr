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
    <div id="cfg-result"></div>

    ${admin ? `<h3 style="margin-top:24px">Import an existing dnsmasq configuration</h3>
    <div class="card" style="max-width:760px">
      <p class="help">Onboarding: paste a <code>dnsmasq.conf</code> (and any <code>dnsmasq.d</code> fragments), or scan this host's
        own <code>/etc/dnsmasq.conf</code> + <code>/etc/dnsmasq.d</code>. Ranges, static leases, options, boot entries, host records,
        overrides, forwards and global settings land in the app's stores; anything else is offered as Extra Options.
        Every record is validated exactly like a UI edit — nothing is half-imported.</p>
      <div class="form-group"><input type="file" id="imp-file" class="form-control" accept=".conf,text/plain" onchange="impReadFile(this)"></div>
      <div class="form-group"><textarea id="imp-text" class="form-control" rows="8" spellcheck="false" placeholder="dhcp-range=10.0.0.100,10.0.0.199,12h&#10;dhcp-host=aa:bb:cc:dd:ee:ff,10.0.0.5,nas&#10;address=/ads.example/0.0.0.0"></textarea></div>
      <div class="toolbar">
        <button class="btn" onclick="impPreview(false)">Preview</button>
        <button class="btn btn-outline" onclick="impPreview(true)" title="Read /etc/dnsmasq.conf and /etc/dnsmasq.d/*.conf on this host (bare metal)">Scan this host</button>
      </div>
      <div id="imp-result"></div>
    </div>` : ''}`;
  cfgShow(_cfgActive);
}

// ─── Existing-config importer ───────────────────────────
let _impScan = false;
function impReadFile(input) {
  const f = input.files && input.files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = () => { $('imp-text').value = reader.result; };
  reader.readAsText(f);
}

async function impPreview(scan) {
  _impScan = !!scan;
  $('imp-result').innerHTML = '<p class="help">Parsing…</p>';
  let r;
  try { r = await API.post('/api/import/preview', scan ? { scan: true } : { text: $('imp-text').value }); }
  catch (e) { $('imp-result').innerHTML = `<div class="alert alert-warning">${escapeHtml(e.message)}</div>`; return; }
  const c = r.counts, p = r.preview;
  const sec = (id, label, n) => `<label class="checkitem"><input type="checkbox" class="imp-sec" value="${id}" ${n ? 'checked' : 'disabled'}> ${label} <span class="help">(${n})</span></label>`;
  $('imp-result').innerHTML = `
    ${p.files && p.files.length ? `<p class="help">Read: ${p.files.map(escapeHtml).join(', ')}</p>` : ''}
    <div class="checklist" style="margin:8px 0">
      ${sec('settings', 'Global settings & upstreams', c.settings)}
      ${sec('hosts', 'Host records', c.hosts)}
      ${sec('dns', 'CNAMEs / overrides / forwards', c.dns)}
      ${sec('dhcp', 'DHCP ranges / static leases / options', c.dhcp)}
      ${sec('netboot', 'Boot entries', c.netboot)}
      ${sec('extra', 'Everything else → Extra Options', c.extra)}
    </div>
    ${p.extra.length ? `<details><summary class="help">${p.extra.length} line(s) going to Extra Options</summary><pre class="raw-output" style="max-height:160px;overflow:auto">${escapeHtml(p.extra.join('\n'))}</pre></details>` : ''}
    ${p.skipped.length ? `<details><summary class="help">${p.skipped.length} line(s) skipped</summary><table class="table">${p.skipped.map(s => `<tr><td><code>${escapeHtml(s.line)}</code></td><td class="help">${escapeHtml(s.reason)}</td></tr>`).join('')}</table></details>` : ''}
    <div class="toolbar" style="margin-top:10px">
      <label class="checkitem" style="padding-left:0"><input id="imp-replace" type="checkbox"> Replace existing records in the chosen sections (unchecked = merge)</label>
    </div>
    <div class="toolbar">
      <button class="btn" onclick="impApply(false)">Import selected</button>
    </div>
    <div id="imp-apply"></div>`;
}

async function impApply(skipInvalid) {
  const sections = [...document.querySelectorAll('.imp-sec:checked')].map(c => c.value);
  if (!sections.length) { alert('Choose at least one section'); return; }
  const replace = $('imp-replace').checked;
  if (replace && !confirm('Replace the existing records in: ' + sections.join(', ') + '?')) return;
  $('imp-apply').innerHTML = '<p class="help">Importing…</p>';
  const body = _impScan ? { scan: true } : { text: $('imp-text').value };
  Object.assign(body, { sections, replace, skip_invalid: !!skipInvalid });
  try {
    const r = await API.post('/api/import/apply', body);
    notifyApply(r);
    $('imp-apply').innerHTML = `<div class="health-ok">✓ Imported ${r.imported.join(', ')}: ${r.added} added, ${r.updated} updated, ${r.unchanged} unchanged
      ${r.problems && r.problems.length ? ` · ${r.problems.length} invalid line(s) skipped` : ''} · applied via ${r.action}</div>
      <div class="toolbar" style="margin-top:8px"><button class="btn btn-sm" onclick="page_config()">Done</button></div>`;
  } catch (e) {
    const probs = e.body && e.body.problems ? `<ul style="margin:6px 0 0 18px">${e.body.problems.map(x => `<li class="help">${escapeHtml(x)}</li>`).join('')}</ul>` : '';
    $('imp-apply').innerHTML = `<div class="alert alert-warning"><strong>${escapeHtml(e.message)}</strong>${probs}
      ${probs ? '<div class="toolbar" style="margin-top:8px"><button class="btn btn-sm btn-outline" onclick="impApply(true)">Import the valid lines anyway</button></div>' : ''}</div>`;
  }
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
