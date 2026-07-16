// Network Boot page: TFTP, proxy-DHCP, arch-matched boot entries.
let _nbData = null;

const NB_ARCHES = [
  ['0', 'BIOS x86'],
  ['6', 'UEFI IA32'],
  ['7', 'UEFI x64'],
  ['9', 'UEFI x64 (9)'],
  ['10', 'ARM32 UEFI'],
  ['11', 'ARM64 UEFI'],
];
const NB_ARCH_LABEL = Object.fromEntries(NB_ARCHES);

async function page_netboot() {
  await refreshMirrorStatus();
  const [nb, st] = await Promise.all([API.get('/api/netboot'), API.get('/api/dnsmasq/status')]);
  _nbData = nb;
  const locked = sectionLocked('netboot');
  const can = currentRole === 'admin' && !locked;

  const entryRows = nb.entries.map(e => `<tr>
    <td>${escapeHtml(e.name)}</td>
    <td>${(e.arches && e.arches.length) ? e.arches.map(a => `<span class="badge-type">${escapeHtml(NB_ARCH_LABEL[a] || 'arch ' + a)}</span>`).join(' ') : '<span class="help">any client</span>'}</td>
    <td><code>${escapeHtml(e.filename)}</code></td>
    <td>${escapeHtml(e.server || 'this host')}</td>
    <td>${enabledBadge(e.enabled)}</td>
    <td class="row-actions">${can ? `
      <button class="btn btn-sm btn-outline" onclick="nbEntryModal('${jsArg(e.id)}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="nbEntryDelete('${jsArg(e.id)}','${jsArg(e.name)}')">Delete</button>` : ''}
    </td></tr>`).join('');

  $('page-content').innerHTML = `
    <h2>Network Boot</h2>
    ${st.dhcp_enabled || nb.proxy_dhcp ? '' : `<div class="alert alert-info">DHCP is disabled and proxy-DHCP is off — boot entries are kept but not served.
      ${currentRole === 'admin' ? '<a href="#" onclick="toggleFeature(\'dhcp_enabled\', true);return false">Enable DHCP</a> or turn on proxy-DHCP below.' : ''}</div>`}
    ${lockedBanner('netboot')}
    <div class="cards">
      <div class="card">
        <div class="card-head">TFTP server</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin:8px 0">
          <span>Serve files over TFTP</span>${switchHtml(nb.tftp_enabled, 'nbSaveSettings({tftp_enabled: this.checked})', !can)}</div>
        <div class="form-group"><label>TFTP root directory</label>
          <input id="nb-root" class="form-control" value="${escapeHtml(nb.tftp_root || '')}" placeholder="(default: app tftp/ dir)" ${can ? '' : 'disabled'}></div>
        <label class="checkitem" style="padding-left:0"><input id="nb-secure" type="checkbox" ${nb.tftp_secure ? 'checked' : ''} ${can ? '' : 'disabled'}> Secure mode (only world-readable files)</label>
        ${can ? '<div class="toolbar" style="margin-top:8px"><button class="btn btn-sm" onclick="nbSaveSettings({tftp_root: $(\'nb-root\').value.trim(), tftp_secure: $(\'nb-secure\').checked})">Save TFTP settings</button></div>' : ''}
        <p class="help">Drop boot files (ipxe.efi, undionly.kpxe, grubx64.efi, …) into the TFTP root on this host.</p>
      </div>
      <div class="card">
        <div class="card-head">Proxy-DHCP (PXE alongside another DHCP server)</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin:8px 0">
          <span>Proxy-DHCP mode</span>${switchHtml(nb.proxy_dhcp, 'nbProxyToggle(this.checked)', !can)}</div>
        <div class="form-group"><label>Subnet (network address of the LAN)</label>
          <input id="nb-proxysub" class="form-control" value="${escapeHtml(nb.proxy_subnet || '')}" placeholder="10.0.0.0" ${can ? '' : 'disabled'}></div>
        <div class="form-group"><label>Boot menu prompt</label>
          <input id="nb-prompt" class="form-control" value="${escapeHtml(nb.pxe_prompt || '')}" placeholder="Network boot" ${can ? '' : 'disabled'}></div>
        ${can ? '<div class="toolbar"><button class="btn btn-sm" onclick="nbSaveSettings({proxy_subnet: $(\'nb-proxysub\').value.trim(), pxe_prompt: $(\'nb-prompt\').value.trim()})">Save proxy settings</button></div>' : ''}
        <p class="help">Use when another router already serves DHCP: dnsmasq only supplies the PXE boot info, leases stay with the existing server.</p>
      </div>
    </div>

    <h3 style="margin-top:24px">Boot Entries</h3>
    ${can ? `<div class="toolbar"><button class="btn btn-sm" onclick="nbEntryModal()">+ Add boot entry</button></div>` : ''}
    <table class="table"><thead><tr><th>Name</th><th>Client architectures</th><th>Boot file</th><th>Server</th><th>State</th><th></th></tr></thead>
      <tbody>${entryRows || '<tr><td colspan="6">No boot entries — clients get no netboot option</td></tr>'}</tbody></table>
    <p class="help">Each entry matches PXE clients by architecture (DHCP option 93) and hands them the right boot file —
      e.g. <code>undionly.kpxe</code> for BIOS, <code>ipxe.efi</code> for UEFI x64. Leave architectures empty to serve one file to every client.</p>`;
}

async function nbSaveSettings(fields) {
  try {
    const r = await API.post('/api/netboot/settings', fields);
    notifyApply(r);
  } catch (e) { alert(e.message); }
  page_netboot();
}

function nbProxyToggle(on) {
  const sub = $('nb-proxysub').value.trim();
  if (on && !sub) {
    alert('Set the subnet first, then enable proxy-DHCP.');
    page_netboot();
    return;
  }
  nbSaveSettings({ proxy_dhcp: on, proxy_subnet: sub });
}

function nbEntryModal(id) {
  const e = id ? (_nbData.entries.find(x => x.id === id) || {}) : {};
  const arches = e.arches || [];
  const checks = NB_ARCHES.map(([v, l]) =>
    `<label class="checkitem"><input type="checkbox" class="nb-arch" value="${v}" ${arches.includes(v) ? 'checked' : ''}> ${escapeHtml(l)}</label>`).join('');
  openModal(id ? 'Edit boot entry' : 'Add boot entry', `
    <div class="form-group"><label>Name</label><input id="nb-name" class="form-control" value="${escapeHtml(e.name || '')}" placeholder="UEFI x64 iPXE"></div>
    <div class="form-group"><label>Client architectures (empty = all clients)</label>
      <div class="checklist">${checks}</div></div>
    <div class="form-group"><label>Boot filename</label><input id="nb-file" class="form-control" value="${escapeHtml(e.filename || '')}" placeholder="ipxe.efi"></div>
    <div class="form-group"><label>Boot server (optional — defaults to this host)</label><input id="nb-server" class="form-control" value="${escapeHtml(e.server || '')}"></div>
    <div class="form-group"><label>Comment</label><input id="nb-comment" class="form-control" value="${escapeHtml(e.comment || '')}"></div>
    <label class="checkitem" style="padding-left:0"><input id="nb-enabled" type="checkbox" ${e.enabled !== false ? 'checked' : ''}> Enabled</label>
    <button class="btn" onclick="nbEntrySave('${jsArg(id || '')}')">${id ? 'Save' : 'Add'}</button>`);
}

async function nbEntrySave(id) {
  const fields = {
    name: $('nb-name').value.trim(),
    arches: Array.from(document.querySelectorAll('.nb-arch:checked')).map(c => c.value),
    filename: $('nb-file').value.trim(),
    server: $('nb-server').value.trim(),
    comment: $('nb-comment').value,
    enabled: $('nb-enabled').checked,
  };
  try {
    const r = await API.post('/api/netboot/entries' + (id ? '/' + encodeURIComponent(id) : ''), fields);
    notifyApply(r);
    closeModal();
    page_netboot();
  } catch (e) { alert(e.message); }
}

async function nbEntryDelete(id, name) {
  if (!confirm(`Delete boot entry "${name}"?`)) return;
  try {
    const r = await API.delete(`/api/netboot/entries/${encodeURIComponent(id)}`);
    notifyApply(r);
    page_netboot();
  } catch (e) { alert(e.message); }
}
