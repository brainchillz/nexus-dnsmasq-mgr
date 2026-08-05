// Network Scan page: ping/ARP sweep over the app's own configured addresses,
// cross-referenced against host records and leases for record hygiene.

let _reconTimer = null;

async function page_recon() {
  if (_reconTimer) { clearTimeout(_reconTimer); _reconTimer = null; }
  const [r] = await Promise.all([API.get('/api/recon'), refreshMirrorStatus()]);
  const admin = currentRole === 'admin';
  const canName = admin && !sectionLocked('hosts');

  const scanBar = r.running
    ? `<div class="toolbar"><span class="help">Scanning… ${r.progress}/${r.total}</span></div>`
    : `<div class="toolbar">
        ${admin ? `<button class="btn" onclick="reconScan()">${icon('cross', 'ico-sm')} Scan now</button>` : ''}
        <span class="help">${r.last ? `last scan ${fmtTs(r.last.ts)} · ${r.last.targets} targets in ${r.last.duration}s${r.last.truncated ? ' (truncated)' : ''}` : 'no scan yet'}</span>
      </div>`;

  let body = '';
  const l = r.last;
  if (l) {
    const tiles = `<div class="cards">
      <div class="card"><div class="card-head">Alive</div><div class="card-value">${l.alive}<span class="card-unit">/ ${l.targets}</span></div><div class="card-sub">${l.neighbors} in ARP table</div></div>
      <div class="card"><div class="card-head">Unnamed devices</div><div class="card-value">${l.unnamed_devices.length}</div><div class="card-sub">live, but no DNS name</div></div>
      <div class="card"><div class="card-head">Stale records</div><div class="card-value">${l.stale_records.length}</div><div class="card-sub">record points at a dead IP</div></div>
      <div class="card"><div class="card-head">Duplicates</div><div class="card-value">${l.duplicates.length}</div><div class="card-sub">conflicting name &harr; IP mappings</div></div>
    </div>`;

    const unnamed = l.unnamed_devices.length ? `
      <h3 style="margin-top:18px">Unnamed devices <span class="help">(alive on the network, no host record or lease hostname)</span></h3>
      <table class="table"><thead><tr><th>IP</th><th>MAC</th><th>Seen via</th><th></th></tr></thead><tbody>
        ${l.unnamed_devices.map(d => `<tr><td><code>${escapeHtml(d.ip)}</code></td><td><code>${escapeHtml(d.mac || '-')}</code></td>
          <td class="help">${d.alive ? 'ping' : 'ARP'}${d.has_lease ? ' · has lease' : ''}</td>
          <td class="row-actions">${canName ? `<button class="btn btn-sm" onclick="reconNameModal('${jsArg(d.ip)}','${jsArg(d.mac || '')}')">+ Create record</button>` : ''}</td></tr>`).join('')}
      </tbody></table>` : '';

    const stale = l.stale_records.length ? `
      <h3 style="margin-top:18px">Stale host records <span class="help">(the IP answers nothing and holds no lease)</span></h3>
      <table class="table"><thead><tr><th>Name</th><th>IP</th><th>Comment</th><th></th></tr></thead><tbody>
        ${l.stale_records.map(s => `<tr><td><code>${escapeHtml(s.name)}</code></td><td>${escapeHtml(s.ip)}</td>
          <td class="help">${escapeHtml(s.comment || '')}</td>
          <td class="row-actions"><button class="btn btn-sm btn-outline" onclick="showPage('dns')">Review</button></td></tr>`).join('')}
      </tbody></table>` : '';

    const dups = l.duplicates.length ? `
      <h3 style="margin-top:18px">Duplicate / conflicting mappings</h3>
      <table class="table"><thead><tr><th>Kind</th><th>Name / IP</th><th>Detail</th></tr></thead><tbody>
        ${l.duplicates.map(d => `<tr><td><span class="badge-type">${escapeHtml(d.kind.replace(/_/g, ' '))}</span></td>
          <td><code>${escapeHtml(d.name)}</code></td><td class="help">${escapeHtml(d.detail)}</td></tr>`).join('')}
      </tbody></table>` : '';

    const clean = !l.unnamed_devices.length && !l.stale_records.length && !l.duplicates.length
      ? `<div class="health-ok" style="margin-top:14px">✓ No hygiene issues found — every live device has a name and every record answers.</div>` : '';

    body = tiles + clean + stale + dups + unnamed;
  }

  $('page-content').innerHTML = `
    <h2>Network Scan</h2>
    <p class="help">Ping/ARP sweep over the addresses this app already manages — enabled DHCP ranges, host-record
      IPs and active leases — cross-referenced against the stores. Results depend on devices answering ping or ARP
      on directly attached subnets.</p>
    ${scanBar}
    ${body}`;

  if (r.running) _reconTimer = setTimeout(() => {
    const active = document.querySelector('.nav-list a.active');
    if (active && active.dataset.page === 'recon') page_recon();
  }, 1500);
}

async function reconScan() {
  try { await API.post('/api/recon/scan', {}); }
  catch (e) { alert(e.message); }
  page_recon();
}

// ─── Name an unnamed device straight from the scan results ──────────
const RECON_TYPES = [
  ['device', 'Device'], ['server', 'Server'], ['vm', 'Virtual machine'],
  ['container', 'Container'], ['network', 'Network gear (switch/AP/router)'],
  ['iot', 'IoT / appliance'], ['printer', 'Printer'], ['other', 'Other'],
];

function reconNameModal(ip, mac) {
  openModal('Create record for ' + ip, `
    <table class="table" style="margin-bottom:10px">
      <tr><td>IP</td><td><code>${escapeHtml(ip)}</code></td></tr>
      <tr><td>MAC</td><td><code>${escapeHtml(mac || 'unknown')}</code></td></tr>
    </table>
    <div class="form-group"><label>Hostname (bare name or FQDN)</label>
      <input id="rn-name" class="form-control" placeholder="switch-rack1 or switch-rack1.lan" spellcheck="false"></div>
    <div class="form-group"><label>Type</label>
      <select id="rn-type" class="form-control">
        ${RECON_TYPES.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}
      </select></div>
    <div class="form-group"><label>Note (optional)</label>
      <input id="rn-note" class="form-control" placeholder="core switch, rack 1"></div>
    ${mac ? `<label class="checkitem" style="padding-left:0"><input id="rn-reserve" type="checkbox">
      Also reserve ${escapeHtml(ip)} for this MAC (static DHCP lease)</label>` : ''}
    <div class="toolbar" style="margin-top:10px">
      <button class="btn" onclick="reconNameGo('${jsArg(ip)}','${jsArg(mac || '')}', this)">Create</button>
    </div>
    <div id="rn-result"></div>`);
  $('rn-name').focus();
}

async function reconNameGo(ip, mac, btn) {
  const name = $('rn-name').value.trim();
  if (!name) { alert('Enter a hostname'); return; }
  const type = $('rn-type').value;
  const note = $('rn-note').value.trim();
  // Type + note ride the record's comment — visible on the DNS page and in
  // exports without a schema change.
  const comment = note ? `${type} — ${note}` : type;
  const reserve = mac && $('rn-reserve') && $('rn-reserve').checked;
  btn.disabled = true;
  try {
    const r = await API.post('/api/dns/hosts', { name, a: ip, comment });
    notifyApply(r);
    if (reserve) {
      try {
        // static-lease hostnames are bare labels — use the first label
        await API.post('/api/dhcp/leases/reserve',
                       { mac, ip, hostname: name.split('.')[0] });
      } catch (e) {
        alert('Record created, but the DHCP reservation failed: ' + e.message);
      }
    }
    closeModal();
    page_recon();     // report recomputes server-side — the device leaves the list
  } catch (e) {
    btn.disabled = false;
    $('rn-result').innerHTML = `<div class="alert alert-warning">${escapeHtml(e.message)}</div>`;
  }
}
