// History page: timeline of applied changes with rendered-config diffs and
// one-click rollback.

const HIST_ACTION_BADGE = { restart: 'yellow', reload: 'green', none: 'gray' };

async function page_history() {
  const r = await API.get('/api/changelog');
  const admin = currentRole === 'admin';
  const rows = (r.entries || []).map((e, i) => `<tr>
    <td style="white-space:nowrap">${fmtTs(e.ts)}</td>
    <td>${escapeHtml(e.user)}</td>
    <td>${(e.sections || []).map(s => `<span class="badge-type">${escapeHtml(s)}</span>`).join(' ')}</td>
    <td><span class="status-badge ${HIST_ACTION_BADGE[e.action] || 'gray'}">${escapeHtml(e.action)}</span></td>
    <td class="help">${(e.changed || []).length} file(s) · ${e.counts.hosts} hosts · ${e.counts.dns} dns · ${e.counts.dhcp} dhcp</td>
    <td class="row-actions">
      <button class="btn btn-sm btn-outline" onclick="histDiff('${jsArg(e.id)}')">Diff</button>
      ${admin && i > 0 ? `<button class="btn btn-sm btn-danger" onclick="histRollback('${jsArg(e.id)}','${jsArg(fmtTs(e.ts))}')">Roll back to</button>` : ''}
    </td></tr>`).join('');

  $('page-content').innerHTML = `
    <h2>History</h2>
    <p class="help">Every applied change — who made it, what it touched, and the rendered-config diff.
      The last ${r.keep} changes are kept. Rolling back re-applies that point-in-time snapshot through the
      normal validate-and-swap pipeline (and is itself recorded here).</p>
    <table class="table"><thead><tr><th>When</th><th>By</th><th>Sections</th><th>Applied via</th><th>Summary</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6">No changes recorded yet — history starts with the next applied change.</td></tr>'}</tbody></table>`;
}

async function histDiff(id) {
  let d;
  try { d = await API.get('/api/changelog/' + encodeURIComponent(id) + '/diff'); }
  catch (e) { alert(e.message); return; }
  const files = Object.keys(d.diffs || {});
  let body;
  if (d.first) {
    body = '<p class="help">This is the oldest recorded change — there is no earlier snapshot to diff against.</p>';
  } else if (!files.length && !(d.blocklist_files_changed || []).length) {
    body = '<p class="help">No rendered-config difference against the previous change (store metadata only).</p>';
  } else {
    body = files.map(f => `<h3 style="margin-top:10px"><code>${escapeHtml(f)}</code></h3>
      <pre class="diff-view" style="overflow-x:auto;font-size:.82em;line-height:1.35">${d.diffs[f].split('\n').map(l => {
        const esc = escapeHtml(l);
        if (l.startsWith('+') && !l.startsWith('+++')) return `<span style="color:var(--ok,#3fb950)">${esc}</span>`;
        if (l.startsWith('-') && !l.startsWith('---')) return `<span style="color:var(--danger,#f85149)">${esc}</span>`;
        return esc;
      }).join('\n')}</pre>`).join('');
    if ((d.blocklist_files_changed || []).length) {
      body += `<p class="help">Blocklist files also changed (content not stored in history): ${d.blocklist_files_changed.map(escapeHtml).join(', ')}</p>`;
    }
  }
  openModal('Change diff', body, { wide: true });
}

async function histRollback(id, when) {
  if (!confirm(`Roll the configuration back to the state recorded at ${when}?\n\nThe change is validated with dnsmasq --test before anything is swapped.`)) return;
  try {
    const r = await API.post('/api/changelog/' + encodeURIComponent(id) + '/rollback', {});
    notifyApply(r);
    page_history();
  } catch (e) { alert(e.message); }
}
