// Statistics page: history charts from the SQLite ring buffer.
let statsRange = '86400';  // seconds of raw history, or 'daily'

const STATS_CHARTS = [
  ['dns_hits', 'DNS cache hits', 'per 5-min sample'],
  ['dns_misses', 'DNS cache misses', 'per 5-min sample'],
  ['dns_insertions', 'Cache insertions', 'per 5-min sample'],
  ['dns_evictions', 'Cache evictions', 'per 5-min sample'],
  ['dns_cache_size', 'Cache size', 'configured slots'],
  ['dhcp_leases', 'Active DHCP leases', 'gauge'],
];

async function page_stats() {
  const cur = await API.get('/api/stats/current').catch(() => null);
  const dns = cur && cur.dns;
  const tiles = `
    <div class="cards">
      <div class="card"><div class="card-head">Hit ratio</div>
        <div class="card-value">${dns && dns.hit_ratio != null ? dns.hit_ratio : '-'}<span class="card-unit">%</span></div>
        <div class="card-sub">${dns ? `${dns.hits} hits · ${dns.misses} misses since dnsmasq start` : 'DNS stats unavailable'}</div></div>
      <div class="card"><div class="card-head">Cache</div>
        <div class="card-value">${dns ? dns.cachesize : '-'}<span class="card-unit">slots</span></div>
        <div class="card-sub">${dns ? `${dns.insertions} insertions · ${dns.evictions} evictions` : ''}</div></div>
      <div class="card"><div class="card-head">Active leases</div>
        <div class="card-value">${cur ? cur.dhcp.active_leases : '-'}</div>
        <div class="card-sub">${cur && cur.dhcp.pools.length ? cur.dhcp.pools.map(p => `${escapeHtml(p.tag)} ${p.pct}%`).join(' · ') : ''}</div></div>
    </div>`;

  const ranges = [['3600', '1 h'], ['21600', '6 h'], ['86400', '24 h'], ['259200', '3 d'], ['daily', 'Daily (long term)']];
  const selector = `<div class="toolbar">${ranges.map(([v, l]) =>
    `<button class="btn btn-sm ${statsRange === v ? '' : 'btn-outline'}" onclick="statsSetRange('${v}')">${l}</button>`).join(' ')}</div>`;

  const charts = STATS_CHARTS.map(([m, title, sub]) => `
    <div class="card">
      <div class="card-head">${title}</div>
      <div id="chart-${m}" style="margin:6px 0">…</div>
      <div class="card-sub" id="chartsub-${m}">${sub}</div>
    </div>`).join('');

  $('page-content').innerHTML = `
    <h2>Statistics</h2>
    ${tiles}
    ${selector}
    <div class="cards">${charts}<div id="pool-charts" style="display:contents"></div></div>
    <p class="help">Counters are sampled every 5 minutes; raw samples are kept 3 days and folded into daily
      min/avg/max for long-term trends. Rates are per-sample deltas of dnsmasq's cumulative counters.</p>`;

  fillStatsCharts();
}

function statsSetRange(v) { statsRange = v; page_stats(); }

async function _statsPoints(metric, label) {
  const q = statsRange === 'daily'
    ? `/api/history?metric=${metric}&label=${encodeURIComponent(label || '')}&res=daily&days=180`
    : `/api/history?metric=${metric}&label=${encodeURIComponent(label || '')}&since=${statsRange}`;
  const h = await API.get(q);
  if (statsRange === 'daily') {
    return (h.points || []).map(p => [new Date(p.day).getTime() / 1000, p.avg]);
  }
  return h.points || [];
}

async function fillStatsCharts() {
  for (const [m] of STATS_CHARTS) {
    const el = document.getElementById('chart-' + m);
    if (!el) continue;
    try {
      const pts = await _statsPoints(m);
      el.innerHTML = sparkline(pts, { w: 260, h: 48 });
      const sub = document.getElementById('chartsub-' + m);
      if (sub && pts.length) {
        const last = pts[pts.length - 1][1];
        const max = Math.max(...pts.map(p => p[1]));
        sub.textContent = `latest ${Math.round(last * 10) / 10} · peak ${Math.round(max * 10) / 10} · ${pts.length} points`;
      }
    } catch (e) { el.innerHTML = '<span class="help">no data</span>'; }
  }
  // Per-pool utilization charts (one per range tag stored in history).
  try {
    const l = await API.get('/api/history/labels?metric=dhcp_pool_util');
    const holder = document.getElementById('pool-charts');
    if (holder && (l.labels || []).length) {
      holder.innerHTML = l.labels.map(t => `
        <div class="card"><div class="card-head">Pool ${escapeHtml(t || '(untagged)')} utilization</div>
          <div id="pool-${escapeHtml(t)}" style="margin:6px 0">…</div>
          <div class="card-sub">percent of range in use</div></div>`).join('');
      for (const t of l.labels) {
        try {
          const pts = await _statsPoints('dhcp_pool_util', t);
          const el = document.getElementById('pool-' + t);
          if (el) el.innerHTML = sparkline(pts, { w: 260, h: 48 });
        } catch (e) {}
      }
    }
  } catch (e) {}
}
