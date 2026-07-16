"""Time-series history — SQLite ring buffer adapted from Nexus Dashboard
core/history.py. Raw 5-min samples are kept a short window and folded to one
row per day for long trends; auto_vacuum + a size backstop keep disk bounded.
Only allowlisted dnsmasq metrics with small labels (range tags) are stored.
Sampling happens in the in-app ticker (stats.start_ticker) — no systemd timer.
"""
import os
import re
import time
import sqlite3
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from .config import DATA_DIR
from .runcmd import err, _num

bp = Blueprint('history', __name__)

HISTORY_DB = os.environ.get('DNSMAQ_HISTORY_DB', os.path.join(DATA_DIR, 'history.db'))
HISTORY_RAW_DAYS = int(os.environ.get('DNSMAQ_HISTORY_RAW_DAYS', 3))
HISTORY_DAILY_DAYS = int(os.environ.get('DNSMAQ_HISTORY_DAILY_DAYS', 400))
HISTORY_MAX_MB = int(os.environ.get('DNSMAQ_HISTORY_MAX_MB', 64))

# Allowlisted metrics. dns_* deltas come from dnsmasq's CHAOS TXT counters;
# dhcp_* from the leases file. Labels are bounded (dhcp range tags).
HISTORY_METRICS = {
    'dns_cache_size', 'dns_hits', 'dns_misses', 'dns_evictions',
    'dns_insertions', 'dns_queries_fwd', 'dhcp_leases', 'dhcp_pool_util',
}
RE_HISTORY_LABEL = re.compile(r'^[A-Za-z0-9 ._:/-]{0,64}$')


def _history_conn():
    first = not os.path.exists(HISTORY_DB)
    conn = sqlite3.connect(HISTORY_DB, timeout=5, isolation_level=None)  # autocommit
    if first:
        conn.execute('PRAGMA auto_vacuum=FULL')   # must precede table creation
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute("CREATE TABLE IF NOT EXISTS samples("
                 "ts INTEGER NOT NULL, metric TEXT NOT NULL, "
                 "label TEXT NOT NULL DEFAULT '', value REAL)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_samples ON samples(metric,label,ts)")
    conn.execute("CREATE TABLE IF NOT EXISTS daily("
                 "day TEXT NOT NULL, metric TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', "
                 "avg REAL, min REAL, max REAL, last REAL, PRIMARY KEY(day,metric,label))")
    conn.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
    return conn


def _history_record(rows):
    """rows: iterable of (metric, label, value). One shared timestamp. Best-effort
    — never raise into a caller (history must not break a request or a tick)."""
    try:
        ts = int(time.time())
        clean = [(ts, m, (l or ''), float(v)) for (m, l, v) in rows
                 if m in HISTORY_METRICS and v is not None]
        if not clean:
            return
        conn = _history_conn()
        try:
            conn.executemany('INSERT INTO samples(ts,metric,label,value) VALUES(?,?,?,?)', clean)
        finally:
            conn.close()
    except Exception:
        pass


def _history_query(metric, label, since_ts):
    conn = _history_conn()
    try:
        cur = conn.execute('SELECT ts,value FROM samples WHERE metric=? AND label=? AND ts>=? '
                           'ORDER BY ts', (metric, label or '', since_ts))
        return [[r[0], r[1]] for r in cur.fetchall()]
    finally:
        conn.close()


def _history_query_daily(metric, label, days):
    conn = _history_conn()
    try:
        cur = conn.execute('SELECT day,avg,min,max,last FROM daily WHERE metric=? AND label=? '
                           'ORDER BY day DESC LIMIT ?', (metric, label or '', days))
        rows = [{'day': r[0], 'avg': r[1], 'min': r[2], 'max': r[3], 'last': r[4]}
                for r in cur.fetchall()]
        return rows[::-1]
    finally:
        conn.close()


def _history_labels(metric):
    """Distinct labels stored for a metric (drives per-pool chart cards)."""
    conn = _history_conn()
    try:
        cur = conn.execute('SELECT DISTINCT label FROM samples WHERE metric=? '
                           'UNION SELECT DISTINCT label FROM daily WHERE metric=?',
                           (metric, metric))
        return sorted(r[0] for r in cur.fetchall())
    finally:
        conn.close()


def _history_prune_raw():
    conn = _history_conn()
    try:
        conn.execute('DELETE FROM samples WHERE ts < ?', (int(time.time()) - HISTORY_RAW_DAYS * 86400,))
    finally:
        conn.close()


def _history_maybe_rollup():
    """Once per day: fold whole prior days of raw into `daily`, prune old daily,
    VACUUM to release disk. Idempotent (upsert), gated by a meta marker."""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = _history_conn()
    try:
        cur = conn.execute("SELECT v FROM meta WHERE k='last_rollup'")
        row = cur.fetchone()
        if row and row[0] == today:
            return
        conn.execute(
            "INSERT INTO daily(day,metric,label,avg,min,max,last) "
            "SELECT date(ts,'unixepoch','localtime') AS d, metric, label, "
            "  AVG(value), MIN(value), MAX(value), "
            "  (SELECT value FROM samples s2 WHERE s2.metric=samples.metric "
            "     AND s2.label=samples.label "
            "     AND date(s2.ts,'unixepoch','localtime')"
            "         =date(samples.ts,'unixepoch','localtime') "
            "   ORDER BY s2.ts DESC LIMIT 1) "
            "FROM samples WHERE date(ts,'unixepoch','localtime') < ? "
            "GROUP BY d, metric, label "
            "ON CONFLICT(day,metric,label) DO UPDATE SET "
            "  avg=excluded.avg, min=excluded.min, max=excluded.max, last=excluded.last",
            (today,))
        day_cut = (datetime.now() - timedelta(days=HISTORY_DAILY_DAYS)).strftime('%Y-%m-%d')
        conn.execute('DELETE FROM daily WHERE day < ?', (day_cut,))
        conn.execute('DELETE FROM samples WHERE ts < ?', (int(time.time()) - HISTORY_RAW_DAYS * 86400,))
        conn.execute("INSERT INTO meta(k,v) VALUES('last_rollup',?) "
                     "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (today,))
        conn.execute('VACUUM')
    finally:
        conn.close()


def _history_size_backstop():
    """Last-resort bound: if the db somehow exceeds the cap, aggressively drop the
    oldest raw and VACUUM. Returns MB after the check."""
    try:
        mb = os.path.getsize(HISTORY_DB) / (1024 * 1024)
        if mb > HISTORY_MAX_MB:
            conn = _history_conn()
            try:
                conn.execute('DELETE FROM samples WHERE ts < ?', (int(time.time()) - 86400,))
                conn.execute('VACUUM')
            finally:
                conn.close()
            print(f'history: size cap hit ({mb:.0f}MB > {HISTORY_MAX_MB}MB) — pruned', flush=True)
        return mb
    except OSError:
        return 0


@bp.route('/api/history')
def history_get():
    metric = request.args.get('metric', '')
    label = request.args.get('label', '')
    if metric not in HISTORY_METRICS:
        return err('Unknown metric')
    if label and not RE_HISTORY_LABEL.match(label):
        return err('Invalid label')
    if request.args.get('res') == 'daily':
        days = max(1, min(_num(request.args.get('days')) or 90, HISTORY_DAILY_DAYS))
        return jsonify({'metric': metric, 'label': label, 'resolution': 'daily',
                        'points': _history_query_daily(metric, label, days)})
    max_since = HISTORY_RAW_DAYS * 86400
    since = min(_num(request.args.get('since')) or max_since, max_since)
    return jsonify({'metric': metric, 'label': label, 'resolution': 'raw',
                    'points': _history_query(metric, label, int(time.time()) - since)})


@bp.route('/api/history/labels')
def history_labels():
    metric = request.args.get('metric', '')
    if metric not in HISTORY_METRICS:
        return err('Unknown metric')
    return jsonify({'metric': metric, 'labels': _history_labels(metric)})


def cli_history_tick():
    # Imported here (not at module top) to avoid a core -> feature import cycle.
    from .. import stats
    _history_record(stats.collect_samples())
    _history_prune_raw()
    _history_maybe_rollup()
    _history_size_backstop()
    return 0
