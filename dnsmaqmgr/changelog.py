"""Change history with diff and rollback.

Every successful apply_change records one JSON snapshot under CHANGELOG_DIR:
who made the change (session user, API token, mirror push, or the system
ticker), which sections and rendered files it touched, the full store contents
AFTER the change, and the rendered base config files. Diffs between entries
are computed from the stored rendered text — exact, cheap, and independent of
whatever the stores render to today. Blocklist conf files are excluded from
the stored render (they are MB-scale and their content is the fetched list,
not operator intent); blocklist changes still appear in the entry metadata.

Rollback re-saves a snapshot's stores and pushes them through the normal
apply pipeline, so `dnsmasq --test` still gates it — and the rollback itself
becomes a new history entry. Store serials are carried FORWARD (max of
current and snapshot), otherwise a rollback would hand mirrors a serial
they've already seen and every push would be rejected as stale.

Recording is best-effort: a failed write must never break the apply that
triggered it.
"""
import os
import glob
import json
import time
import difflib
import secrets
from flask import Blueprint, jsonify, g, has_request_context

from .core.config import CHANGELOG_DIR, CHANGELOG_KEEP, write_json_atomic
from .core.runcmd import err

bp = Blueprint('changelog', __name__)

TRACKED = ('settings', 'dns', 'dhcp', 'netboot', 'blocklists', 'encdns')
# Rendered files snapshotted for diffs — everything except 50-block-*.conf.
DIFF_EXCLUDE_PREFIX = 'dnsmasq.d/50-block-'

# Fields whose changes alone are bookkeeping, not an operator action.
_NOISE_KEYS = ('serial',)


def _identity(from_mirror):
    if has_request_context() and getattr(g, 'identity_name', None):
        return g.identity_name
    return 'mirror' if from_mirror else 'system'


def _strip_noise(store):
    return {k: v for k, v in store.items() if k not in _NOISE_KEYS}


def _counts(stores):
    """Compact per-store item counts for the timeline row."""
    out = {}
    d = stores.get('dns', {})
    out['hosts'] = len(d.get('hosts', []))
    out['dns'] = sum(len(d.get(c, [])) for c in ('cnames', 'addresses', 'forwards'))
    h = stores.get('dhcp', {})
    out['dhcp'] = sum(len(h.get(c, [])) for c in ('ranges', 'static_leases', 'options'))
    out['netboot'] = len(stores.get('netboot', {}).get('entries', []))
    out['blocklists'] = len(stores.get('blocklists', {}).get('lists', []))
    return out


def _entry_path(cid):
    return os.path.join(CHANGELOG_DIR, cid + '.json')


def _entry_ids():
    """All entry ids, oldest first (ids sort chronologically by construction)."""
    return sorted(os.path.basename(p)[:-5]
                  for p in glob.glob(os.path.join(CHANGELOG_DIR, '*.json')))


def _load(cid):
    if '/' in cid or '..' in cid:
        return None
    try:
        with open(_entry_path(cid)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def record(sections, action, changed, before, after, rendered, from_mirror=False):
    """Called by apply_change (inside STORE_LOCK) after a successful apply.
    `before`/`after` are full store dicts keyed by TRACKED names."""
    try:
        if action == 'none' and all(
                _strip_noise(after.get(n, {})) == _strip_noise(before.get(n, {}))
                for n in ('settings', 'dns', 'dhcp', 'netboot', 'encdns')):
            # Bookkeeping-only writes (e.g. a blocklist refresh that fetched
            # identical data) would flood the timeline.
            return
        ts = time.time()
        cid = '%013d-%s' % (int(ts * 1000), secrets.token_hex(3))
        entry = {
            'id': cid, 'ts': int(ts),
            'user': _identity(from_mirror),
            'sections': sorted(sections),
            'action': action, 'changed': sorted(changed),
            'counts': _counts(after),
            'stores': {n: after[n] for n in TRACKED if n in after},
            'rendered': {rel: text for rel, text in rendered.items()
                         if not rel.startswith(DIFF_EXCLUDE_PREFIX)},
        }
        write_json_atomic(_entry_path(cid), entry, 0o600)
        ids = _entry_ids()
        for old in ids[:-CHANGELOG_KEEP]:
            try:
                os.remove(_entry_path(old))
            except OSError:
                pass
    except Exception as e:
        print('changelog: failed to record change: %s' % e, flush=True)


def _meta(entry):
    return {k: entry[k] for k in ('id', 'ts', 'user', 'sections', 'action',
                                  'changed', 'counts')}


@bp.route('/api/changelog')
def changelog_list():
    entries = []
    for cid in reversed(_entry_ids()):
        e = _load(cid)
        if e:
            entries.append(_meta(e))
    return jsonify({'entries': entries, 'keep': CHANGELOG_KEEP})


@bp.route('/api/changelog/<cid>/diff')
def changelog_diff(cid):
    entry = _load(cid)
    if not entry:
        return err('No such change', 404)
    ids = _entry_ids()
    try:
        idx = ids.index(cid)
    except ValueError:
        return err('No such change', 404)
    prev = _load(ids[idx - 1]) if idx > 0 else None
    old_files = (prev or {}).get('rendered', {})
    new_files = entry.get('rendered', {})
    diffs = {}
    for rel in sorted(set(old_files) | set(new_files)):
        a = (old_files.get(rel) or '').splitlines(keepends=True)
        b = (new_files.get(rel) or '').splitlines(keepends=True)
        if a == b:
            continue
        diffs[rel] = ''.join(difflib.unified_diff(
            a, b, fromfile='%s (before)' % rel, tofile='%s (after)' % rel, n=2))
    blockfiles = [f for f in entry.get('changed', [])
                  if f.startswith(DIFF_EXCLUDE_PREFIX)]
    return jsonify({'id': cid, 'against': prev['id'] if prev else None,
                    'diffs': diffs, 'blocklist_files_changed': blockfiles,
                    'first': prev is None})


@bp.route('/api/changelog/<cid>/rollback', methods=['POST'])
def changelog_rollback(cid):
    entry = _load(cid)
    if not entry:
        return err('No such change', 404)
    stores = entry.get('stores') or {}
    if not stores:
        return err('Entry carries no store snapshot', 422)

    from .core.store import load_store, save_store
    from .dnsmasq import apply_change   # lazy: dnsmasq imports this module

    def mutate():
        for name in TRACKED:
            if name not in stores:
                continue
            data = dict(stores[name])
            # Serials move forward even when content moves back — a mirror
            # that already saw serial N would reject N-1 as stale.
            cur = load_store(name)
            data['serial'] = max(int(cur.get('serial', 0)),
                                 int(data.get('serial', 0)))
            save_store(name, data)

    res = apply_change(mutate, sections=['hosts', 'dns', 'dhcp', 'netboot'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, 'rolled_back_to': cid, **res})
