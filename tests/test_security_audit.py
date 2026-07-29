"""Regression tests for the 2026-07-29 security audit (shared-core fixes)."""


def test_deleted_user_session_is_rejected_not_promoted(client, monkeypatch):
    """A session for a user no longer in the store must be rejected, not
    resolved to admin. Regression for _user_role(None) -> 'admin'."""
    from dnsmaqmgr.core import auth
    monkeypatch.setattr(auth, '_users', lambda: {})       # account deleted
    assert auth._user_role(None) == 'readonly'            # fails safe, never admin
    # A mutating call from the orphaned session is refused as unauthenticated.
    assert client.post('/api/settings', json={'domain': 'lan'}).status_code == 401


def test_scope_id_ip_is_rejected_end_to_end(client):
    """An IPv6 scope-id can smuggle newlines past ipaddress into a rendered
    dnsmasq line. The validators must reject it and the API must 400."""
    from dnsmaqmgr.core.validators import is_ipv6, is_ip, is_upstream
    payload = 'fe80::1%lo\ndhcp-option=option:dns-server,192.0.2.66'
    assert is_ipv6(payload) is False
    assert is_ip(payload) is False
    assert is_upstream(payload) is False
    assert is_ipv6('fe80::1%eth0') is False               # even a benign scope-id
    assert is_ipv6('2001:db8::5') is True                 # a real address still works

    # The upstreams path (settings -> server= line) must reject it, not render it.
    r = client.post('/api/settings', json={'upstreams': ['1.1.1.1', payload]})
    assert r.status_code == 400
    # And the AAAA-in-address path likewise.
    r = client.post('/api/dns/addresses', json={'domain': 'evil.example', 'ip': payload})
    assert r.status_code == 400


def test_login_hashes_once_per_path(client, monkeypatch):
    """Unknown user and known-user-wrong-password must each cost exactly one
    password hash, so response time cannot enumerate usernames."""
    from dnsmaqmgr.core import auth
    calls = {'n': 0}
    real = auth.check_password_hash
    monkeypatch.setattr(auth, 'check_password_hash',
                        lambda h, p: (calls.__setitem__('n', calls['n'] + 1), real(h, p))[1])
    monkeypatch.setattr(auth, 'load_config',
                        lambda: {'users': {'admin': {'password': auth.generate_password_hash('right'),
                                                      'role': 'admin'}}})
    calls['n'] = 0
    client.post('/api/login', json={'username': 'ghost', 'password': 'x'})
    assert calls['n'] == 1                                 # unknown: one dummy hash
    calls['n'] = 0
    client.post('/api/login', json={'username': 'admin', 'password': 'wrong'})
    assert calls['n'] == 1                                 # known-wrong: one real hash
