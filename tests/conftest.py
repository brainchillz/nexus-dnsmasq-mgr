import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix='dnsmaq-test-')
os.environ['DNSMAQ_DATA_DIR'] = _tmp
os.environ['DNSMAQ_TLS'] = '0'
os.environ['DNSMAQ_NO_SUDO'] = '1'

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def client(monkeypatch):
    """Flask test client with auth bypassed as admin and service control stubbed."""
    from dnsmaqmgr import create_app
    from dnsmaqmgr import dnsmasq as dm

    class FakeController:
        mode = 'test'
        def status(self): return {'running': True, 'state': 'active'}
        def restart(self): return True, ''
        def reload(self): return True, ''
        def stop(self): pass
        def logs(self, lines=200): return ''

    monkeypatch.setattr(dm, '_controller', FakeController())
    monkeypatch.setattr(dm.time, 'sleep', lambda s: None)

    # Never probe the real network from tests (the conflict test re-patches).
    from dnsmaqmgr import probe as probe_mod
    monkeypatch.setattr(probe_mod, 'probe_for_foreign_dhcp',
                        lambda ifaces: {'servers': [], 'error': None})

    app = create_app()
    app.config['TESTING'] = True
    app.secret_key = 'test-secret'
    dm.write_render(dm.render_all())  # baseline render, as app.py does at startup
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess['user'] = 'admin'
        from dnsmaqmgr.core import auth
        monkeypatch.setattr(auth, '_users', lambda: {'admin': {'password': 'x', 'role': 'admin'}})
        yield c


@pytest.fixture(autouse=True)
def clean_state():
    """Fresh stores for every test."""
    import glob
    from dnsmaqmgr.core.config import STATE_DIR, RENDER_DIR
    yield
    for p in glob.glob(os.path.join(STATE_DIR, '*.json')):
        os.remove(p)
    for root, _dirs, files in os.walk(RENDER_DIR):
        for f in files:
            os.remove(os.path.join(root, f))
