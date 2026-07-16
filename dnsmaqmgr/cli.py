"""CLI subcommands (invoked as `python app.py <command>`)."""
import os

from werkzeug.security import generate_password_hash

from .core.auth import (RE_USERNAME, MIN_PASSWORD_LEN, ensure_bootstrap,
                        save_config)


def cli_set_password(argv):
    import getpass
    user = argv[2] if len(argv) > 2 else 'admin'
    if not RE_USERNAME.match(user):
        print('Invalid username')
        return 1
    pw = os.environ.get('DNSMAQ_ADMIN_PASSWORD')
    if not pw:
        pw = getpass.getpass(f'New password for {user}: ')
        if pw != getpass.getpass('Confirm password: '):
            print('Passwords do not match')
            return 1
    if len(pw) < MIN_PASSWORD_LEN:
        print(f'Password must be at least {MIN_PASSWORD_LEN} characters')
        return 1
    cfg = ensure_bootstrap()
    users = cfg.setdefault('users', {})
    rec = users[user] if isinstance(users.get(user), dict) else {'role': 'admin'}
    rec['password'] = generate_password_hash(pw)
    rec.pop('must_change', None)  # operator set it explicitly — no forced change
    users[user] = rec
    save_config(cfg)
    print(f'Password updated for {user}')
    return 0


def cli_history_tick(argv=None):
    from .core.history import cli_history_tick as tick
    return tick()


def cli_render(argv=None):
    """Render + validate the config from the stores without touching the
    service (debugging / pre-flight in scripts)."""
    from . import dnsmasq
    rendered = dnsmasq.render_all()
    ok, output = dnsmasq.validate_render(rendered)
    print(output or 'syntax check OK')
    if ok:
        dnsmasq.write_render(rendered)
        print('rendered %d files' % len(rendered))
        return 0
    return 1


def cli_dhcp_probe(argv=None):
    from .probe import cli_dhcp_probe as probe
    return probe(argv)


COMMANDS = {
    'set-password': cli_set_password,
    'history-tick': cli_history_tick,
    'render': cli_render,
    'dhcp-probe': cli_dhcp_probe,
}


def dispatch(argv):
    """Return an exit code if argv names a CLI subcommand, else None."""
    import inspect
    if len(argv) > 1 and argv[1] in COMMANDS:
        fn = COMMANDS[argv[1]]
        if len(inspect.signature(fn).parameters) >= 1:
            rc = fn(argv)
        else:
            rc = fn()
        # A matched command must ALWAYS yield an exit code: app.py starts the
        # web server when dispatch returns None.
        return 0 if rc is None else rc
    return None
