"""Command execution — NEVER through a shell.

Adapted from Nexus Dashboard core/runcmd.py. All system commands go
through run()/run_safe(), which take an ARGUMENT LIST and run with shell=False;
that is what prevents command injection. ``sudo -n`` fails fast when a sudoers
rule is missing instead of hanging on a password prompt. In Docker
(DNSMAQ_NO_SUDO=1) the app runs as root and sudo is never prefixed.
"""
import subprocess
from flask import jsonify, request

from .config import NO_SUDO


def run(args, input_data=None, no_sudo=False, timeout=120):
    """Run a command given as an argument list (NO shell).

    Passing a list and shell=False means user-supplied values can never be
    interpreted by a shell, which closes off command injection. ``sudo -n``
    is used so a missing/incorrect sudoers rule fails immediately instead of
    blocking on a password prompt.
    """
    if isinstance(args, str):
        # Only fixed, trusted command strings should be passed as strings.
        args = args.split()
    if not (no_sudo or NO_SUDO):
        args = ['sudo', '-n'] + list(args)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=input_data)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Command timed out', -1
    except FileNotFoundError:
        return '', 'Command not found', -1


def run_safe(args, input_data=None):
    out, err_, rc = run(args, input_data=input_data)
    return {'success': rc == 0, 'stdout': out, 'stderr': err_, 'returncode': rc}


def err(message, code=400):
    return jsonify({'success': False, 'error': message}), code


def json_object():
    """Return (body_dict, None) or (None, error_response).

    `request.get_json(silent=True) or {}` 500s on a valid-JSON non-dict body
    (`[1]`, `"x"`, `5`) the moment a route calls `.get()` on it. This parses
    once and rejects a non-object cleanly; an empty/absent body is an empty
    object, matching the old `or {}` intent."""
    data = request.get_json(silent=True)
    if data is None:
        return {}, None
    if not isinstance(data, dict):
        return None, err('Expected a JSON object')
    return data, None


def _num(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None
