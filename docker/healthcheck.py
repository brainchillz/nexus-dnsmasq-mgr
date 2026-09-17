#!/usr/bin/env python3
"""Docker HEALTHCHECK: GET /api/health on the app's own port; exit 0 on 200."""
import os
import ssl
import sys
import urllib.request

tls = os.environ.get('DNSMAQ_TLS', '1').lower() in ('1', 'true', 'yes', 'on')
port = os.environ.get('DNSMAQ_PORT') or ('8443' if tls else '8080')
url = '%s://127.0.0.1:%s/api/health' % ('https' if tls else 'http', port)
ctx = ssl._create_unverified_context() if tls else None
try:
    with urllib.request.urlopen(url, timeout=4, context=ctx) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
