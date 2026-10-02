"""Bounded functional probes for trusted backend contracts, never package scripts.

Probe definitions must come from reviewed adapter code. Intake metadata cannot
supply commands, endpoints or expected results. XPC requires a protocol-specific
adapter; a PID or open socket never serves as an XPC functional probe.
"""
import json
import socket
import urllib.request


def http_json(url, expected, timeout=5):
    # Device-local health endpoints only. No arbitrary third-party probing.
    from urllib.parse import urlsplit
    target = urlsplit(url)
    if target.scheme != 'http' or target.hostname not in ('127.0.0.1', '::1') or target.username or target.password:
        raise ValueError('functional HTTP probes must target a local reviewed service')
    try:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError('health probe redirects are not allowed')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(url, timeout=min(timeout, 10)) as response:
            if response.status != 200:
                return {'passed': False, 'detail': 'local health endpoint rejected request'}
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('health response exceeds limit')
        value = json.loads(raw)
        passed = isinstance(value, dict) and all(value.get(key) == item for key, item in expected.items())
        return {'passed': passed, 'detail': 'local service protocol response matched' if passed else 'health response did not match contract'}
    except (OSError, ValueError) as error:
        return {'passed': False, 'detail': type(error).__name__}


def unix_protocol(path, request, expected_response, timeout=5):
    if not str(path).startswith('/var/jb/var/run/') or '..' in str(path).split('/'):
        raise ValueError('Unix protocol probes must target reviewed bootstrap sockets')
    if len(request) > 4096 or len(expected_response) > 65536:
        raise ValueError('protocol probe limit exceeded')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(min(timeout, 10))
            connection.connect(str(path))
            connection.sendall(request)
            response = bytearray()
            while len(response) < len(expected_response):
                chunk = connection.recv(len(expected_response) - len(response))
                if not chunk:
                    break
                response.extend(chunk)
        return {'passed': bytes(response) == expected_response,
                'detail': 'Unix service protocol exchange completed'}
    except OSError as error:
        return {'passed': False, 'detail': type(error).__name__}


def xpc_unavailable():
    return {'passed': None, 'detail': 'protocol-specific supported XPC adapter required'}
