"""
Tests for the optional CORS middleware (SLACSSH_CORS_ORIGINS).

Business logic under test:
  - unset: no CORS headers, so an ingress that adds its own is not duplicated
  - set: preflights from a listed origin are answered with credentials allowed
  - set: preflights from any other origin are not granted
"""
import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

COACT = 'https://coact-dev.slac.stanford.edu'


def load_app(monkeypatch, origins):
    if origins is None:
        monkeypatch.delenv('SLACSSH_CORS_ORIGINS', raising=False)
    else:
        monkeypatch.setenv('SLACSSH_CORS_ORIGINS', origins)
    import app
    return importlib.reload(app).app


def preflight(client, origin, method='PATCH'):
    return client.options(
        '/refresh/alice/SHA256:' + 'a' * 43,
        headers={'Origin': origin, 'Access-Control-Request-Method': method},
    )


def test_cors_disabled_when_unset(monkeypatch):
    client = TestClient(load_app(monkeypatch, None))
    resp = preflight(client, COACT)
    assert 'access-control-allow-origin' not in resp.headers


@pytest.mark.parametrize('method', ['GET', 'POST', 'PATCH', 'DELETE'])
def test_preflight_from_listed_origin(monkeypatch, method):
    client = TestClient(load_app(monkeypatch, f' {COACT} , https://coact.slac.stanford.edu'))
    resp = preflight(client, COACT, method)
    assert resp.status_code == 200
    assert resp.headers['access-control-allow-origin'] == COACT
    assert resp.headers['access-control-allow-credentials'] == 'true'
    assert method in resp.headers['access-control-allow-methods']


def test_preflight_from_unlisted_origin(monkeypatch):
    client = TestClient(load_app(monkeypatch, COACT))
    resp = preflight(client, 'https://evil.example.com')
    assert resp.status_code == 400
    assert 'access-control-allow-origin' not in resp.headers
