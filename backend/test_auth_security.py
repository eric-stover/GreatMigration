import importlib
import sys
from pathlib import Path

from fastapi import FastAPI


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def _middleware_options(app: FastAPI):
    for item in app.user_middleware:
        if item.cls.__name__ == "SessionMiddleware":
            return item.kwargs
    raise AssertionError("SessionMiddleware not installed")


def test_local_auth_uses_http_compatible_session_cookies_by_default(monkeypatch):
    monkeypatch.delenv("SESSION_HTTPS_ONLY", raising=False)
    monkeypatch.setenv("LOCAL_USERS", "alice:strong-password")

    auth_local = importlib.reload(importlib.import_module("auth_local"))
    app = FastAPI()
    auth_local.install_auth(app)

    options = _middleware_options(app)
    assert options["https_only"] is False


def test_ldap_auth_allows_http_override_for_local_dev(monkeypatch):
    monkeypatch.setenv("SESSION_HTTPS_ONLY", "false")

    auth_ldap = importlib.reload(importlib.import_module("auth_ldap"))
    app = FastAPI()
    auth_ldap.install_auth(app)

    options = _middleware_options(app)
    assert options["https_only"] is False


def test_local_auth_requires_explicit_users(monkeypatch):
    monkeypatch.delenv("LOCAL_USERS", raising=False)

    auth_local = importlib.reload(importlib.import_module("auth_local"))

    assert auth_local.USERS == {}
