"""Tests for anchor_auth — the shared login-gate helpers.

Pure helpers (safe_next, verify_credentials, lockout) are tested directly; the
request-bound bits (client_ip, login_required) use a tiny Flask app.
Run: pytest -q
"""

import pytest
from flask import Flask
from urllib.parse import urlparse

import anchor_auth as a


@pytest.fixture(autouse=True)
def _reset():
    a.reset_lockout_state()
    yield
    a.reset_lockout_state()


# ── safe_next (the #27 regression set) ───────────────────────────────────────

@pytest.mark.parametrize("evil", [
    "/\\evil.com",       # backslash → browser rewrites to //evil.com
    "\\/evil.com",
    "\\\\evil.com",
    "//evil.com",
    "https://evil.com",
    "http:evil.com",
    "javascript:alert(1)",
    "",
    None,
])
def test_safe_next_rejects_offsite(evil):
    assert a.safe_next(evil) == "/"


@pytest.mark.parametrize("ok", ["/", "/dashboard", "/api/rentals?status=active", "/reports#s"])
def test_safe_next_allows_same_site(ok):
    assert a.safe_next(ok) == ok


# ── verify_credentials ───────────────────────────────────────────────────────

def test_verify_credentials_ok():
    assert a.verify_credentials("admin", "s3cret", "admin", "s3cret") is True


@pytest.mark.parametrize("u,p", [("admin", "wrong"), ("nope", "s3cret"), ("nope", "wrong")])
def test_verify_credentials_bad(u, p):
    assert a.verify_credentials(u, p, "admin", "s3cret") is False


def test_verify_credentials_disabled_when_no_password():
    # No configured password → login disabled, even if the input is also empty.
    assert a.verify_credentials("admin", "", "admin", "") is False


# ── lockout ──────────────────────────────────────────────────────────────────

def test_lockout_after_threshold():
    ip = "203.0.113.7"
    for _ in range(a.LOCKOUT_THRESHOLD - 1):
        a.record_failure(ip)
    assert a.is_locked_out(ip) is False
    a.record_failure(ip)
    assert a.is_locked_out(ip) is True


def test_lockout_is_per_ip():
    a.record_failure("1.1.1.1")
    assert a.is_locked_out("2.2.2.2") is False


# ── request-bound: client_ip + login_required ────────────────────────────────

@pytest.fixture
def app():
    app = Flask(__name__)
    app.secret_key = "test"

    @app.route("/login")
    def login():
        return "login page"

    @app.route("/secret")
    @a.login_required
    def secret():
        return "secret"

    return app


def test_client_ip_prefers_forwarded_for(app):
    with app.test_request_context("/", headers={"X-Forwarded-For": "9.9.9.9, 10.0.0.1"}):
        assert a.client_ip() == "9.9.9.9"


def test_login_required_redirects_when_logged_out(app):
    c = app.test_client()
    r = c.get("/secret")
    assert r.status_code == 302
    assert urlparse(r.headers["Location"]).path == "/login"


def test_login_required_allows_when_logged_in(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["logged_in"] = True
    r = c.get("/secret")
    assert r.status_code == 200
    assert r.get_data(as_text=True) == "secret"


def test_apply_session_cookie_config():
    app = Flask(__name__)
    a.apply_session_cookie_config(app, secure=True)
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_SECURE"] is True
