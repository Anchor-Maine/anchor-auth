"""anchor_auth — shared Flask login-gate helpers for Anchor apps.

Extracted from pilot-house-core / anchor-audit, which carried identical copies
that drifted into a duplicated open-redirect bug (pilot-house-core#27). One
audited source so a fix lands once.

Apps keep their own login page (branding) and route wiring; they import the
security-critical logic from here:

    from anchor_auth import (
        apply_session_cookie_config, login_required, safe_next,
        client_ip, is_locked_out, record_failure, verify_credentials,
    )

    apply_session_cookie_config(app)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        next_url = safe_next(request.args.get("next") or request.form.get("next") or "/")
        if request.method == "POST":
            ip = client_ip()
            if not APP_PASSWORD:
                error = "APP_PASSWORD is not set."
            elif is_locked_out(ip):
                error = "Too many failed attempts. Try again in 15 minutes."
            elif verify_credentials(username, password, APP_USERNAME, APP_PASSWORD):
                session["logged_in"] = True
                session.permanent = True
                return redirect(next_url)
            else:
                record_failure(ip)
                error = "Invalid username or password."
        return render_template_string(LOGIN_HTML, error=error, next=next_url)
"""

import hmac
import os
import time
import urllib.parse
from functools import wraps

from flask import redirect, request, session, url_for

__version__ = "0.1.0"

__all__ = [
    "LOCKOUT_THRESHOLD",
    "LOCKOUT_WINDOW",
    "apply_session_cookie_config",
    "client_ip",
    "is_locked_out",
    "record_failure",
    "safe_next",
    "verify_credentials",
    "login_required",
    "reset_lockout_state",
]

# ── Login rate limiting (in-memory, per source IP) ────────────────────────────
LOCKOUT_THRESHOLD = 5        # failures...
LOCKOUT_WINDOW = 900         # ...within 15 minutes → locked out for the window

_failed_logins = {}          # ip -> [timestamps of recent failures]


def client_ip():
    """Best-effort source IP, trusting the proxy's X-Forwarded-For first hop."""
    return request.headers.get(
        "X-Forwarded-For", request.remote_addr or "?"
    ).split(",")[0].strip()


def is_locked_out(ip):
    now = time.time()
    attempts = [t for t in _failed_logins.get(ip, []) if now - t < LOCKOUT_WINDOW]
    _failed_logins[ip] = attempts
    return len(attempts) >= LOCKOUT_THRESHOLD


def record_failure(ip):
    _failed_logins.setdefault(ip, []).append(time.time())


def reset_lockout_state():
    """Clear all recorded failures — for tests / process reset."""
    _failed_logins.clear()


def safe_next(url):
    """Return `url` only if it is a same-site relative path, else '/'.

    Blocks open redirects. Browsers normalize backslashes to forward slashes, so
    "/\\evil.com" becomes "//evil.com" (off-site) after the browser rewrites it;
    reject any backslash outright (pilot-house-core#27).
    """
    if not url or "\\" in url:
        return "/"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme or parsed.netloc:
        return "/"
    if not url.startswith("/") or url.startswith("//"):
        return "/"
    return url


def verify_credentials(username, password, expected_user, expected_password):
    """Constant-time credential check.

    Uses a non-short-circuiting `&` so username validity leaks no timing signal.
    Returns False when no password is configured (login disabled).
    """
    if not expected_password:
        return False
    return bool(
        hmac.compare_digest(username.encode(), expected_user.encode())
        & hmac.compare_digest(password.encode(), expected_password.encode())
    )


def login_required(f):
    """Redirect to the app's `login` route (preserving `next`) if not logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def apply_session_cookie_config(app, secure=None):
    """Apply the standard hardened session-cookie config.

    `secure` defaults to on whenever RAILWAY_ENVIRONMENT is set (HTTPS in prod),
    off for plain-HTTP local dev. Pass an explicit bool to override.
    """
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(
            bool(os.environ.get("RAILWAY_ENVIRONMENT")) if secure is None else secure
        ),
    )
