# anchor-auth

Shared Flask login-gate helpers for Anchor web apps. One audited copy of the
security-critical auth logic so a fix lands once — instead of being hand-patched
in every app (which is how pilot-house-core#27's open-redirect bug ended up in
two repos).

## What's in it
- `safe_next(url)` — same-site relative-path guard (blocks open redirects, incl. the backslash-normalization bypass)
- `login_required` — redirect-to-login decorator, preserving `next`
- `client_ip()`, `is_locked_out(ip)`, `record_failure(ip)`, `LOCKOUT_THRESHOLD`/`LOCKOUT_WINDOW` — the 5-failures/15-min IP lockout
- `verify_credentials(user, pw, expected_user, expected_pw)` — constant-time, non-short-circuiting credential check
- `apply_session_cookie_config(app)` — HttpOnly + SameSite=Lax + Secure-under-Railway

The apps keep their **own login page (branding) and route wiring**; they import
the logic from here.

## Install (consumers)
Pin to a release tag over git+SSH, same as `onboarding-contract`:

```
anchor-auth @ git+ssh://git@github.com/Anchor-Maine/anchor-auth.git@v0.1.0
```

## Usage
```python
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
        if is_locked_out(ip):
            error = "Too many failed attempts. Try again in 15 minutes."
        elif verify_credentials(username, password, APP_USERNAME, APP_PASSWORD):
            session["logged_in"] = True
            return redirect(next_url)
        else:
            record_failure(ip)
            error = "Invalid username or password."
    return render_template_string(LOGIN_HTML, error=error, next=next_url)
```

## Develop
```
pip install -e ".[dev]"
pytest -q
```

## Releasing
Bump `version` in `pyproject.toml` and `__version__`, tag `vX.Y.Z`, push the tag.
Consumers pin to the tag; a change here is a deliberate, reviewed bump — never a
silent drift between apps.
