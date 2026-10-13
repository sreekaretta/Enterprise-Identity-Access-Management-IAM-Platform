import secrets
from datetime import datetime
from functools import wraps
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, session, current_app)
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, write_audit_log

auth_bp = Blueprint("auth", __name__)

# ── Google OAuth endpoints (OpenID Connect) ────────────────────────────────────
_GOOGLE_AUTH_URL     = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL    = "https://oauth2.googleapis.com/token"
_GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


# ── Helpers ────────────────────────────────────────────────────────────────────

def role_required(*roles):
    """Decorator that restricts a route to users with one of the given system roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login"))
            if current_user.system_role not in roles:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("auth.dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ── Login ──────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))

    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if user.status == "Inactive":
                flash("Your account has been disabled. Contact an administrator.", "danger")
                write_audit_log(
                    actor_id=user.id, action="LOGIN_BLOCKED",
                    target_type="User", target_id=user.id,
                    details=f"Login attempt on inactive account: {user.email}",
                    ip_address=request.remote_addr,
                )
                return render_template("login.html", oauth_enabled=_oauth_configured())

            # ── TOTP intercept ────────────────────────────────────────────────
            if user.totp_enabled:
                session["pending_totp_user_id"] = user.id
                return redirect(url_for("auth.totp_verify"))

            # Normal login (no MFA)
            _complete_login(user, method="password")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("auth.dashboard"))

        else:
            flash("Invalid email or password.", "danger")
            write_audit_log(
                actor_id=None, action="LOGIN_FAILED",
                target_type="User", target_id=None,
                details=f"Failed login attempt for: {email}",
                ip_address=request.remote_addr,
            )

    return render_template("login.html", oauth_enabled=_oauth_configured())


def _complete_login(user, method="password"):
    """Finalise login — call login_user, update last_login, write audit log."""
    login_user(user, remember=False)
    user.last_login = datetime.utcnow()
    db.session.commit()
    mfa_note = " with MFA (TOTP)" if method == "totp" else (" via Google OAuth" if method == "oauth" else "")
    write_audit_log(
        actor_id=user.id, action="LOGIN_SUCCESS",
        target_type="User", target_id=user.id,
        details=f"{user.name} logged in{mfa_note}",
        ip_address=request.remote_addr,
    )


def _oauth_configured():
    """Return True if Google OAuth credentials are set in config."""
    return bool(current_app.config.get("GOOGLE_CLIENT_ID"))


# ── Logout ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
@login_required
def logout():
    write_audit_log(
        actor_id=current_user.id, action="LOGOUT",
        target_type="User", target_id=current_user.id,
        details=f"{current_user.name} logged out",
        ip_address=request.remote_addr,
    )
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ── Dashboard redirect ─────────────────────────────────────────────────────────

@auth_bp.route("/dashboard")
@login_required
def dashboard():
    if current_user.system_role == "Admin":
        return redirect(url_for("admin.dashboard"))
    elif current_user.system_role == "Manager":
        return redirect(url_for("manager.dashboard"))
    else:
        return redirect(url_for("employee.dashboard"))


# ══════════════════════════════════════════════════════════════════════════════
# TOTP / Two-Factor Authentication
# ══════════════════════════════════════════════════════════════════════════════

@auth_bp.route("/totp/verify", methods=["GET", "POST"])
def totp_verify():
    """Step-2 of login: verify the TOTP code after password is accepted."""
    user_id = session.get("pending_totp_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user or not user.totp_enabled:
        session.pop("pending_totp_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        import pyotp
        code = request.form.get("code", "").strip().replace(" ", "")
        totp = pyotp.TOTP(user.totp_secret)

        if totp.verify(code, valid_window=1):   # valid_window=1 allows ±30 s clock drift
            session.pop("pending_totp_user_id", None)
            _complete_login(user, method="totp")
            return redirect(url_for("auth.dashboard"))
        else:
            write_audit_log(
                actor_id=user.id, action="MFA_FAILED",
                target_type="User", target_id=user.id,
                details=f"Invalid TOTP code entered for {user.email}",
                ip_address=request.remote_addr,
            )
            flash("Invalid code. Please try again.", "danger")

    return render_template("auth/totp_verify.html", email=user.email)


@auth_bp.route("/totp/setup", methods=["GET", "POST"])
@login_required
def totp_setup():
    """Enrol the current user in TOTP-based MFA."""
    import pyotp

    if request.method == "POST":
        action = request.form.get("action", "enable")

        if action == "disable":
            return redirect(url_for("auth.totp_disable"))

        # Verify the code against the pending secret before saving
        secret = session.get("pending_totp_secret")
        if not secret:
            flash("Session expired. Please try again.", "danger")
            return redirect(url_for("auth.totp_setup"))

        code = request.form.get("code", "").strip().replace(" ", "")
        totp = pyotp.TOTP(secret)

        if totp.verify(code, valid_window=1):
            current_user.totp_secret  = secret
            current_user.totp_enabled = True
            db.session.commit()
            session.pop("pending_totp_secret", None)
            write_audit_log(
                actor_id=current_user.id, action="MFA_ENABLED",
                target_type="User", target_id=current_user.id,
                details=f"{current_user.name} enabled TOTP two-factor authentication",
                ip_address=request.remote_addr,
            )
            flash("Two-factor authentication enabled. Your account is now protected by MFA.", "success")
            return redirect(url_for("auth.dashboard"))
        else:
            flash("Incorrect code — make sure your authenticator app is synced and try again.", "danger")
            return redirect(url_for("auth.totp_setup"))

    # GET — generate a fresh secret for this setup session
    if "pending_totp_secret" not in session:
        session["pending_totp_secret"] = pyotp.random_base32()

    secret = session["pending_totp_secret"]
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name="IAM Lab",
    )
    return render_template(
        "auth/totp_setup.html",
        secret=secret,
        provisioning_uri=provisioning_uri,
        already_enabled=current_user.totp_enabled,
    )


@auth_bp.route("/totp/disable", methods=["POST"])
@login_required
def totp_disable():
    """Disable TOTP for the currently logged-in user."""
    current_user.totp_secret  = None
    current_user.totp_enabled = False
    db.session.commit()
    write_audit_log(
        actor_id=current_user.id, action="MFA_DISABLED",
        target_type="User", target_id=current_user.id,
        details=f"{current_user.name} disabled TOTP two-factor authentication",
        ip_address=request.remote_addr,
    )
    flash("Two-factor authentication has been disabled.", "warning")
    return redirect(url_for("auth.dashboard"))


@auth_bp.route("/totp/admin-disable/<int:user_id>", methods=["POST"])
@login_required
@role_required("Admin")
def totp_admin_disable(user_id):
    """Admin: force-disable TOTP for any user (e.g. lost authenticator)."""
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.user_list"))
    user.totp_secret  = None
    user.totp_enabled = False
    db.session.commit()
    write_audit_log(
        actor_id=current_user.id, action="MFA_ADMIN_DISABLED",
        target_type="User", target_id=user.id,
        details=f"{current_user.name} force-disabled TOTP for {user.name}",
        ip_address=request.remote_addr,
    )
    flash(f"MFA disabled for {user.name}.", "warning")
    return redirect(url_for("admin.user_detail", user_id=user_id))


# ══════════════════════════════════════════════════════════════════════════════
# OAuth 2.0 — Google Authorization Code Flow
# ══════════════════════════════════════════════════════════════════════════════

@auth_bp.route("/oauth/google")
def oauth_google():
    """Step 1 — redirect the user to Google's authorization endpoint."""
    client_id = current_app.config.get("GOOGLE_CLIENT_ID", "")
    if not client_id:
        flash("Google login is not configured. Contact your administrator.", "warning")
        return redirect(url_for("auth.login"))

    # Generate a random state token for CSRF protection
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state

    import urllib.parse
    params = {
        "client_id":     client_id,
        "redirect_uri":  current_app.config["GOOGLE_REDIRECT_URI"],
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
        "access_type":   "online",
    }
    auth_url = _GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)
    return redirect(auth_url)


@auth_bp.route("/oauth/google/callback")
def oauth_callback():
    """Step 2 — Google redirects back with an authorization code."""
    import requests as reqs   # alias avoids shadowing Flask's `request`

    # ── CSRF state check ──────────────────────────────────────────────────────
    returned_state = request.args.get("state", "")
    expected_state = session.pop("oauth_state", None)
    if returned_state != expected_state:
        flash("OAuth security check failed. Please try again.", "danger")
        return redirect(url_for("auth.login"))

    # ── Handle user-cancelled / denied ────────────────────────────────────────
    error = request.args.get("error")
    if error:
        flash(f"Google login was cancelled or denied.", "warning")
        return redirect(url_for("auth.login"))

    code = request.args.get("code")
    if not code:
        flash("No authorization code received from Google.", "danger")
        return redirect(url_for("auth.login"))

    # ── Exchange authorization code for access token ───────────────────────────
    try:
        token_resp = reqs.post(
            _GOOGLE_TOKEN_URL,
            data={
                "code":          code,
                "client_id":     current_app.config["GOOGLE_CLIENT_ID"],
                "client_secret": current_app.config["GOOGLE_CLIENT_SECRET"],
                "redirect_uri":  current_app.config["GOOGLE_REDIRECT_URI"],
                "grant_type":    "authorization_code",
            },
            timeout=10,
        )
        token_data   = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError(f"No access_token in response: {token_data}")
    except Exception as exc:
        flash("Could not obtain access token from Google. Please try again.", "danger")
        return redirect(url_for("auth.login"))

    # ── Fetch user profile from Google's UserInfo endpoint ────────────────────
    try:
        info_resp    = reqs.get(
            _GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        userinfo     = info_resp.json()
        google_email = userinfo.get("email", "").lower()
        google_name  = userinfo.get("name", "")
        if not google_email:
            raise ValueError("No email in userinfo response")
    except Exception:
        flash("Could not retrieve your profile from Google. Please try again.", "danger")
        return redirect(url_for("auth.login"))

    # ── Match Google email to an existing IAM account ─────────────────────────
    user = User.query.filter_by(email=google_email).first()
    if not user:
        flash(
            f"No IAM account found for {google_email}. "
            "Contact your administrator to provision an account.",
            "danger",
        )
        write_audit_log(
            actor_id=None, action="OAUTH_NO_ACCOUNT",
            target_type="User", target_id=None,
            details=f"OAuth login — no matching account for: {google_email}",
            ip_address=request.remote_addr,
        )
        return redirect(url_for("auth.login"))

    if user.status == "Inactive":
        flash("Your account is disabled. Contact an administrator.", "danger")
        write_audit_log(
            actor_id=user.id, action="LOGIN_BLOCKED",
            target_type="User", target_id=user.id,
            details=f"OAuth login blocked — account inactive: {google_email}",
            ip_address=request.remote_addr,
        )
        return redirect(url_for("auth.login"))

    # ── If user also has TOTP enabled, require that too ───────────────────────
    if user.totp_enabled:
        session["pending_totp_user_id"] = user.id
        return redirect(url_for("auth.totp_verify"))

    _complete_login(user, method="oauth")
    return redirect(url_for("auth.dashboard"))
