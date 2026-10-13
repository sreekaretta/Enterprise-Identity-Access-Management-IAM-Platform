import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "iam-lab-secret-key-change-in-production")
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "iam.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # ── Google OAuth 2.0 ──────────────────────────────────────────────────────
    # To enable: set these environment variables (see OAUTH_SETUP.md)
    # or replace the empty strings with your credentials for local dev only.
    GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID",     "")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    # Must exactly match the URI registered in Google Cloud Console
    GOOGLE_REDIRECT_URI  = "https://127.0.0.1:5000/oauth/google/callback"
