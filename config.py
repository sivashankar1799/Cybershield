"""
CyberShield AI - Application Configuration
------------------------------------------
Centralizes all configuration values. Uses environment variables when present,
falling back to safe development defaults. Keep SECRET_KEY secret in production.
"""

import os
from datetime import timedelta

# Absolute path of the directory this file lives in (project root)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration shared by all environments."""

    # --- Security ---
    # Used to sign session cookies and CSRF tokens. Override in production!
    SECRET_KEY = os.environ.get("SECRET_KEY", "cybershield-dev-secret-change-me-9f3a2b")

    # --- Database ---
    # Set DATABASE_URL in production, e.g. mysql+pymysql://user:password@host/cybershield
    DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "mysql+pymysql://root:@localhost/cybershield"
)

    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# Aiven MySQL requires an encrypted TLS connection
    if "aivencloud.com" in DATABASE_URL:
        SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "ssl": {}
        }
    }

    # --- SMTP / password reset email ---
    # Gmail: smtp.gmail.com:587 + a Google App Password (not the account password).
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "")
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"

    # --- Session / Login ---
    # Auto-logout after 30 minutes of inactivity (requirement #14).
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_REFRESH_EACH_REQUEST = True

    # --- CSRF (Flask-WTF) ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # token valid for the life of the session

    # --- Uploads ---
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "instance", "uploads")