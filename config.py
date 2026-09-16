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
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "cybershield-dev-secret-change-me-9f3a2b"
    )

    # --- Database ---
    # Use Railway MySQL in production, local MySQL as fallback.
    database_url = os.environ.get("MYSQL_URL")

    if database_url and database_url.startswith("mysql://"):
        database_url = database_url.replace(
            "mysql://",
            "mysql+pymysql://",
            1
        )

    SQLALCHEMY_DATABASE_URI = (
        database_url
        or "mysql+pymysql://root:@localhost/cybershield"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Session / Login ---
    # Auto-logout after 30 minutes of inactivity
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_REFRESH_EACH_REQUEST = True

    # --- CSRF (Flask-WTF) ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    # --- Uploads ---
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "instance", "uploads")