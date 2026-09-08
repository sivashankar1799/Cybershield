"""
CyberShield AI - Database Models (SQLAlchemy ORM)
-------------------------------------------------
Defines every table used across the application. A single SQLAlchemy() instance
('db') is created here and bound to the Flask app in app.py via db.init_app().
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Single shared ORM handle. Bound to the app in app.py.
db = SQLAlchemy()


class User(UserMixin, db.Model):
    """Application user. Passwords are stored as bcrypt hashes (never plaintext)."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    avatar_color = db.Column(db.String(7), default="#00d4ff")  # hex color for avatar
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Token-based password reset support (requirement #14).
    reset_token = db.Column(db.String(128), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    # Relationships
    logs = db.relationship("ActivityLog", backref="user", lazy=True, cascade="all, delete-orphan")
    chats = db.relationship("ChatMessage", backref="user", lazy=True, cascade="all, delete-orphan")
    progress = db.relationship("TrainingProgress", backref="user", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username}>"


class ActivityLog(db.Model):
    """Audit log of every meaningful action (requirement #13)."""

    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action_type = db.Column(db.String(64), nullable=False, index=True)  # e.g. LOGIN, SCAN, ENCRYPT
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ThreatIntel(db.Model):
    """Threat intelligence entries (requirement #10)."""

    __tablename__ = "threat_intel"

    id = db.Column(db.Integer, primary_key=True)
    threat_name = db.Column(db.String(128), nullable=False)
    threat_type = db.Column(db.String(64), nullable=False)  # APT, Ransomware, Zero-Day, ...
    severity = db.Column(db.String(16), nullable=False)  # Critical/High/Medium/Low
    date = db.Column(db.DateTime, default=datetime.utcnow)
    affected_systems = db.Column(db.String(256))
    description = db.Column(db.Text)
    recommendations = db.Column(db.Text)


class ChatMessage(db.Model):
    """AI assistant conversation history per user (requirement #9)."""

    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    role = db.Column(db.String(16), nullable=False)  # 'user' or 'assistant'
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class TrainingProgress(db.Model):
    """Per-user training module progress and quiz scores (requirement #11)."""

    __tablename__ = "training_progress"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    module = db.Column(db.String(64), nullable=False)  # phishing, password, social, browsing
    score = db.Column(db.Integer, default=0)  # 0-100
    completed = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SecurityMetric(db.Model):
    """Time-series security metrics used for dashboard charts (requirement #1)."""

    __tablename__ = "security_metrics"

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    threats_detected = db.Column(db.Integer, default=0)
    threats_blocked = db.Column(db.Integer, default=0)
    vulnerabilities = db.Column(db.Integer, default=0)
    security_score = db.Column(db.Integer, default=0)