"""
CyberShield AI - Main Flask Application
=======================================
A complete cybersecurity dashboard. Contains:
  * App factory & extension setup (SQLAlchemy, Login, Bcrypt, CSRF)
  * All routes (auth, dashboard pages, JSON APIs for every tool)
  * Real working implementations for encryption, hashing, scanning,
    vulnerability checks, malware/phishing analysis, AI assistant, reports.
  * 'flask seed-db' CLI command to populate realistic sample data.

Run:
    pip install -r requirements.txt
    flask --app app seed-db      # create + seed the database
    flask --app app run --debug  # start the server
"""

import os
import io
import csv
import json
import time
import socket
import base64
import hashlib
import secrets
import random
import ipaddress
import smtplib
from email.message import EmailMessage
from datetime import datetime, date, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote, unquote

import click
import requests
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    jsonify, session, send_file, abort, g, Response, stream_with_context
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Cryptography for AES / RSA
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

# QR code generation
import qrcode

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from config import Config
from models import (
    db, User, ActivityLog, ThreatIntel, ChatMessage,
    TrainingProgress, SecurityMetric
)

# ---------------------------------------------------------------------------
# Application factory & extension instances
# ---------------------------------------------------------------------------
bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app():
    """Create and configure the Flask application instance."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    # Ensure instance & upload folders exist.
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message_category = "warning"

    register_routes(app)
    register_cli(app)

    # Expose csrf_token() to all templates for AJAX headers.
    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=generate_csrf)

    # Create tables automatically if database file is missing.
    with app.app_context():
        db.create_all()

    return app


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader."""
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def log_action(action_type, details=""):
    """Persist an audit log entry. Used across every feature (requirement #13)."""
    try:
        entry = ActivityLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action_type=action_type,
            details=details[:2000],  # cap length defensively
            ip_address=request.remote_addr,
            timestamp=datetime.utcnow(),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()  # never let logging break the request


def sanitize(text, max_len=2000):
    """Basic server-side input sanitization: strip + length-cap + neutralize angle brackets."""
    if text is None:
        return ""
    text = str(text).strip()[:max_len]
    return text.replace("<", "&lt;").replace(">", "&gt;")


def send_password_reset_email(app, recipient, reset_url):
    """Send a real password-reset email through the configured SMTP server."""
    host = app.config.get("MAIL_SERVER")
    port = int(app.config.get("MAIL_PORT", 587))
    username = app.config.get("MAIL_USERNAME")
    password = app.config.get("MAIL_PASSWORD")
    sender = app.config.get("MAIL_DEFAULT_SENDER") or username
    use_tls = bool(app.config.get("MAIL_USE_TLS", True))

    if not host or not sender or not username or not password:
        raise RuntimeError(
            "SMTP is not configured. Set MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, "
            "MAIL_PASSWORD and MAIL_DEFAULT_SENDER in the environment."
        )

    msg = EmailMessage()
    msg["Subject"] = "CyberShield AI – Password Reset"
    msg["From"] = sender
    msg["To"] = recipient
    msg.set_content(
        "We received a request to reset your CyberShield AI password.\n\n"
        f"Open this link to choose a new password:\n{reset_url}\n\n"
        "This link expires in 30 minutes and can only be used once.\n"
        "If you did not request this, you can safely ignore this email.\n"
    )

    with smtplib.SMTP(host, port, timeout=20) as smtp:
        smtp.ehlo()
        if use_tls:
            smtp.starttls()
            smtp.ehlo()
        smtp.login(username, password)
        smtp.send_message(msg)


# Common TCP ports mapped to service names for the network scanner.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB", 139: "NetBIOS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 5900: "VNC", 9200: "Elasticsearch",
}

# Risk level per service (used to color-code scanner results).
PORT_RISK = {
    23: "Critical", 21: "High", 3389: "High", 445: "High", 139: "High",
    3306: "Medium", 5432: "Medium", 1433: "Medium", 6379: "High",
    27017: "High", 5900: "High", 22: "Low", 80: "Low", 443: "Low",
}

# Hardcoded breached passwords (requirement #2).
BREACHED_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "football", "monkey", "letmein", "111111", "iloveyou",
    "admin", "welcome", "dragon", "sunshine", "princess", "password1",
    "qwerty123", "1q2w3e4r",
}

# Hardcoded "known malicious" hashes (requirement #7) — 30 sample md5/sha256.
MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f", "e99a18c428cb38d5f260853678922e03",
    "5f4dcc3b5aa765d61d8327deb882cf99", "098f6bcd4621d373cade4e832627b4f6",
    "d41d8cd98f00b204e9800998ecf8427e", "25f9e794323b453885f5181f1b624d0b",
    "827ccb0eea8a706c4c34a16891f84e7b", "e10adc3949ba59abbe56e057f20f883e",
    "1f3870be274f6c49b3e31a0c6728957f", "5d41402abc4b2a76b9719d911017c592",
    "7c4a8d09ca3762af61e59520943dc26494f8941b",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "356a192b7913b04c54574d18c28d46e6395428ab",
    "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15",
    "9d4e1e23bd5b727046a9e3b4b7db57bd8d6ee684",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
    "badc0debadc0debadc0debadc0debadc0debadc0debadc0debadc0debadc0de00",
    "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210",
    "1337133713371337133713371337133713371337", "abad1deaabad1deaabad1dea",
    "feedfacefeedfacefeedfacefeedface", "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff", "c0ffeec0ffeec0ffeec0ffeec0ffeec0",
    "b1ade1b1ade1b1ade1b1ade1b1ade1b1",
}

# Phishing keyword list (requirement #8).
PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "bank", "account", "confirm",
    "signin", "password", "billing", "paypal", "wallet", "suspended",
    "unlock", "alert", "webscr", "ebayisapi",
]
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".click"]


# ===========================================================================
# ROUTES
# ===========================================================================
def register_routes(app):

    # -------------------- Session timeout enforcement --------------------
    @app.before_request
    def enforce_session_timeout():
        """Auto-logout after 30 minutes of inactivity (requirement #14)."""
        session.permanent = True
        now = datetime.utcnow().timestamp()
        last = session.get("last_active")
        if current_user.is_authenticated and last:
            if now - last > app.config["PERMANENT_SESSION_LIFETIME"].total_seconds():
                logout_user()
                session.clear()
                flash("Session expired due to inactivity. Please log in again.", "warning")
                return redirect(url_for("login"))
        session["last_active"] = now

    # ----------------------------- AUTH ---------------------------------
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("overview"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("overview"))
        if request.method == "POST":
            try:
                username = sanitize(request.form.get("username"), 64)
                password = request.form.get("password", "")
                user = User.query.filter(
                    (User.username == username) | (User.email == username)
                ).first()
                if user and bcrypt.check_password_hash(user.password_hash, password):
                    login_user(user)
                    session.permanent = True
                    log_action("LOGIN", f"User {user.username} logged in.")
                    flash(f"Welcome back, {user.username}!", "success")
                    return redirect(url_for("overview"))
                flash("Invalid credentials. Please try again.", "danger")
            except Exception as e:
                flash(f"Login error: {e}", "danger")
        return render_template("auth/login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("overview"))
        if request.method == "POST":
            try:
                username = sanitize(request.form.get("username"), 64)
                email = sanitize(request.form.get("email"), 120)
                password = request.form.get("password", "")
                if not username or not email or len(password) < 6:
                    flash("All fields required; password must be 6+ characters.", "danger")
                    return render_template("auth/register.html")
                if User.query.filter((User.username == username) | (User.email == email)).first():
                    flash("Username or email already exists.", "danger")
                    return render_template("auth/register.html")
                pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
                user = User(username=username, email=email, password_hash=pw_hash,
                            avatar_color=random.choice(["#00d4ff", "#00ff88", "#bf00ff"]))
                db.session.add(user)
                db.session.commit()
                log_action("REGISTER", f"New user {username} registered.")
                flash("Account created! Please log in.", "success")
                return redirect(url_for("login"))
            except Exception as e:
                db.session.rollback()
                flash(f"Registration error: {e}", "danger")
        return render_template("auth/register.html")

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        """Request a password-reset email without revealing account existence."""
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            if not email or len(email) > 120:
                flash("Please enter a valid email address.", "danger")
                return render_template("auth/forgot_password.html")

            try:
                user = User.query.filter(db.func.lower(User.email) == email).first()

                # Always show the same response to avoid account enumeration.
                if user:
                    raw_token = secrets.token_urlsafe(32)
                    user.reset_token = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
                    user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=30)
                    db.session.commit()

                    reset_url = url_for("reset_password", token=raw_token, _external=True)
                    try:
                        send_password_reset_email(app, user.email, reset_url)
                    except Exception as mail_error:
                        db.session.rollback()
                        app.logger.exception("Password reset email failed")
                        flash("We could not send the reset email right now. Please try again later.", "danger")
                        return render_template("auth/forgot_password.html")

                    log_action("PASSWORD_RESET_REQUEST", "Password reset email sent.")

                flash("If that email is registered, a password reset link has been sent. Check your inbox and spam folder.", "info")
                return render_template("auth/forgot_password.html", show_reset=True)
            except Exception:
                db.session.rollback()
                app.logger.exception("Password reset request failed")
                flash("We could not process the reset request right now. Please try again later.", "danger")

        return render_template("auth/forgot_password.html", show_reset=False)

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        """Validate a one-time reset token and set the user's new password."""
        token_hash = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
        user = User.query.filter_by(reset_token=token_hash).first()

        if not user or not user.reset_token_expiry or user.reset_token_expiry <= datetime.utcnow():
            flash("This password reset link is invalid or has expired.", "danger")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if len(new_password) < 8:
                flash("Password must be at least 8 characters long.", "danger")
                return render_template("auth/reset_password.html", token=token)
            if new_password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_template("auth/reset_password.html", token=token)

            try:
                user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
                user.reset_token = None
                user.reset_token_expiry = None
                db.session.commit()
                log_action("PASSWORD_RESET", "Password reset completed.")
                flash("Password reset successful! Please log in.", "success")
                return redirect(url_for("login"))
            except Exception:
                db.session.rollback()
                app.logger.exception("Password reset completion failed")
                flash("We could not reset your password right now. Please try again.", "danger")

        return render_template("auth/reset_password.html", token=token)

    @app.route("/logout")
    @login_required
    def logout():
        log_action("LOGOUT", f"User {current_user.username} logged out.")
        logout_user()
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    # --------------------------- DASHBOARD PAGES ------------------------
    @app.route("/dashboard")
    @login_required
    def overview():
        # Aggregate live stats for the overview cards.
        metrics = SecurityMetric.query.order_by(SecurityMetric.date).all()
        latest = metrics[-1] if metrics else None
        active_threats = ThreatIntel.query.filter(
            ThreatIntel.severity.in_(["Critical", "High"])
        ).count()
        stats = {
            "security_score": latest.security_score if latest else 78,
            "active_threats": active_threats,
            "vulnerabilities": latest.vulnerabilities if latest else 12,
            "password_health": 84,
            "firewall": "Active",
            "encryption": "AES-256 Enabled",
        }
        return render_template("dashboard/overview.html", stats=stats)

    @app.route("/dashboard/passwords")
    @login_required
    def password_center():
        return render_template("dashboard/password_center.html")

    @app.route("/dashboard/encryption")
    @login_required
    def encryption_lab():
        return render_template("dashboard/encryption_lab.html")

    @app.route("/dashboard/hash")
    @login_required
    def hash_generator():
        return render_template("dashboard/hash_generator.html")

    @app.route("/dashboard/network")
    @login_required
    def network_scanner():
        return render_template("dashboard/network_scanner.html")

    @app.route("/dashboard/vulnerabilities")
    @login_required
    def vulnerability_scanner():
        return render_template("dashboard/vulnerability_scanner.html")

    @app.route("/dashboard/malware")
    @login_required
    def malware_detector():
        return render_template("dashboard/malware_detector.html")

    @app.route("/dashboard/phishing")
    @login_required
    def phishing_detector():
        return render_template("dashboard/phishing_detector.html")

    @app.route("/dashboard/assistant")
    @login_required
    def ai_assistant():
        history = ChatMessage.query.filter_by(user_id=current_user.id).order_by(
            ChatMessage.timestamp).all()
        return render_template("dashboard/ai_assistant.html", history=history)

    @app.route("/dashboard/threats")
    @login_required
    def threat_intelligence():
        threats = ThreatIntel.query.order_by(ThreatIntel.date.desc()).all()
        return render_template("dashboard/threat_intelligence.html", threats=threats)

    @app.route("/dashboard/training")
    @login_required
    def awareness_training():
        progress = {p.module: p for p in TrainingProgress.query.filter_by(
            user_id=current_user.id).all()}
        # Leaderboard: top 10 total scores per user.
        leaderboard = db.session.query(
            User.username, db.func.sum(TrainingProgress.score).label("total")
        ).join(TrainingProgress).group_by(User.id).order_by(db.text("total DESC")).limit(10).all()
        return render_template("dashboard/awareness_training.html",
                               progress=progress, leaderboard=leaderboard)

    @app.route("/dashboard/tools")
    @login_required
    def tools_hub():
        return render_template("dashboard/tools_hub.html")

    @app.route("/dashboard/logs")
    @login_required
    def activity_logs():
        page = request.args.get("page", 1, type=int)
        q = request.args.get("q", "", type=str)
        action = request.args.get("action", "", type=str)
        query = ActivityLog.query.order_by(ActivityLog.timestamp.desc())
        if q:
            query = query.filter(ActivityLog.details.contains(q))
        if action:
            query = query.filter(ActivityLog.action_type == action)
        logs = query.paginate(page=page, per_page=15, error_out=False)
        action_types = [r[0] for r in db.session.query(ActivityLog.action_type).distinct().all()]
        return render_template("dashboard/activity_logs.html", logs=logs,
                               action_types=action_types, q=q, action=action)

    @app.route("/dashboard/reports")
    @login_required
    def reports():
        return render_template("dashboard/reports.html")

    @app.route("/dashboard/settings", methods=["GET", "POST"])
    @login_required
    def settings():
        if request.method == "POST":
            try:
                action = request.form.get("action")
                if action == "profile":
                    new_username = sanitize(request.form.get("username"), 64)
                    color = sanitize(request.form.get("avatar_color"), 7)
                    if new_username:
                        current_user.username = new_username
                    if color:
                        current_user.avatar_color = color
                    db.session.commit()
                    log_action("SETTINGS", "Profile updated.")
                    flash("Profile updated successfully.", "success")
                elif action == "password":
                    current_pw = request.form.get("current_password", "")
                    new_pw = request.form.get("new_password", "")
                    if not bcrypt.check_password_hash(current_user.password_hash, current_pw):
                        flash("Current password is incorrect.", "danger")
                    elif len(new_pw) < 6:
                        flash("New password must be 6+ characters.", "danger")
                    else:
                        current_user.password_hash = bcrypt.generate_password_hash(new_pw).decode("utf-8")
                        db.session.commit()
                        log_action("SETTINGS", "Password changed.")
                        flash("Password changed successfully.", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Settings error: {e}", "danger")
            return redirect(url_for("settings"))
        return render_template("dashboard/settings.html")

    # =======================================================================
    # JSON API ENDPOINTS (the working engines behind every tool)
    # =======================================================================

    # ---- Dashboard chart data ----
    @app.route("/api/dashboard-data")
    @login_required
    def api_dashboard_data():
        try:
            metrics = SecurityMetric.query.order_by(SecurityMetric.date).all()
            line = {
                "labels": [m.date.strftime("%b %d") for m in metrics],
                "detected": [m.threats_detected for m in metrics],
                "blocked": [m.threats_blocked for m in metrics],
            }
            # Threat categories pie from ThreatIntel types.
            cats = {}
            for t in ThreatIntel.query.all():
                cats[t.threat_type] = cats.get(t.threat_type, 0) + 1
            pie = {"labels": list(cats.keys()), "data": list(cats.values())}
            score = metrics[-1].security_score if metrics else 78
            return jsonify(success=True, line=line, pie=pie, score=score)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Live dashboard activity feed (Server-Sent Events) ----
    @app.route("/api/live-events")
    @login_required
    def api_live_events():
        """Stream new activity-log entries to the dashboard in near real time.

        SSE keeps one lightweight HTTP connection open and checks MySQL for new
        activity every second. The stream is scoped to the logged-in user.
        """
        def severity_for(action_type, details):
            text = f"{action_type} {details}".upper()
            if any(k in text for k in ("MALWARE", "CRITICAL", "BLOCKED", "VULNER")):
                return "Critical"
            if any(k in text for k in ("PHISHING", "THREAT", "FAIL", "ERROR", "SCAN")):
                return "High"
            if any(k in text for k in ("PASSWORD", "SETTINGS", "LOGIN")):
                return "Medium"
            return "Info"

        @stream_with_context
        def event_stream():
            last_id = request.args.get("last_id", type=int)
            if last_id is None:
                latest = (ActivityLog.query
                          .filter(ActivityLog.user_id == current_user.id)
                          .order_by(ActivityLog.id.desc())
                          .first())
                last_id = latest.id if latest else 0

            # Tell the browser the connection is alive immediately.
            yield ": connected\n\n"

            while True:
                try:
                    rows = (ActivityLog.query
                            .filter(ActivityLog.user_id == current_user.id,
                                    ActivityLog.id > last_id)
                            .order_by(ActivityLog.id.asc())
                            .limit(25)
                            .all())

                    payloads = []
                    for row in rows:
                        payloads.append({
                            "id": row.id,
                            "action": row.action_type,
                            "details": row.details or "",
                            "ip": row.ip_address or "Local",
                            "timestamp": row.timestamp.strftime("%Y-%m-%d %H:%M:%S") if row.timestamp else "",
                            "severity": severity_for(row.action_type, row.details or ""),
                        })

                    # MySQL commonly uses REPEATABLE READ. End this SELECT transaction
                    # before the next poll so a long-lived SSE connection can see rows
                    # committed by other requests.
                    db.session.rollback()

                    for payload in payloads:
                        yield f"id: {payload['id']}\ndata: {json.dumps(payload)}\n\n"
                        last_id = payload["id"]

                    # SSE comment heartbeat prevents idle proxies from closing the stream.
                    yield ": heartbeat\n\n"
                    time.sleep(1)
                except GeneratorExit:
                    break
                except Exception:
                    # Keep the stream alive; the next iteration can recover from transient DB errors.
                    yield ": stream-error\n\n"
                    time.sleep(2)

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @app.route("/api/recent-events")
    @login_required
    def api_recent_events():
        """Return recent activity for the initial live-feed render."""
        try:
            rows = (ActivityLog.query
                    .filter(ActivityLog.user_id == current_user.id)
                    .order_by(ActivityLog.timestamp.desc())
                    .limit(25)
                    .all())

            def severity_for(action_type, details):
                text = f"{action_type} {details}".upper()
                if any(k in text for k in ("MALWARE", "CRITICAL", "BLOCKED", "VULNER")):
                    return "Critical"
                if any(k in text for k in ("PHISHING", "THREAT", "FAIL", "ERROR", "SCAN")):
                    return "High"
                if any(k in text for k in ("PASSWORD", "SETTINGS", "LOGIN")):
                    return "Medium"
                return "Info"

            return jsonify(success=True, events=[{
                "id": r.id,
                "action": r.action_type,
                "details": r.details or "",
                "ip": r.ip_address or "Local",
                "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "",
                "severity": severity_for(r.action_type, r.details or ""),
            } for r in rows])
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Password strength + breach ----
    @app.route("/api/password-check", methods=["POST"])
    @login_required
    def api_password_check():
        try:
            data = request.get_json(force=True)
            pw = data.get("password", "")
            breached = pw.lower() in BREACHED_PASSWORDS
            log_action("PASSWORD_CHECK", "Checked password strength.")
            return jsonify(success=True, breached=breached)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    @app.route("/api/password-generate", methods=["POST"])
    @login_required
    def api_password_generate():
        try:
            data = request.get_json(force=True)
            length = max(8, min(64, int(data.get("length", 16))))
            use_upper = data.get("upper", True)
            use_lower = data.get("lower", True)
            use_num = data.get("numbers", True)
            use_sym = data.get("symbols", True)
            pool = ""
            if use_lower: pool += "abcdefghijklmnopqrstuvwxyz"
            if use_upper: pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if use_num: pool += "0123456789"
            if use_sym: pool += "!@#$%^&*()-_=+[]{};:,.<>?"
            if not pool:
                pool = "abcdefghijklmnopqrstuvwxyz"
            pw = "".join(secrets.choice(pool) for _ in range(length))
            log_action("PASSWORD_GEN", f"Generated {length}-char password.")
            return jsonify(success=True, password=pw)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    @app.route("/api/passphrase-generate", methods=["POST"])
    @login_required
    def api_passphrase_generate():
        try:
            words = ["cyber", "shield", "nebula", "quantum", "phoenix", "vortex",
                     "matrix", "falcon", "titan", "raptor", "cipher", "vector",
                     "photon", "glacier", "horizon", "summit", "comet", "atlas",
                     "orbit", "fusion", "neon", "pulse", "echo", "delta"]
            data = request.get_json(force=True)
            count = max(3, min(8, int(data.get("count", 4))))
            chosen = [secrets.choice(words).capitalize() for _ in range(count)]
            sep = secrets.choice(["-", ".", "_"])
            passphrase = sep.join(chosen) + str(secrets.randbelow(90) + 10)
            log_action("PASSPHRASE_GEN", "Generated passphrase.")
            return jsonify(success=True, passphrase=passphrase)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Encryption Lab ----
    @app.route("/api/encrypt", methods=["POST"])
    @login_required
    def api_encrypt():
        try:
            data = request.get_json(force=True)
            algo = data.get("algorithm")
            text = data.get("text", "")
            mode = data.get("mode", "encrypt")
            key = data.get("key", "")
            start = time.perf_counter()
            result, info = "", {}

            if algo == "aes":
                # AES-256-CBC with PKCS7 padding. Derive 32-byte key from passphrase via SHA-256.
                key_bytes = hashlib.sha256(key.encode()).digest()
                if mode == "encrypt":
                    iv = os.urandom(16)
                    padder = padding.PKCS7(128).padder()
                    padded = padder.update(text.encode()) + padder.finalize()
                    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
                    enc = cipher.encryptor()
                    ct = enc.update(padded) + enc.finalize()
                    result = base64.b64encode(iv + ct).decode()
                    info = {"key_size": "256-bit", "mode": "CBC", "padding": "PKCS7"}
                else:
                    raw = base64.b64decode(text)
                    iv, ct = raw[:16], raw[16:]
                    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
                    dec = cipher.decryptor()
                    padded = dec.update(ct) + dec.finalize()
                    unpadder = padding.PKCS7(128).unpadder()
                    result = (unpadder.update(padded) + unpadder.finalize()).decode()
                    info = {"key_size": "256-bit", "mode": "CBC"}

            elif algo == "base64":
                result = (base64.b64encode(text.encode()).decode() if mode == "encrypt"
                          else base64.b64decode(text).decode())
                info = {"encoding": "Base64"}

            elif algo in ("sha256", "sha512", "md5"):
                h = hashlib.new(algo)
                h.update(text.encode())
                result = h.hexdigest()
                info = {"type": "one-way hash", "algorithm": algo.upper()}

            else:
                return jsonify(success=False, error="Unsupported algorithm"), 400

            elapsed = round((time.perf_counter() - start) * 1000, 3)
            log_action("ENCRYPT", f"{algo.upper()} {mode}")
            return jsonify(success=True, result=result, time_ms=elapsed, info=info)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    @app.route("/api/rsa-generate", methods=["POST"])
    @login_required
    def api_rsa_generate():
        """Generate an RSA-2048 keypair in-session."""
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                           backend=default_backend())
            priv = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()).decode()
            pub = key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            log_action("RSA_GEN", "Generated RSA-2048 keypair.")
            return jsonify(success=True, private=priv, public=pub)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    @app.route("/api/rsa", methods=["POST"])
    @login_required
    def api_rsa():
        """RSA encrypt/decrypt with OAEP padding."""
        try:
            data = request.get_json(force=True)
            mode = data.get("mode", "encrypt")
            text = data.get("text", "")
            key_pem = data.get("key", "").encode()
            start = time.perf_counter()
            if mode == "encrypt":
                pub = serialization.load_pem_public_key(key_pem, backend=default_backend())
                ct = pub.encrypt(text.encode(), asym_padding.OAEP(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None))
                result = base64.b64encode(ct).decode()
            else:
                priv = serialization.load_pem_private_key(key_pem, password=None,
                                                           backend=default_backend())
                pt = priv.decrypt(base64.b64decode(text), asym_padding.OAEP(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None))
                result = pt.decode()
            elapsed = round((time.perf_counter() - start) * 1000, 3)
            log_action("RSA", f"RSA {mode}")
            return jsonify(success=True, result=result, time_ms=elapsed)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Hash generator (server fallback) ----
    @app.route("/api/hash", methods=["POST"])
    @login_required
    def api_hash():
        try:
            data = request.get_json(force=True)
            text = data.get("text", "")
            out = {
                "md5": hashlib.md5(text.encode()).hexdigest(),
                "sha1": hashlib.sha1(text.encode()).hexdigest(),
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "sha512": hashlib.sha512(text.encode()).hexdigest(),
            }
            log_action("HASH", "Generated hashes.")
            return jsonify(success=True, hashes=out)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Network scanner ----
    @app.route("/api/network-scan", methods=["POST"])
    @login_required
    def api_network_scan():
        """Real TCP connect scan using socket + ThreadPoolExecutor."""
        try:
            data = request.get_json(force=True)
            target = sanitize(data.get("target", "127.0.0.1"), 64)
            # Resolve hostname to IP (also validates input).
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                return jsonify(success=False, error="Cannot resolve target."), 400

            ports = sorted(COMMON_PORTS.keys())

            def scan_port(port):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.6)
                try:
                    status = "open" if s.connect_ex((ip, port)) == 0 else "closed"
                finally:
                    s.close()
                return {
                    "ip": ip, "port": port,
                    "service": COMMON_PORTS.get(port, "Unknown"),
                    "status": status,
                    "risk": PORT_RISK.get(port, "Info") if status == "open" else "None",
                }

            results = []
            with ThreadPoolExecutor(max_workers=50) as ex:
                futures = [ex.submit(scan_port, p) for p in ports]
                for f in as_completed(futures):
                    results.append(f.result())
            results.sort(key=lambda r: r["port"])
            log_action("NETWORK_SCAN", f"Scanned {target} ({ip})")
            return jsonify(success=True, ip=ip, results=results)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Vulnerability scanner ----
    @app.route("/api/vuln-scan", methods=["POST"])
    @login_required
    def api_vuln_scan():
        """Performs real HTTP checks for missing headers, plus heuristic probes."""
        try:
            data = request.get_json(force=True)
            target = sanitize(data.get("target", ""), 256)
            if not target.startswith("http"):
                target = "http://" + target
            findings = []

            try:
                resp = requests.get(target, timeout=6, allow_redirects=True)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                # Missing security headers.
                checks = {
                    "x-frame-options": ("Missing X-Frame-Options", "Medium",
                                        "Add X-Frame-Options: DENY to prevent clickjacking."),
                    "content-security-policy": ("Missing Content-Security-Policy", "High",
                                                 "Implement a strict CSP to mitigate XSS."),
                    "strict-transport-security": ("Missing HSTS", "Medium",
                                                   "Add Strict-Transport-Security header."),
                    "x-content-type-options": ("Missing X-Content-Type-Options", "Low",
                                                "Add X-Content-Type-Options: nosniff."),
                }
                for h, (title, sev, fix) in checks.items():
                    if h not in headers:
                        findings.append({"title": title, "severity": sev,
                                         "description": f"The response is missing the {h} header.",
                                         "fix": fix, "cve": "CWE-693"})

                # Directory listing detection.
                if "index of /" in resp.text.lower():
                    findings.append({"title": "Directory Listing Enabled", "severity": "Medium",
                                     "description": "Server exposes directory contents.",
                                     "fix": "Disable autoindex / directory browsing.",
                                     "cve": "CWE-548"})

                # Reflected XSS probe.
                xss_payload = "<script>cs_xss_test</script>"
                try:
                    x = requests.get(target, params={"q": xss_payload}, timeout=6)
                    if xss_payload in x.text:
                        findings.append({"title": "Reflected XSS Indicator", "severity": "Critical",
                                         "description": "Injected payload reflected unencoded.",
                                         "fix": "Encode all user output; deploy CSP.",
                                         "cve": "CWE-79"})
                except Exception:
                    pass

                # SQL injection error-based probe.
                try:
                    sqli = requests.get(target, params={"id": "1'"}, timeout=6)
                    errors = ["sql syntax", "mysql_fetch", "odbc", "ora-01756", "sqlite error"]
                    if any(e in sqli.text.lower() for e in errors):
                        findings.append({"title": "SQL Injection Indicator", "severity": "Critical",
                                         "description": "Database error returned for crafted input.",
                                         "fix": "Use parameterized queries / prepared statements.",
                                         "cve": "CWE-89"})
                except Exception:
                    pass

                # Open redirect probe.
                if "location" in headers and "http" in headers.get("location", ""):
                    findings.append({"title": "Possible Open Redirect", "severity": "Medium",
                                     "description": "Redirect target may be user-controllable.",
                                     "fix": "Whitelist redirect destinations.",
                                     "cve": "CWE-601"})

            except requests.exceptions.RequestException as re:
                return jsonify(success=False, error=f"Target unreachable: {re}"), 400

            if not findings:
                findings.append({"title": "No major issues detected", "severity": "Info",
                                 "description": "Basic checks passed.",
                                 "fix": "Continue regular security testing.", "cve": "-"})
            log_action("VULN_SCAN", f"Scanned {target}: {len(findings)} findings.")
            return jsonify(success=True, target=target, findings=findings)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Malware detector ----
    @app.route("/api/malware-scan", methods=["POST"])
    @login_required
    def api_malware_scan():
        try:
            if "file" not in request.files:
                return jsonify(success=False, error="No file uploaded."), 400
            f = request.files["file"]
            content = f.read()
            md5 = hashlib.md5(content).hexdigest()
            sha256 = hashlib.sha256(content).hexdigest()
            size = len(content)
            name = f.filename or "unknown"

            score = 0
            reasons = []
            if md5 in MALICIOUS_HASHES or sha256 in MALICIOUS_HASHES:
                score += 90
                reasons.append("Hash matches known malware signature.")
            risky_ext = (".exe", ".scr", ".bat", ".vbs", ".js", ".jar", ".dll", ".ps1", ".cmd")
            if name.lower().endswith(risky_ext):
                score += 25
                reasons.append("Potentially dangerous file extension.")
            if any(p in name.lower() for p in ["invoice", "crack", "keygen", "patch", "setup_"]):
                score += 15
                reasons.append("Suspicious filename pattern.")
            if size < 100:
                score += 10
                reasons.append("Unusually small file size.")
            if name.count(".") > 2:
                score += 15
                reasons.append("Multiple extensions (possible disguise).")

            score = min(score, 100)
            classification = ("Malicious" if score >= 70 else
                              "Suspicious" if score >= 35 else "Safe")
            if not reasons:
                reasons.append("No malicious indicators found.")
            log_action("MALWARE_SCAN", f"{name}: {classification} ({score}%)")
            return jsonify(success=True, md5=md5, sha256=sha256, size=size, name=name,
                           score=score, classification=classification, reasons=reasons)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Phishing detector ----
    @app.route("/api/phishing-check", methods=["POST"])
    @login_required
    def api_phishing_check():
        try:
            data = request.get_json(force=True)
            url = sanitize(data.get("url", ""), 512)
            parsed = urlparse(url if "://" in url else "http://" + url)
            host = parsed.netloc or parsed.path
            checks = []
            threat = 0

            # IP-as-domain
            is_ip = False
            try:
                ipaddress.ip_address(host.split(":")[0])
                is_ip = True
            except ValueError:
                is_ip = False
            checks.append({"name": "IP used as domain", "flagged": is_ip})
            if is_ip: threat += 25

            # Suspicious TLD
            sus_tld = any(host.endswith(t) for t in SUSPICIOUS_TLDS)
            checks.append({"name": "Suspicious TLD", "flagged": sus_tld})
            if sus_tld: threat += 20

            # Excessive subdomains
            many_sub = host.count(".") > 3
            checks.append({"name": "Excessive subdomains", "flagged": many_sub})
            if many_sub: threat += 15

            # URL length
            long_url = len(url) > 75
            checks.append({"name": "URL length > 75 chars", "flagged": long_url})
            if long_url: threat += 10

            # Phishing keywords
            kw = [k for k in PHISHING_KEYWORDS if k in url.lower()]
            checks.append({"name": "Phishing keywords", "flagged": bool(kw),
                           "detail": ", ".join(kw) if kw else "none"})
            if kw: threat += min(20, 5 * len(kw))

            # Missing HTTPS
            no_https = not url.lower().startswith("https")
            checks.append({"name": "Missing HTTPS", "flagged": no_https})
            if no_https: threat += 10

            # Lookalike (digit substitution / hyphen-heavy)
            lookalike = host.count("-") > 2 or any(c.isdigit() for c in host.replace(".", ""))
            checks.append({"name": "Lookalike domain pattern", "flagged": lookalike})
            if lookalike: threat += 10

            # Domain age simulation (deterministic from hash).
            seed = int(hashlib.md5(host.encode()).hexdigest(), 16)
            domain_age_days = seed % 4000
            young = domain_age_days < 90
            checks.append({"name": "Domain age < 90 days", "flagged": young,
                           "detail": f"{domain_age_days} days (simulated)"})
            if young: threat += 15

            threat = min(threat, 100)
            safe = 100 - threat
            verdict = "Dangerous" if threat >= 60 else "Suspicious" if threat >= 30 else "Safe"
            log_action("PHISHING_CHECK", f"{host}: {verdict} ({threat}%)")
            return jsonify(success=True, host=host, checks=checks,
                           threat_score=threat, safe_score=safe, verdict=verdict)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- AI Assistant ----
    @app.route("/api/assistant", methods=["POST"])
    @login_required
    def api_assistant():
        try:
            data = request.get_json(force=True)
            msg = sanitize(data.get("message", ""), 1000)
            reply = ai_respond(msg)
            # Persist conversation.
            db.session.add(ChatMessage(user_id=current_user.id, role="user", content=msg))
            db.session.add(ChatMessage(user_id=current_user.id, role="assistant", content=reply))
            db.session.commit()
            log_action("AI_CHAT", f"Q: {msg[:60]}")
            return jsonify(success=True, reply=reply,
                           timestamp=datetime.utcnow().strftime("%H:%M"))
        except Exception as e:
            db.session.rollback()
            return jsonify(success=False, error=str(e)), 500

    # ---- Training quiz submission ----
    @app.route("/api/training-submit", methods=["POST"])
    @login_required
    def api_training_submit():
        try:
            data = request.get_json(force=True)
            module = sanitize(data.get("module"), 64)
            score = max(0, min(100, int(data.get("score", 0))))
            prog = TrainingProgress.query.filter_by(
                user_id=current_user.id, module=module).first()
            if not prog:
                prog = TrainingProgress(user_id=current_user.id, module=module)
                db.session.add(prog)
            prog.score = max(prog.score, score)
            prog.completed = score >= 100
            db.session.commit()
            log_action("TRAINING", f"{module} score {score}%")
            return jsonify(success=True, score=prog.score, completed=prog.completed)
        except Exception as e:
            db.session.rollback()
            return jsonify(success=False, error=str(e)), 500

    # ---- Tools Hub APIs ----
    @app.route("/api/tool/base64", methods=["POST"])
    @login_required
    def api_tool_base64():
        try:
            data = request.get_json(force=True)
            text, mode = data.get("text", ""), data.get("mode", "encode")
            out = (base64.b64encode(text.encode()).decode() if mode == "encode"
                   else base64.b64decode(text).decode())
            log_action("TOOL_BASE64", mode)
            return jsonify(success=True, result=out)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    @app.route("/api/tool/url", methods=["POST"])
    @login_required
    def api_tool_url():
        try:
            data = request.get_json(force=True)
            text, mode = data.get("text", ""), data.get("mode", "encode")
            out = quote(text) if mode == "encode" else unquote(text)
            log_action("TOOL_URL", mode)
            return jsonify(success=True, result=out)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    @app.route("/api/tool/qrcode", methods=["POST"])
    @login_required
    def api_tool_qrcode():
        try:
            data = request.get_json(force=True)
            content = sanitize(data.get("content", ""), 1000)
            if not content:
                return jsonify(success=False, error="No content."), 400
            qr = qrcode.QRCode(box_size=8, border=2)
            qr.add_data(content)
            qr.make(fit=True)
            img = qr.make_image(fill_color="#0a0a0f", back_color="#00d4ff")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode()
            log_action("TOOL_QR", "Generated QR code.")
            return jsonify(success=True, image=f"data:image/png;base64,{b64}")
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    @app.route("/api/tool/dns", methods=["POST"])
    @login_required
    def api_tool_dns():
        try:
            data = request.get_json(force=True)
            host = sanitize(data.get("host", ""), 128)
            infos = socket.getaddrinfo(host, None)
            ips = sorted({i[4][0] for i in infos})
            log_action("TOOL_DNS", host)
            return jsonify(success=True, host=host, ips=ips)
        except Exception as e:
            return jsonify(success=False, error=f"DNS lookup failed: {e}"), 400

    @app.route("/api/tool/whois", methods=["POST"])
    @login_required
    def api_tool_whois():
        try:
            data = request.get_json(force=True)
            domain = sanitize(data.get("domain", ""), 128)
            try:
                import whois  # python-whois
                w = whois.whois(domain)
                result = {
                    "domain": domain,
                    "registrar": str(w.registrar) if w.registrar else "N/A",
                    "creation_date": str(w.creation_date),
                    "expiration_date": str(w.expiration_date),
                    "name_servers": list(w.name_servers) if w.name_servers else [],
                }
            except Exception:
                # Simulated fallback when python-whois unavailable / lookup fails.
                seed = int(hashlib.md5(domain.encode()).hexdigest(), 16)
                result = {
                    "domain": domain,
                    "registrar": ["GoDaddy", "Namecheap", "Cloudflare", "Google Domains"][seed % 4],
                    "creation_date": (datetime(2005, 1, 1) + timedelta(days=seed % 6000)).strftime("%Y-%m-%d"),
                    "expiration_date": (datetime(2025, 1, 1) + timedelta(days=seed % 1000)).strftime("%Y-%m-%d"),
                    "name_servers": [f"ns1.{domain}", f"ns2.{domain}"],
                    "note": "Simulated data (live WHOIS unavailable).",
                }
            log_action("TOOL_WHOIS", domain)
            return jsonify(success=True, result=result)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    @app.route("/api/tool/geoip", methods=["POST"])
    @login_required
    def api_tool_geoip():
        try:
            data = request.get_json(force=True)
            ip = sanitize(data.get("ip", ""), 64)
            try:
                r = requests.get(f"http://ip-api.com/json/{ip}", timeout=6).json()
                if r.get("status") == "success":
                    log_action("TOOL_GEOIP", ip)
                    return jsonify(success=True, result=r)
            except Exception:
                pass
            # Simulated fallback.
            seed = int(hashlib.md5(ip.encode()).hexdigest(), 16)
            countries = ["United States", "Germany", "Japan", "Brazil", "India"]
            result = {"query": ip, "country": countries[seed % 5],
                      "city": ["NYC", "Berlin", "Tokyo", "Rio", "Mumbai"][seed % 5],
                      "isp": "Simulated ISP", "lat": (seed % 90), "lon": (seed % 180),
                      "note": "Simulated data."}
            log_action("TOOL_GEOIP", ip)
            return jsonify(success=True, result=result)
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Reports & exports ----
    @app.route("/api/report/<report_type>")
    @login_required
    def api_report(report_type):
        try:
            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4, title="CyberShield AI Report")
            styles = getSampleStyleSheet()
            brand = ParagraphStyle("brand", parent=styles["Title"],
                                   textColor=colors.HexColor("#00d4ff"), fontSize=22)
            elements = [Paragraph("🛡️ CyberShield AI", brand),
                        Paragraph(f"{report_type.replace('_',' ').title()} Report", styles["Heading2"]),
                        Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                                  styles["Normal"]),
                        Paragraph(f"User: {current_user.username}", styles["Normal"]),
                        Spacer(1, 0.5 * cm),
                        Paragraph("Table of Contents", styles["Heading3"]),
                        Paragraph("1. Summary &nbsp; 2. Findings &nbsp; 3. Recommendations",
                                  styles["Normal"]),
                        Spacer(1, 0.5 * cm)]

            if report_type == "vulnerability":
                rows = [["Severity", "Finding", "Recommendation"]]
                for t in ThreatIntel.query.limit(10).all():
                    rows.append([t.severity, t.threat_name, (t.recommendations or "")[:60]])
            elif report_type == "scan":
                rows = [["Date", "Action", "Details"]]
                for l in ActivityLog.query.filter_by(user_id=current_user.id).order_by(
                        ActivityLog.timestamp.desc()).limit(15).all():
                    rows.append([l.timestamp.strftime("%Y-%m-%d %H:%M"),
                                 l.action_type, (l.details or "")[:50]])
            else:  # overview
                m = SecurityMetric.query.order_by(SecurityMetric.date.desc()).first()
                rows = [["Metric", "Value"],
                        ["Security Score", str(m.security_score if m else 78)],
                        ["Threats Detected", str(m.threats_detected if m else 0)],
                        ["Vulnerabilities", str(m.vulnerabilities if m else 0)],
                        ["Active Threats", str(ThreatIntel.query.count())]]

            tbl = Table(rows, repeatRows=1, colWidths=[3.5*cm, 6*cm, 7*cm][:len(rows[0])])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a0a0f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00d4ff")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(tbl)
            doc.build(elements)
            buf.seek(0)
            log_action("REPORT", f"Generated {report_type} PDF.")
            return send_file(buf, mimetype="application/pdf", as_attachment=True,
                             download_name=f"cybershield_{report_type}_report.pdf")
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    @app.route("/api/export/<fmt>")
    @login_required
    def api_export(fmt):
        """Export activity logs to CSV or JSON."""
        try:
            logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(500).all()
            if fmt == "json":
                payload = [{"id": l.id, "action": l.action_type, "details": l.details,
                            "ip": l.ip_address, "timestamp": l.timestamp.isoformat()}
                           for l in logs]
                buf = io.BytesIO(json.dumps(payload, indent=2).encode())
                return send_file(buf, mimetype="application/json", as_attachment=True,
                                 download_name="activity_logs.json")
            else:  # csv
                out = io.StringIO()
                w = csv.writer(out)
                w.writerow(["ID", "Action", "Details", "IP", "Timestamp"])
                for l in logs:
                    w.writerow([l.id, l.action_type, l.details, l.ip_address, l.timestamp])
                buf = io.BytesIO(out.getvalue().encode())
                return send_file(buf, mimetype="text/csv", as_attachment=True,
                                 download_name="activity_logs.csv")
        except Exception as e:
            return jsonify(success=False, error=str(e)), 500

    # ---- Error handlers ----
    @app.errorhandler(404)
    def not_found(e):
        return render_template("base.html", error="404 - Page Not Found"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("base.html", error="500 - Internal Server Error"), 500


# ---------------------------------------------------------------------------
# Rule-based AI assistant engine (keyword-intent matching) — requirement #9
# ---------------------------------------------------------------------------
def ai_respond(message):
    """Return a concise, professional, technical response based on keyword intents."""
    m = message.lower()
    intents = [
        (["owasp", "top 10", "top ten"],
         "The OWASP Top 10 (2021) covers: A01 Broken Access Control, A02 Cryptographic Failures, "
         "A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable Components, "
         "A07 Identification/Authentication Failures, A08 Software/Data Integrity Failures, "
         "A09 Logging/Monitoring Failures, A10 SSRF. Prioritize A01 and A03 — they are the most exploited."),
        (["cve", "vulnerability id"],
         "A CVE (Common Vulnerabilities and Exposures) is a unique identifier like CVE-2021-44228 (Log4Shell). "
         "Each CVE links to severity (CVSS score), affected products, and remediation guidance. "
         "Always check the NVD for the authoritative record."),
        (["password", "passphrase"],
         "Best practices: use 16+ character unique passwords, prefer passphrases, enable MFA, never reuse, "
         "and store them in a reputable password manager. Avoid dictionary words and personal info."),
        (["phishing", "social engineering"],
         "Social engineering exploits human trust. Defenses: verify sender domains, hover before clicking, "
         "never share OTPs, use email authentication (SPF/DKIM/DMARC), and run regular awareness training."),
        (["encryption", "aes", "rsa", "cipher"],
         "Use AES-256 (symmetric) for data-at-rest and TLS 1.3 in transit. RSA-2048/4096 or ECC handle key "
         "exchange and signatures. Never roll your own crypto — use vetted libraries and proper IV/nonce handling."),
        (["incident response", "ir", "breach"],
         "Incident Response follows NIST SP 800-61: 1) Preparation, 2) Detection & Analysis, "
         "3) Containment, 4) Eradication, 5) Recovery, 6) Post-Incident Lessons Learned. "
         "Preserve evidence and maintain a clear chain of custody."),
        (["pentest", "penetration", "ethical hacking"],
         "A penetration test phases: Reconnaissance → Scanning → Gaining Access → Maintaining Access → "
         "Covering Tracks → Reporting. Always operate within an authorized scope and rules of engagement."),
        (["certification", "certs", "ceh", "oscp", "cissp"],
         "Popular certs: CompTIA Security+ (foundation), CEH (offensive theory), OSCP (hands-on offensive), "
         "CISSP (management/architecture), CISM (governance). Choose based on offensive vs. defensive goals."),
        (["xss", "cross site scripting"],
         "XSS injects malicious scripts into pages. Mitigate by output-encoding, a strict Content-Security-Policy, "
         "HttpOnly cookies, and input validation. Types: Stored, Reflected, and DOM-based."),
        (["sql injection", "sqli"],
         "SQL injection manipulates queries via untrusted input. Defend with parameterized queries / prepared "
         "statements, least-privilege DB accounts, and a WAF. Never concatenate user input into SQL."),
        (["firewall", "network security"],
         "A firewall enforces allow/deny rules on traffic. Combine with IDS/IPS, network segmentation, "
         "and zero-trust principles. Default-deny inbound is the safest baseline."),
        (["hello", "hi", "hey"],
         "Hello! I'm the CyberShield AI Assistant. Ask me about OWASP, CVEs, encryption, phishing, "
         "incident response, pentesting, or security certifications."),
    ]
    for keywords, response in intents:
        if any(k in m for k in keywords):
            return response
    return ("I can help with cybersecurity topics: OWASP Top 10, CVEs, password best practices, "
            "encryption, phishing/social engineering, incident response, penetration testing, and "
            "certifications. Could you rephrase your question with one of those topics?")


# ---------------------------------------------------------------------------
# CLI: seed-db — populate realistic sample data (requirement)
# ---------------------------------------------------------------------------
def register_cli(app):
    @app.cli.command("seed-db")
    def seed_db():
        """Create tables and seed realistic demo data."""
        db.drop_all()
        db.create_all()

        # Demo user
        demo = User(
            username="demo",
            email="demo@cybershield.ai",
            password_hash=bcrypt.generate_password_hash("CyberShield2024!").decode("utf-8"),
            avatar_color="#00ff88",
        )
        db.session.add(demo)
        db.session.commit()

        # 30 days of security metrics
        base_score = 70
        for i in range(30):
            d = date.today() - timedelta(days=29 - i)
            detected = random.randint(5, 40)
            db.session.add(SecurityMetric(
                date=d,
                threats_detected=detected,
                threats_blocked=int(detected * random.uniform(0.7, 0.98)),
                vulnerabilities=random.randint(3, 20),
                security_score=min(98, base_score + i // 2 + random.randint(-3, 5)),
            ))

        # 26 threat intelligence entries
        threats = [
            ("Lazarus Group", "APT", "Critical", "Financial, Defense"),
            ("LockBit 3.0", "Ransomware", "Critical", "Enterprise, Healthcare"),
            ("Log4Shell", "Zero-Day", "Critical", "Java Applications"),
            ("APT29 (Cozy Bear)", "APT", "High", "Government, Diplomacy"),
            ("BlackCat/ALPHV", "Ransomware", "Critical", "Energy, Finance"),
            ("Volt Typhoon", "APT", "High", "Critical Infrastructure"),
            ("MOVEit Transfer Exploit", "Zero-Day", "Critical", "File Transfer Servers"),
            ("Emotet", "Malware", "High", "Email Systems"),
            ("Cl0p Ransomware", "Ransomware", "High", "Managed File Transfer"),
            ("FIN7", "APT", "High", "Retail, Hospitality"),
            ("Pegasus Spyware", "Spyware", "Critical", "Mobile Devices"),
            ("Conti", "Ransomware", "High", "Healthcare, Government"),
            ("APT41", "APT", "High", "Tech, Telecom"),
            ("Citrix Bleed (CVE-2023-4966)", "Zero-Day", "Critical", "NetScaler ADC"),
            ("Qakbot", "Malware", "Medium", "Banking"),
            ("Royal Ransomware", "Ransomware", "High", "Manufacturing"),
            ("Sandworm", "APT", "Critical", "Energy Grids"),
            ("Raspberry Robin", "Worm", "Medium", "Windows USB"),
            ("Akira Ransomware", "Ransomware", "High", "SMBs, VPN Appliances"),
            ("Scattered Spider", "APT", "High", "Telecom, Cloud"),
            ("Gootloader", "Malware", "Medium", "SEO-poisoned sites"),
            ("ProxyShell", "Zero-Day", "Critical", "MS Exchange"),
            ("Spring4Shell", "Zero-Day", "High", "Spring Framework"),
            ("Vidar Stealer", "Malware", "Medium", "Browsers, Crypto"),
            ("BianLian", "Ransomware", "High", "Healthcare"),
            ("DarkGate", "Malware", "Medium", "Windows Endpoints"),
        ]
        for i, (name, ttype, sev, systems) in enumerate(threats):
            db.session.add(ThreatIntel(
                threat_name=name, threat_type=ttype, severity=sev,
                date=datetime.utcnow() - timedelta(days=i * 2),
                affected_systems=systems,
                description=f"{name} is an active {ttype.lower()} threat targeting {systems}. "
                            f"Observed using advanced TTPs aligned with MITRE ATT&CK.",
                recommendations="Patch affected systems, enable MFA, monitor IOCs, segment networks, "
                                "and review EDR alerts for related activity.",
            ))

        # Sample activity logs
        for i in range(40):
            db.session.add(ActivityLog(
                user_id=demo.id,
                action_type=random.choice(["LOGIN", "SCAN", "ENCRYPT", "HASH", "TOOL_QR", "VULN_SCAN"]),
                details="Sample seeded activity entry.",
                ip_address="127.0.0.1",
                timestamp=datetime.utcnow() - timedelta(hours=i),
            ))

        db.session.commit()
        click.echo("✅ Database seeded! Login: demo / CyberShield2024!")


# Module-level app for `flask --app app run`
app = create_app()

if __name__ == "__main__":
    app.run(debug=True)