# 🛡️ CyberShield AI

CyberShield AI is a comprehensive cybersecurity dashboard built using Flask, MySQL, and modern security libraries. It provides multiple security tools including password analysis, encryption, vulnerability scanning, malware detection, phishing detection, threat intelligence, cybersecurity awareness training, and an AI-powered security assistant.

---

## Features

### 🔐 Authentication & Account Security

* User Registration
* Secure Login System
* Bcrypt Password Hashing
* Password Reset Tokens
* Session Timeout Protection
* Profile Management

### 📊 Security Dashboard

* Security Score Monitoring
* Threat Statistics
* Vulnerability Tracking
* Security Metrics Visualization

### 🔑 Password Security Center

* Password Strength Analysis
* Breached Password Detection
* Secure Password Generator
* Passphrase Generator

### 🔒 Encryption Laboratory

* AES-256 Encryption & Decryption
* RSA-2048 Key Generation
* RSA Encryption & Decryption
* Base64 Encoding & Decoding
* Hash Generation (MD5, SHA1, SHA256, SHA512)

### 🌐 Network Security Tools

* Network Port Scanner
* DNS Lookup
* WHOIS Lookup
* GeoIP Lookup

### 🛡️ Threat Detection

* Malware Detection
* File Hash Analysis
* Phishing URL Detection
* Vulnerability Scanner
* Threat Intelligence Feed

### 🤖 AI Security Assistant

* Cybersecurity Knowledge Assistant
* OWASP Guidance
* Security Best Practices
* Incident Response Recommendations

### 🎓 Security Awareness Training

* Training Modules
* Quiz System
* Score Tracking
* User Leaderboard

### 📑 Reporting & Export

* PDF Security Reports
* CSV Export
* JSON Export
* Activity Logs

### 📋 Audit Logging

* Login Tracking
* User Activity Monitoring
* Security Event Logging

---

## Technology Stack

### Backend

* Python 3.11+
* Flask 3.0
* Flask-SQLAlchemy
* Flask-Login
* Flask-Bcrypt
* Flask-WTF

### Database

* MySQL
* SQLAlchemy ORM
* PyMySQL

### Security Libraries

* Cryptography
* Flask-Bcrypt

### Reporting

* ReportLab

### Utilities

* Requests
* QRCode
* Pillow
* Python-WHOIS

---

## Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/cybershield-ai.git
cd cybershield-ai
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment

Windows:

```bash
venv\Scripts\activate
```

Linux / macOS:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Database Configuration

Create a MySQL database:

```sql
CREATE DATABASE cybershield;
```

Update database settings inside `config.py`:

```python
SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:@localhost/cybershield"
```

---

## Run Application

```bash
flask --app app run --debug
```

or

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Seed Demo Data

CyberShield AI includes a database seeding command:

```bash
flask --app app seed-db
```

Demo Credentials:

```text
Username: demo
Password: CyberShield2024!
```

---

## Project Structure

```text
CyberShield/
│
├── app.py
├── config.py
├── models.py
├── requirements.txt
│
├── templates/
├── static/
├── instance/
│   └── uploads/
│
└── README.md
```

---

## Security Features

* AES-256 Encryption
* RSA-2048 Encryption
* Password Hashing with Bcrypt
* CSRF Protection
* Session Expiration
* Input Sanitization
* Audit Logging
* Threat Detection
* Vulnerability Assessment

---

## Screenshots

### Login Page

Secure authentication interface with bcrypt-protected credentials.

### Dashboard

Real-time cybersecurity metrics and threat overview.

### Encryption Lab

AES and RSA encryption utilities.

### Threat Intelligence

Latest threat information and security insights.

---

## Requirements

See `requirements.txt` for the complete dependency list.

---

## Author

**Siva Shankar**

CyberShield AI Project

---

## License

This project is intended for educational, research, and cybersecurity learning purposes.

## Password reset email setup

The forgot-password flow sends a real, one-time reset link through SMTP. It does not display the reset token in the browser.

Set these environment variables before starting the app:

- `SECRET_KEY`
- `DATABASE_URL`
- `MAIL_SERVER`
- `MAIL_PORT`
- `MAIL_USERNAME`
- `MAIL_PASSWORD`
- `MAIL_DEFAULT_SENDER`
- `MAIL_USE_TLS`

For Gmail, enable 2-Step Verification and create a Google App Password. Use that App Password as `MAIL_PASSWORD`; do not use the normal Gmail password.

## Real-time dashboard feed

`/api/live-events` uses Server-Sent Events (SSE). The browser connects only on the dashboard page. The server polls the activity log and ends each MySQL read transaction before the next poll so newly committed rows are visible under MySQL's default transaction isolation.

## Test on a phone over local Wi-Fi

1. Connect the phone and development PC to the same Wi-Fi network.
2. Find the PC's LAN IPv4 address with `ipconfig` (for example `192.168.1.10`).
3. Run Flask so it listens on the LAN interface, for example: `flask --app app run --host 0.0.0.0 --port 5000`.
4. On the phone open `http://192.168.1.10:5000`.
5. If Windows Firewall prompts for Python, allow it on the Private network.

Do not use `127.0.0.1`/`localhost` on the phone; those addresses refer to the phone itself.
