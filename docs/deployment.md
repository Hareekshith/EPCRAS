# EPCRAS Production Deployment Guide

**Target System:** Enterprise Patch Compliance and Risk Assessment System (EPCRAS)  
**Target Environment:** Standard Low-Resource Linux Server (Ubuntu 22.04/24.04 LTS, Debian 12, RHEL 9, AlmaLinux 9)  
**Architecture:** Monolithic Python / Flask application powered by Gunicorn WSGI and Nginx reverse proxy.  
**Hardware Profile:** Low-resource compatible (Minimum: 1 vCPU, 1 GB RAM, 10 GB Disk). No Docker, Kubernetes, or cloud-specific services required.

---

## 1. Architectural Overview

```
                      +-----------------------------+
                      |   Client Web Browser / UI   |
                      +-----------------------------+
                                     |
                                     | HTTPS (Port 443) / HTTP (Port 80)
                                     v
                      +-----------------------------+
                      |        Nginx Reverse        |
                      |            Proxy            |
                      | (SSL Term, Static Files,    |
                      |   Gzip, Security Headers)   |
                      +-----------------------------+
                                     |
                                     | HTTP Unix Socket or Loopback (127.0.0.1:8000)
                                     v
                      +-----------------------------+
                      |       Gunicorn WSGI         |
                      |       (Sync Workers)        |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      |       EPCRAS (Flask)        |
                      | (ProxyFix, CSRF, RBAC)      |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      |       SQLite Database       |
                      |    (instance/epcras.db)     |
                      +-----------------------------+
```

---

## 2. Linux Server Prerequisites

Ensure standard OS packages, Python 3, pip, and Nginx are installed.

### 2.1 Ubuntu / Debian
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git nginx libpq-dev
```

### 2.2 RHEL / AlmaLinux / Rocky Linux 9
```bash
sudo dnf update -y
sudo dnf install -y python3 python3-pip git nginx
```

---

## 3. Dedicated System User & Directory Setup

For production security, do not run the application as `root`. Create a dedicated system user `epcras`:

```bash
# Create system user and application directory
sudo useradd -r -m -d /opt/epcras -s /bin/bash epcras

# Switch to the application user
sudo -u epcras -i
cd /opt/epcras

# Clone or copy the EPCRAS repository
git clone https://github.com/Hareekshith/EPCRAS.git /opt/epcras/app
cd /opt/epcras/app
```

---

## 4. Python Virtual Environment & Dependencies

Establish an isolated Python 3 virtual environment and install production dependencies.

```bash
# Create virtual environment
python3 -m venv /opt/epcras/venv

# Activate virtual environment
source /opt/epcras/venv/bin/activate

# Upgrade packaging tools
pip install --upgrade pip setuptools wheel

# Install dependencies from requirements.txt
pip install -r requirements.txt

# Install the application package in editable mode
pip install -e .
```

---

## 5. Environment Configuration & Secrets Management

Configuration is handled via `.env` without committing secrets to version control.

### 5.1 Create Environment File
```bash
cp .env.example .env
chmod 600 .env
```

### 5.2 Generate a High-Entropy Production Secret Key
Generate a cryptographically secure 32-byte hexadecimal secret key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 5.3 Configure `.env`
Edit `/opt/epcras/app/.env`:
```ini
# Flask Environment Mode
FLASK_CONFIG=production

# Generated Production Secret Key
SECRET_KEY=e839f972b22049d59bc40ceef365eef72304918e950ec462b47417e92b8d4231

# Database Configuration (Default: SQLite for academic / single-node deployment)
DATABASE_URL=sqlite:////opt/epcras/app/instance/epcras.db

# Cookie & Session Security
# Set to 'true' once HTTPS/TLS is configured on Nginx; set to 'false' if running on plain HTTP
SESSION_COOKIE_SECURE=false
SESSION_LIFETIME_MINUTES=30
WTF_CSRF_TIME_LIMIT=3600

# Reverse Proxy (Nginx) Integration
USE_PROXY_FIX=true
PROXY_FIX_FOR=1
PROXY_FIX_PROTO=1
PROXY_FIX_HOST=1
PROXY_FIX_PREFIX=1

# Logging Settings
LOG_LEVEL=INFO
LOG_FILE=/opt/epcras/app/instance/logs/epcras.log

# Gunicorn Settings
GUNICORN_BIND=127.0.0.1:8000
GUNICORN_WORKERS=2
GUNICORN_THREADS=2
GUNICORN_TIMEOUT=60
```

---

## 6. Database Initialization & Administrator Provisioning

EPCRAS includes built-in Flask CLI commands for deterministic schema initialization and administrative seeding.

### 6.1 Initialize Database Schema
```bash
# Ensure the virtual environment is active
source /opt/epcras/venv/bin/activate
export FLASK_APP=wsgi.py

# Initialize database schema
flask init-db
```

Output:
```
Database schema initialized successfully.
```

### 6.2 Provision Initial Administrator Account
Seed the initial administrator user via CLI (replace password with a strong production credential):
```bash
flask seed-admin --username admin --email admin@example.local --password "YourStrongAdminPassword2026!"
```

Output:
```
Successfully created administrator user 'admin' (admin@example.local).
```

### 6.3 Optional: Seed Baseline Vulnerability Database
To populate baseline vulnerability data (Log4Shell, XZ Utils, libwebp, Spring4Shell):
```bash
flask seed-vulnerabilities
```

---

## 7. Gunicorn WSGI Server Configuration

Gunicorn serves the Flask application concurrently with low memory overhead.

### 7.1 Local Verification
Test Gunicorn manually from the command line:
```bash
/opt/epcras/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 2 --timeout 60 wsgi:app
```
Test with curl in a separate terminal:
```bash
curl -I http://127.0.0.1:8000/auth/login
```
*(Response will show `HTTP/1.1 200 OK` and `Server: gunicorn`)*. Stop the test process with `Ctrl+C`.

### 7.2 Systemd Service Configuration
Create a persistent system service to manage Gunicorn automatically across system reboots.

Create `/etc/systemd/system/epcras.service` (run as `sudo`):

```ini
[Unit]
Description=EPCRAS Gunicorn WSGI Server
After=network.target

[Service]
User=epcras
Group=epcras
WorkingDirectory=/opt/epcras/app
Environment="PATH=/opt/epcras/venv/bin"
EnvironmentFile=/opt/epcras/app/.env
ExecStart=/opt/epcras/venv/bin/gunicorn \
    --bind 127.0.0.1:8000 \
    --workers 2 \
    --threads 2 \
    --timeout 60 \
    --access-logfile /opt/epcras/app/instance/logs/access.log \
    --error-logfile /opt/epcras/app/instance/logs/error.log \
    wsgi:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable epcras
sudo systemctl start epcras
sudo systemctl status epcras
```

---

## 8. Nginx Reverse Proxy Configuration

Nginx terminates external client requests, serves static files efficiently, enforces security headers, and proxies application requests to Gunicorn.

### 8.1 Create Nginx Site Configuration
Create `/etc/nginx/sites-available/epcras.conf`:

```nginx
server {
    listen 80;
    server_name epcras.example.local; # Replace with your domain or server IP

    # Client upload size limit (allows CSV inventory imports up to 16MB)
    client_max_body_size 16M;

    # Static file serving directly from disk (bypasses Python WSGI for performance)
    location /static/ {
        alias /opt/epcras/app/src/epcras/static/;
        expires 30d;
        add_header Cache-Control "public, no-transform";
        access_log off;
    }

    # Proxy dynamic requests to Gunicorn WSGI
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }

    # Custom Error Pages
    error_page 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}
```

### 8.2 Enable Site and Test Configuration
```bash
# Enable site in Nginx
sudo ln -s /etc/nginx/sites-available/epcras.conf /etc/nginx/sites-enabled/

# Remove default site if not needed
sudo rm -f /etc/nginx/sites-enabled/default

# Test Nginx syntax
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

### 8.3 Enabling HTTPS with Certbot (Optional / Recommended)
If deploying with a public Fully Qualified Domain Name (FQDN):
```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d epcras.example.com
```
When SSL is active, update `.env` setting:
```ini
SESSION_COOKIE_SECURE=true
```
Then restart the service:
```bash
sudo systemctl restart epcras
```

---

## 9. Backup and Recovery Procedure

### 9.1 Data Assets to Backup
1. **SQLite Database**: `/opt/epcras/app/instance/epcras.db`
2. **Environment Configuration**: `/opt/epcras/app/.env`
3. **Application Logs**: `/opt/epcras/app/instance/logs/`

### 9.2 Safe SQLite Backup
SQLite provides an online `.backup` command that ensures atomic, non-locking backups without stopping the service:

```bash
#!/bin/bash
# EPCRAS Automated Database Backup Script
set -e

BACKUP_DIR="/opt/epcras/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DB_FILE="/opt/epcras/app/instance/epcras.db"
BACKUP_FILE="${BACKUP_DIR}/epcras_backup_${TIMESTAMP}.db"

mkdir -p "$BACKUP_DIR"

# Online atomic backup via sqlite3 CLI
sqlite3 "$DB_FILE" ".backup '${BACKUP_FILE}'"

# Compress backup
gzip -9 "$BACKUP_FILE"

# Retention: Delete backups older than 30 days
find "$BACKUP_DIR" -type f -name "epcras_backup_*.db.gz" -mtime +30 -delete

echo "[$(date)] Backup completed successfully: ${BACKUP_FILE}.gz"
```

### 9.3 Scheduled Daily Cron Job
Add to `/etc/cron.d/epcras-backup`:
```cron
0 2 * * * epcras /opt/epcras/scripts/backup.sh >> /var/log/epcras_backup.log 2>&1
```

### 9.4 Restoration Procedure
To restore from backup:
```bash
# Stop application
sudo systemctl stop epcras

# Restore database file
gunzip -c /opt/epcras/backups/epcras_backup_YYYYMMDD_HHMMSS.db.gz > /opt/epcras/app/instance/epcras.db
chown epcras:epcras /opt/epcras/app/instance/epcras.db
chmod 640 /opt/epcras/app/instance/epcras.db

# Restart application
sudo systemctl start epcras
```

---

## 10. Operational Monitoring & Health Checks

### Check System Status
```bash
# Check Gunicorn service status
sudo systemctl status epcras

# View real-time journal logs
sudo journalctl -u epcras -f

# View application logs
tail -f /opt/epcras/app/instance/logs/epcras.log

# View Nginx access & error logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```
