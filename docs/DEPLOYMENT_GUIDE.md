# PHISHGUARD Deployment & Operations Guide

## 1. Prerequisites & System Requirements

- **Operating System**: Linux (Ubuntu 22.04 LTS / Debian 12 recommended) or macOS / Windows with WSL2
- **Python Runtime**: Python 3.11 or Python 3.12
- **Memory & Storage**: Minimum 2 GB RAM, 10 GB disk space
- **Network**: Outbound HTTPS (443) for DNS / Threat Intel queries (if enabled)

---

## 2. Local Setup & Execution

### 2.1 Clone Repository & Environment Setup
```bash
git clone https://github.com/your-org/AI-Phishing-Detection.git
cd AI-Phishing-Detection

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 2.2 Configure Environment Variables
Create a `.env` file in the project root:
```env
# Core Application Settings
ENVIRONMENT=production
SECRET_KEY=your_cryptographically_strong_random_secret_key_here_min_32_chars
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Database Configuration (SQLite default; PostgreSQL supported)
DATABASE_URL=sqlite:///./phishguard.db

# Optional Third-Party Threat Intel & LLM Keys
GEMINI_API_KEY=your_google_gemini_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Security Gateway Settings
ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
RATE_LIMIT_PER_MINUTE=60
```

### 2.3 Run Automated Test Suite
Verify that all unit and integration tests pass:
```bash
pytest -v
```

### 2.4 Start the Application
Start FastAPI with Uvicorn:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```
Access the application:
- **Web UI**: `http://localhost:8000/`
- **Interactive API Docs (Swagger UI)**: `http://localhost:8000/docs`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

---

## 3. Production Deployment Architecture

```text
[ Incoming HTTPS:443 ]
          │
          ▼
+─────────────────────────────────────────+
|      Nginx Reverse Proxy & TLS          |
|  - Rate limiting (req_zone)             |
|  - SSL/TLS Termination (Let's Encrypt)  |
|  - Static file caching for frontend/    |
+─────────────────────────────────────────+
          │  Proxy Pass (127.0.0.1:8000)
          ▼
+─────────────────────────────────────────+
|      Uvicorn ASGI Process Pool          |
|  - Managed via Systemd service          |
|  - 4 Gunicorn/Uvicorn worker processes  |
+─────────────────────────────────────────+
          │
          ▼
+─────────────────────────────────────────+
|      PostgreSQL / SQLite Database       |
+─────────────────────────────────────────+
```

### 3.1 Sample Systemd Unit File (`/etc/systemd/system/phishguard.service`)
```ini
[Unit]
Description=PHISHGUARD AI Threat Analysis Platform
After=network.target

[Service]
User=phishguard
Group=phishguard
WorkingDirectory=/opt/phishguard
Environment="PATH=/opt/phishguard/.venv/bin"
EnvironmentFile=/opt/phishguard/.env
ExecStart=/opt/phishguard/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 3.2 Sample Nginx Virtual Host (`/etc/nginx/sites-available/phishguard`)
```nginx
server {
    listen 80;
    server_name phishguard.enterprise.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name phishguard.enterprise.com;

    ssl_certificate /etc/letsencrypt/live/phishguard.enterprise.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phishguard.enterprise.com/privkey.pem;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
