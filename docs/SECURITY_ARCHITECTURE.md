# PHISHGUARD Security Architecture & Hardening Guide

## 1. Threat Model & Security Perimeter

PHISHGUARD processes untrusted, potentially malicious inputs (untrusted URLs, phishing emails, weaponized attachments, QR images). The security architecture enforces defensive controls across six priority layers:

```mermaid
flowchart LR
    subgraph Layer 1: Network & Gateway
        Rate["Rate Limiter"]
        CORS["Strict CORS"]
        Headers["CSP & Sec Headers"]
    end

    subgraph Layer 2: Authentication & AuthZ
        Argon["Argon2id Hash"]
        JWT["HS256 JWT Tokens"]
        IDOR["Scan Ownership Check"]
    end

    subgraph Layer 3: Network Fetch & SSRF
        DNS["DNS Pre-Resolution"]
        IPBlock["Private IP Filter"]
        MetaBlock["Cloud Metadata Filter"]
    end

    subgraph Layer 4: File & Memory Isolation
        SizeCap["10MB Upload Cap"]
        TempIso["Temporary File Isolation"]
        Clean["Post-Scan Cleanup"]
    end

    subgraph Layer 5: Data Persistence & API
        Pydantic["Pydantic Schemas"]
        ORM["SQLAlchemy Parameterization"]
    end

    subgraph Layer 6: AI Prompt Isolation
        Sanitize["Telemetry Sanitizer"]
        SysPrompt["Prompt Injection Guard"]
    end

    Layer 1 --> Layer 2 --> Layer 3 --> Layer 4 --> Layer 5 --> Layer 6
```

---

## 2. Implemented Security Controls

### 2.1 Authentication & Authorization `[IMPLEMENTED]`
- **Password Storage**: Argon2id via `passlib.context.CryptContext(schemes=["argon2"])` with strong parameterization.
- **Complexity Requirements**: Minimum 8 characters; enforced uppercase, lowercase, numeric, and special character requirements.
- **Token Security**: Stateless JWTs with HS256 signatures, `exp` claim (60 minutes), and cryptographically secure secret keys.
- **IDOR Protection**: All scan queries (`GET /api/history/{id}`, `POST /api/chat`) execute tenant isolation checks:
  ```python
  if scan.user_id != current_user.id:
      raise HTTPException(status_code=403, detail="Access forbidden: You do not own this scan resource")
  ```

### 2.2 Server-Side Request Forgery (SSRF) & DNS Rebinding `[IMPLEMENTED]`
- **Pre-Execution IP Resolution**: Target hostnames are resolved via `socket.getaddrinfo()` before any network requests.
- **Reserved IP Blocking**: Evaluated using Python's standard `ipaddress` module:
  - `ip.is_private` (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - `ip.is_loopback` (`127.0.0.0/8`, `::1`)
  - `ip.is_link_local` (`169.254.0.0/16`)
  - `ip.is_reserved` (`0.0.0.0/8`, `240.0.0.0/4`)
  - `ip.is_multicast` (`224.0.0.0/4`)
- **Cloud Metadata Endpoint Blocking**: Explicit hard-coded checks for AWS/GCP/Azure link-local metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- **Redirect Re-Validation**: In `src/features/redirect_analyzer.py`, `is_safe_url()` is invoked at *every* redirect hop before following `Location` headers.

### 2.3 Upload & File Handling `[IMPLEMENTED]`
- **Payload Size Caps**: Maximum file size limited to 10 MB ($10 \times 1024 \times 1024$ bytes); oversized payloads rejected with `413 Request Entity Too Large`.
- **Filename Sanitization**: Uploaded filenames are stripped of path separators (`../`, `..\\`) and replaced with UUID-prefixed temporary hashes.
- **Deterministic Cleanup**: Uploads written to temporary directories are guaranteed deletion in `finally:` blocks after processing.

### 2.4 Browser Security & Security Headers `[IMPLEMENTED]`
Every HTTP response via FastAPI middleware includes:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### 2.5 Cross-Origin Resource Sharing (CORS) `[IMPLEMENTED]`
- Restricted to explicit local development origins (`http://localhost:8000`, `http://127.0.0.1:8000`).
- Wildcards (`*`) are disallowed on authenticated API endpoints.

### 2.6 SQL Injection & Database Isolation `[IMPLEMENTED]`
- All database transactions utilize SQLAlchemy 2.0 ORM with parametrized query building; no raw SQL string concatenation.

### 2.7 AI Prompt Injection Defense `[IMPLEMENTED]`
- User inquiries in `POST /api/chat` are wrapped in a strict system boundary separating analyst prompts from verified JSON scan telemetry.
- Prevents user instructions from overriding system behavioral constraints.

---

## 3. Production Limitations & Remaining Hardening Tasks

| Limitation | Current State | Production Remediation Requirement |
| :--- | :--- | :--- |
| **Distributed Rate Limiting** | In-memory IP dictionary | Migrate to Redis-backed distributed token bucket (`redis-py` / `fastapi-limiter`). |
| **Dynamic Sandbox Detonation** | Static interface only | Provision isolated KVM/QEMU hypervisors with ephemeral snapshot rollbacks. |
| **Secret Management** | Local `.env` / environment | Integrate HashiCorp Vault or AWS/GCP Secret Manager for key rotation. |
| **HTTPS Termination** | Local HTTP (Uvicorn) | Deploy reverse proxy (Nginx, Traefik, or Cloudflare) with automated TLS certificates. |
