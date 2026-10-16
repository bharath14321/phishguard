# PHISHGUARD REST API Documentation

**Base URL**: `http://localhost:8000/api`  
**Authentication Scheme**: HTTP Bearer (Header: `Authorization: Bearer <JWT_TOKEN>`)  
**Format**: `application/json` (or `multipart/form-data` for file uploads)

---

## 1. Authentication Endpoints

### 1.1 Register User `[IMPLEMENTED]`
- **Route**: `POST /api/auth/register`
- **Request Body**:
  ```json
  {
    "email": "analyst@enterprise.com",
    "password": "SecurePassword123!",
    "full_name": "Security Analyst"
  }
  ```
- **Responses**:
  - `201 Created`: User created successfully. Returns user object (without password hash).
  - `400 Bad Request`: Email already registered or password does not meet complexity requirements.

### 1.2 Login & Token Generation `[IMPLEMENTED]`
- **Route**: `POST /api/auth/login`
- **Request Body** (`application/x-www-form-urlencoded` or JSON):
  ```json
  {
    "username": "analyst@enterprise.com",
    "password": "SecurePassword123!"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "token_type": "bearer",
    "expires_in": 3600
  }
  ```

### 1.3 Current User Profile `[IMPLEMENTED]`
- **Route**: `GET /api/auth/me`
- **Headers**: `Authorization: Bearer <JWT>`
- **Response `200 OK`**: Returns authenticated user profile details.

---

## 2. Threat Analysis Endpoints

### 2.1 URL Analysis `[IMPLEMENTED]`
- **Route**: `POST /api/analyze/url`
- **Headers**: `Authorization: Bearer <JWT>`
- **Request Body**:
  ```json
  {
    "url": "http://secure-paypal-verify.com.phish.cc/login"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "id": 142,
    "url": "http://secure-paypal-verify.com.phish.cc/login",
    "risk": {
      "score": 85.0,
      "level": "CRITICAL",
      "signals": [
        {"name": "brand_domain_mismatch", "weight": 20.0, "reason": "A known brand appears inconsistent with the registrable domain.", "source": "brand_intelligence"}
      ]
    },
    "features": {"url_length": 46, "dot_count": 3, "subdomain_count": 2},
    "domain_intelligence": {"hostname": "secure-paypal-verify.com.phish.cc", "tld": "phish.cc"},
    "brand_intelligence": {"detected_brands": ["paypal"], "brand_domain_mismatch": true},
    "webpage_analysis": {"password_field_count": 1, "fetch_success": false},
    "ml": {"model_available": true, "probability": 0.942},
    "created_at": "2026-10-02T23:30:00Z"
  }
  ```

### 2.2 Email RFC 5322 Analysis `[IMPLEMENTED]`
- **Route**: `POST /api/analyze/email`
- **Headers**: `Authorization: Bearer <JWT>`
- **Form Data / Multipart**: `file` (.eml, .msg) OR JSON `{"raw_email": "..."}`
- **Response `200 OK`**:
  ```json
  {
    "risk": {"score": 70.0, "level": "HIGH"},
    "authentication": {"spf": "FAIL", "dkim": "NONE", "dmarc": "FAIL"},
    "nlp": {"urgency_score": 0.85, "detected_triggers": ["account suspension", "verify immediately"]},
    "extracted_urls": ["http://phish-link.cc"]
  }
  ```

### 2.3 Attachment Static Analysis `[IMPLEMENTED]`
- **Route**: `POST /api/analyze/attachment`
- **Headers**: `Authorization: Bearer <JWT>`
- **Form Data**: `file` (Binary upload $\le 10\text{ MB}$)
- **Response `200 OK`**:
  ```json
  {
    "filename": "invoice_october.docm",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "mime_type": "application/vnd.ms-word.document.macroEnabled.12",
    "has_macros": true,
    "risk": {"score": 80.0, "level": "CRITICAL"}
  }
  ```

### 2.4 QR Code (Quishing) Analysis `[IMPLEMENTED]`
- **Route**: `POST /api/analyze/qr`
- **Headers**: `Authorization: Bearer <JWT>`
- **Form Data**: `file` (Image payload)
- **Response `200 OK`**: Decodes embedded URL and returns full URL threat inspection.

### 2.5 Unified Multi-Vector Analysis `[IMPLEMENTED]`
- **Route**: `POST /api/analyze/unified`
- **Headers**: `Authorization: Bearer <JWT>`
- **Request Body**:
  ```json
  {
    "url": "http://phish-domain.com",
    "email_content": "...",
    "attachment_id": null
  }
  ```
- **Response `200 OK`**: Full correlated multi-layer analysis payload including `multi_layer_risk` and `correlated_evidence`.

---

## 3. History & Telemetry Endpoints

### 3.1 List Scan History `[IMPLEMENTED]`
- **Route**: `GET /api/history?limit=50&offset=0`
- **Headers**: `Authorization: Bearer <JWT>`
- **Response `200 OK`**: Paginated array of scan summaries owned by authenticated user.

### 3.2 Get Detailed Scan Resource `[IMPLEMENTED]`
- **Route**: `GET /api/history/{id}`
- **Headers**: `Authorization: Bearer <JWT>`
- **Response `200 OK`**: Full analysis payload for scan `{id}`.
- **Response `403 Forbidden`**: Returned if scan `{id}` belongs to another user (IDOR protection).

---

## 4. AI Security Analyst Chat Endpoint

### 4.1 Debrief & Inquire on Scan `[IMPLEMENTED]`
- **Route**: `POST /api/chat`
- **Headers**: `Authorization: Bearer <JWT>`
- **Request Body**:
  ```json
  {
    "scan_id": 142,
    "message": "Why was this marked as CRITICAL risk and what actions should I take?"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "response": "The scan was classified as CRITICAL (Score: 85.0) because of brand impersonation (PayPal) on an unverified domain with credential collection fields...",
    "scan_id": 142,
    "provider": "gemini-1.5-flash"  // or "deterministic-fallback"
  }
  ```
