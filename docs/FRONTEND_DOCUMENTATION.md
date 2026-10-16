# PHISHGUARD Frontend Architecture & UI Guide

## 1. Overview & Design Philosophy

The PHISHGUARD user interface is engineered as an enterprise-grade cybersecurity SaaS application built entirely with **Vanilla JavaScript (ES6 Modules), Modern CSS3, and HTML5**.

### Key Design Principles
- **No Heavy SPA Frameworks**: Zero dependencies on React, Vue, or Angular ensures instant load times, zero bundle compilation, and high maintainability.
- **Enterprise Aesthetics**: Clean light backgrounds, modern typography (Inter), cyan/blue status accents, subtle border radii, crisp threat badges, and responsive CSS grid/flex layouts.
- **Defensive Client Architecture**: Strict client-side XSS escaping via `textContent` and `encodeURIComponent`, token handling in `sessionStorage`/`localStorage`, and automated redirect guards on unauthenticated routes.

---

## 2. Directory Layout

```text
frontend/
├── index.html              # Marketing & Enterprise Product Landing Page
├── login.html              # User Authentication Portal
├── signup.html             # User Registration Portal
├── dashboard.html          # Main SOC Analyst Dashboard (Quick Scans & Metrics)
├── analysis.html           # Deep Dive Multi-Layer Inspection & AI Analyst Chat
├── history.html            # Paginated Historical Audit Logs & Search
├── settings.html           # Profile & System Configuration View
├── css/
│   ├── main.css            # Global CSS variables, typography, reset & layout
│   ├── auth.css            # Form card layouts, input focus states & error badges
│   ├── dashboard.css       # KPI metric cards, quick scan forms & threat lists
│   └── analysis.css        # Multi-layer tab navigation, risk meters & AI chat panel
└── js/
    ├── api.js              # Centralized Fetch client with JWT header injection & error toast
    ├── auth.js             # Login, register, token validation & session logout
    ├── dashboard.js        # KPI calculations, recent scans table & trigger actions
    ├── analysis.js         # Layer tab switching, score visualization & AI chat client
    ├── upload.js           # Drag-and-drop file upload handler for attachments/emails
    └── history.js          # Audit log table pagination, filter by risk level & search
```

---

## 3. Key Views & Component Specifications

### 3.1 Marketing Landing Page (`index.html`) `[IMPLEMENTED]`
- Enterprise hero section detailing multi-layer architecture.
- Feature grid highlighting URL, Email, Attachment, and QR analysis capabilities.
- Live security posture metrics and navigation to authentication portals.

### 3.2 Authentication Views (`login.html`, `signup.html`) `[IMPLEMENTED]`
- Responsive auth card with live client-side validation for password complexity.
- Asynchronous API communication via `auth.js` storing JWT in browser session.

### 3.3 Security Operations Dashboard (`dashboard.html`) `[IMPLEMENTED]`
- **KPI Metrics**: Total Scans, High/Critical Threat Count, Clean Domain Ratio, Average Threat Score.
- **Quick Submission Module**: Single-click tabbed inputs for URL scanning, EML file upload, attachment upload, or QR decode.
- **Recent Telemetry Table**: Real-time listing of recent scans with severity badges (LOW, MEDIUM, HIGH, CRITICAL).

### 3.4 Deep Analysis View (`analysis.html`) `[IMPLEMENTED]`
- **Risk Score Gauge**: Visual dial displaying normalized score ($[0, 100]$) and color-coded threat level.
- **Multi-Layer Tabs**:
  - **Overview**: High-level verdict, ML probability, active risk signals, and recommendations.
  - **URL & Domain**: Full lexical feature breakdown, DNS records, TLD info, and brand mismatch indicators.
  - **Email Analysis**: SPF/DKIM/DMARC status, header spoofing alerts, NLP urgency score.
  - **Web & DOM**: Password field detection, external form action targets, iframe inspection.
  - **Attachment**: OLE macro indicators, PE header analysis, file hashes.
- **AI Security Analyst Drawer**: Interactive side panel allowing analysts to query the scan data via `POST /api/chat` with real-time conversational streaming.

### 3.5 History & Audit Logs (`history.html`) `[IMPLEMENTED]`
- Searchable and filterable table of previous scans.
- Filter by threat severity (CRITICAL, HIGH, MEDIUM, LOW) and artifact type.
- Direct links to reload full deep-dive views in `analysis.html?id={id}`.
