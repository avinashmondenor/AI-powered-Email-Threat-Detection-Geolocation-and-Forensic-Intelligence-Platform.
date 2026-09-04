# Email Threat Detection & Investigation Platform

A complete end-to-end cybersecurity system designed for automated `.eml` email threat parsing, security indicator extraction, external intelligence enrichment, look-alike domain detection, risk scoring, machine learning classification, and SOC analyst investigation reporting.

---

## Key Features

1. **End-to-End Pipeline**:
   $$\text{Raw Evidence} \longrightarrow \text{Enrichment} \longrightarrow \text{Derived Features} \longrightarrow \text{Risk Assessment}$$
2. **Comprehensive `.eml` Parsing**:
   - Headers: `From`, `To`, `Cc`, `Reply-To`, `Subject`, `Date`, `Received`, `Authentication-Results`, `Received-SPF`, `DKIM-Signature`.
   - Extract URLs from plain text & HTML body.
   - Attachment metadata & SHA-256 calculation (No execution!).
3. **Multi-Vector Analysis**:
   - **Sender & Reply-To**: Mismatch detection (`reply_to_mismatch`).
   - **Authentication**: SPF evaluation, DKIM cryptographic/selector verification, DMARC policy & alignment checks (`PASS`/`FAIL`/`UNKNOWN`). Explicit distinction between `observed` and `independently_verified` sources.
   - **Infrastructure**: Received hop chain route, IP geolocation, ASN, Proxy/VPN/Tor exit node/Hosting datacenter flags.
   - **Look-alike Algorithm**: Custom Levenshtein distance, homoglyph character substitutions (`0` $\to$ `o`, `1` $\to$ `l`), and brand target matching.
   - **Content Analysis**: Urgency cues, credential harvesting, financial/wire requests, executive impersonation.
   - **Attachment Threat**: Macro documents (`.docm`), executables (`.exe`, `.ps1`), double extensions (`.pdf.exe`).
4. **Explainable Risk Engine & ML**:
   - Weighted risk score ($0\text{--}100$) mapped to `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
   - `scikit-learn` Random Forest ML model providing probability metrics and feature importance.
   - Ranked list of human-understandable evidence-backed reasons.
5. **SOC Analyst Investigation Dashboard**:
   - Built with React & Vite in a dark glassmorphic cybersecurity aesthetic.
   - Interactive file dropzone + 1-click sample email test buttons.
   - Visual risk score gauge, hop route timeline, URL inspection table, feature matrix, and Markdown SOC report generator.
6. **SQLite Storage & Mock Mode**:
   - Persistent analysis storage in SQLite (`email_threats.db`).
   - `USE_MOCK_INTELLIGENCE=true` default mode for offline hackathon testing with clearly marked demo tags.

---

## Quick Start Guide

### 1. Install Backend Dependencies & Run Server
```bash
pip install -r requirements.txt
python -m uvicorn backend.main:app --port 8000 --reload
```

Backend endpoints:
- `http://localhost:8000/api/health`
- `http://localhost:8000/docs` (Interactive Swagger OpenAPI Documentation)

### 2. Install Frontend Dependencies & Run React UI
```bash
cd frontend
npm install
npm run dev
```

Frontend App:
- Open `http://localhost:3000` in your browser.

---

## Quick Sample Testing

The platform includes 5 synthetic `.eml` sample test emails in `samples/`:

1. **Phishing & PayPal Lookalike** (`samples/phishing.eml`):
   - Demonstrates look-alike domain `paypa1-security.com` (0.95 similarity), Reply-To mismatch, DMARC failure, Tor exit node IP, credential harvesting URL, `.docm` attachment. (Result: **CRITICAL - 91/100**).
2. **Executive CEO Spoofing** (`samples/spoofed_sender.eml`):
   - Demonstrates CEO wire transfer request, external Reply-To mismatch, SPF fail. (Result: **CRITICAL**).
3. **Suspicious IP & Shortened URL** (`samples/suspicious_url.eml`):
   - Demonstrates raw IP server link (`http://45.142.214.88/`), shorteners (`bit.ly`), urgency text. (Result: **HIGH**).
4. **Executable Attachment** (`samples/suspicious_attachment.eml`):
   - Demonstrates double extension `.Invoice.pdf.exe` attachment and overdue payment threats. (Result: **CRITICAL**).
5. **Legitimate Newsletter** (`samples/legitimate.eml`):
   - Corporate email passing SPF, DKIM, and DMARC with matching domains and clean links. (Result: **LOW**).

---

## Running Unit Tests

Run full Pytest suite:
```bash
python -m pytest
```

---

## REST API Specification

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Upload `.eml` file via multipart/form-data for threat analysis |
| `GET` | `/api/analysis/{id}` | Retrieve stored JSON analysis result by Analysis ID |
| `GET` | `/api/analysis/{id}/report` | Retrieve Markdown SOC Investigation Report |
| `GET` | `/api/samples/{name}` | Quick-run synthetic sample email (`phishing`, `legitimate`, `spoofed_sender`, etc.) |
| `GET` | `/api/history` | List recent analysis records |
| `GET` | `/api/health` | Service health status & mock mode toggle state |
