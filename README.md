# 🛡️ AI-Powered Email Threat Detection & Forensic Intelligence Platform

### Detect • Investigate • Correlate • Explain

An AI-assisted cybersecurity platform that analyzes suspicious emails, extracts technical evidence, enriches indicators with threat intelligence, correlates relationships, and generates an explainable forensic assessment.

---

## 📌 Overview

Traditional email security tools can detect suspicious messages, but investigation often requires collecting and connecting evidence from multiple sources.

Our platform brings this investigation workflow into a single interface:

**Email → Extract → Analyze → Enrich → Correlate → AI → Report**

---

## ❗ Problem

Investigating a suspicious email can require manual analysis of:

- Email headers and authentication
- URLs and domains
- Sending IP and infrastructure
- Attachments
- Threat-intelligence results
- Social-engineering indicators

This can make investigations slower and harder to understand.

---

## 💡 Solution

The platform automatically extracts and analyzes important indicators from a suspicious email, enriches them using external intelligence, connects the evidence, and presents the findings through an investigator-friendly dashboard.

> **Evidence → Intelligence → Explanation**

---

## ✨ Key Features

- 📧 **Email & Header Analysis**
- 🔐 **SPF / DKIM / DMARC Analysis**
- 🌐 **URL & Domain Threat Analysis**
- 🌍 **IP & Infrastructure Intelligence**
- 📎 **Attachment / Hash Analysis**
- 🔗 **Evidence Correlation**
- 🤖 **AI-Assisted Risk Explanation**
- 📊 **Investigation Dashboard**
- 📄 **Forensic Report Generation**

---

## 🔄 How It Works

```text
Suspicious Email
       ↓
Email Ingestion
       ↓
Evidence Extraction
       ↓
Header / URL / Attachment Analysis
       ↓
Threat Intelligence Enrichment
       ↓
Evidence Correlation
       ↓
AI-Assisted Analysis
       ↓
Risk Assessment
       ↓
Forensic Report
```

---

## 🏗️ System Architecture

```text
                    ┌──────────────────────┐
                    │    Suspicious Email  │
                    │       (.eml)         │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Email Ingestion    │
                    │   & MIME Parsing     │
                    └──────────┬───────────┘
                               │
                               ▼
                 ┌─────────────────────────────┐
                 │     Evidence Extraction    │
                 └─────────────┬───────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
 ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
 │ Header Analysis │  │ URL & Domain    │  │  Attachment     │
 │ SPF/DKIM/DMARC  │  │ Analysis        │  │  Analysis       │
 └────────┬────────┘  └────────┬────────┘  └────────┬────────┘
          │                    │                    │
          └────────────────────┼────────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Threat Intelligence  │
                    │ IP / URL / Domain     │
                    │ Reputation & Enrich.  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Evidence Correlation │
                    │ Email → URL → IP →   │
                    │ ASN / Infrastructure │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ AI-Assisted Analysis │
                    │ & Risk Assessment    │
                    └──────────┬───────────┘
                               │
                               ▼
              ┌─────────────────────────────────┐
              │       Investigation Dashboard  │
              │       + Forensic Report         │
              └─────────────────────────────────┘
```

### Architecture Flow

**Input → Extraction → Analysis → Enrichment → Correlation → AI → Report**


## 🔍 Investigation Evidence

The platform connects related indicators instead of showing them as isolated results.

```text
Email
  ↓
Sender Domain
  ↓
Embedded URL
  ↓
Resolved IP
  ↓
ASN / Infrastructure
  ↓
Approximate Location
  ↓
Threat Intelligence



## 🤖 AI-Assisted Analysis

The AI layer uses the collected investigation evidence to provide an explainable assessment.

Example:

```text
Risk Level: HIGH

Reasons:
• Suspicious sender/domain relationship
• Suspicious URL characteristics
• Authentication anomaly
• Threat-intelligence indicators
• Social-engineering signals
```

The AI supports the investigator rather than replacing human investigation.

---

## 🧰 Technology Stack

## 🧰 Technology Stack

### ⚙️ Backend
**Python • FastAPI • Celery • Redis**

### 🔎 Forensics
**dkimpy • dnspython • Authentication Results**

### 🤖 Machine Learning
**ONNX Runtime • DistilBERT**

### 🗄️ Data & Correlation
**PostgreSQL • NetworkX**

### 🎨 Frontend
**React • Tailwind CSS • Leaflet • Cytoscape**

### 🐳 Deployment
**Docker Compose**

---

## 📁 Project Structure


### One small recommendation

You **shouldn't show `node_modules/` and `dist/`** in the README because they are generated folders and make the structure look unnecessarily large.

So the cleaner version I'd recommend is:

```markdown
## 📁 Project Structure

```text
project/
├── backend/
│   ├── services/
│   ├── config.py
│   ├── database.py
│   └── main.py
│
├── frontend/
│   ├── src/
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
├── samples/
│   ├── legitimate.eml
│   ├── phishing.eml
│   ├── spoofed_sender.eml
│   ├── suspicious_attachment.eml
│   └── suspicious_url.eml
│
├── tests/
├── .env.example
├── .gitignore
├── email_threats.db
├── requirements.txt
└── README.md

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd <PROJECT-NAME>

### 2. Backend

```cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

### 4. Environment Variables

Create a `.env` file using `.env.example` and add the required API configuration.

**Never commit API keys or secrets to GitHub.**

---

## 🔬 Example Investigation

A suspicious email is uploaded.

The platform:

1. Extracts headers and indicators
2. Checks SPF, DKIM and DMARC
3. Extracts URLs and domains
4. Enriches IP/domain information
5. Correlates the evidence
6. Generates an explainable risk assessment
7. Produces a forensic report

---

## 🎯 Innovation

The core focus is not creating another standalone phishing classifier.

The platform focuses on **automating the investigation workflow** by connecting:

**Extraction + Threat Intelligence + Correlation + AI Explanation + Reporting**

This helps investigators move from simply detecting a suspicious email to understanding the evidence behind it.

---

## ⚠️ Limitations

- Threat intelligence depends on available external data.
- A zero-detection reputation result does not guarantee safety.
- IP geolocation represents approximate infrastructure location.
- Newly created domains may have limited historical intelligence.
- AI assessment should be treated as decision support.

---

## 🔮 Future Scope

- Cross-email campaign correlation
- Advanced phishing-language analysis
- Historical investigation database
- SIEM / SOC integration
- Improved IOC correlation
- Automated incident-report generation

---

## 📚 References

## 📚 References & Data Sources

- [APWG — Phishing Activity Trends Reports](https://apwg.org/trendreports)
- [PhishTank — Phishing URL Database & API](https://www.phishtank.org/)
- [AbuseIPDB — IP Reputation Database & API](https://www.abuseipdb.com/)
- [VirusTotal — Threat Intelligence & API Documentation](https://docs.virustotal.com/docs/api-overview)
- [Enron Email Dataset — CMU](https://www.cs.cmu.edu/~enron/)
- [Nazario Phishing Corpus](https://monkey.org/~jose/phishing/)
- [RFC 5322 — Internet Message Format](https://www.rfc-editor.org/rfc/rfc5322.html)
- [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208.html)
- [RFC 6376 — DomainKeys Identified Mail (DKIM)](https://www.rfc-editor.org/rfc/rfc6376.html)
- [RFC 9989 — Domain-Based Message Authentication, Reporting & Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc9989.html)
- [ICANN — Registration Data Access Protocol (RDAP)](https://www.icann.org/rdap/)
- [Google — Email Sender Guidelines](https://support.google.com/mail/answer/81126)

---

---

## 🛡️ From Detection to Investigation

> **Detecting a suspicious email is only the beginning. Understanding the evidence behind it is the real investigation.**

### Evidence → Intelligence → Correlation → Explanation → Forensic Report
