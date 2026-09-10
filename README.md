# SENTINEL AI — Enterprise Email Threat, Phishing & Spam SOC Platform

[![Vercel Deployment](https://img.shields.io/badge/Deployment-Vercel-black?logo=vercel)](https://vercel.com)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Security Operations](https://img.shields.io/badge/SOC-Level_3_Threat_Hunting-red.svg)](#)
[![Compliance](https://img.shields.io/badge/Compliance-SOC2_%7C_ISO_27001-green.svg)](#)

> **Enterprise-grade, explainable AI email security platform** designed for real-time phishing detection, cryptographic email authentication verification, multi-hop relay forensics, and executive threat triage.

---

## 🛡️ Core Highlights

- **17-Stage Animated Visual Pipeline**: Live automated forensic pipeline inspecting headers, cryptographic signatures (SPF, DKIM, DMARC), reverse DNS, domain age, TR39 homoglyphs, brand spoofing, URLs, and static attachment payloads.
- **Explainable Multi-Vector Scoring**: Calibrated 0–100 risk scoring with full mathematical transparency (+30 Auth, +25 Sender, +20 URLs, etc.) and human-readable executive threat rationale ("Why Was This Flagged?").
- **3-Column Threat Investigation Workspace**:
  - **Left**: RFC 5322 Metadata & Dynamic SVG Threat Evidence Graph.
  - **Center**: Email Journey Map (hop-by-hop relay telemetry), Cryptographic Authentication Matrix, Sender Reputation, URL Inspection Table with open-redirect testing, Social Engineering Gauges, and SIEM Audit Timeline.
  - **Right**: Glowing Risk Score Gauge, Final Classification Verdict, Auditable Point Breakdown, and Incident Response Playbook.
- **Executive Demo Suite**: 4 pre-calibrated realistic scenario datasets for instant 1-click executive testing (`Phishing`, `Suspicious BEC`, `Spam`, and `Safe`).
- **Reporting & Compliance**: Instant incident audit export to `.txt`, `.json`, and print-ready PDF reports formatted for SOC 2 Type II and ISO 27001 compliance reviews.

---

## 🚀 Quick Start & Deployment

### 1. Run Locally with Python

```bash
# Clone the repository
git clone https://github.com/Crypto0203/sentinel-ai-soc.git
cd sentinel-ai-soc

# Install dependencies
pip install -r requirements.txt

# Start local server
python studio_app.py
```
Open **`http://localhost:5050`** in your browser.

### 2. Deploy to Vercel (1-Click)

This repository includes native Vercel configuration (`vercel.json` and `api/index.py`).

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod
```

---

## 📋 Technology Stack

- **Backend / Engine**: Python 3.11, Flask, `dnspython`, `python-whois`, `dkimpy`, SQLite
- **Frontend**: Vanilla ES6+ JavaScript, CSS3 Glassmorphism, Google Fonts (`Inter`, `JetBrains Mono`)
- **Analytics**: Chart.js for real-time telemetry visualizations
- **Packaging**: PyInstaller for standalone zero-dependency Windows desktop executable (`.exe`)

---

## 🔒 Forensic Verification Checklist

- [x] RFC 5322 MIME Structure Extraction & Unfolding
- [x] Sender Policy Framework (SPF) Authorization
- [x] DomainKeys Identified Mail (DKIM) RSA Public Key Signature Verification
- [x] Domain-based Message Authentication (DMARC) Alignment & Policy Enforcement
- [x] Multi-MTA Server Hop & Reverse DNS (PTR) Geolocation Mapping
- [x] Unicode TR39 Confusable Homoglyph Normalization
- [x] Protected VIP Brand Impersonation Detection (Levenshtein Distance)
- [x] Deep Hyperlink Extraction & Raw IP Host Detection
- [x] Linguistic Panic & Urgent Financial Trap (BEC) Profiling
- [x] Static Attachment Sandboxing (PE Magic Bytes & VBA Macros)
- [x] Auditable Risk Weight Matrix & Incident Response Containment Playbook

---

## 📄 License
Enterprise Commercial License. Developed by Suresh P. (Lead SOC Threat Hunter).
