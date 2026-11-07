# TRUSTX AI — Intelligent Web Security & Collaborative Threat Intelligence Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![FastAPI](https://img.shields.io/badge/FastAPI-2.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![SHAP](https://img.shields.io/badge/SHAP-Explainable_AI-764ABC?style=for-the-badge)
![Chrome](https://img.shields.io/badge/Chrome-Extension_MV3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)

An advanced web security and collaborative threat intelligence platform designed to detect phishing websites, malicious URLs, brand lookalikes, fraudulent payment portals, and certificate vulnerabilities using AI inference, DNS/RDAP intelligence, and unified trust scoring.

</div>

---

## 🌟 Platform Highlights

TRUSTX AI goes beyond basic binary safe/malicious classification. It correlates **ten synchronized intelligence modules** into an explainable **0–100 Unified Trust Score** with deterministic risk tiers and actionable guidance:

- **Module A: Advanced Phishing Engine** — Machine learning inference (36 features) + Levenshtein typosquatting distance against top 500 protected brands + URL obfuscation & zero-width character detection.
- **Module B: Domain & DNS Intelligence** — Authoritative DNS resolution (A, AAAA, MX, NS, TXT) + RDAP provenance auditing (creation date, registrar, expiration, age in days).
- **Module C: SSL/TLS Certificate Intelligence** — Live TLS socket handshake + x509 chain verification + crt.sh Certificate Transparency logs + untrusted root / eMudhra incident compliance monitoring.
- **Module D: Website Security Assessment** — Safe, non-invasive audit of HTTP headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), cookie security flags (`Secure`, `HttpOnly`, `SameSite`), and redirect chains.
- **Module E: Visual Brand Impersonation** — Protected brand profile matching, claimed entity vs. host domain correlation, and credential harvesting form alerts.
- **Module F: Collaborative Threat Intelligence** — Community crowdsourcing with upvoting/downvoting, URLhaus threat feed correlation, and IOC database.
- **Module G: AI Security Investigation Agent** — Concurrent multi-module orchestrator synthesizing evidence-grounded reports without hallucinations.
- **Module H: QR Code Phishing Scanner** — Computer vision QR decoder (OpenCV / pyzbar), payload URL unshortening, and automated deep investigation.
- **Module I: Threat Relationship Graph** — Interactive node-link network visualizer mapping shared hosting IPs, nameservers, MX exchanges, and certificate authorities.
- **Module J: Chrome Browser Protection Extension** — Manifest V3 real-time background protection, animated in-DOM warning banners, and popup dashboard.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TRUSTX AI Architecture                          │
├─────────────────┬──────────────────┬─────────────────┬─────────────────┤
│ Chrome          │ React 19         │ FastAPI         │ Intelligence    │
│ Extension       │ Dashboard        │ Backend         │ Services        │
│                 │                  │                 │                 │
│ Manifest V3     │ Home / Overview  │ /investigate    │ Multi-Model ML  │
│ Tab Auto-Scan   │ Scanner          │ /qr/scan        │ Typosquatting   │
│ DOM Banners     │ Deep Report      │ /threat-intel   │ RDAP & DNS      │
│ Trust Score     │ QR Code Studio   │ /community      │ TLS & crt.sh    │
│ Deep Links      │ Threat Graph     │ /predict        │ Trust Engine    │
│ Notifications   │ History/Analytics│ /history        │ Threat Graph    │
└─────────────────┴──────────────────┴─────────────────┴─────────────────┘
```

---

## 🎯 Unified Trust Score Engine (0–100)

| Trust Score | Risk Classification | Interpretation |
| :--- | :--- | :--- |
| **80 – 100** | **Low Observed Risk** | Established provenance, valid TLS, clean threat feeds, trusted entity |
| **50 – 79** | **Moderate Risk** | Missing security headers, young domain age, proceed with caution |
| **25 – 49** | **High Risk** | Typosquatting lookalike, suspicious redirects, anomalous URL structure |
| **0 – 24** | **Critical Threat** | Confirmed phishing, active URLhaus hit, blacklisted, brand clone |

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.11+**
- **Node.js 18+** & npm
- **Google Chrome** (for browser extension)

### 1. Start the Backend API (Port 8000)
```bash
# Windows bat launcher:
start_backend.bat

# Or manually:
cd backend
python main.py
```
- API Base: `http://localhost:8000`
- Interactive Swagger Documentation: `http://localhost:8000/docs`

### 2. Start the Frontend Dashboard (Port 5173)
```bash
# Windows bat launcher:
start_frontend.bat

# Or manually:
cd frontend
npm install
npm run dev
```
- Web Application: `http://localhost:5173`

### 3. Load the Chrome Browser Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** toggle in the top-right corner.
3. Click **Load unpacked** and select the folder:
   ```text
   extension
   ```
   (or the absolute path `<project-root>/extension`)

---

## 📡 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/investigate` | Complete 10-step investigation workflow (Trust Score, DNS, SSL, Headers, Recommendations) |
| `GET` | `/investigation/{id}` | Retrieve previously stored investigation report |
| `POST` | `/qr/scan` | Upload and decode QR code image, extract payload, and trigger investigation |
| `GET` | `/threat-intel/graph/{domain}` | Generate interactive Threat Relationship Graph node-edge payload |
| `GET` | `/threat-intel/summary` | Aggregated community reports and URLhaus telemetry |
| `POST` | `/community/vote` | Upvote or downvote reported threat to establish community consensus |
| `POST` | `/predict` | Legacy baseline ML classification endpoint |
| `GET` | `/history` | Paginated scan history with risk level filters |
| `POST` | `/report` | Submit community threat report |
| `GET` | `/health` | API and model health status |

---

## 🛡️ Machine Learning Baseline Performance

Evaluated using 5-fold stratified cross-validation on 36 engineered URL features:

| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression** (Production Best) | **99.7%** | **99.6%** | **99.8%** | **99.7%** | **99.99%** |
| Random Forest | 99.7% | 99.6% | 99.8% | 99.7% | 100.0% |
| SVM | 99.7% | 99.6% | 99.8% | 99.7% | 100.0% |
| XGBoost | 99.65% | 99.6% | 99.7% | 99.65% | 100.0% |

---

## 📜 License
MIT License
