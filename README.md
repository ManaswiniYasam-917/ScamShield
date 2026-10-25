# ScamShield Enterprise — Autonomous Cyber Fraud & AI Threat Defense Platform

An enterprise-grade, multi-engine cybersecurity platform for detecting fake e-commerce websites, credential phishing, quishing (QR phishing), and brand impersonation. 

Built with **FastAPI**, **SQLite (WAL mode)**, **Scikit-Learn**, **PyTorch Deep Learning**, and an ultra-modern cyber-glassmorphic frontend.

---

## 🚀 Key Highlights & Advanced Features

### 1. Multi-Engine AI / ML / DL Fraud Detection
- **Scikit-Learn Machine Learning Ensemble**: Random Forest and Gradient Boosting classifier trained on 28 lexical, syntactic, structural, and Shannon entropy features.
- **PyTorch Deep Learning Neural Core**: Character-level Multi-Scale 1D-CNN + Bidirectional GRU (BiGRU) sequence neural network classifying raw URL character n-grams and token transitions.
- **Explainable AI (XAI)**: Visual breakdown of top SHAP-style feature contributions and high-risk token subsequences.
- **Heuristic & Multi-Signal Fusion**: Blends Rule heuristics, ML ensemble probabilities, Deep Learning activations, and Threat Intelligence into a composite 0–100 Scam Risk Index.

### 2. Quishing (QR Code) Optical Shield
- Decodes optical QR codes and barcodes using computer vision (`cv2.QRCodeDetector` + PIL).
- Automatically extracts destination URLs and executes full multi-engine neural fraud audits on the target link.

### 3. Brand Protection & Typosquatting Matrix
- Defends against typosquatting, compound subdomain nesting, and Cyrillic/Greek IDN homoglyph substitution attacks against 50+ major brands (Amazon, PayPal, Apple, Netflix, Microsoft, Google, Chase, Binance, Steam, DHL, FedEx, etc.).

### 4. Batch URL Security Matrix
- Asynchronous parallel scanning engine that audits up to 50 URLs simultaneously with aggregated statistics and exportable JSON audit records.

### 5. Enterprise Authentication & Role-Based Access Control (RBAC)
- Full JWT authentication (HS256) with PBKDF2-SHA256 password hashing.
- Role-based permissions (`admin`, `analyst`, `user`).
- Developer API key management with 1-click clipboard copy.
- 1-Click Instant Demo Login for effortless reviewer evaluation (`Admin`, `Analyst`, `User`).

### 6. Community Threat Vault & Live Scam Radar
- Crowdsourced fraud report submission with severity tagging, category filtering, and community upvotes.
- Pre-seeded local domain reputation database with high-abuse TLD monitoring.

### 7. Executive Cyber Security Audit Dossiers (PDF)
- ReportLab generated PDF audits featuring classification badges, cryptographic hash stamps, multi-engine technical telemetry, SSL handshake forensics, and actionable mitigation guidance.

### 8. Security Operations Center (SOC) Analytics
- Real-time telemetry: Daily scan volumes, top flagged domains, AI engine performance metrics, and immutable SQLite audit trail logs.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Backend API** | Python 3.10+, FastAPI, Uvicorn, Pydantic v2 |
| **Machine Learning** | Scikit-Learn (Random Forest, Gradient Boosting), Joblib, NumPy |
| **Deep Learning** | PyTorch 2.x (Character 1D-CNN + BiGRU Neural Network) |
| **Computer Vision** | OpenCV (`cv2.QRCodeDetector`), Pillow (PIL) |
| **Database & Security** | SQLite3, PyJWT, Cryptography, Hashlib PBKDF2 |
| **Network & Forensics** | Requests, BeautifulSoup4, Python-WHOIS, SSL, Socket, dnspython |
| **Reporting** | ReportLab Enterprise PDF generation |
| **Frontend** | Vanilla JavaScript, Modern CSS Glassmorphism, Semantic HTML5 |

---

## ⚡ Quick Start on Windows

### 1. Start the FastAPI Backend

Open a PowerShell terminal in the project directory:

```powershell
cd ScamShield_Advanced\backend
python -m pip install -r requirements.txt
python train_models.py       # Trains and compiles model.joblib and dl_model.pt (pre-bundled!)
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### 2. Start the Frontend Server

Open a second terminal window:

```powershell
cd ScamShield_Advanced\frontend
python -m http.server 5500 --bind 127.0.0.1
```

### 3. Open in Browser

- **Frontend Application**: [http://127.0.0.1:5500/](http://127.0.0.1:5500/)
- **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check & AI Telemetry**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

## 👥 Demo Credentials (Pre-Seeded)

For testing and demonstration, 1-Click buttons are provided in the UI, or you can sign in directly:

| Role | Email | Password |
|---|---|---|
| **Security Operations Lead (Admin)** | `admin@scamshield.io` | `Admin@12345` |
| **Cyber Threat Analyst** | `analyst@scamshield.io` | `Analyst@12345` |
| **Verified Consumer (User)** | `user@scamshield.io` | `User@12345` |

---

## 📡 Core API Endpoints

- `POST /api/scan` — Comprehensive single URL AI fraud scan.
- `POST /api/scan/batch` — Concurrently scan up to 50 URLs.
- `POST /api/scan/qr` — Upload and decode optical QR code image, then analyze target URL.
- `POST /api/brand/check` — Standalone brand typosquatting & homoglyph analysis.
- `GET /api/scans` — Scan history with pagination.
- `GET /api/reports/{scan_id}.pdf` — Download official Cyber Security Audit Dossier PDF.
- `POST /api/auth/login` — Authenticate and receive JWT access token.
- `POST /api/auth/demo-login` — 1-click role switcher.
- `GET /api/threats/community` — Community reported scam feeds.
- `POST /api/threats/report` — Submit a new scam URL with incident notes.
- `GET /api/admin/overview` — SOC dashboard analytics and threat patterns.
- `GET /api/admin/audit-logs` — Security audit logs.
