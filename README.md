# 🛡️ NetSec AI Scanner
> *Automated Network Vulnerability Scanning & AI-Powered Intelligence Analysis*

![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Node](https://img.shields.io/badge/Node-20%2B-339933?style=for-the-badge&logo=node.js)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)

![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi)
![React](https://img.shields.io/badge/React-19.2.4-61dafb?style=for-the-badge&logo=react)
![Gemini](https://img.shields.io/badge/Google%20Gemini%202.5-8E75B2?style=for-the-badge&logo=google)

---

## 🚩 Problem Statement
Network security tools generate high-fidelity data, but the output is often too cryptic for non-experts to act on quickly. Critical services remain exposed because remediation guidance is unclear or buried in raw logs.

---

## 💡 The Solution
**NetSec AI** turns raw network telemetry into clear, actionable security guidance:
1.  **Scans** the network using industry-standard engines (Nmap & Scapy).
2.  **Analyzes** the raw logs using **Google Gemini 2.5 Flash**.
3.  **Translates** technical jargon into a concise remediation report.

It turns *"Port 445 Open (Microsoft-DS)"* into *"High Risk: Your file sharing service is exposed. Block it using this firewall command..."*

---

## ✅ Why NetSec AI Scanner?
- **Signal over noise**: Nmap provides high-quality data; Gemini turns it into prioritized, plain-language remediation steps.
- **Actionable by design**: Findings are formatted for quick fixes, not just diagnostics.
- **Security-grade workflow**: Sanitization, token optimization, and strict input validation are built in.
- **Modern UX**: Real-time progress and reports through a React interface.

---

## ⚙️ Architecture & How It Works

The application is built on a modern **Full-Stack Architecture**:

```mermaid
flowchart LR
  A["Frontend (Vercel)"] --> B["Backend (GCP VM)"]
  B --> C[Nmap Engine]
  C --> D[Gemini API]
  D --> E[Result / Report]
  E --> A
```

### Backend Stack (FastAPI)
- **Server**: FastAPI with Uvicorn ASGI server
- **Scanning Engines**: Nmap, Scapy, TShark integration
- **AI Analysis**: Google Gemini 2.5 Flash for intelligent threat assessment
- **API**: RESTful endpoints for network scanning and threat analysis

### Frontend Stack (React + Vite)
- **Framework**: React 19.2.4 with modern hooks
- **Build Tool**: Vite 7.3.1 for fast development
- **Styling**: Tailwind CSS for responsive design
- **Animations**: Framer Motion for interactive UI
- **Visualization**: Particle network effects and threat dashboards

### 4-Stage Intelligence Pipeline

#### 1. **Reconnaissance (Network Scanning)**
- **Nmap Engine**: Performs comprehensive port scanning, service version detection, OS fingerprinting
- **Scapy Engine**: Custom firewall detection using TCP ACK packet injection
- **TShark Capture**: Optional packet-level analysis for advanced diagnostics
- **Output**: Structured JSON with port states, services, and vulnerability metadata

#### 2. **Firewall Intelligence (Dual-Engine Approach)**
- **Primary**: Scapy-based ACK packet analysis to determine firewall state
- **Fallback**: Intelligent Nmap output inference if Scapy fails (port state patterns, filtered port analysis)
- **Confidence Scoring**: Risk assessment based on open, filtered, and closed port combinations
- **Output**: Firewall detection results with confidence levels and port breakdowns

#### 3. **AI Analysis (Threat Intelligence)**
- **Model**: Google Gemini 2.5 Flash for contextual threat analysis
- **Input**: Sanitized scan data (PII removed by data_sanitizer.py)
- **Processing**: AI correlates open ports with known CVEs, exploitation risks, and business impact
- **Output**: Executive-grade threat report with CVSS scores and remediation steps

#### 4. **Presentation & Insights (React Dashboard)**
- **Real-time Display**: Live scan progress with threat indicators
- **Threat Metrics**: CVSS scoring, risk severity categorization
- **Actionable Reports**: Clear remediation steps and firewall rules

---

## 🔧 Google Technologies Integrated

### **Google Gemini 2.5 Flash** (Threat Intelligence Engine)
| Component | Details |
|-----------|---------|
| **Purpose** | AI-powered threat analysis and vulnerability assessment |
| **Capabilities** | Context-aware analysis of scan data, CVE correlation, remediation guidance |
| **Implementation** | [src/ai_agent/gemini_client.py](src/ai_agent/gemini_client.py) |
| **Prompting** | Specialized security analysis prompts in [src/ai_agent/prompts.py](src/ai_agent/prompts.py) |
| **Integration** | Real-time API calls via `google-generativeai` SDK (v0.8.6+) |

## 📂 Project Directory Structure

```
NetSec_AI_Scanner/
│
├── 📄 server.py                    # FastAPI entry point (core backend)
├── 📄 requirements.txt             # Python dependencies
├── 📄 README.md                    # This file
├── 📄 .env                         # Environment variables (API keys, credentials)
├── 📄 .gitignore                   # Git ignore rules
│
├── 📁 config/                      # Configuration & Credentials
│   ├── settings.py                 # Application configuration
│   └── __init__.py
│
├── 📁 src/                         # Core Application Source Code
│   │
│   ├── ai_agent/                   # AI/Intelligence Module
│   │   ├── gemini_client.py        # Google Gemini API integration
│   │   ├── check_models.py         # Model availability checker
│   │   ├── report_generator.py     # Threat report generation
│   │   └── prompts.py              # AI system prompts & instructions
│   │
│   ├── scanner/                    # Security Scanning Module
│   │   ├── nmap_engine.py          # Nmap port scanning orchestration
│   │   ├── scapy_engine.py         # Firewall detection (ACK packets)
│   │   ├── tshark_capture.py       # Packet capture analysis
│   │   └── vuln_checker.py         # Vulnerability pattern extraction
│   │
│   └── utils/                      # Utility Functions
│       ├── data_sanitizer.py       # PII redaction & data privacy
│       ├── token_optimizer.py      # API token optimization
│       ├── validators.py           # Input validation
│       └── __init__.py
│
└── 📁 frontend/                    # React Frontend Application
    ├── index.html                  # HTML entry point
    ├── package.json                # npm dependencies (React 19.2.4, Vite 7.3.1)
    ├── package-lock.json           # Lock file for reproducible builds
    ├── vite.config.js              # Vite build configuration
    ├── tailwind.config.js          # Tailwind CSS configuration
    ├── postcss.config.js           # PostCSS configuration
    ├── eslint.config.js            # Code quality configuration
    │
    ├── src/                        # React Source Code
    │   ├── main.jsx                # React entry point
    │   ├── App.jsx                 # Main application component
    │   ├── App.css                 # Application styles
    │   ├── index.css               # Global styles
    │   │
    │   ├── components/             # React Components
    │   │   └── ParticleNetwork.jsx # Interactive particle visualization
    │   │
    │   └── assets/                 # Static assets
    │
    └── public/                     # Static files served as-is

```

### **Notes on Directory Structure:**
- ✅ **Committed to Git**: All source code, configuration templates, documentation
- ❌ **Not Committed** (.gitignore): `node_modules/`, `__pycache__/`, `.venv/`, `logs/`, `.env` (use template)
- 🔐 **Security**: API keys and backend URLs are never committed to the repository
- 🚀 **Production Ready**: Modular architecture, separated frontend/backend, clear concerns

---

## 💻 Local Development Setup

Follow these steps to get the NetSec AI Scanner running on your local machine for development and testing.

### Prerequisites

- **Python 3.12+** (Tested with Python 3.12.6)
- **Nmap** - Network scanning engine
  - **Windows**: Download from [nmap.org](https://nmap.org/download.html) and ensure **Npcap** is installed during setup
  - **Linux**: `sudo apt install nmap` (Debian/Ubuntu) or `sudo yum install nmap` (RHEL/CentOS)
  - **macOS**: `brew install nmap`
- **Npcap/libpcap** - Required for Scapy packet injection
  - **Windows**: Installed with Nmap (check the Npcap option)
  - **Linux/macOS**: Usually pre-installed with Nmap
- **Node.js 18+** and **npm** - For frontend development

### Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/NetSec_AI_Scanner.git
cd NetSec_AI_Scanner
```

#### 2. Backend Setup (Python)

Create a Python virtual environment:
```bash
python -m venv .venv

# Windows
.\.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Install Python dependencies:
```bash
pip install -r requirements.txt
```

#### 3. Environment Configuration

You need to configure environment variables for both backend and frontend.

Use the provided templates:
- Backend: `backend/.env.example`
- Frontend: `frontend/.env.example`

Create your local `.env` files by copying the examples and filling in values.

> **Note:** For production deployment, `VITE_API_URL` should point to your production backend URL.

#### 4. Frontend Setup (React) - Optional

If developing the frontend:
```bash
cd frontend
npm install
npm run dev
```

The frontend will be served at `http://localhost:5173`

### Running the Application

#### Start the Backend Server
```bash
python server.py
```

The API will be available at `http://localhost:8000`

**Available Endpoints:**
- `POST /api/scan` - Start a new network scan
- `GET /api/health` - Health check endpoint
- View full API docs at `http://localhost:8000/docs` (Swagger UI)

#### Start the Frontend (Development)
```bash
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser.

---
## ✨ Key Features

- **🎯 Intelligent Scanning**: Combines Nmap, Scapy, and TShark for comprehensive network analysis
- **🤖 AI-Powered Analysis**: Google Gemini 2.5 Flash correlates vulnerabilities with real-world exploits
- **🔐 Firewall Detection**: Dual-engine approach with fallback inference for robust firewall identification
- **📊 Executive Reports**: Clear, actionable threat reports with remediation guidance
- **🎨 Modern UI**: React-based dashboard with real-time visualization
- **📈 Threat Scoring**: CVSS-based severity assessment for all discovered vulnerabilities
- **🔒 Privacy-First**: PII redaction in all scanned data before AI analysis

---

## 🔌 API Usage Examples

### Start a Network Scan
```bash
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.0/24",
    "scan_type": "comprehensive",
    "enable_firewall_detection": true
  }'
```

### Response
```json
{
  "scan_id": "scan_abc123",
  "status": "running",
  "target": "192.168.1.0/24",
  "scan_type": "comprehensive",
  "started_at": "2026-01-31T03:18:34.065Z"
}
```

### Check Server Health
```bash
curl "http://localhost:8000/api/health"
```

### View API Documentation
Visit `http://localhost:8000/docs` for interactive Swagger UI documentation of all endpoints.

---
## 🧰 Technology Stack

### Backend
- **Framework**: FastAPI 0.128.0 (Async web framework)
- **Server**: Uvicorn 0.40.0 (ASGI server)
- **Scanning Tools**: 
  - `python-nmap` - Network reconnaissance
  - `scapy` 2.7.0 - Packet crafting & firewall testing
  - TShark - Packet capture analysis
- **AI Integration**: `google-generativeai` 0.8.6 (Gemini 2.5 Flash)
- **Data Processing**: requests
- **Environment**: `python-dotenv` for configuration

### Frontend
- **Framework**: React 19.2.4
- **Build Tool**: Vite 7.3.1
- **Styling**: Tailwind CSS 3.4
- **Animation**: Framer Motion
- **Code Quality**: ESLint, PostCSS
- **Package Manager**: npm

### Cloud Services (Google)
- **Gemini 2.5 Flash** - Threat intelligence

---

## 🌐 Production Deployment

### Live Application
**Frontend:** [https://netsec-ai-scanner.vercel.app/](https://netsec-ai-scanner.vercel.app/)

### Architecture Overview
The **NetSec AI Scanner** is deployed using a secure, hybrid cloud architecture:

#### Frontend Deployment
- **Platform:** [Vercel](https://vercel.com/)
- **SSL/TLS:** Automatic HTTPS with Vercel's edge network
- **Build:** Vite production build with optimized assets
- **CDN:** Global content delivery for low-latency access

#### Backend Deployment
- **Platform:** Google Cloud Platform (GCP)
- **Instance Type:** `e2-micro` (Always Free Tier)
- **Region:** `us-central1-a` (Iowa, USA)
- **Operating System:** Ubuntu Server with Nginx reverse proxy
- **SSL/TLS:** Let's Encrypt certificates managed via Certbot
- **Domain Strategy:** Using `.nip.io` wildcard DNS for SSL certificate validation
- **Optimization:** Configured with 2GB swap file to handle network scanning on 1GB RAM

#### Security Features
- **End-to-End Encryption:** All communication encrypted via SSL/TLS (HTTPS)
- **CORS Policy:** Backend API access restricted to authorized frontend origins
- **Environment Isolation:** Production credentials managed via secure environment variables
- **No Hardcoded Secrets:** Backend URL and API keys never committed to repository

#### Infrastructure Highlights
- **Zero-Cost Deployment:** Leveraging GCP Always Free Tier + Vercel free hosting
- **24/7 Availability:** Both frontend and backend run continuously
- **SSL Verification:** Green lock in browsers - no "Mixed Content" warnings
- **API Documentation:** Interactive Swagger UI available at backend `/docs` endpoint

### Backend Configuration
The frontend communicates with the FastAPI backend via the `VITE_API_URL` environment variable.

- **Production:** Backend URL is configured securely via environment variables (not exposed publicly)
- **Local Development:** `http://localhost:8000`

> **Security Note:** The production backend URL is intentionally not published in documentation to prevent unauthorized access and potential abuse of scanning capabilities.

---

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📧 Contact

For questions or support, please open an issue in the repository.