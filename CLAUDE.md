# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetSec AI Scanner is a network vulnerability scanner with AI-powered threat analysis. It combines Nmap/Scapy/TShark scanning with Google Gemini AI to transform raw network data into actionable security reports.

**Stack**: Python/FastAPI backend + React 19/Vite 7 frontend + Google Gemini 2.5 Flash AI

## Build & Run Commands

### Backend (Python)
```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment (copy .env.example to .env and add GOOGLE_API_KEY)
cp .env.example .env

# Start server (default: http://127.0.0.1:8000)
python server.py

# Run benchmarks (optional, requires Nmap)
python benchmark_tests.py
```

### Frontend (React)
```bash
cd frontend
npm install
npm run dev      # Development server at http://localhost:5173
npm run build    # Production build
npm run lint     # ESLint
```

## Architecture

**4-Stage Pipeline**:
1. **Reconnaissance**: Nmap scans (fast/deep/pen_test modes) → structured JSON
2. **Firewall Intelligence**: Scapy ACK probes with Nmap inference fallback
3. **AI Analysis**: Gemini receives sanitized, token-optimized scan data
4. **Presentation**: React dashboard displays threat reports

**Data Flow**:
```
Nmap scan → vuln extraction → data sanitizer → token optimizer → Gemini API → markdown report
```

## Key Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI endpoints (`/api/scan`, `/api/analyze`, `/health`) |
| `src/scanner/nmap_engine.py` | Scan modes: `fast` (-F), `deep` (-sV --script vuln), `pen_test` (-p-) |
| `src/scanner/scapy_engine.py` | Firewall detection via TCP ACK probes |
| `src/ai_agent/gemini_client.py` | Gemini API integration with model fallback chain |
| `src/utils/data_sanitizer.py` | PII redaction (MACs, emails, passwords, private IPs) |
| `src/utils/token_optimizer.py` | Payload pruning for Gemini context limits |
| `frontend/src/App.jsx` | Entire frontend SPA (single component file) |

## Environment Variables

| Variable | Location | Purpose |
|----------|----------|---------|
| `GOOGLE_API_KEY` | `.env` (root) | Gemini API authentication |
| `VITE_API_URL` | `frontend/.env` | Backend URL (default: `http://localhost:8000`) |

## Technical Notes

### Cloud-Compatible Nmap Settings
The scanner uses `-sT` (Connect Scan) instead of `-sS` (SYN Scan) and omits `-O` (OS detection) because cloud environments (Streamlit, Heroku, GCP) don't allow root access. All scan modes include `-Pn` to skip host discovery.

### Scan Mode Arguments
- `fast`: `-Pn -sT -F` (top 100 ports, ~30s)
- `deep`: `-Pn -sT -sV --version-intensity 5 --script vuln` (~90s)
- `pen_test`: `-Pn -sT -sV --version-intensity 9 -p-` (all ports, ~3min)

### Data Sanitization
All scan data passes through `sanitize_scan_data()` before Gemini API calls. This strips MAC addresses, masks private IPs, and removes credential patterns for privacy-by-design compliance.

### Gemini Model Selection
`gemini_client.py` tries models in order: `gemini-2.5-flash` → `gemini-2.0-flash` → `gemini-flash-latest` → `gemini-pro` (fallback).

## Testing

No formal test framework configured. `benchmark_tests.py` provides manual performance benchmarks for scanning, sanitization, and token optimization.

When adding tests:
- **Python**: Use `pytest`. Run single test: `pytest path/to/test.py::test_function -v`
- **Frontend**: Use `vitest`. Run single test: `npx vitest run path/to/test.jsx -t "test name"`

## Code Style

### Python
- 4-space indent, double quotes, f-strings
- Google-style docstrings with `Args:` and `Returns:`
- Error dicts return `{"error": str(e)}`, validation raises `ValueError`
- Imports: stdlib → third-party → local (use `sys.path.append()` for local imports)

### JavaScript/JSX
- 2-space indent, single quotes for JS, double quotes for JSX attributes
- React 19 hooks, Tailwind CSS with `cyber.*` color tokens
- Component files: `PascalCase.jsx`

## Prerequisites

- Python 3.10+
- Node.js 18+
- Nmap installed and on PATH
- Google Gemini API key
- Scapy/TShark optional (for firewall detection and packet capture)