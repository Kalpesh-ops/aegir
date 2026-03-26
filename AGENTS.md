# AGENTS.md — NetSec AI Scanner

## Project Overview

Network security scanner with Python/FastAPI backend and React/Vite frontend.
Backend orchestrates Nmap, Scapy, and TShark scans, sends results to Google Gemini
for AI-powered security analysis. Frontend is a cyberpunk-themed SPA dashboard.

## Repository Layout

```
server.py                  # FastAPI entry point (/scan POST, /health GET)
config/settings.py         # Constants (unused — values hardcoded elsewhere)
src/scanner/               # Nmap, Scapy, TShark scanning engines
src/ai_agent/              # Gemini client, prompts, report generator
src/utils/                 # Data sanitizer, token optimizer, validators
benchmark_tests.py         # Manual performance benchmarks (exits 1 on failure)
requirements.txt           # Python deps
frontend/src/App.jsx       # Entire SPA UI
frontend/src/components/   # ParticleNetwork.jsx (Three.js background)
```

## Build & Run Commands

### Backend
```bash
pip install -r requirements.txt
python server.py                    # FastAPI server (127.0.0.1:8000)
python benchmark_tests.py           # Full benchmark suite
python -c "from benchmark_tests import fn; fn()"  # Single benchmark
```

### Frontend
```bash
cd frontend
npm install
npm run dev                         # Dev server (0.0.0.0:5173)
npm run build                       # Production build
npm run preview                     # Preview production build
npm run lint                        # ESLint
```

### Testing
No formal test framework configured. If adding tests:
- **Python**: `pytest path/to/test.py::test_function -v`
- **Frontend**: `npx vitest run path/to/test.jsx -t "test name"`

## Linting & Formatting

| Tool   | Scope    | Status                                  |
|--------|----------|-----------------------------------------|
| ESLint | Frontend | Configured (`frontend/eslint.config.js`)|
| Prettier| Frontend| Not configured                         |
| Ruff   | Python   | Not configured                         |
| mypy   | Python   | Not configured                          |

ESLint rules: `no-unused-vars` error (`varsIgnorePattern: '^[A-Z_]'`), React Hooks, React Refresh.

## Code Style

### Python

**Imports** (order by group, no blank lines between):
1. Standard library (`os`, `sys`, `re`, `logging`, `enum`)
2. Third-party (`fastapi`, `pydantic`, `nmap`, `scapy`)
3. Local project (`src.scanner.*`, `src.ai_agent.*`, `src.utils.*`)

Note: `server.py` and `benchmark_tests.py` use `sys.path.append()` for local imports.

**Naming**: `snake_case` files/funcs, `PascalCase` classes, `_underscore` private,
`UPPER_SNAKE_CASE` constants, `EnumClass.snake_case` enum members.

**Formatting**: 4-space indent, double quotes, f-strings, ~120 char lines,
2 blank lines between top-level definitions.

**Docstrings**: Google-style with `Args:`/`Returns:`. One-line minimum for public functions.

**Error handling**: `try/except` with `logging.error()`, return `{"error": str(e)}`
from scanner/utility functions, raise `ValueError` for validation, `HTTPException`
for FastAPI endpoints. Catch specific exceptions before bare `Exception`.

**Types**: Pydantic `BaseModel` for API schemas. Add annotations to new functions.

### JavaScript / JSX (Frontend)

**Imports** (order by group, CSS last):
1. React
2. Third-party (`axios`, `framer-motion`, `lucide-react`)
3. Local components
4. CSS

**Naming**: `PascalCase.jsx` components, `camelCase.js` config/files/vars,
`UPPER_SNAKE_CASE` constants.

**Formatting**: 2-space indent, single quotes for JS, double quotes for JSX attrs,
ESM throughout (`"type": "module"`), trailing commas.

**Tailwind CSS**: Custom `cyber.*` tokens (`cyber.neon`=`#00f3ff`, `cyber.alert`=`#ff003c`),
JetBrains Mono font.

## Environment Variables

| Variable         | File            | Purpose                          |
|------------------|-----------------|----------------------------------|
| `GOOGLE_API_KEY` | `.env` (root)   | Gemini API key                   |
| `VITE_API_URL`   | `.env` (frontend)| Backend URL for Axios calls     |

Copy `.env.example` to `.env` in both directories.

## Architecture

- **Pipeline**: Nmap scan → vulnerability extraction → data sanitization →
  token optimization → Gemini analysis → markdown report
- **Privacy**: `data_sanitizer.py` redacts PII (MACs, emails, passwords, IPs)
- **Scan modes**: `fast`, `normal`, `pen_test` — Nmap args in `nmap_engine.py` `SCAN_PROFILES`
- **Note**: `config/settings.py` values are unused; hardcoded in modules

## Prerequisites

Python 3.10+, Node.js, Nmap (on PATH), Gemini API key.
Scapy and TShark are optional.
