# Aegir — Showcase Site

This branch (`live-demo-site`) is the **public, no-backend showcase** of the
Aegir network security intelligence platform. It is a fully static Next.js
app: no API calls, no authentication, no database. Every scan, CVE record
and AI summary you see is rendered from baked-in demo data.

The actual product — local-first scanning, packet capture, CVE correlation
and Gemini-powered remediation reports — runs inside the **Aegir desktop
application** (Electron), which is **coming soon**. The full source tree
for the desktop app and CLI lives on the [`main`](https://github.com/Kalpesh-ops/aegir/tree/main)
branch.

---

## Stack

| Layer | Tool |
|---|---|
| Framework | Next.js 16 (App Router) |
| Runtime | React 19 |
| Language | JavaScript (JSX) |
| Output | Standard Next.js build (every page SSG; emits static HTML at the edge on Vercel) |
| Hosting | Vercel (recommended) — or any host that runs `next start` |
| Charts | Recharts |
| Markdown | react-markdown + rehype-sanitize |

No backend services are configured or required.

---

## Local development

```bash
npm install
npm run dev
```

Then open http://localhost:3000.

---

## Production build

```bash
npm install
npm run build
```

Vercel will run this automatically; the prerendered HTML lands in `./.next/`.

---

## Deploy on Vercel

This repo includes a `vercel.json` so import is one click:

1. **Add New Project → Import** `Kalpesh-ops/aegir`
2. **Production Branch**: `live-demo-site`
3. **Root Directory**: leave blank (this branch IS the site root)
4. **Framework Preset**: Next.js (auto-detected)
5. **Build Command**: `next build` (auto)
6. **Output Directory**: `.next` (auto-detected — Vercel handles it)
7. No environment variables required.

Click **Deploy**.

---

## Project layout

```
.
├── app/                    # Next.js App Router routes
│   ├── page.jsx            # Landing page
│   ├── login/              # No-auth "enter dashboard" gate
│   ├── dashboard/          # Demo dashboard (mock data)
│   │   ├── page.jsx
│   │   ├── history/
│   │   ├── scan/
│   │   │   ├── page.jsx    # Scan form (submit → "desktop-only" modal)
│   │   │   └── [id]/       # Per-scan results
│   │   ├── settings/
│   │   └── setup/          # Native-deps wizard preview
│   └── legal/              # Public legal docs
│       ├── privacy-policy/
│       ├── terms-of-service/
│       ├── consent-policy/
│       └── disclaimer/
├── components/             # Navbar / Footer / charts / etc.
├── lib/
│   └── demoData.js         # Mock scans + curated Metasploitable 2 record
├── public/                 # Static assets (favicon)
├── next.config.js          # trailingSlash, image-unoptimized
├── vercel.json             # Vercel build + security headers
└── package.json
```

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).

The Aegir trademark and brand assets are not covered by the source license.

---

## Links

- Main repo (source for the desktop app + CLI): https://github.com/Kalpesh-ops/aegir
- License: https://github.com/Kalpesh-ops/aegir/blob/main/LICENSE
