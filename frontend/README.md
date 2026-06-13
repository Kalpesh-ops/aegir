# Aegir Frontend

Next.js 16 (App Router) dashboard for the Aegir network scanner. See the
[root README](../README.md) for full architecture and setup instructions.

## Quick start

```bash
cp .env.example .env.local   # fill in Supabase credentials + backend URL
npm install
npm run dev                  # http://localhost:3000
```

## Layout

- `app/` — routes: landing page, `/login`, and the auth-gated `/dashboard`
  (scanner, history, setup wizard, settings + legal docs)
- `components/` — shared client components (scan results, charts, sidebar)
- `hooks/` — `useScrollAnimation` for landing-page reveals
- `lib/` — `apiUrl.js` (backend base URL) and `localCache.js` (TTL cache)
- `proxy.js` — Next.js 16 request proxy (replaces `middleware.js`); redirects
  unauthenticated visitors away from `/dashboard`

The production build uses `output: 'standalone'` (see `next.config.js`) so the
Electron shell can run the compiled server without `node_modules`.
