// Single source of truth for the backend base URL.
//
// NEXT_PUBLIC_API_URL is inlined at build time (set it in .env.local). The
// fallback matches the backend's default bind address — server.py binds
// 127.0.0.1:8000 unless NETSEC_BIND_HOST / NETSEC_BIND_PORT override it.
export const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'
