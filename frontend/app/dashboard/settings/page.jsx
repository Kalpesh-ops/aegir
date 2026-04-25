'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'

const supabaseRef = { current: null }
function getSupabase() {
  if (!supabaseRef.current) {
    try {
      const { createBrowserClient } = require('@supabase/ssr')
      supabaseRef.current = createBrowserClient(
        process.env.NEXT_PUBLIC_SUPABASE_URL,
        process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
      )
    } catch { return null }
  }
  return supabaseRef.current
}

// CRITICAL FIX: Match FastAPI's binding exactly to prevent CORS/Networking drops
const API_URL = 'http://127.0.0.1:8000'

export default function SettingsPage() {
  const router = useRouter()

  const [loading, setLoading]           = useState(true)
  const [token, setToken]               = useState(null)
  const [userEmail, setUserEmail]       = useState('')

  // BYOK State
  const [apiKey, setApiKey]             = useState('')
  const [keyStatus, setKeyStatus]       = useState(null)
  const [keyWorking, setKeyWorking]     = useState(false)

  // Consent state
  const [consentStatus, setConsentStatus] = useState(null)
  const [consentChecked, setConsentChecked] = useState(false)
  const [consentWorking, setConsentWorking] = useState(false)
  const [consentMsg, setConsentMsg]     = useState(null)

  useEffect(() => {
    async function init() {
      const { data: { session } } = await getSupabase().auth.getSession()
      if (!session) { router.push('/login'); return }
      setToken(session.access_token)
      setUserEmail(session.user?.email || '')
      await fetchConsent(session.access_token)
      setLoading(false)
    }
    init()
  }, [])

  async function fetchConsent(t) {
    try {
      const res = await fetch(`${API_URL}/api/consent`, {
        headers: { Authorization: `Bearer ${t}` },
      })
      if (!res.ok) { setConsentStatus(false); return }
      const data = await res.json()
      setConsentStatus(data.has_consent === true)
    } catch {
      setConsentStatus(false)
    }
  }

  async function handleSaveKey() {
    if (!apiKey.trim()) return
    setKeyWorking(true)
    setKeyStatus(null)
    try {
      const res = await fetch(`${API_URL}/api/settings/apikey`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ api_key: apiKey }),
      })
      if (res.ok) {
        setKeyStatus({ type: 'ok', text: 'API Key securely saved to local SQLite database.' })
        setApiKey('') // Clear input for security
      } else {
        setKeyStatus({ type: 'err', text: 'Failed to save key. Check backend logs.' })
      }
    } catch {
      setKeyStatus({ type: 'err', text: 'Could not reach backend.' })
    }
    setKeyWorking(false)
  }

  async function handleGrantConsent() {
    setConsentWorking(true)
    setConsentMsg(null)
    try {
      const res = await fetch(`${API_URL}/api/consent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ app_version: '1.0' }),
      })
      if (res.ok) {
        setConsentStatus(true)
        setConsentChecked(false)
        setConsentMsg({ type: 'ok', text: 'Consent granted. Deep and Pen Test modes are now unlocked.' })
      } else {
        setConsentMsg({ type: 'err', text: 'Failed to save consent. Try again.' })
      }
    } catch {
      setConsentMsg({ type: 'err', text: 'Could not reach backend.' })
    }
    setConsentWorking(false)
  }

  async function handleRevokeConsent() {
    setConsentWorking(true)
    setConsentMsg(null)
    try {
      const res = await fetch(`${API_URL}/api/consent`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (res.ok) {
        setConsentStatus(false)
        setConsentMsg({ type: 'ok', text: 'Consent revoked. Advanced scan modes are now locked.' })
      } else {
        setConsentMsg({ type: 'err', text: 'Failed to revoke. Try again.' })
      }
    } catch {
      setConsentMsg({ type: 'err', text: 'Could not reach backend.' })
    }
    setConsentWorking(false)
  }

  // ── Styles ──────────────────────────────────────────────────────────────
  const sectionCard = {
    background: 'rgba(255,255,255,0.02)',
    border: '1px solid rgba(255,255,255,0.07)',
    padding: '28px 32px',
    marginBottom: '16px',
  }
  const sectionLabel = {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '9px',
    textTransform: 'uppercase',
    letterSpacing: '0.18em',
    color: '#00ff88',
    marginBottom: '6px',
  }
  const sectionTitle = {
    fontFamily: "'Syne', sans-serif",
    fontSize: '18px',
    fontWeight: 600,
    color: '#f0ede8',
    marginBottom: '10px',
  }
  const sectionBody = {
    fontFamily: "'Instrument Sans', sans-serif",
    fontSize: '13px',
    color: 'rgba(240,237,232,0.55)',
    lineHeight: 1.7,
    marginBottom: '20px',
  }
  const pill = (active) => ({
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '10px',
    letterSpacing: '0.1em',
    padding: '4px 12px',
    border: `1px solid ${active ? '#00ff88' : 'rgba(255,69,96,0.5)'}`,
    color: active ? '#00ff88' : '#ff4560',
    background: active ? 'rgba(0,255,136,0.06)' : 'rgba(255,69,96,0.06)',
    marginBottom: '20px',
  })
  const btnPrimary = (disabled) => ({
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '10px',
    letterSpacing: '0.12em',
    textTransform: 'uppercase',
    padding: '10px 24px',
    border: '1px solid #00ff88',
    background: disabled ? 'transparent' : 'rgba(0,255,136,0.08)',
    color: disabled ? 'rgba(0,255,136,0.3)' : '#00ff88',
    cursor: disabled ? 'not-allowed' : 'pointer',
    transition: 'all 0.2s',
    marginRight: '12px',
  })
  const btnDanger = {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '10px',
    letterSpacing: '0.12em',
    textTransform: 'uppercase',
    padding: '10px 24px',
    border: '1px solid rgba(255,69,96,0.4)',
    background: 'transparent',
    color: '#ff4560',
    cursor: 'pointer',
    transition: 'all 0.2s',
  }
  const docCard = {
    flex: 1,
    background: 'rgba(255,255,255,0.02)',
    border: '1px solid rgba(255,255,255,0.06)',
    padding: '20px 24px',
    minWidth: '220px',
    textDecoration: 'none',
    transition: 'all 0.2s',
    cursor: 'pointer',
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh' }}>
        <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: 'rgba(240,237,232,0.3)', letterSpacing: '0.1em' }}>
          Loading...
        </span>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: '720px' }}>

      {/* Page header */}
      <div style={{ marginBottom: '36px' }}>
        <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.18em', color: '#00ff88', marginBottom: '8px' }}>
          Settings
        </p>
        <h1 style={{ fontFamily: "'Syne',sans-serif", fontWeight: 600, fontSize: '28px', color: '#f0ede8', marginBottom: '6px' }}>
          Account & Preferences
        </h1>
        <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: 'rgba(240,237,232,0.3)', letterSpacing: '0.05em' }}>
          {userEmail}
        </p>
      </div>

      {/* ── Section 1: Gemini API Configuration (BYOK) ── */}
      <div style={sectionCard}>
        <p style={sectionLabel}>Local AI Engine</p>
        <h2 style={sectionTitle}>Gemini API Key (BYOK)</h2>
        <p style={sectionBody}>
          To analyze vulnerabilities privately, enter your Google Gemini API Key.
          This key is stored securely in your local SQLite database and is never sent to our servers.
        </p>

        <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
          <input
            type="password"
            placeholder="AIzaSy..."
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            style={{
              flex: 1,
              background: 'rgba(0,0,0,0.2)',
              border: '1px solid rgba(255,255,255,0.1)',
              padding: '10px 16px',
              color: '#f0ede8',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '12px',
              outline: 'none',
            }}
          />
          <button
            disabled={keyWorking || !apiKey.trim()}
            onClick={handleSaveKey}
            style={btnPrimary(keyWorking || !apiKey.trim())}
          >
            {keyWorking ? 'Saving...' : 'Save Key'}
          </button>
        </div>
        {keyStatus && (
          <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: keyStatus.type === 'ok' ? '#00ff88' : '#ff4560' }}>
            {keyStatus.text}
          </p>
        )}
      </div>

      {/* ── Section 2: Advanced Scan Consent ── */}
      <div style={sectionCard}>
        <p style={sectionLabel}>Advanced Scan Modes</p>
        <h2 style={sectionTitle}>System-Level Access Consent</h2>
        <p style={sectionBody}>
          Deep and Pen Test scan modes use Scapy (raw socket firewall probing) and TShark
          (packet header capture, 80 bytes max). These tools require elevated system privileges
          and access your local network adapter. <strong style={{ color: '#f0ede8' }}>No data
          leaves your machine.</strong> Only protocol headers are captured — never payloads or content.
        </p>

        {/* Status pill */}
        <div style={pill(consentStatus)}>
          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: consentStatus ? '#00ff88' : '#ff4560', display: 'inline-block' }} />
          {consentStatus ? 'Consent Active — Advanced modes unlocked' : 'No Consent — Advanced modes locked'}
        </div>

        {/* What's collected list */}
        <div style={{ marginBottom: '24px' }}>
          <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', color: 'rgba(240,237,232,0.3)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '10px' }}>
            What runs when you use these modes
          </p>
          {[
            { tool: 'Scapy', desc: 'Sends a single raw ACK packet to detect firewall state. Deep + Pen Test.', stays: true },
            { tool: 'TShark', desc: 'Captures 30s of packet headers (80 bytes max) on your local adapter. Pen Test only.', stays: true },
            { tool: 'Interface detection', desc: 'Reads ipconfig to match your target IP to the correct network adapter.', stays: true },
            { tool: 'Consent record', desc: 'Timestamp, policy version, and consent method saved to your account.', stays: false },
          ].map(({ tool, desc, stays }) => (
            <div key={tool} style={{ display: 'flex', gap: '16px', padding: '10px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: '#00ff88', width: '160px', flexShrink: 0 }}>{tool}</span>
              <span style={{ fontFamily: "'Instrument Sans',sans-serif", fontSize: '13px', color: 'rgba(240,237,232,0.5)', flex: 1 }}>{desc}</span>
              <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '9px', color: stays ? 'rgba(0,255,136,0.5)' : 'rgba(255,255,255,0.2)', flexShrink: 0, paddingTop: '2px' }}>
                {stays ? 'LOCAL ONLY' : 'YOUR ACCOUNT'}
              </span>
            </div>
          ))}
        </div>

        {/* Feedback message */}
        {consentMsg && (
          <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: consentMsg.type === 'ok' ? '#00ff88' : '#ff4560', marginBottom: '16px' }}>
            {consentMsg.text}
          </p>
        )}

        {/* Grant consent */}
        {!consentStatus && (
          <div>
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', cursor: 'pointer', marginBottom: '16px' }}>
              <input
                type="checkbox"
                checked={consentChecked}
                onChange={(e) => setConsentChecked(e.target.checked)}
                style={{ marginTop: '3px', accentColor: '#00ff88' }}
              />
              <span style={{ fontFamily: "'Instrument Sans',sans-serif", fontSize: '13px', color: 'rgba(240,237,232,0.65)' }}>
                I understand that advanced scan modes require elevated system access and I consent
                to their use on my own private network.
              </span>
            </label>
            <button
              disabled={!consentChecked || consentWorking}
              onClick={handleGrantConsent}
              style={btnPrimary(!consentChecked || consentWorking)}
            >
              {consentWorking ? 'Saving...' : 'Grant Consent'}
            </button>
          </div>
        )}

        {/* Revoke consent */}
        {consentStatus && (
          <div>
            <p style={{ fontFamily: "'Instrument Sans',sans-serif", fontSize: '13px', color: 'rgba(240,237,232,0.4)', marginBottom: '16px' }}>
              Revoking consent will immediately lock Deep and Pen Test modes. Your consent record
              will be updated with a revocation timestamp.
            </p>
            <button
              disabled={consentWorking}
              onClick={handleRevokeConsent}
              style={btnDanger}
            >
              {consentWorking ? 'Revoking...' : 'Revoke Consent'}
            </button>
          </div>
        )}
      </div>

      {/* ── Section 3: Documentation ── */}
      <div style={sectionCard}>
        <p style={sectionLabel}>Legal & Documentation</p>
        <h2 style={sectionTitle}>Policies & Terms</h2>
        <p style={sectionBody}>
          Review policy, legal, and consent documents for system use and data handling.
        </p>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {[
            { title: 'Privacy Policy', href: '/dashboard/settings/docs/privacy-policy' },
            { title: 'Terms of Service', href: '/dashboard/settings/docs/terms-of-service' },
            { title: 'User Consent Policy', href: '/dashboard/settings/docs/consent-policy' },
            { title: 'Disclaimer', href: '/dashboard/settings/docs/disclaimer' },
          ].map((doc) => (
            <Link
              key={doc.title}
              href={doc.href}
              style={docCard}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'rgba(0,255,136,0.45)'
                e.currentTarget.style.background = 'rgba(0,255,136,0.05)'
                e.currentTarget.style.transform = 'translateY(-1px)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'
                e.currentTarget.style.background = 'rgba(255,255,255,0.02)'
                e.currentTarget.style.transform = 'translateY(0)'
              }}
            >
              <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', color: 'rgba(240,237,232,0.3)', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: '4px' }}>
                {doc.title}
              </p>
              <p style={{ fontFamily: "'Instrument Sans',sans-serif", fontSize: '12px', color: 'rgba(240,237,232,0.55)' }}>
                View document
              </p>
            </Link>
          ))}
        </div>
      </div>

      {/* ── Section 4: About ── */}
      <div style={{ ...sectionCard, marginBottom: 0 }}>
        <p style={sectionLabel}>About</p>
        <h2 style={sectionTitle}>Aegir</h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {[
            ['Version', '1.0.0-beta'],
            ['Privacy Policy Version', '1.0'],
            ['Stack', 'Next.js · FastAPI · Nmap · Scapy · TShark · Gemini'],
            ['Data Residency', 'Local machine + your Supabase instance'],
          ].map(([k, v]) => (
            <div key={k} style={{ display: 'flex', gap: '24px', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: 'rgba(240,237,232,0.3)', width: '180px', flexShrink: 0 }}>{k}</span>
              <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: 'rgba(240,237,232,0.6)' }}>{v}</span>
            </div>
          ))}
        </div>
      </div>

    </div>
  )
}