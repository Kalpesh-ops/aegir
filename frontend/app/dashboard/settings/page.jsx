'use client'

import Link from 'next/link'
import { DEMO_USER } from '@/lib/demoData'

const SECTION_STYLE = {
  background: 'rgba(255,255,255,0.03)',
  border: '1px solid rgba(255,255,255,0.07)',
  padding: '32px 28px',
  marginBottom: '24px',
}

const LABEL_STYLE = {
  display: 'block',
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '10px',
  letterSpacing: '0.15em',
  textTransform: 'uppercase',
  color: 'rgba(240,237,232,0.45)',
  marginBottom: '12px',
}

const VALUE_STYLE = {
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '14px',
  color: '#f0ede8',
  lineHeight: 1.7,
}

const INPUT_STYLE = {
  width: '100%',
  background: 'rgba(255,255,255,0.04)',
  border: '1px solid rgba(255,255,255,0.08)',
  padding: '12px 14px',
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '12px',
  color: '#f0ede8',
  outline: 'none',
}

const COMING_SOON_BUTTON = {
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '10px',
  letterSpacing: '0.18em',
  textTransform: 'uppercase',
  color: 'rgba(240,237,232,0.55)',
  background: 'rgba(255,255,255,0.04)',
  border: '1px solid rgba(255,255,255,0.1)',
  padding: '11px 22px',
  cursor: 'not-allowed',
}

const LEGAL_DOCS = [
  { href: '/legal/privacy-policy',   label: 'Privacy Policy' },
  { href: '/legal/terms-of-service', label: 'Terms of Service' },
  { href: '/legal/consent-policy',   label: 'Consent Policy' },
  { href: '/legal/disclaimer',       label: 'Disclaimer' },
]

export default function SettingsPage() {
  return (
    <div style={{ maxWidth: '900px', margin: '0 auto', paddingBottom: '80px' }}>
      <div style={{
        marginBottom: '14px',
        padding: '14px 20px',
        border: '1px solid rgba(0,255,136,0.25)',
        background: 'rgba(0,255,136,0.05)',
        borderRadius: '6px',
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '11px',
        letterSpacing: '0.08em',
        color: '#cfe8d8',
      }}>
        ● SHOWCASE PREVIEW — account, API-key and consent management run inside the desktop app.
      </div>

      <header style={{ marginBottom: '36px' }}>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          letterSpacing: '0.18em',
          textTransform: 'uppercase',
          color: 'rgba(240,237,232,0.4)',
          marginBottom: '10px',
        }}>
          Configuration
        </div>
        <h1 style={{
          fontFamily: "'Syne', sans-serif",
          fontWeight: 700,
          fontSize: '44px',
          color: '#f0ede8',
          letterSpacing: '-0.02em',
          margin: 0,
        }}>
          Settings<span style={{ color: '#00ff88' }}>.</span>
        </h1>
      </header>

      <section style={SECTION_STYLE}>
        <div style={LABEL_STYLE}>Account</div>
        <div style={VALUE_STYLE}>{DEMO_USER.email}</div>
        <div style={{ ...VALUE_STYLE, fontSize: '12px', color: 'rgba(240,237,232,0.45)', marginTop: '6px' }}>
          Demo identity · no real account
        </div>
      </section>

      <section style={SECTION_STYLE}>
        <div style={LABEL_STYLE}>Gemini API Key · BYOK</div>
        <p style={{ ...VALUE_STYLE, fontSize: '12px', color: 'rgba(240,237,232,0.55)', marginBottom: '16px' }}>
          Free tier ships with Aegir-managed Gemini access. Premium users may also bring their
          own Google AI Studio key for unlimited analyses.
        </p>
        <input type="password" placeholder="••••••••••••••••••••••••" style={INPUT_STYLE} disabled />
        <div style={{ marginTop: '14px' }}>
          <button style={COMING_SOON_BUTTON} disabled>● Coming soon</button>
        </div>
      </section>

      <section style={SECTION_STYLE}>
        <div style={LABEL_STYLE}>Advanced Scan Consent</div>
        <p style={{ ...VALUE_STYLE, fontSize: '12px', color: 'rgba(240,237,232,0.55)', marginBottom: '16px' }}>
          Deep and Pen Test profiles use raw sockets and live packet capture. They require explicit
          consent before each run from inside the desktop app.
        </p>
        <button style={COMING_SOON_BUTTON} disabled>● Managed in desktop app</button>
      </section>

      <section style={SECTION_STYLE}>
        <div style={LABEL_STYLE}>Legal Documents</div>
        <p style={{ ...VALUE_STYLE, fontSize: '12px', color: 'rgba(240,237,232,0.55)', marginBottom: '20px' }}>
          The Aegir privacy, terms, consent and disclaimer documents — published openly so anyone
          can review them before installing the desktop app.
        </p>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '12px',
        }}>
          {LEGAL_DOCS.map((d) => (
            <Link
              key={d.href}
              href={d.href}
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '11px',
                letterSpacing: '0.12em',
                textTransform: 'uppercase',
                color: '#cfe8d8',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.1)',
                padding: '14px 18px',
                textDecoration: 'none',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              {d.label}
              <span>→</span>
            </Link>
          ))}
        </div>
      </section>

      <section style={SECTION_STYLE}>
        <div style={LABEL_STYLE}>Danger Zone · Account Deletion</div>
        <p style={{ ...VALUE_STYLE, fontSize: '12px', color: 'rgba(240,237,232,0.55)', marginBottom: '16px' }}>
          Permanently delete your account and purge all scan history. Available from the
          desktop-app settings screen once the public release ships.
        </p>
        <button style={COMING_SOON_BUTTON} disabled>● Coming soon</button>
      </section>
    </div>
  )
}
