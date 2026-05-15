import Link from 'next/link'

const EFFECTIVE_DATE = 'April 4, 2026'
const POLICY_VERSION = '1.0'

const pageWrap = {
  maxWidth: '860px',
}

const sectionCard = {
  background: 'rgba(255,255,255,0.02)',
  border: '1px solid rgba(255,255,255,0.07)',
  padding: '28px 32px',
  marginBottom: '16px',
}

const eyebrow = {
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '10px',
  textTransform: 'uppercase',
  letterSpacing: '0.18em',
  color: '#00ff88',
  marginBottom: '8px',
}

const title = {
  fontFamily: "'Syne', sans-serif",
  fontWeight: 600,
  fontSize: '30px',
  color: '#f0ede8',
  marginBottom: '12px',
}

const meta = {
  display: 'flex',
  gap: '16px',
  flexWrap: 'wrap',
  marginBottom: '20px',
}

const metaPill = {
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '10px',
  letterSpacing: '0.1em',
  padding: '5px 12px',
  border: '1px solid rgba(0,255,136,0.35)',
  color: '#00ff88',
  background: 'rgba(0,255,136,0.08)',
}

const h2 = {
  fontFamily: "'Syne', sans-serif",
  fontSize: '20px',
  color: '#f0ede8',
  marginBottom: '10px',
}

const p = {
  fontFamily: "'Instrument Sans', sans-serif",
  fontSize: '14px',
  lineHeight: 1.75,
  color: 'rgba(240,237,232,0.62)',
  marginBottom: '12px',
}

const backButton = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '8px',
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '10px',
  letterSpacing: '0.12em',
  textTransform: 'uppercase',
  padding: '10px 16px',
  border: '1px solid rgba(255,255,255,0.14)',
  color: 'rgba(240,237,232,0.7)',
  textDecoration: 'none',
  marginBottom: '18px',
  transition: 'all 0.2s',
}

export default function DisclaimerPage() {
  return (
    <div style={pageWrap}>
      <Link
        href="/"
        style={backButton}
      >
        Back to Home
      </Link>

      <div style={sectionCard}>
        <p style={eyebrow}>Documentation</p>
        <h1 style={title}>Disclaimer</h1>
        <div style={meta}>
          <span style={metaPill}>Effective Date: {EFFECTIVE_DATE}</span>
          <span style={metaPill}>Version: {POLICY_VERSION}</span>
        </div>

        <h2 style={h2}>Use Scope</h2>
        <p style={p}>
          Aegir is intended for educational and professional security research and assessment use.
        </p>

        <h2 style={h2}>Responsibility</h2>
        <p style={p}>
          The creator and contributors are not responsible for misuse of this software, including unauthorized
          scanning or unlawful testing activity.
        </p>

        <h2 style={h2}>CVE Data Source</h2>
        <p style={p}>
          Vulnerability intelligence is sourced from the CIRCL CVE service. Availability and accuracy are not guaranteed.
        </p>

        <h2 style={h2}>AI Analysis Limitations</h2>
        <p style={p}>
          AI-generated analysis is advisory only and should not be treated as a substitute for a professional,
          manual security audit.
        </p>

        <h2 style={h2}>No Warranty</h2>
        <p style={p}>
          This tool is provided without warranties of any kind, express or implied, including merchantability,
          fitness for a particular purpose, and non-infringement.
        </p>
      </div>
    </div>
  )
}
