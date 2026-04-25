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

const li = {
  ...p,
  marginBottom: '8px',
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

export default function PrivacyPolicyPage() {
  return (
    <div style={pageWrap}>
      <Link
        href="/dashboard/settings"
        style={backButton}
      >
        Back to Settings
      </Link>

      <div style={sectionCard}>
        <p style={eyebrow}>Documentation</p>
        <h1 style={title}>Privacy Policy</h1>
        <div style={meta}>
          <span style={metaPill}>Effective Date: {EFFECTIVE_DATE}</span>
          <span style={metaPill}>Version: {POLICY_VERSION}</span>
        </div>

        <h2 style={h2}>What We Collect</h2>
        <p style={p}>
          Aegir collects security scan targets, CVE lookup results, AI-generated analysis
          reports, consent records, and the client IP address observed at consent time for audit integrity.
        </p>

        <h2 style={h2}>What Stays Local</h2>
        <ul style={{ margin: '0 0 14px 18px' }}>
          <li style={li}>TShark packet capture files and capture metadata generated on your host.</li>
          <li style={li}>Scapy probe outputs used for firewall inference on your environment.</li>
          <li style={li}>Local network interface detection details used to bind capture interfaces.</li>
          <li style={li}>Nmap XML output and temporary parse artifacts produced during scan execution.</li>
        </ul>

        <h2 style={h2}>What Goes To Supabase</h2>
        <p style={p}>
          The backend stores scan metadata (such as scan mode, counts, and timestamps), redacted vulnerability
          summaries, AI summaries, and your consent audit trail for account history and compliance records.
        </p>

        <h2 style={h2}>Third-Party Data Flow</h2>
        <ul style={{ margin: '0 0 14px 18px' }}>
          <li style={li}>
            CIRCL CVE API receives only product and vendor strings required for vulnerability enrichment.
            IP addresses and direct targets are not sent.
          </li>
          <li style={li}>
            Google Gemini receives redacted port and CVE context for advisory summarization. Direct scan targets,
            host identifiers, and raw packet capture data are excluded.
          </li>
        </ul>

        <h2 style={h2}>Your Rights</h2>
        <ul style={{ margin: '0 0 14px 18px' }}>
          <li style={li}>Request access to your stored scan and consent records.</li>
          <li style={li}>Request deletion of your account-linked records where legally permissible.</li>
          <li style={li}>Revoke advanced-scan consent at any time from the Settings page.</li>
        </ul>

        <h2 style={h2}>Contact</h2>
        <p style={p}>
          Contact placeholder: security@your-domain.example
        </p>
      </div>
    </div>
  )
}
