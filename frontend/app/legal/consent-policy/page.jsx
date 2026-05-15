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

export default function ConsentPolicyPage() {
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
        <h1 style={title}>User Consent Policy</h1>
        <div style={meta}>
          <span style={metaPill}>Effective Date: {EFFECTIVE_DATE}</span>
          <span style={metaPill}>Version: {POLICY_VERSION}</span>
        </div>

        <h2 style={h2}>What Consent Gates</h2>
        <p style={p}>
          Consent is required to unlock Deep and Pen Test modes because these modes use elevated
          network inspection capabilities beyond baseline fast scanning.
        </p>

        <h2 style={h2}>What Elevated Access Means</h2>
        <ul style={{ margin: '0 0 14px 18px' }}>
          <li style={li}>Scapy raw socket probes are used for firewall behavior inference.</li>
          <li style={li}>TShark runs controlled packet-header capture during Pen Test mode windows.</li>
        </ul>

        <h2 style={h2}>What Is Not Captured</h2>
        <p style={p}>
          The system does not intentionally capture packet payload content, account credentials,
          or application message bodies as part of these advanced mode workflows.
        </p>

        <h2 style={h2}>How Consent Is Recorded</h2>
        <p style={p}>
          Consent records include timestamp, policy version, consent method, and client IP address
          to support account-level auditability and revocation history.
        </p>

        <h2 style={h2}>Revocation</h2>
        <p style={p}>
          You may revoke consent at any time from Settings. Revocation immediately disables Deep and
          Pen Test modes for your account until consent is granted again.
        </p>

        <h2 style={h2}>Effect Of Revocation</h2>
        <p style={p}>
          Existing historical scan records remain in your account history unless separately deleted,
          but no new elevated-access scans can be initiated while consent remains inactive.
        </p>
      </div>
    </div>
  )
}
