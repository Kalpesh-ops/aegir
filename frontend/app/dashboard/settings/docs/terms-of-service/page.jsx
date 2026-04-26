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

export default function TermsOfServicePage() {
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
        <h1 style={title}>Terms of Service</h1>
        <div style={meta}>
          <span style={metaPill}>Effective Date: {EFFECTIVE_DATE}</span>
          <span style={metaPill}>Version: {POLICY_VERSION}</span>
        </div>

        <h2 style={h2}>Authorized Use Only</h2>
        <p style={p}>
          You must own, control, or have explicit written authorization to scan any network or host through
          Aegir. Unauthorized scanning is prohibited.
        </p>

        <h2 style={h2}>Public IP Restrictions</h2>
        <p style={p}>
          The platform includes technical controls intended to block unsafe public-target scanning paths.
          You remain legally responsible for all submitted targets and must ensure lawful scope.
        </p>

        <h2 style={h2}>No Liability For Misuse</h2>
        <p style={p}>
          The creators, maintainers, and contributors are not liable for any direct or indirect loss,
          damage, enforcement action, or operational impact resulting from misuse.
        </p>

        <h2 style={h2}>As-Is Service</h2>
        <p style={p}>
          Aegir is provided as-is for educational and professional security assessment use.
          Features may change without notice.
        </p>

        <h2 style={h2}>Compliance Responsibility</h2>
        <p style={p}>
          You are responsible for complying with all local, national, and international laws,
          regulations, and contractual obligations that apply to your testing activity.
        </p>

        <h2 style={h2}>Abuse and Termination</h2>
        <p style={p}>
          Accounts involved in abuse, prohibited use, or attempts to bypass safeguards may be suspended
          or terminated without prior notice.
        </p>
      </div>
    </div>
  )
}
