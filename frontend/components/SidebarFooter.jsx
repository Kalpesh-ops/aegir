'use client'

import Link from 'next/link'

export default function SidebarFooter({ userEmail }) {
  const displayEmail = userEmail && userEmail.length > 22
    ? userEmail.substring(0, 22) + '...'
    : userEmail

  return (
    <div style={{
      padding: '16px 12px',
      borderTop: '1px solid rgba(255,255,255,0.06)',
    }}>
      <p style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '10px',
        color: 'rgba(240,237,232,0.4)',
        marginBottom: '10px',
        wordBreak: 'break-all',
        paddingLeft: '2px',
      }}>
        {displayEmail}
      </p>
      <p style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '9px',
        color: 'rgba(0,255,136,0.7)',
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        marginBottom: '10px',
        paddingLeft: '2px',
      }}>
        ● Showcase preview
      </p>
      <Link
        href="/"
        style={{
          display: 'block',
          width: '100%',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          textTransform: 'uppercase',
          letterSpacing: '0.12em',
          color: 'rgba(240,237,232,0.35)',
          background: 'transparent',
          border: '1px solid rgba(255,255,255,0.08)',
          padding: '8px',
          textAlign: 'center',
          textDecoration: 'none',
        }}
      >
        Back to Home
      </Link>
    </div>
  )
}
