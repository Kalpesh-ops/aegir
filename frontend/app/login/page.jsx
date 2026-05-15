'use client'

import Link from 'next/link'
import ParticleBackground from '@/components/ParticleBackground'

export default function LoginPage() {
  return (
    <div style={{
      display: 'flex',
      minHeight: '100vh',
      background: '#060608',
    }}>
      <style jsx>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .form-card {
          animation: slideIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        .submit-btn {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          font-weight: 500;
          letter-spacing: 0.12em;
          text-transform: uppercase;
          color: #060608;
          background: #00ff88;
          border: none;
          padding: 14px 36px;
          cursor: pointer;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
          transition: all 0.2s;
          clip-path: polygon(10px 0%, 100% 0%, calc(100% - 10px) 100%, 0% 100%);
          text-decoration: none;
        }
        .submit-btn:hover {
          box-shadow: 0 0 32px rgba(0,255,136,0.45);
          transform: translateY(-2px);
        }
        .ghost-btn {
          font-family: 'JetBrains Mono', monospace;
          font-size: 10px;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: rgba(240,237,232,0.6);
          background: transparent;
          border: 1px solid rgba(255,255,255,0.12);
          padding: 12px 22px;
          text-decoration: none;
          display: inline-block;
          transition: all 0.2s;
        }
        .ghost-btn:hover {
          color: #f0ede8;
          border-color: rgba(255,255,255,0.3);
        }
        .divider {
          width: 1px;
          background: rgba(255,255,255,0.06);
          min-height: 100vh;
        }
        @media (max-width: 768px) {
          .left-half { display: none; }
          .divider { display: none; }
        }
      `}</style>

      <div className="left-half" style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        <ParticleBackground />
        <div style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          padding: '64px',
          zIndex: 2,
        }}>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '10px',
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: 'rgba(0,255,136,0.8)',
            marginBottom: '24px',
          }}>
            ● Showcase preview
          </div>
          <h1 style={{
            fontFamily: "'Syne', sans-serif",
            fontWeight: 800,
            fontSize: 'clamp(48px, 7vw, 88px)',
            color: '#f0ede8',
            lineHeight: 0.95,
            marginBottom: '24px',
          }}>
            No login needed.
          </h1>
          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '13px',
            color: 'rgba(240,237,232,0.55)',
            maxWidth: '460px',
            lineHeight: 1.7,
          }}>
            This is a public showcase of the Aegir dashboard. Live scanning, account management
            and the global AI cache are exclusive to the desktop app — coming soon.
          </p>
        </div>
      </div>

      <div className="divider" />

      <div style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px',
      }}>
        <div className="form-card" style={{
          width: '100%',
          maxWidth: '420px',
          background: 'rgba(255,255,255,0.02)',
          border: '1px solid rgba(255,255,255,0.06)',
          padding: '40px',
        }}>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '10px',
            letterSpacing: '0.15em',
            textTransform: 'uppercase',
            color: 'rgba(240,237,232,0.35)',
            marginBottom: '8px',
          }}>
            Access · Demo Mode
          </div>
          <h2 style={{
            fontFamily: "'Syne', sans-serif",
            fontWeight: 700,
            fontSize: '28px',
            color: '#f0ede8',
            marginBottom: '24px',
            letterSpacing: '-0.02em',
          }}>
            Enter Dashboard
          </h2>
          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '12px',
            color: 'rgba(240,237,232,0.5)',
            lineHeight: 1.7,
            marginBottom: '32px',
          }}>
            All scan data shown is illustrative. The real product runs locally on
            your machine; download links go live with the public launch.
          </p>

          <Link href="/dashboard" className="submit-btn">
            Launch Demo Dashboard →
          </Link>

          <div style={{
            marginTop: '32px',
            paddingTop: '24px',
            borderTop: '1px solid rgba(255,255,255,0.06)',
            display: 'flex',
            gap: '12px',
            flexWrap: 'wrap',
          }}>
            <Link href="/" className="ghost-btn">← Back home</Link>
            <a
              href="https://github.com/Kalpesh-ops/aegir"
              target="_blank"
              rel="noreferrer"
              className="ghost-btn"
            >
              View on GitHub
            </a>
          </div>
        </div>
      </div>
    </div>
  )
}
