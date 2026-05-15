'use client'

import Link from 'next/link'

const STATUS = [
  { name: 'Nmap', version: 'v7.94', state: 'installed', accent: '#00ff88', detail: 'Detected on system PATH · v7.94 · 7.5 MB' },
  { name: 'Npcap (Windows) / libpcap (POSIX)', version: 'v1.79', state: 'installed', accent: '#00ff88', detail: 'WinPcap-API-compatible driver installed and loaded' },
  { name: 'TShark / Wireshark CLI', version: '—', state: 'missing', accent: '#ffb340', detail: 'Required for Pen Test packet capture · install via the wizard below' },
]

const STAGES = [
  { label: 'License acceptance', state: 'done' },
  { label: 'Download verified binary', state: 'queued' },
  { label: 'Privileged install (UAC / sudo)', state: 'queued' },
  { label: 'Post-install verification', state: 'queued' },
]

export default function SetupWizardPage() {
  return (
    <div style={{ maxWidth: '1120px', margin: '0 auto', paddingBottom: '80px' }}>
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
        ● SHOWCASE PREVIEW — the native-dependency wizard runs inside the desktop app with full UAC / sudo elevation.
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
          Setup · Native Dependencies
        </div>
        <h1 style={{
          fontFamily: "'Syne', sans-serif",
          fontWeight: 700,
          fontSize: '44px',
          color: '#f0ede8',
          letterSpacing: '-0.02em',
          margin: 0,
        }}>
          One-click scanner setup<span style={{ color: '#00ff88' }}>.</span>
        </h1>
        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '13px',
          color: 'rgba(240,237,232,0.55)',
          marginTop: '14px',
          maxWidth: '720px',
          lineHeight: 1.7,
        }}>
          Aegir bundles a guided installer for Nmap, Npcap and Wireshark on every supported
          platform. License acceptance is captured per-tool; binaries are verified by SHA-256
          before they run. Below is what the wizard looks like in production.
        </p>
      </header>

      <section style={{
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.07)',
        padding: '32px 28px',
        marginBottom: '24px',
      }}>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          letterSpacing: '0.18em',
          textTransform: 'uppercase',
          color: 'rgba(240,237,232,0.45)',
          marginBottom: '18px',
        }}>
          Detection
        </div>

        {STATUS.map((s) => (
          <div key={s.name} style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '18px 0',
            borderTop: '1px solid rgba(255,255,255,0.05)',
            gap: '16px',
            flexWrap: 'wrap',
          }}>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{
                fontFamily: "'Syne', sans-serif",
                fontWeight: 600,
                fontSize: '18px',
                color: '#f0ede8',
              }}>
                {s.name}
              </div>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '11px',
                color: 'rgba(240,237,232,0.55)',
                marginTop: '4px',
              }}>
                {s.detail}
              </div>
            </div>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '11px',
              letterSpacing: '0.15em',
              textTransform: 'uppercase',
              color: s.accent,
              padding: '6px 14px',
              border: `1px solid ${s.accent}66`,
              background: `${s.accent}10`,
              whiteSpace: 'nowrap',
            }}>
              ● {s.state}
            </div>
          </div>
        ))}
      </section>

      <section style={{
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.07)',
        padding: '32px 28px',
        marginBottom: '24px',
      }}>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          letterSpacing: '0.18em',
          textTransform: 'uppercase',
          color: 'rgba(240,237,232,0.45)',
          marginBottom: '18px',
        }}>
          Install · TShark
        </div>

        {STAGES.map((stage, i) => (
          <div key={stage.label} style={{
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
            padding: '14px 0',
            borderTop: i === 0 ? 'none' : '1px solid rgba(255,255,255,0.05)',
          }}>
            <div style={{
              width: '24px',
              height: '24px',
              borderRadius: '50%',
              border: `1px solid ${stage.state === 'done' ? '#00ff88' : 'rgba(255,255,255,0.18)'}`,
              background: stage.state === 'done' ? 'rgba(0,255,136,0.12)' : 'transparent',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '10px',
              color: stage.state === 'done' ? '#00ff88' : 'rgba(240,237,232,0.5)',
            }}>
              {stage.state === 'done' ? '✓' : i + 1}
            </div>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '12px',
              color: stage.state === 'done' ? '#f0ede8' : 'rgba(240,237,232,0.6)',
            }}>
              {stage.label}
            </div>
          </div>
        ))}

        <div style={{ marginTop: '24px', display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
          <button
            disabled
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '11px',
              letterSpacing: '0.15em',
              textTransform: 'uppercase',
              color: 'rgba(240,237,232,0.45)',
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.1)',
              padding: '14px 28px',
              cursor: 'not-allowed',
            }}
          >
            ● Install (Desktop app only)
          </button>
          <Link
            href="https://github.com/Kalpesh-ops/aegir"
            target="_blank"
            rel="noreferrer"
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '11px',
              letterSpacing: '0.15em',
              textTransform: 'uppercase',
              color: 'rgba(240,237,232,0.7)',
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.15)',
              padding: '13px 26px',
              textDecoration: 'none',
            }}
          >
            View source on GitHub →
          </Link>
        </div>
      </section>
    </div>
  )
}
