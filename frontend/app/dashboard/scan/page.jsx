'use client'

import { useState } from 'react'
import Link from 'next/link'
import { DEMO_SCAN_DETAIL } from '@/lib/demoData'

const PRIVATE_IP_REGEX = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.0\.0\.1)/

const SCAN_MODES = [
  {
    id: 'fast',
    label: 'Fast',
    accent: '#00ff88',
    blurb: '~38s · top 100 ports · service detection',
  },
  {
    id: 'deep',
    label: 'Deep',
    accent: '#4af4ff',
    blurb: '~105s · full TCP · firewall probe · default scripts',
  },
  {
    id: 'pen_test',
    label: 'Pen Test',
    accent: '#ffb340',
    blurb: '~225s · all 65,535 ports · packet capture · max intensity',
  },
]

export default function ScanPage() {
  const [target, setTarget] = useState('')
  const [scanMode, setScanMode] = useState('fast')
  const [inputError, setInputError] = useState(null)
  const [showNotice, setShowNotice] = useState(false)

  function handleTargetChange(val) {
    setTarget(val)
    if (val && !PRIVATE_IP_REGEX.test(val)) {
      setInputError('Only private IP ranges allowed — 10.x, 172.16.x, 192.168.x, 127.0.0.1')
    } else {
      setInputError(null)
    }
  }

  function handleSubmit(e) {
    e.preventDefault()
    setShowNotice(true)
  }

  const validTarget = target.trim() && PRIVATE_IP_REGEX.test(target.trim())

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', paddingBottom: '80px' }}>
      <div style={{
        marginBottom: '14px',
        padding: '14px 20px',
        border: '1px solid rgba(0,255,136,0.25)',
        background: 'rgba(0,255,136,0.05)',
        borderRadius: '6px',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '11px',
        letterSpacing: '0.08em',
        color: '#cfe8d8',
      }}>
        <span style={{
          width: '8px',
          height: '8px',
          background: '#00ff88',
          borderRadius: '50%',
          boxShadow: '0 0 10px #00ff88',
        }} />
        SHOWCASE PREVIEW — The scan UI is fully interactive but live scanning is exclusive to the desktop app.
      </div>

      <header style={{ marginBottom: '40px' }}>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          letterSpacing: '0.18em',
          textTransform: 'uppercase',
          color: 'rgba(240,237,232,0.4)',
          marginBottom: '10px',
        }}>
          New scan
        </div>
        <h1 style={{
          fontFamily: "'Syne', sans-serif",
          fontSize: '44px',
          fontWeight: 700,
          color: '#f0ede8',
          letterSpacing: '-0.02em',
          margin: 0,
        }}>
          Sweep your network<span style={{ color: '#00ff88' }}>.</span>
        </h1>
        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '13px',
          color: 'rgba(240,237,232,0.55)',
          marginTop: '14px',
          maxWidth: '640px',
          lineHeight: 1.7,
        }}>
          Choose a profile, point Aegir at a private IP and let the deterministic
          pipeline correlate ports, services and CVEs before Gemini assembles a
          plain-language risk briefing.
        </p>
      </header>

      <form onSubmit={handleSubmit} style={{
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.07)',
        padding: '32px 28px',
      }}>
        <label style={{
          display: 'block',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          letterSpacing: '0.18em',
          textTransform: 'uppercase',
          color: 'rgba(240,237,232,0.5)',
          marginBottom: '12px',
        }}>
          Target · IPv4
        </label>
        <input
          value={target}
          onChange={(e) => handleTargetChange(e.target.value)}
          placeholder="192.168.1.1"
          style={{
            width: '100%',
            background: 'rgba(255,255,255,0.04)',
            border: `1px solid ${inputError ? 'rgba(255,69,96,0.6)' : 'rgba(255,255,255,0.08)'}`,
            padding: '16px 18px',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '14px',
            color: '#f0ede8',
            outline: 'none',
            letterSpacing: '0.05em',
          }}
        />
        {inputError ? (
          <p style={{
            color: 'rgba(255,69,96,0.85)',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '11px',
            marginTop: '10px',
          }}>{inputError}</p>
        ) : (
          <p style={{
            color: 'rgba(240,237,232,0.4)',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '11px',
            marginTop: '10px',
          }}>Only private IPs allowed — 10.x · 172.16.x · 192.168.x · 127.0.0.1</p>
        )}

        <div style={{
          marginTop: '32px',
          marginBottom: '12px',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          letterSpacing: '0.18em',
          textTransform: 'uppercase',
          color: 'rgba(240,237,232,0.5)',
        }}>
          Scan Profile
        </div>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '14px',
        }}>
          {SCAN_MODES.map((m) => {
            const active = scanMode === m.id
            return (
              <button
                type="button"
                key={m.id}
                onClick={() => setScanMode(m.id)}
                style={{
                  textAlign: 'left',
                  padding: '20px 18px',
                  background: active ? `rgba(${m.id === 'fast' ? '0,255,136' : m.id === 'deep' ? '74,244,255' : '255,179,64'},0.06)` : 'rgba(255,255,255,0.02)',
                  border: `1px solid ${active ? m.accent + '99' : 'rgba(255,255,255,0.08)'}`,
                  cursor: 'pointer',
                  transition: 'all 0.18s',
                }}
              >
                <div style={{
                  fontFamily: "'Syne', sans-serif",
                  fontWeight: 600,
                  fontSize: '18px',
                  color: active ? m.accent : '#f0ede8',
                  marginBottom: '8px',
                }}>
                  {m.label}
                </div>
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '11px',
                  color: 'rgba(240,237,232,0.55)',
                  lineHeight: 1.6,
                }}>
                  {m.blurb}
                </div>
              </button>
            )
          })}
        </div>

        <div style={{ marginTop: '32px', display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
          <button
            type="submit"
            disabled={!validTarget}
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '11px',
              letterSpacing: '0.15em',
              textTransform: 'uppercase',
              color: '#060608',
              background: validTarget ? '#00ff88' : 'rgba(0,255,136,0.25)',
              border: 'none',
              padding: '16px 32px',
              cursor: validTarget ? 'pointer' : 'not-allowed',
              clipPath: 'polygon(10px 0%, 100% 0%, calc(100% - 10px) 100%, 0% 100%)',
              transition: 'all 0.2s',
            }}
          >
            ● Initialize Scan
          </button>
          <Link
            href={`/dashboard/scan/${DEMO_SCAN_DETAIL.id}`}
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '11px',
              letterSpacing: '0.15em',
              textTransform: 'uppercase',
              color: 'rgba(240,237,232,0.7)',
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.15)',
              padding: '15px 28px',
              textDecoration: 'none',
            }}
          >
            View Demo Result →
          </Link>
        </div>
      </form>

      {showNotice && (
        <div
          onClick={() => setShowNotice(false)}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(6,6,8,0.78)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '24px',
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              maxWidth: '560px',
              width: '100%',
              background: '#0a0a0d',
              border: '1px solid rgba(0,255,136,0.35)',
              padding: '48px 40px',
              clipPath: 'polygon(16px 0%, 100% 0%, 100% calc(100% - 16px), calc(100% - 16px) 100%, 0% 100%, 0% 16px)',
            }}
          >
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '10px',
              letterSpacing: '0.2em',
              textTransform: 'uppercase',
              color: 'rgba(0,255,136,0.85)',
              marginBottom: '14px',
            }}>
              ● Desktop-only feature
            </div>
            <h2 style={{
              fontFamily: "'Syne', sans-serif",
              fontWeight: 700,
              fontSize: '30px',
              color: '#f0ede8',
              marginBottom: '14px',
              letterSpacing: '-0.02em',
            }}>
              Live scanning is in the app.
            </h2>
            <p style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '13px',
              color: 'rgba(240,237,232,0.6)',
              lineHeight: 1.7,
              marginBottom: '28px',
            }}>
              The web showcase is a static preview of the dashboard. Real Nmap /
              Scapy / TShark execution and Gemini AI summaries run locally inside
              the Aegir desktop application — coming soon.
            </p>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <Link
                href={`/dashboard/scan/${DEMO_SCAN_DETAIL.id}`}
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '11px',
                  letterSpacing: '0.15em',
                  textTransform: 'uppercase',
                  color: '#060608',
                  background: '#00ff88',
                  padding: '12px 22px',
                  textDecoration: 'none',
                  clipPath: 'polygon(8px 0%, 100% 0%, calc(100% - 8px) 100%, 0% 100%)',
                }}
              >
                View Demo Scan →
              </Link>
              <button
                onClick={() => setShowNotice(false)}
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '11px',
                  letterSpacing: '0.15em',
                  textTransform: 'uppercase',
                  color: 'rgba(240,237,232,0.6)',
                  background: 'transparent',
                  border: '1px solid rgba(255,255,255,0.15)',
                  padding: '11px 22px',
                  cursor: 'pointer',
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
