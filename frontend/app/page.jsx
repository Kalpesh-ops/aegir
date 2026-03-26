'use client'

import { useEffect } from 'react'
import Link from 'next/link'
import ParticleBackground from '@/components/ParticleBackground'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'
import { useScrollAnimation } from '@/hooks/useScrollAnimation'

export default function Home() {
  useEffect(() => {
    document.querySelectorAll('[data-tilt]').forEach((card) => {
      card.addEventListener('mousemove', (e) => {
        const r = card.getBoundingClientRect()
        const x = (e.clientX - r.left) / r.width - 0.5
        const y = (e.clientY - r.top) / r.height - 0.5
        card.style.transform = `perspective(600px) rotateY(${x * 8}deg) rotateX(${-y * 6}deg) translateZ(8px)`
      })
      card.addEventListener('mouseleave', () => {
        card.style.transform = ''
        card.style.transition = 'transform 0.5s ease'
        setTimeout(() => { card.style.transition = '' }, 500)
      })
    })
  }, [])
  useScrollAnimation()

  return (
    <>
      <Navbar />

      {/* HERO */}
      <section id="hero">
        <ParticleBackground />
        <div className="hero-glow" />
        <div className="hero-content">
          <div className="hero-eyebrow">Network Security Intelligence Platform</div>
          <h1 className="hero-h1">NETSEC<span className="accent">.</span></h1>
          <div className="hero-h1-sub">INTELLIGENCE</div>
          <p className="hero-sub">
            Real CVE correlation. AI-powered analysis. Your network&apos;s threat surface, decoded in seconds.
          </p>
          <div className="hero-actions">
            <Link href="/login" className="btn-primary">
              <svg width="14" height="14" fill="none" viewBox="0 0 24 24">
                <path d="M13 5l7 7-7 7M5 12h15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              Start Scanning
            </Link>
            <a href="#how-it-works" className="btn-secondary">See How It Works</a>
          </div>
        </div>
        <div className="scroll-hint">
          <span>Scroll</span>
          <div className="scroll-line" />
        </div>
      </section>

      {/* STATS TICKER */}
      <div id="stats-ticker">
        <div className="ticker-track" id="ticker">
          {[
            ['247,891', 'CVEs in database'],
            ['99.7%', 'Detection accuracy'],
            ['<3s', 'Average scan time'],
            ['0', 'Data stored externally'],
            ['Gemini 2.5', 'AI analysis engine'],
            ['Real-time', 'CVE correlation'],
          ].map(([val, label], i) => (
            <div className="ticker-item" key={i}>
              <span className="val">{val}</span> {label} <span className="ticker-sep">|</span>
            </div>
          ))}
          {[...Array(6)].map((_, i) => (
            <div className="ticker-item" key={`dup-${i}`}>
              <span className="val">{['247,891', '99.7%', '<3s', '0', 'Gemini 2.5', 'Real-time'][i]}</span>
              {['CVEs in database', 'Detection accuracy', 'Average scan time', 'Data stored externally', 'AI analysis engine', 'CVE correlation'][i]}
              <span className="ticker-sep">|</span>
            </div>
          ))}
        </div>
      </div>

      {/* FEATURES */}
      <section id="features">
        <div className="section-label">Capabilities</div>
        <h2 className="section-h2 reveal">
          Engineered for<br /><em>real intelligence</em>
        </h2>
        <div className="features-grid">
          {[
            {
              num: '01',
              icon: (
                <svg viewBox="0 0 24 24" fill="none">
                  <circle cx="11" cy="11" r="7" stroke="#00ff88" strokeWidth="1.5" />
                  <path d="M16.5 16.5L21 21" stroke="#00ff88" strokeWidth="1.5" strokeLinecap="round" />
                  <path d="M8 11h6M11 8v6" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round" />
                </svg>
              ),
              title: 'Deterministic CVE Correlation',
              desc: 'Every open port maps to verified CVEs from the CIRCL vulnerability database. Zero hallucination. Real data, real risk scores.',
              tag: '247K+ CVEs indexed',
            },
            {
              num: '02',
              icon: (
                <svg viewBox="0 0 24 24" fill="none">
                  <path d="M12 3L20 7.5V16.5L12 21L4 16.5V7.5L12 3Z" stroke="#4af4ff" strokeWidth="1.5" />
                  <path d="M12 8v4l3 2" stroke="#4af4ff" strokeWidth="1.2" strokeLinecap="round" />
                </svg>
              ),
              title: 'AI-Powered Threat Analysis',
              desc: 'Gemini 2.5 Flash translates raw vulnerability data into executive-grade remediation reports. No jargon, just action.',
              tagStyle: { color: 'var(--ice)', borderColor: 'var(--ice-dim)', background: 'rgba(74,244,255,0.05)' },
              tag: 'Gemini 2.5 Flash',
            },
            {
              num: '03',
              icon: (
                <svg viewBox="0 0 24 24" fill="none">
                  <rect x="3" y="11" width="18" height="10" rx="1" stroke="#00ff88" strokeWidth="1.5" />
                  <path d="M7 11V7a5 5 0 0110 0v4" stroke="#00ff88" strokeWidth="1.5" strokeLinecap="round" />
                  <circle cx="12" cy="16" r="1.5" fill="#00ff88" />
                </svg>
              ),
              title: 'Privacy by Architecture',
              desc: 'PII stripped before any external call. Your network topology never leaves your infrastructure unredacted. We see the risk, not the identity.',
              tag: 'Zero raw IP exposure',
            },
          ].map((card) => (
            <div className="feature-card" data-tilt key={card.num}>
              <div className="feature-num">{card.num}</div>
              <div className="feature-icon">{card.icon}</div>
              <div className="feature-title">{card.title}</div>
              <div className="feature-desc">{card.desc}</div>
              <span className="feature-tag" style={card.tagStyle}>{card.tag}</span>
            </div>
          ))}
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section id="how-it-works">
        <div className="how-sticky">
          <div className="how-inner">
            <div className="how-left">
              <div className="section-label" style={{ marginBottom: '36px' }}>Process</div>
              <div className="how-progress-track">
                <div className="how-progress-fill" id="progress-fill" />
              </div>
              <div className="how-steps">
                {[
                  ['01', 'Target & Scan', 'Enter a private IP. Nmap and Scapy sweep every port, fingerprint services, detect OS and firewall state.'],
                  ['02', 'CVE Correlation', 'Each discovered service maps against 247K+ real CVEs. CVSS scores calculated. No AI involved at this stage — pure determinism.'],
                  ['03', 'AI Synthesis', 'Verified findings feed Gemini 2.5. It explains, prioritizes, and writes your remediation playbook in plain English.'],
                ].map(([num, title, desc]) => (
                  <div className="how-step active" key={num} data-step="0">
                    <div className="step-num">Step {num}</div>
                    <div className="step-title">{title}</div>
                    <div className="step-desc">{desc}</div>
                  </div>
                ))}
              </div>
            </div>
            <div className="how-right">
              <div className="terminal-header">
                <div className="terminal-dot" style={{ background: '#ff5f57' }} />
                <div className="terminal-dot" style={{ background: '#ffbd2e' }} />
                <div className="terminal-dot" style={{ background: '#28c840' }} />
                <span className="terminal-title">netsec-ai — scanner kernel</span>
              </div>
              <div className="terminal-body" id="terminal-body">
                {[
                  ['22:14:01', 'ok', 'INIT', 'Scanner kernel started', ''],
                  ['22:14:01', '', 'INFO', 'Target: ', '192.168.1.1'],
                  ['22:14:02', '', 'SCAN', 'Nmap engine initialized', ''],
                  ['22:14:03', 'ok', 'OPEN', 'Port ', '22/tcp — OpenSSH 8.4'],
                  ['22:14:03', 'ok', 'OPEN', 'Port ', '80/tcp — Apache 2.4.49'],
                  ['22:14:04', 'warn', 'WARN', 'Port ', '3306/tcp — MySQL exposed'],
                  ['22:14:05', '', 'CVE', 'Querying CIRCL database...', ''],
                  ['22:14:05', 'err', 'CRIT', '', 'CVE-2021-41773 CVSS 9.8'],
                  ['22:14:06', 'warn', 'HIGH', '', 'CVE-2022-22965 CVSS 7.2'],
                  ['22:14:07', 'ok', 'PII', 'Redaction complete — 3 fields masked', ''],
                  ['22:14:08', '', 'AI', 'Gemini analysis in progress...', ''],
                  ['22:14:11', 'ok', 'DONE', 'Report generated — ', '2 critical'],
                ].map(([time, tagClass, tag, msg, val], i) => (
                  <div className="term-line" key={i}>
                    <span className="term-time">{time}</span>
                    <span className={`term-tag ${tagClass}`}>[{tag}]</span>
                    <span className="term-msg">{msg}<span className="term-val">{val}</span></span>
                    {i === 11 && <span className="term-cursor" />}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* METRICS */}
      <div id="metrics">
        <div className="metrics-grid">
          {[
            [247891, '', 'CVEs in database'],
            [99, '.7%', 'Detection accuracy'],
            [3, 's', 'Average scan time'],
            [0, '', 'Raw IPs stored externally'],
          ].map(([target, suffix, label]) => (
            <div className="metric-item" data-target={target} data-suffix={suffix} key={target}>
              <div className="metric-val"><span className="count-val">0</span><span className="unit">{suffix}</span></div>
              <div className="metric-label">{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* PRIVACY */}
      <section id="privacy">
        <div className="privacy-visual">
          <div className="pipeline-flow">
            {[
              [{ color: 'var(--text2)' }, '01 — Network Scan', 'Nmap + Scapy enumerate ports and services'],
              [{ color: 'var(--text2)' }, '02 — CVE Correlation', 'CIRCL database lookup — deterministic, no AI'],
              [{ color: 'var(--green)' }, '03 — PII Redaction', 'IPs, hostnames, MACs stripped before any external call'],
              [{ color: 'var(--text2)' }, '04 — AI Analysis', 'Redacted data feeds Gemini — no PII in context'],
              [{ color: 'var(--text2)' }, '05 — Report Delivery', 'Anonymized results stored in your personal dashboard'],
            ].map(([nodeStyle, name, detail], i) => (
              <div className={`pipe-step ${i === 2 ? 'highlight' : ''}`} key={i}>
                <div className="pipe-node">
                  <svg viewBox="0 0 24 24" fill="none">
                    {i === 0 && <><circle cx="12" cy="12" r="8" stroke={nodeStyle.color} strokeWidth="1.5" /><path d="M12 8v4l2 2" stroke={nodeStyle.color} strokeWidth="1.2" strokeLinecap="round" /></>}
                    {i === 1 && <><rect x="4" y="6" width="16" height="12" rx="2" stroke={nodeStyle.color} strokeWidth="1.5" /><path d="M8 10h8M8 14h5" stroke={nodeStyle.color} strokeWidth="1.2" strokeLinecap="round" /></>}
                    {i === 2 && <><path d="M12 3L12 8M12 16L12 21M3 12L8 12M16 12L21 12" stroke={nodeStyle.color} strokeWidth="1.5" strokeLinecap="round" /><circle cx="12" cy="12" r="4" stroke={nodeStyle.color} strokeWidth="1.5" /></>}
                    {i === 3 && <path d="M12 2L15 8H21L16 12L18 18L12 14L6 18L8 12L3 8H9L12 2Z" stroke={nodeStyle.color} strokeWidth="1.5" strokeLinejoin="round" />}
                    {i === 4 && <path d="M9 12l2 2 4-4M7 4a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-4-4H7z" stroke={nodeStyle.color} strokeWidth="1.5" strokeLinecap="round" />}
                  </svg>
                </div>
                <div className="pipe-info">
                  <div className="pipe-name">{name}</div>
                  <div className="pipe-detail">{detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="privacy-text">
          <div className="privacy-tag"><span className="dot" /> Privacy Architecture</div>
          <h2 className="privacy-h2 reveal">Your network.<br />Not our data.</h2>
          <p className="privacy-p">Every scan result passes through mandatory PII redaction before touching any external service. Raw IP addresses never reach Gemini&apos;s context window.</p>
          <p className="privacy-p">We built the pipeline so the AI sees threat signatures, not your infrastructure topology. The difference matters.</p>
        </div>
      </section>

      {/* CTA */}
      <section id="cta">
        <h2 className="cta-h2 reveal">
          Know your<br />
          <span className="green-stroke">attack surface.</span>
        </h2>
        <p className="cta-sub">Scan your network. Get real CVEs. Understand your risk in plain English.</p>
        <div className="hero-actions" style={{ opacity: 1, animation: 'none' }}>
          <Link href="/login" className="btn-primary">
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24">
              <path d="M13 5l7 7-7 7M5 12h15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Launch Scanner
          </Link>
        </div>
      </section>

      <Footer />
    </>
  )
}
