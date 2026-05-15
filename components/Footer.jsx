'use client'

import { useEffect } from 'react'
import Link from 'next/link'

export default function Footer() {
  useEffect(() => {
    const footerText = document.getElementById('footer-hero-text')
    const footer = document.getElementById('footer')
    if (!footer) return

    function updateFooter() {
      const rect = footer.getBoundingClientRect()
      const winH = window.innerHeight
      const progress = Math.max(0, Math.min(1, (winH - rect.top) / (winH * 0.7)))

      if (progress > 0.05) {
        footerText?.classList.add('emerged')
      } else {
        footerText?.classList.remove('emerged')
      }
    }

    window.addEventListener('scroll', updateFooter, { passive: true })
    updateFooter()

    return () => window.removeEventListener('scroll', updateFooter)
  }, [])

  return (
    <footer id="footer">
      <div className="footer-hero-wrap">
        <span className="footer-hero-text" id="footer-hero-text">AEGIR</span>
      </div>

      <div className="footer-top">
        <div className="footer-brand">
          <div className="footer-logo">AEGIR</div>
          <div className="footer-tagline">Network Security Intelligence</div>
          <div className="footer-tagline" style={{ marginTop: '8px', color: 'rgba(0,255,136,0.7)' }}>
            ● Showcase preview · public release coming soon
          </div>
        </div>

        <div className="footer-column">
          <div className="footer-col-title">Product</div>
          <Link href="/dashboard">Dashboard preview</Link>
          <a href="/#features">Features</a>
          <a href="/#how-it-works">How it works</a>
          <a href="/#privacy">Privacy architecture</a>
          <span className="footer-coming">Desktop app — coming soon</span>
          <span className="footer-coming">CLI distribution — coming soon</span>
        </div>

        <div className="footer-column">
          <div className="footer-col-title">Legal</div>
          <Link href="/legal/privacy-policy">Privacy Policy</Link>
          <Link href="/legal/terms-of-service">Terms of Service</Link>
          <Link href="/legal/consent-policy">Consent Policy</Link>
          <Link href="/legal/disclaimer">Disclaimer</Link>
        </div>

        <div className="footer-column">
          <div className="footer-col-title">Open source</div>
          <a
            href="https://github.com/Kalpesh-ops/aegir"
            target="_blank"
            rel="noreferrer"
          >
            GitHub repository
          </a>
          <a
            href="https://github.com/Kalpesh-ops/aegir/blob/main/LICENSE"
            target="_blank"
            rel="noreferrer"
          >
            Apache 2.0 License
          </a>
          <a
            href="https://github.com/Kalpesh-ops/aegir/blob/main/README.md"
            target="_blank"
            rel="noreferrer"
          >
            README
          </a>
          <span className="footer-coming">Discord — coming soon</span>
        </div>
      </div>

      <div className="footer-bottom">
        <div className="footer-copy">© 2026 Aegir — Built with intent.</div>
        <div className="footer-copy">
          Apache 2.0 License · <a
            href="https://github.com/Kalpesh-ops/aegir"
            target="_blank"
            rel="noreferrer"
            style={{ color: 'inherit', textDecoration: 'underline' }}
          >
            github.com/Kalpesh-ops/aegir
          </a>
        </div>
      </div>

      <style jsx>{`
        .footer-column {
          display: flex;
          flex-direction: column;
          gap: 10px;
          min-width: 180px;
        }
        .footer-col-title {
          font-family: 'JetBrains Mono', monospace;
          font-size: 10px;
          letter-spacing: 0.18em;
          text-transform: uppercase;
          color: rgba(0, 255, 136, 0.75);
          margin-bottom: 4px;
        }
        .footer-column :global(a),
        .footer-column a {
          font-family: 'Instrument Sans', sans-serif;
          font-size: 13px;
          color: rgba(240, 237, 232, 0.7);
          text-decoration: none;
          transition: color 0.2s;
        }
        .footer-column :global(a):hover,
        .footer-column a:hover {
          color: #f0ede8;
        }
        .footer-coming {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          color: rgba(240, 237, 232, 0.35);
          letter-spacing: 0.04em;
        }
      `}</style>
    </footer>
  )
}
