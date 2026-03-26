'use client'

import { useEffect } from 'react'
import Link from 'next/link'

export default function Footer() {
  useEffect(() => {
    const footerText = document.getElementById('footer-hero-text')
    const footer = document.getElementById('footer')

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
        <span className="footer-hero-text" id="footer-hero-text">NETSEC AI</span>
      </div>
      <div className="footer-top">
        <div className="footer-brand">
          <div className="footer-logo">NETSEC AI</div>
          <div className="footer-tagline">Network Security Intelligence</div>
        </div>
        <div className="footer-links">
          <a href="#features">Features</a>
          <a href="#how-it-works">How It Works</a>
          <a href="https://github.com/Kalpesh-ops/netsec-ai-scanner">GitHub</a>
        </div>
        <div className="footer-status">
          <span className="dot" />
          All systems operational
        </div>
      </div>
      <div className="footer-bottom">
        <div className="footer-copy">© 2026 NetSec AI — Built with intent.</div>
        <div className="footer-copy">Apache 2.0 License</div>
      </div>
    </footer>
  )
}
