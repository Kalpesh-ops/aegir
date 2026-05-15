'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    function onScroll() {
      setScrolled(window.scrollY > 60)
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <nav id="navbar" className={scrolled ? 'scrolled' : ''}>
      <Link href="/" className="nav-logo">
        <span className="nav-logo-dot" />
        AEGIR
      </Link>
      <ul className="nav-links">
        <li><a href="/#features">Features</a></li>
        <li><a href="/#how-it-works">How It Works</a></li>
        <li><a href="/#privacy">Privacy</a></li>
        <li><Link href="/dashboard">Dashboard</Link></li>
        <li>
          <a href="https://github.com/Kalpesh-ops/aegir" target="_blank" rel="noreferrer">
            GitHub
          </a>
        </li>
      </ul>
      <Link href="/dashboard" className="nav-cta">
        Launch Demo
      </Link>
    </nav>
  )
}
