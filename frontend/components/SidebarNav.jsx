'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'

const navItems = [
  {
    href: '/dashboard',
    label: 'Overview',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
      </svg>
    ),
  },
  {
    href: '/dashboard/scan',
    label: 'New Scan',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="11" cy="11" r="7" />
        <path d="M21 21l-4.35-4.35" />
        <path d="M11 8v6M8 11h6" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    href: '/dashboard/history',
    label: 'History',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 3" strokeLinecap="round" />
      </svg>
    ),
  },
]

export default function SidebarNav() {
  const pathname = usePathname()

  function isActive(href) {
    if (href === '/dashboard') return pathname === '/dashboard'
    return pathname === href || pathname.startsWith(href + '/')
  }

  return (
    <div style={{ padding: '20px 12px', flex: 1 }}>
      <p style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '9px',
        color: 'rgba(240,237,232,0.25)',
        letterSpacing: '0.18em',
        textTransform: 'uppercase',
        marginBottom: '8px',
        paddingLeft: '12px',
      }}>
        Navigation
      </p>
      <nav style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
        {navItems.map(({ href, label, icon }) => {
          const active = isActive(href)
          return (
            <Link
              key={href}
              href={href}
              prefetch={true}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px 12px',
                color: active ? '#f0ede8' : 'rgba(240,237,232,0.5)',
                background: active ? 'rgba(255,255,255,0.04)' : 'transparent',
                borderLeft: active ? '2px solid #00ff88' : '2px solid transparent',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '11px',
                letterSpacing: '0.08em',
                textDecoration: 'none',
                transition: 'color 0.2s, background 0.2s, border-color 0.2s',
              }}
              onMouseEnter={(e) => {
                if (!active) {
                  e.currentTarget.style.color = 'rgba(240,237,232,0.8)'
                  e.currentTarget.style.background = 'rgba(255,255,255,0.02)'
                }
              }}
              onMouseLeave={(e) => {
                if (!active) {
                  e.currentTarget.style.color = 'rgba(240,237,232,0.5)'
                  e.currentTarget.style.background = 'transparent'
                }
              }}
            >
              <span style={{ flexShrink: 0 }}>{icon}</span>
              {label}
            </Link>
          )
        })}
      </nav>
    </div>
  )
}
