'use client'

import { useRouter } from 'next/navigation'

export default function SidebarFooter({ userEmail }) {
  const router = useRouter()

  function getSupabase() {
    let createBrowserClient
    try {
      createBrowserClient = require('@supabase/ssr').createBrowserClient
    } catch {
      return null
    }
    return createBrowserClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    )
  }

  async function handleSignOut() {
    await getSupabase().auth.signOut()
    router.push('/login')
    router.refresh()
  }

  const displayEmail = userEmail.length > 22
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
      <button
        onClick={handleSignOut}
        style={{
          width: '100%',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          textTransform: 'uppercase',
          letterSpacing: '0.12em',
          color: 'rgba(240,237,232,0.35)',
          background: 'transparent',
          border: '1px solid rgba(255,255,255,0.08)',
          padding: '8px',
          cursor: 'pointer',
          transition: 'color 0.2s, border-color 0.2s, background 0.2s',
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.color = 'rgba(240,237,232,0.7)'
          e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)'
          e.currentTarget.style.background = 'rgba(255,255,255,0.03)'
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.color = 'rgba(240,237,232,0.35)'
          e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'
          e.currentTarget.style.background = 'transparent'
        }}
      >
        Sign Out
      </button>
    </div>
  )
}
