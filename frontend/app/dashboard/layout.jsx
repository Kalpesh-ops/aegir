import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export const dynamic = 'force-dynamic'
import { redirect } from 'next/navigation'
import Link from 'next/link'
import SidebarNav from '@/components/SidebarNav'
import SidebarFooter from '@/components/SidebarFooter'

export default async function DashboardLayout({ children }) {
  const cookieStore = await cookies()
  const supabase = createServerClient(
    process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll()
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options)
            )
          } catch {
            // Server component - setAll called from middleware is fine to ignore
          }
        },
      },
    }
  )
  const { data: { user }, error } = await supabase.auth.getUser()

  if (!user || error) {
    redirect('/login')
  }

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'row',
      minHeight: '100vh',
      background: '#060608',
    }}>
      {/* SIDEBAR */}
      <aside style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '240px',
        height: '100vh',
        zIndex: 50,
        background: 'rgba(255,255,255,0.02)',
        borderRight: '1px solid rgba(255,255,255,0.06)',
        display: 'flex',
        flexDirection: 'column',
      }}>
        {/* Logo */}
        <div style={{
          padding: '28px 24px',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
        }}>
          <Link href="/" style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontFamily: "'Syne', sans-serif",
            fontWeight: 600,
            fontSize: '18px',
            color: '#f0ede8',
            textDecoration: 'none',
            letterSpacing: '0.08em',
            marginBottom: '4px',
          }}>
            <span style={{
              width: '7px',
              height: '7px',
              background: '#00ff88',
              borderRadius: '50%',
              boxShadow: '0 0 12px #00ff88',
              display: 'inline-block',
              flexShrink: 0,
            }} />
            AEGIR
          </Link>
          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '9px',
            color: 'rgba(240,237,232,0.3)',
            letterSpacing: '0.15em',
            textTransform: 'uppercase',
          }}>
            Security Platform
          </p>
        </div>

        {/* Nav */}
        <SidebarNav />

        {/* Footer */}
        <SidebarFooter userEmail={user.email} />
      </aside>

      {/* MAIN CONTENT */}
      <main style={{
        marginLeft: '240px',
        flex: 1,
        minHeight: '100vh',
        position: 'relative',
        zIndex: 1,
        background: '#060608',
        padding: '40px',
      }}>
        {children}
      </main>

      {/* MOBILE BOTTOM NAV */}
      <style>{`
        @media (max-width: 768px) {
          aside { display: none; }
          main { margin-left: 0; padding: 20px; padding-bottom: 80px; }
        }
      `}</style>

      <nav style={{
        display: 'none',
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        height: '60px',
        background: 'rgba(6,6,8,0.95)',
        borderTop: '1px solid rgba(255,255,255,0.06)',
        backdropFilter: 'blur(20px)',
        zIndex: 100,
        justifyContent: 'space-around',
        alignItems: 'center',
        padding: '0 20px',
      }} className="mobile-nav">
        {[
          { href: '/dashboard', label: 'Overview', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg> },
          { href: '/dashboard/scan', label: 'Scan', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/><path d="M11 8v6M8 11h6"/></svg> },
          { href: '/dashboard/history', label: 'History', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg> },
        ].map(({ href, label, icon }) => (
          <Link key={href} href={href} style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '4px',
            color: 'rgba(240,237,232,0.4)',
            textDecoration: 'none',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '9px',
            letterSpacing: '0.08em',
            padding: '8px 16px',
            transition: 'color 0.2s',
          }}>
            {icon}
            {label}
          </Link>
        ))}
      </nav>
    </div>
  )
}
