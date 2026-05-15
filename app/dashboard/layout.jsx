import Link from 'next/link'
import SidebarNav from '@/components/SidebarNav'
import SidebarFooter from '@/components/SidebarFooter'
import { DEMO_USER } from '@/lib/demoData'

export default function DashboardLayout({ children }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'row',
      minHeight: '100vh',
      background: '#060608',
    }}>
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
            Showcase Preview
          </p>
        </div>

        <SidebarNav />

        <SidebarFooter userEmail={DEMO_USER.email} />
      </aside>

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

      <style>{`
        @media (max-width: 768px) {
          aside { display: none; }
          main { margin-left: 0; padding: 20px; padding-bottom: 80px; }
        }
      `}</style>
    </div>
  )
}
