import DashboardClient from '@/components/DashboardClient'
import { DEMO_SCANS } from '@/lib/demoData'

export default function DashboardPage() {
  return (
    <>
      <ShowcaseBanner />
      <DashboardClient scans={DEMO_SCANS} />
    </>
  )
}

function ShowcaseBanner() {
  return (
    <div style={{
      maxWidth: '1280px',
      margin: '0 auto 24px',
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
      SHOWCASE PREVIEW — All scan data on this page is illustrative. Live scanning is available in the desktop app.
    </div>
  )
}
