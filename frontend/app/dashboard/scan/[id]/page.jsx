import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import ScanResultClient from '@/components/ScanResultClient'

export const dynamic = 'force-dynamic'

export default async function ScanResultPage({ params: paramsPromise }) {
  const params = await paramsPromise
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

  const { data: scan } = await supabase
    .from('scans')
    .select('*')
    .eq('id', params.id)
    .eq('user_id', user.id)
    .single()

  if (!scan) {
    redirect('/dashboard/history')
  }

  const ports = (() => {
    try {
      // Fix: Check for ports_json first, fallback to ports
      const raw = scan.ports_json || scan.ports 
      if (Array.isArray(raw)) return raw
      if (typeof raw === 'string') return JSON.parse(raw)
      if (raw && typeof raw === 'object') return Object.values(raw)
      return []
    } catch { return [] }
  })()

  const cveFindings = (() => {
    try {
      // Fix: Apply the same bulletproof fallback here
      const raw = scan.cve_findings_json || scan.cve_findings
      if (Array.isArray(raw)) return raw
      if (typeof raw === 'string') return JSON.parse(raw)
      if (raw && typeof raw === 'object') return Object.values(raw)
      return []
    } catch { return [] }
  })()

  return (
    <ScanResultClient
      id={scan.id}
      target_redacted={scan.target_redacted}
      scan_timestamp={scan.scan_timestamp}
      ports={ports}
      cve_findings={cveFindings}
      ai_summary={scan.ai_summary}
      firewall={scan.firewall_json}
      traffic={scan.traffic_json}
      scan_mode={scan.scan_mode}  
      cve_count={scan.cve_count}
      highest_cvss={scan.highest_cvss}
    />
  )
}