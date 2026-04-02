import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import DashboardClient from '@/components/DashboardClient'
import { scanCache } from '@/lib/localCache'

export const dynamic = 'force-dynamic'

export default async function DashboardPage() {
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
          } catch {}
        },
      },
    }
  )
  
  const { data: { session }, error } = await supabase.auth.getSession()
    const user = session?.user

  if (!user || error) {
    redirect('/login')
  }

  // Use let, and ensure no other 'scans' variable exists in this function
  let scans = scanCache.get(user.id, 50)

  if (!scans) {
    const { data } = await supabase
      .from('scans')
      .select('id, target_redacted, scan_timestamp, cve_count, highest_cvss, crit_count, high_count, med_count, low_count')
      .eq('user_id', user.id)
      .order('scan_timestamp', { ascending: false })
      .limit(50)
      
    scans = data || []
    scanCache.set(user.id, 50, scans)
  }

  return <DashboardClient scans={scans} />
}