import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import DashboardClient from '@/components/DashboardClient'
import { scanCache } from '@/lib/localCache' // <-- Add this import

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

  // --- NEW CACHE LOGIC ---
  let scans = scanCache.get(user.id, 50)

  if (!scans) {
    // Cache miss or expired: Fetch from database
    const { data } = await supabase
      .from('scans')
      .select('id, target_redacted, scan_timestamp, cve_count, highest_cvss')
      .eq('user_id', user.id)
      .order('scan_timestamp', { ascending: false })
      .limit(50)
      
    scans = data || []
    scanCache.set(user.id, 50, scans) // Save to cache
  }

  return <DashboardClient scans={scans} />
}