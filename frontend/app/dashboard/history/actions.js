'use server'

import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
import { scanCache } from '@/lib/localCache'
import { revalidatePath } from 'next/cache'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

// All page sizes used by the app. Keep in sync with any fetchScans() callers.
const CACHE_PAGE_SIZES = [10, 25, 50, 100]

export async function clearUserHistoryAction() {
  const cookieStore = await cookies()
  const supabase = createServerClient(
    process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() { return cookieStore.getAll() },
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
    throw new Error('Unauthorized')
  }

  // 1. Delete all records for this specific user in the remote Supabase table
  const { error: deleteError } = await supabase
    .from('scans')
    .delete()
    .eq('user_id', user.id)

  if (deleteError) {
    throw new Error(deleteError.message)
  }

  // 2. Clear the local Node.js memory cache for this user across ALL page sizes
  CACHE_PAGE_SIZES.forEach((size) => scanCache.set(user.id, size, []))

  // 3. Delete from the local Python SQLite Database via API
  try {
    const res = await fetch(`${API_URL}/api/scans`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${session.access_token}`,
      },
    })
    if (!res.ok) {
      console.warn('Failed to clear local Python DB, but Supabase was cleared.')
    }
  } catch (err) {
    console.warn('Could not reach Python backend to clear local DB:', err)
  }

  // 4. Tell Next.js to refresh the UI
  revalidatePath('/dashboard')
  revalidatePath('/dashboard/history')

  return { success: true }
}
