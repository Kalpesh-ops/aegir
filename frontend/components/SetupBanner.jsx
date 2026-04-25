'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { createBrowserClient } from '@supabase/ssr'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'

let supabaseClient = null
function getSupabase() {
  if (!supabaseClient) {
    supabaseClient = createBrowserClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    )
  }
  return supabaseClient
}

/**
 * Banner that informs the user if any native scanner dependency is missing.
 *
 * - Calls `/api/setup/detect` on mount; renders nothing while loading or if
 *   everything is installed.
 * - Honours a session-level dismiss (sessionStorage) so power users on
 *   POSIX hosts that already have nmap/tshark installed via their package
 *   manager don't see it again until they reload.
 */
export default function SetupBanner() {
  const [missing, setMissing] = useState(null)
  const [dismissed, setDismissed] = useState(false)

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setDismissed(sessionStorage.getItem('netsec.setup-banner.dismissed') === '1')
    }

    async function probe() {
      try {
        const sb = getSupabase()
        const { data: { session } } = await sb.auth.getSession()
        if (!session) return

        const res = await fetch(`${API_URL}/api/setup/detect`, {
          headers: { Authorization: `Bearer ${session.access_token}` },
        })
        if (!res.ok) return
        const data = await res.json()
        const out = (data.dependencies || []).filter(
          (d) => !d.installed && d.install_method !== 'not_applicable',
        )
        setMissing(out)
      } catch {
        // Silent — backend may not be running yet; the wizard handles surfacing
        // that itself when the user navigates to /dashboard/setup.
      }
    }
    probe()
  }, [])

  if (dismissed || !missing || missing.length === 0) return null

  function dismiss() {
    if (typeof window !== 'undefined') {
      sessionStorage.setItem('netsec.setup-banner.dismissed', '1')
    }
    setDismissed(true)
  }

  return (
    <div className="mb-4 rounded-lg border border-amber-700 bg-amber-950/30 px-4 py-3 flex items-start gap-3">
      <div className="flex-1">
        <p className="text-sm text-amber-100">
          {missing.length} native dependenc{missing.length === 1 ? 'y' : 'ies'} missing for full scan capability:{' '}
          <span className="font-medium">{missing.map((d) => d.display_name).join(', ')}</span>.
        </p>
        <p className="text-xs text-amber-200/70 mt-1">
          The scanner will fall back to limited mode without these. Each is
          downloaded directly from the upstream vendor with your consent.
        </p>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <Link
          href="/dashboard/setup"
          className="px-3 py-1.5 text-sm rounded bg-amber-500/90 hover:bg-amber-500 text-zinc-900 font-medium"
        >
          Set up
        </Link>
        <button
          onClick={dismiss}
          className="px-2 py-1.5 text-xs text-amber-200/80 hover:text-amber-100"
          aria-label="Dismiss until reload"
        >
          Dismiss
        </button>
      </div>
    </div>
  )
}
