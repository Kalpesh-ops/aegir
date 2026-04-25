'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
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

const POLL_INTERVAL_MS = 1500

export default function SetupWizardPage() {
  const router = useRouter()
  const [token, setToken] = useState(null)
  const [loading, setLoading] = useState(true)
  const [deps, setDeps] = useState([])
  const [accepted, setAccepted] = useState({})
  const [activeJobs, setActiveJobs] = useState({})
  const [globalError, setGlobalError] = useState(null)
  const pollRef = useRef(null)

  useEffect(() => {
    async function init() {
      const sb = getSupabase()
      const { data: { session } } = await sb.auth.getSession()
      if (!session) {
        router.push('/login')
        return
      }
      setToken(session.access_token)
      await refreshDetect(session.access_token)
      setLoading(false)
    }
    init()
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function refreshDetect(t = token) {
    if (!t) return
    try {
      const res = await fetch(`${API_URL}/api/setup/detect`, {
        headers: { Authorization: `Bearer ${t}` },
      })
      if (!res.ok) {
        setGlobalError(`Detection failed (${res.status}). Backend may be offline.`)
        return
      }
      const json = await res.json()
      setDeps(json.dependencies || [])
      setGlobalError(null)
    } catch (err) {
      setGlobalError(`Could not reach backend: ${err.message}`)
    }
  }

  async function acceptLicense(dep) {
    if (!dep.license_url) return true
    if (accepted[dep.id]) return true
    try {
      const res = await fetch(`${API_URL}/api/setup/license`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ dep_id: dep.id }),
      })
      if (!res.ok) return false
      setAccepted((prev) => ({ ...prev, [dep.id]: true }))
      return true
    } catch {
      return false
    }
  }

  async function startInstall(dep) {
    const ok = await acceptLicense(dep)
    if (!ok) {
      setGlobalError(`Could not record license acceptance for ${dep.display_name}.`)
      return
    }

    try {
      const res = await fetch(`${API_URL}/api/setup/install`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ dep_id: dep.id }),
      })
      const json = await res.json()
      if (!res.ok) {
        setGlobalError(json.detail || `Install failed for ${dep.display_name}.`)
        return
      }
      setActiveJobs((prev) => ({ ...prev, [dep.id]: json.job }))
      ensurePolling()
    } catch (err) {
      setGlobalError(`Install request failed: ${err.message}`)
    }
  }

  async function cancelInstall(dep) {
    const job = activeJobs[dep.id]
    if (!job) return
    await fetch(`${API_URL}/api/setup/install/${job.id}/cancel`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
  }

  function ensurePolling() {
    if (pollRef.current) return
    pollRef.current = setInterval(async () => {
      const updates = await Promise.all(
        Object.values(activeJobs).map(async (j) => {
          try {
            const res = await fetch(`${API_URL}/api/setup/install/${j.id}`, {
              headers: { Authorization: `Bearer ${token}` },
            })
            if (!res.ok) return j
            const data = await res.json()
            return data.job
          } catch {
            return j
          }
        }),
      )

      const next = {}
      let anyActive = false
      for (const j of updates) {
        if (!j) continue
        next[j.dep_id] = j
        if (!['succeeded', 'failed', 'cancelled'].includes(j.status)) {
          anyActive = true
        }
      }
      setActiveJobs(next)

      if (!anyActive) {
        clearInterval(pollRef.current)
        pollRef.current = null
        await refreshDetect()
      }
    }, POLL_INTERVAL_MS)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-200 p-8">
        Loading…
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-200 p-8">
      <div className="max-w-3xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-semibold">Setup &amp; Dependencies</h1>
            <p className="text-sm text-zinc-400 mt-1">
              The scanner uses three native tools. Install only what you need —
              every dependency is downloaded directly from the upstream vendor.
            </p>
          </div>
          <Link href="/dashboard" className="text-sm text-zinc-400 hover:text-zinc-100">
            ← Dashboard
          </Link>
        </div>

        {globalError ? (
          <div className="mb-4 rounded border border-red-700 bg-red-950/40 px-4 py-3 text-sm text-red-200">
            {globalError}
          </div>
        ) : null}

        <ul className="space-y-4">
          {deps.map((dep) => (
            <DepCard
              key={dep.id}
              dep={dep}
              accepted={accepted[dep.id] === true}
              onAccept={() => acceptLicense(dep)}
              onInstall={() => startInstall(dep)}
              onCancel={() => cancelInstall(dep)}
              job={activeJobs[dep.id]}
            />
          ))}
        </ul>

        <p className="text-xs text-zinc-500 mt-8 leading-relaxed">
          Nothing leaves your machine other than the HTTPS downloads from the
          vendors above. The app does not redistribute Nmap, Wireshark, or
          Npcap — clicking <em>Install</em> downloads the official installer
          and runs it locally with your acknowledgement of the upstream
          license.
        </p>
      </div>
    </div>
  )
}

function DepCard({ dep, accepted, onAccept, onInstall, onCancel, job }) {
  const isActive = job && !['succeeded', 'failed', 'cancelled'].includes(job.status)
  const statusLabel = job ? job.status : dep.installed ? 'installed' : 'missing'

  return (
    <li className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-medium">{dep.display_name}</h3>
            <StatusBadge status={statusLabel} version={dep.version} />
          </div>
          <p className="text-sm text-zinc-400 mt-1">{dep.purpose}</p>

          {dep.license_url ? (
            <p className="text-xs text-zinc-500 mt-2">
              License: <a href={dep.license_url} target="_blank" rel="noreferrer" className="underline hover:text-zinc-200">{dep.license_name}</a>
              {dep.url ? (
                <>
                  {' · '}
                  Source:{' '}
                  <a href={dep.url} target="_blank" rel="noreferrer" className="underline hover:text-zinc-200">
                    {new URL(dep.url).hostname}
                  </a>
                  {dep.size_mb ? ` · ~${dep.size_mb} MB` : null}
                </>
              ) : null}
            </p>
          ) : null}
        </div>

        <div className="flex flex-col items-end gap-2 shrink-0">
          {dep.installed ? (
            <span className="text-xs text-emerald-400">Already installed</span>
          ) : dep.install_method === 'not_applicable' ? (
            <span className="text-xs text-zinc-500">Not applicable on {dep.platform}</span>
          ) : isActive ? (
            <button
              onClick={onCancel}
              className="px-3 py-1.5 text-sm rounded bg-zinc-800 hover:bg-zinc-700 border border-zinc-700"
            >
              Cancel
            </button>
          ) : (
            <>
              {dep.license_url ? (
                <label className="flex items-center gap-2 text-xs text-zinc-400">
                  <input
                    type="checkbox"
                    checked={accepted}
                    onChange={onAccept}
                    className="accent-emerald-500"
                  />
                  I accept the upstream license
                </label>
              ) : null}
              <button
                onClick={onInstall}
                disabled={dep.license_url && !accepted}
                className="px-3 py-1.5 text-sm rounded bg-emerald-600 hover:bg-emerald-500 disabled:bg-zinc-800 disabled:text-zinc-500 disabled:cursor-not-allowed"
              >
                Install
              </button>
            </>
          )}
        </div>
      </div>

      {job ? <JobProgress job={job} /> : null}
    </li>
  )
}

function StatusBadge({ status, version }) {
  const colour =
    status === 'installed'
      ? 'bg-emerald-900/50 text-emerald-300 border-emerald-700'
      : status === 'failed' || status === 'cancelled'
      ? 'bg-red-900/50 text-red-300 border-red-700'
      : status === 'succeeded'
      ? 'bg-emerald-900/50 text-emerald-300 border-emerald-700'
      : status === 'missing'
      ? 'bg-zinc-800 text-zinc-300 border-zinc-700'
      : 'bg-amber-900/40 text-amber-200 border-amber-700'
  return (
    <span className={`px-2 py-0.5 text-xs rounded border ${colour}`}>
      {status}{version ? ` · v${version}` : ''}
    </span>
  )
}

function JobProgress({ job }) {
  const pct = job.bytes_total
    ? Math.min(100, Math.round((job.bytes_downloaded / job.bytes_total) * 100))
    : null

  return (
    <div className="mt-3 text-xs text-zinc-400">
      <div className="flex items-center gap-2">
        <span className="font-mono uppercase tracking-wide">{job.status}</span>
        {pct !== null ? <span>{pct}%</span> : null}
        {job.error ? <span className="text-red-300">— {job.error}</span> : null}
      </div>
      {pct !== null ? (
        <div className="mt-1.5 h-1 w-full bg-zinc-800 rounded overflow-hidden">
          <div
            className="h-full bg-emerald-500 transition-all"
            style={{ width: `${pct}%` }}
          />
        </div>
      ) : null}
      {job.log && job.log.length > 0 ? (
        <pre className="mt-2 max-h-24 overflow-auto text-[10px] text-zinc-500 whitespace-pre-wrap">
          {job.log.slice(-3).join('\n')}
        </pre>
      ) : null}
    </div>
  )
}
