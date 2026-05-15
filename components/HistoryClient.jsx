'use client'

import { useState, useMemo } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { clearUserHistoryAction } from '../app/dashboard/history/actions'

function formatDate(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
  const mm = months[d.getMonth()]
  const dd = String(d.getDate()).padStart(2, '0')
  const yyyy = d.getFullYear()
  return `${mm} ${dd}, ${yyyy}`
}

function parseCvss(cvss) {
  if (cvss === null || cvss === undefined) return 0
  return parseFloat(cvss) || 0
}

function getPortCount(scan) {
  if (!scan) return null

  if (scan.ports_count !== null && scan.ports_count !== undefined && scan.ports_count !== '') {
    const explicitCount = Number(scan.ports_count)
    if (Number.isFinite(explicitCount)) return explicitCount
  }

  const rawPorts = scan.ports_json ?? scan.ports
  if (rawPorts === null || rawPorts === undefined) return null

  if (typeof rawPorts === 'string') {
    try {
      const parsed = JSON.parse(rawPorts)
      if (Array.isArray(parsed)) return parsed.length
      if (parsed && typeof parsed === 'object') {
        if (Array.isArray(parsed.open_ports)) return parsed.open_ports.length
        if (Array.isArray(parsed.ports)) return parsed.ports.length
      }
    } catch {
      return null
    }
    return null
  }

  if (Array.isArray(rawPorts)) return rawPorts.length

  if (rawPorts && typeof rawPorts === 'object') {
    if (Array.isArray(rawPorts.open_ports)) return rawPorts.open_ports.length
    if (Array.isArray(rawPorts.ports)) return rawPorts.ports.length
  }

  return null
}

function getRisk(cvss, cveCount) {
  const score = parseCvss(cvss)
  if (cveCount === 0) return 'clean'
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  return 'low'
}

const riskConfig = {
  critical: { color: '#ff4560', bg: 'rgba(255,69,96,0.12)', label: 'Critical' },
  high:     { color: '#ffb340', bg: 'rgba(255,179,64,0.12)', label: 'High' },
  medium:   { color: '#4af4ff', bg: 'rgba(74,244,255,0.12)', label: 'Medium' },
  low:       { color: '#00ff88', bg: 'rgba(0,255,136,0.08)', label: 'Low' },
  clean:    { color: '#00ff88', bg: 'rgba(0,255,136,0.08)', label: 'Clean' },
}

const accentColors = {
  critical: '#ff4560',
  high:     '#ffb340',
  medium:   '#4af4ff',
  low:      'rgba(0,255,136,0.5)',
  clean:    'rgba(240,237,232,0.15)',
}

const filterFilters = {
  All: () => true,
  Critical: (s) => parseCvss(s.highest_cvss) >= 9,
  High:     (s) => parseCvss(s.highest_cvss) >= 7 && parseCvss(s.highest_cvss) < 9,
  Medium:   (s) => parseCvss(s.highest_cvss) >= 4 && parseCvss(s.highest_cvss) < 7,
  Low:      (s) => parseCvss(s.highest_cvss) < 4 && parseCvss(s.cve_count) > 0,
  Clean:    (s) => s.cve_count === 0 || s.cve_count === null,
}

function ScanCard({ scan, index }) {
  const router = useRouter()
  const risk = getRisk(scan.highest_cvss, scan.cve_count)
  const cfg = riskConfig[risk]
  const accentColor = accentColors[risk]
  const portCount = getPortCount(scan)
  const animDelay = Math.min(index * 40, 400)

  return (
    <div
      onClick={() => router.push(`/dashboard/scan/${scan.id}`)}
      style={{
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.07)',
        padding: '24px',
        position: 'relative',
        overflow: 'hidden',
        cursor: 'pointer',
        transition: 'all 0.2s',
        animation: `fadeUp 0.4s cubic-bezier(0.16,1,0.3,1) ${animDelay}ms both`,
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = 'rgba(255,255,255,0.14)'
        e.currentTarget.style.background = 'rgba(255,255,255,0.05)'
        e.currentTarget.style.transform = 'translateY(-2px)'
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'
        e.currentTarget.style.background = 'rgba(255,255,255,0.03)'
        e.currentTarget.style.transform = 'translateY(0)'
      }}
    >
      <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: '2px', background: accentColor }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '13px', color: '#f0ede8', paddingLeft: '8px', wordBreak: 'break-all' }}>
          {scan.target_redacted || '—'}
        </span>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.08em', color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.color}`, padding: '3px 8px', marginLeft: '8px', flexShrink: 0 }}>
          {cfg.label}
        </span>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', paddingLeft: '8px' }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', color: 'rgba(240,237,232,0.35)' }}>
          {formatDate(scan.scan_timestamp)}
        </span>
        {scan.scan_mode && (
          <span style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: '8px', textTransform: 'uppercase',
            letterSpacing: '0.08em',
            color: scan.scan_mode === 'pen_test' ? '#ffb340' : scan.scan_mode === 'deep' ? '#4af4ff' : '#00ff88',
            opacity: 0.7,
          }}>
            {scan.scan_mode === 'pen_test' ? 'Pen Test' : scan.scan_mode === 'deep' ? 'Deep' : 'Fast'}
          </span>
        )}
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', color: cfg.color }}>
          {scan.cve_count ?? 0} CVEs
        </span>
      </div>
      <div style={{ height: '1px', background: 'rgba(255,255,255,0.06)', marginBottom: '14px', marginLeft: '8px' }} />
      <div style={{ display: 'flex', gap: '24px', paddingLeft: '8px', marginBottom: '16px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '8px', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'rgba(240,237,232,0.3)' }}>CVSS</span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', fontWeight: 500, color: cfg.color }}>{parseCvss(scan.highest_cvss).toFixed(1)}</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '8px', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'rgba(240,237,232,0.3)' }}>Ports</span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', fontWeight: 500, color: 'rgba(240,237,232,0.6)' }}>{portCount === null ? 'N/A' : portCount}</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '8px', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'rgba(240,237,232,0.3)' }}>Status</span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', fontWeight: 500, color: '#00ff88' }}>Complete</span>
        </div>
      </div>
      <div style={{ paddingLeft: '8px' }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', color: '#00ff88', letterSpacing: '0.05em' }}>View Report →</span>
      </div>
    </div>
  )
}

const FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low', 'Clean']

export default function HistoryClient({ scans }) {
  const router = useRouter()
  const [activeFilter, setActiveFilter] = useState('All')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [modeFilter, setModeFilter] = useState('All')
  
  // Modal State
  const [showModal, setShowModal] = useState(false)
  const [isClearing, setIsClearing] = useState(false)

  const PER_PAGE = 20

  const filtered = useMemo(() => {
    let result = scans
    if (activeFilter !== 'All') {
      result = result.filter(filterFilters[activeFilter])
    }
    if (modeFilter !== 'All') {
      const modeMap = { Fast: 'fast', Deep: 'deep', 'Pen Test': 'pen_test' }
      result = result.filter((s) => (s.scan_mode || 'fast') === modeMap[modeFilter])
    }
    if (search.trim()) {
      const q = search.trim().toLowerCase()
      result = result.filter((s) => (s.target_redacted || '').toLowerCase().includes(q))
    }
    return result
  }, [scans, activeFilter, modeFilter, search])

  const totalPages = Math.ceil(filtered.length / PER_PAGE)
  const paginated = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE)
  const gridKey = `${activeFilter}-${modeFilter}-${search}`

  const handleClearHistory = async () => {
    try {
      setIsClearing(true)
      await clearUserHistoryAction()
      setShowModal(false)
    } catch (err) {
      console.error("Failed to clear history:", err)
      alert("Failed to clear history. Please try again.")
    } finally {
      setIsClearing(false)
    }
  }

  const filterBtn = (f) => {
    const isActive = activeFilter === f
    const riskColor = f === 'All' ? '#00ff88' : f === 'Critical' ? '#ff4560' : f === 'High' ? '#ffb340' : f === 'Medium' ? '#4af4ff' : f === 'Low' ? 'rgba(240,237,232,0.3)' : '#00ff88'
    return {
      fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.1em', padding: '8px 18px',
      border: isActive ? `1px solid ${riskColor}` : '1px solid rgba(255,255,255,0.08)',
      background: isActive ? `${riskColor}10` : 'transparent',
      color: isActive ? riskColor : 'rgba(240,237,232,0.4)',
      cursor: 'pointer', transition: 'all 0.2s',
    }
  }

  return (
    <div>
      <style>{`
        @keyframes fadeUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes modalFade { from { opacity: 0; backdrop-filter: blur(0px); } to { opacity: 1; backdrop-filter: blur(4px); } }
      `}</style>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
        <div>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.18em', color: '#00ff88', marginBottom: '8px' }}>Scan History</p>
          <h1 style={{ fontFamily: "'Syne', sans-serif", fontWeight: 500, fontSize: '40px', color: '#f0ede8', lineHeight: 1, marginBottom: '8px' }}>All Scans</h1>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: 'rgba(240,237,232,0.35)' }}>{scans.length} scans recorded</p>
        </div>
        
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <input
            type="text"
            placeholder="Search by target..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1) }}
            style={{
              background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', padding: '12px 16px',
              fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: '#f0ede8', outline: 'none', width: '280px', transition: 'all 0.2s',
            }}
            onFocus={(e) => { e.target.style.borderColor = 'rgba(0,255,136,0.5)'; e.target.style.boxShadow = '0 0 0 3px rgba(0,255,136,0.06)' }}
            onBlur={(e) => { e.target.style.borderColor = 'rgba(255,255,255,0.08)'; e.target.style.boxShadow = 'none' }}
          />
          <button
            onClick={() => setShowModal(true)}
            disabled={scans.length === 0}
            style={{
              fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.1em',
              padding: '12px 20px', background: 'transparent', border: '1px solid #ff4560', color: '#ff4560',
              cursor: scans.length === 0 ? 'not-allowed' : 'pointer', opacity: scans.length === 0 ? 0.3 : 1, transition: 'all 0.2s'
            }}
            onMouseEnter={(e) => { if (scans.length > 0) { e.currentTarget.style.background = 'rgba(255,69,96,0.1)'; e.currentTarget.style.color = '#fff' } }}
            onMouseLeave={(e) => { if (scans.length > 0) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#ff4560' } }}
          >
            Clear History
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '24px' }}>
        {FILTERS.map((f) => (
          <button
            key={f} style={filterBtn(f)} onClick={() => { setActiveFilter(f); setPage(1) }}
            onMouseEnter={(e) => { if (activeFilter !== f) { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.15)'; e.currentTarget.style.color = '#f0ede8' } }}
            onMouseLeave={(e) => {
              if (activeFilter !== f) {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.color = 'rgba(240,237,232,0.4)'
              }
            }}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Mode Filters */}
      <div style={{ display: 'flex', gap: '8px', marginTop: '10px', marginBottom: '8px' }}>
        {['All', 'Fast', 'Deep', 'Pen Test'].map((m) => {
          const isActive = modeFilter === m
          const color = m === 'Fast' ? '#00ff88' : m === 'Deep' ? '#4af4ff' : m === 'Pen Test' ? '#ffb340' : 'rgba(240,237,232,0.5)'
          const activeBackground = m === 'Fast'
            ? 'rgba(0,255,136,0.12)'
            : m === 'Deep'
              ? 'rgba(74,244,255,0.12)'
              : m === 'Pen Test'
                ? 'rgba(255,179,64,0.12)'
                : 'rgba(240,237,232,0.12)'
          return (
            <button
              key={m}
              onClick={() => { setModeFilter(m); setPage(1) }}
              style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: '9px', textTransform: 'uppercase',
                letterSpacing: '0.1em', padding: '5px 14px',
                border: isActive ? `1px solid ${color}` : '1px solid rgba(255,255,255,0.06)',
                background: isActive ? activeBackground : 'transparent',
                color: isActive ? color : 'rgba(240,237,232,0.3)',
                cursor: 'pointer', transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => { if (!isActive) { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.15)'; e.currentTarget.style.color = '#f0ede8' } }}
              onMouseLeave={(e) => { if (!isActive) { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = 'rgba(240,237,232,0.3)' } }}
            >
              {m === 'All' ? 'All Modes' : m}
            </button>
          )
        })}
      </div>

      {/* Cards Grid */}
      {scans.length === 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '80px 40px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', marginTop: '32px' }}>
          <p style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: '120px', color: 'rgba(240,237,232,0.06)', lineHeight: 1, marginBottom: '24px' }}>0</p>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'rgba(240,237,232,0.3)', marginBottom: '32px' }}>No scans recorded yet.</p>
          <Link href="/dashboard/scan" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', fontWeight: 500, letterSpacing: '0.12em', textTransform: 'uppercase', color: '#060608', background: '#00ff88', border: 'none', padding: '14px 36px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', clipPath: 'polygon(10px 0%, 100% 0%, calc(100% - 10px) 100%, 0% 100%)' }}>
            Run First Scan →
          </Link>
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px', marginTop: '32px', fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'rgba(240,237,232,0.3)' }}>No scans match this filter.</div>
      ) : (
        <>
          <div key={gridKey} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '12px', marginTop: '24px' }}>
            {paginated.map((scan, i) => <ScanCard key={scan.id} scan={scan} index={(page - 1) * PER_PAGE + i} />)}
          </div>

          {totalPages > 1 && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '16px', marginTop: '36px', paddingBottom: '20px' }}>
              <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em', padding: '8px 18px', border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: page === 1 ? 'rgba(240,237,232,0.3)' : 'rgba(240,237,232,0.5)', cursor: page === 1 ? 'default' : 'pointer', opacity: page === 1 ? 0.3 : 1, transition: 'all 0.2s' }}>← Prev</button>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: 'rgba(240,237,232,0.4)' }}>Page {page} of {totalPages}</span>
              <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em', padding: '8px 18px', border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: page === totalPages ? 'rgba(240,237,232,0.3)' : 'rgba(240,237,232,0.5)', cursor: page === totalPages ? 'default' : 'pointer', opacity: page === totalPages ? 0.3 : 1, transition: 'all 0.2s' }}>Next →</button>
            </div>
          )}
        </>
      )}

      {/* Warning Modal */}
      {showModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, zIndex: 999, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.8)', animation: 'modalFade 0.2s ease forwards' }}>
          <div style={{ background: '#0a0a0f', border: '1px solid #ff4560', padding: '40px', width: '100%', maxWidth: '440px', boxShadow: '0 20px 40px rgba(0,0,0,0.8)' }}>
            <h2 style={{ fontFamily: "'Syne', sans-serif", fontSize: '24px', color: '#ff4560', marginBottom: '16px', fontWeight: 600 }}>Clear Scan History?</h2>
            <p style={{ fontFamily: "'Instrument Sans', sans-serif", fontSize: '15px', color: 'rgba(240,237,232,0.7)', marginBottom: '32px', lineHeight: 1.6 }}>
              This will permanently delete all your personal scan records. This action cannot be undone. <br /><br />
              <span style={{ fontSize: '13px', color: 'rgba(240,237,232,0.4)' }}>(Note: Anonymized AI reports contributed to the global hive mind will remain available to the community.)</span>
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '16px' }}>
              <button
                onClick={() => setShowModal(false)}
                style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em', padding: '12px 24px', background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', color: 'rgba(240,237,232,0.6)', cursor: 'pointer', transition: 'all 0.2s' }}
                onMouseEnter={(e) => { e.currentTarget.style.color = '#fff'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.3)' }}
                onMouseLeave={(e) => { e.currentTarget.style.color = 'rgba(240,237,232,0.6)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)' }}
              >
                Cancel
              </button>
              <button
                onClick={handleClearHistory}
                disabled={isClearing}
                style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em', padding: '12px 24px', background: isClearing ? '#330000' : 'rgba(255,69,96,0.15)', border: '1px solid #ff4560', color: isClearing ? 'rgba(255,69,96,0.5)' : '#ff4560', cursor: isClearing ? 'not-allowed' : 'pointer', transition: 'all 0.2s' }}
                onMouseEnter={(e) => { if (!isClearing) { e.currentTarget.style.background = '#ff4560'; e.currentTarget.style.color = '#000' } }}
                onMouseLeave={(e) => { if (!isClearing) { e.currentTarget.style.background = 'rgba(255,69,96,0.15)'; e.currentTarget.style.color = '#ff4560' } }}
              >
                {isClearing ? 'Clearing...' : 'Confirm Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}