'use client'

import { useState, useMemo } from 'react'
import Link from 'next/link'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, defs, linearGradient,
} from 'recharts'

function formatRelative(ts) {
  if (!ts) return '—'
  const now = Date.now()
  const date = new Date(ts).getTime()
  const diff = Math.floor((now - date) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`
  return new Date(date).toLocaleDateString()
}

function formatDate(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const yyyy = d.getFullYear()
  const HH = String(d.getHours()).padStart(2, '0')
  const MM = String(d.getMinutes()).padStart(2, '0')
  return `${mm}/${dd}/${yyyy} ${HH}:${MM}`
}

function getRiskBadge(cvss) {
  if (cvss === null || cvss === undefined) return null
  if (cvss >= 9) return { label: 'Critical', color: '#ff4560', bg: 'rgba(255,69,96,0.08)' }
  if (cvss >= 7) return { label: 'High', color: '#ffb340', bg: 'rgba(255,179,64,0.08)' }
  if (cvss >= 4) return { label: 'Medium', color: '#4af4ff', bg: 'rgba(74,244,255,0.08)' }
  return { label: 'Low', color: '#00ff88', bg: 'rgba(0,255,136,0.08)' }
}

function parseCvss(cvss) {
  if (cvss === null || cvss === undefined) return 0
  return parseFloat(cvss) || 0
}

const cardStyle = (accent) => ({
  background: 'rgba(255,255,255,0.03)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderTop: `2px solid ${accent}`,
  padding: '32px 28px',
})

const labelStyle = {
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '10px',
  textTransform: 'uppercase',
  letterSpacing: '0.15em',
  color: 'rgba(240,237,232,0.35)',
  marginBottom: '12px',
}

const chartCardStyle = {
  background: 'rgba(255,255,255,0.03)',
  border: '1px solid rgba(255,255,255,0.07)',
  padding: '28px',
}

const chartLabelStyle = {
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '10px',
  textTransform: 'uppercase',
  letterSpacing: '0.18em',
  color: '#00ff88',
  marginBottom: '24px',
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'rgba(10,10,15,0.95)',
      border: '1px solid rgba(255,255,255,0.1)',
      padding: '10px 14px',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '11px',
      color: '#f0ede8',
    }}>
      <p style={{ marginBottom: '4px', color: 'rgba(240,237,232,0.5)' }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

export default function DashboardClient({ scans }) {
  const [filter, setFilter] = useState('')

  const stats = useMemo(() => {
    const total = scans.length
    const criticalCount = scans
      .filter((s) => parseCvss(s.highest_cvss) >= 9)
      .reduce((sum, s) => sum + (parseCvss(s.cve_count) || 0), 0)
    const avgCvss = total > 0
      ? (scans.reduce((sum, s) => sum + parseCvss(s.highest_cvss), 0) / total).toFixed(1)
      : '0.0'
    const lastTs = scans[0]?.scan_timestamp || null
    return { total, criticalCount, avgCvss, lastTs }
  }, [scans])

  const severityData = useMemo(() => {
    let crit = 0, high = 0, med = 0, low = 0

    scans.forEach(scan => {
      crit += (scan.crit_count || 0)
      high += (scan.high_count || 0)
      med += (scan.med_count || 0)
      low += (scan.low_count || 0)
    })

    return [
      { name: 'Critical', count: crit, fill: '#ff4560' },
      { name: 'High', count: high, fill: '#ffb340' },
      { name: 'Medium', count: med, fill: '#4af4ff' },
      { name: 'Low', count: low, fill: 'rgba(0,255,136,0.5)' },
    ]
  }, [scans])

  const trendData = useMemo(() => {
    return [...scans]
      .reverse()
      .slice(-10)
      .map((s) => ({
        date: formatDate(s.scan_timestamp).split(' ')[0],
        cvss: parseCvss(s.highest_cvss),
      }))
  }, [scans])

  const filteredScans = useMemo(() => {
    if (!filter) return scans.slice(0, 10)
    const q = filter.toLowerCase()
    return scans
      .filter((s) => (s.target_redacted || '').toLowerCase().includes(q))
      .slice(0, 10)
  }, [scans, filter])

  return (
    <div>
      <style>{`
        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(16px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .stat-card {
          animation: fadeUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
          opacity: 0;
        }
        .table-row:hover {
          background: rgba(255,255,255,0.02) !important;
        }
      `}</style>

      {/* Header */}
      <div style={{ marginBottom: '36px' }}>
        <h1 style={{
          fontFamily: "'Syne', sans-serif",
          fontWeight: 600,
          fontSize: '28px',
          color: '#f0ede8',
          marginBottom: '6px',
        }}>
          Overview
        </h1>
        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '11px',
          color: 'rgba(240,237,232,0.35)',
          letterSpacing: '0.1em',
        }}>
          Security intelligence dashboard
        </p>
      </div>

      {/* Stats Row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '2px',
        marginBottom: '32px',
      }}>
        <div className="stat-card" style={{ ...cardStyle('#00ff88'), animationDelay: '0ms' }}>
          <p style={labelStyle}>Total Scans</p>
          <p style={{ fontFamily: "'Syne', sans-serif", fontWeight: 600, fontSize: '48px', color: '#f0ede8', lineHeight: 1, marginBottom: '8px' }}>
            {stats.total}
          </p>
        </div>
        <div className="stat-card" style={{ ...cardStyle('#4af4ff'), animationDelay: '100ms' }}>
          <p style={labelStyle}>Critical CVEs</p>
          <p style={{ fontFamily: "'Syne', sans-serif", fontWeight: 600, fontSize: '48px', color: '#4af4ff', lineHeight: 1, marginBottom: '8px' }}>
            {stats.criticalCount}
          </p>
        </div>
        <div className="stat-card" style={{ ...cardStyle('#ffb340'), animationDelay: '200ms' }}>
          <p style={labelStyle}>Average CVSS</p>
          <p style={{ fontFamily: "'Syne', sans-serif", fontWeight: 600, fontSize: '48px', color: '#ffb340', lineHeight: 1, marginBottom: '8px' }}>
            {stats.avgCvss}
          </p>
        </div>
        <div className="stat-card" style={{ ...cardStyle('rgba(240,237,232,0.4)'), animationDelay: '300ms' }}>
          <p style={labelStyle}>Last Scan</p>
            <p style={{ fontFamily: "'Syne', sans-serif", fontWeight: 600, fontSize: '48px', color: '#f0ede8', lineHeight: 1, marginBottom: '8px' }} suppressHydrationWarning>
            {formatRelative(stats.lastTs)}
          </p>
        </div>
      </div>

      {/* Charts or Empty */}
      {scans.length === 0 ? (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '80px 40px',
          background: 'rgba(255,255,255,0.02)',
          border: '1px solid rgba(255,255,255,0.06)',
          marginBottom: '32px',
        }}>
          <p style={{
            fontFamily: "'Syne', sans-serif",
            fontWeight: 800,
            fontSize: '120px',
            color: 'rgba(240,237,232,0.06)',
            lineHeight: 1,
            marginBottom: '24px',
          }}>
            0
          </p>
          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '12px',
            color: 'rgba(240,237,232,0.3)',
            marginBottom: '32px',
          }}>
            No scans yet.
          </p>
          <Link href="/dashboard/scan" style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '11px',
            fontWeight: 500,
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
            color: '#060608',
            background: '#00ff88',
            border: 'none',
            padding: '14px 36px',
            textDecoration: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            clipPath: 'polygon(10px 0%, 100% 0%, calc(100% - 10px) 100%, 0% 100%)',
          }}>
            Start Scanning
          </Link>
        </div>
      ) : (
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '2px',
          marginBottom: '32px',
        }}>
          {/* Severity Chart */}
          <div style={chartCardStyle}>
            <p style={chartLabelStyle}>CVE Severity Distribution</p>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={severityData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="sevGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00ff88" stopOpacity={0.8} />
                    <stop offset="100%" stopColor="#00ff88" stopOpacity={0.4} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis
                  dataKey="name"
                  tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, fill: 'rgba(240,237,232,0.35)' }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, fill: 'rgba(240,237,232,0.35)' }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#00ff88" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Trend Chart */}
          <div style={chartCardStyle}>
            <p style={chartLabelStyle}>CVSS Trend</p>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trendData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="cvssGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00ff88" stopOpacity={0.15} />
                    <stop offset="100%" stopColor="#00ff88" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis
                  dataKey="date"
                  tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, fill: 'rgba(240,237,232,0.35)' }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 10]}
                  tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, fill: 'rgba(240,237,232,0.35)' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Area
                  type="monotone"
                  dataKey="cvss"
                  stroke="#00ff88"
                  strokeWidth={2}
                  fill="url(#cvssGradient)"
                  dot={{ fill: '#00ff88', r: 4 }}
                  activeDot={{ r: 6 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Recent Scans Table */}
      <div>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '16px',
        }}>
          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '10px',
            textTransform: 'uppercase',
            letterSpacing: '0.18em',
            color: '#00ff88',
          }}>
            Recent Scans
          </p>
          <input
            placeholder="Filter by target..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.08)',
              padding: '8px 12px',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '11px',
              color: '#f0ede8',
              outline: 'none',
              width: '220px',
            }}
          />
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['Target', 'Date', 'CVEs', 'Highest CVSS', 'Risk', 'Action'].map((h) => (
                <th key={h} style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '10px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.12em',
                  color: 'rgba(240,237,232,0.3)',
                  borderBottom: '1px solid rgba(255,255,255,0.07)',
                  padding: '10px 16px',
                  textAlign: 'left',
                  fontWeight: 400,
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredScans.length === 0 ? (
              <tr>
                <td colSpan={6} style={{
                  textAlign: 'center',
                  padding: '40px',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '11px',
                  color: 'rgba(240,237,232,0.3)',
                }}>
                  No scans yet — run your first scan
                </td>
              </tr>
            ) : (
              filteredScans.map((scan) => {
                const risk = getRiskBadge(parseCvss(scan.highest_cvss))
                return (
                  <tr key={scan.id} className="table-row" style={{
                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                    transition: 'background 0.2s',
                  }}>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '12px',
                        color: '#f0ede8',
                      }}>
                        {scan.target_redacted || '—'}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '11px',
                        color: 'rgba(240,237,232,0.5)',
                      }}>
                        {formatDate(scan.scan_timestamp)}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '12px',
                        color: '#f0ede8',
                      }}>
                        {scan.cve_count ?? 0}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '12px',
                        color: risk?.color || '#f0ede8',
                      }}>
                        {parseCvss(scan.highest_cvss).toFixed(1)}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      {risk ? (
                        <span style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '9px',
                          textTransform: 'uppercase',
                          letterSpacing: '0.1em',
                          color: risk.color,
                          background: risk.bg,
                          border: `1px solid ${risk.color}`,
                          padding: '3px 8px',
                        }}>
                          {risk.label}
                        </span>
                      ) : (
                        <span style={{ color: 'rgba(240,237,232,0.3)', fontFamily: "'JetBrains Mono', monospace", fontSize: '10px' }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <Link
                        href={`/dashboard/scan/${scan.id}`}
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '10px',
                          color: '#00ff88',
                          textDecoration: 'none',
                          letterSpacing: '0.05em',
                        }}
                      >
                        View →
                      </Link>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
