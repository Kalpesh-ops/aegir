'use client'

import { useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import ReactMarkdown from 'react-markdown'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'

function formatDate(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
  const mm = months[d.getMonth()]
  const dd = String(d.getDate()).padStart(2, '0')
  const yyyy = d.getFullYear()
  const HH = String(d.getHours()).padStart(2, '0')
  const MM = String(d.getMinutes()).padStart(2, '0')
  return `${mm} ${dd}, ${yyyy} at ${HH}:${MM}`
}

function parseCvss(cvss) {
  if (cvss === null || cvss === undefined) return 0
  return parseFloat(cvss) || 0
}

function getRiskBadge(cvss, size = 'sm') {
  const score = parseCvss(cvss)
  if (score >= 9) return { label: 'Critical', color: '#ff4560', bg: 'rgba(255,69,96,0.12)' }
  if (score >= 7) return { label: 'High', color: '#ffb340', bg: 'rgba(255,179,64,0.12)' }
  if (score >= 4) return { label: 'Medium', color: '#4af4ff', bg: 'rgba(74,244,255,0.12)' }
  return { label: 'Low', color: '#00ff88', bg: 'rgba(0,255,136,0.08)' }
}

// Maps scan_mode values to display labels and accent colors
const SCAN_MODE_META = {
  fast:     { label: 'Fast Scan',     color: '#00ff88', bg: 'rgba(0,255,136,0.08)' },
  deep:     { label: 'Deep Scan',     color: '#4af4ff', bg: 'rgba(74,244,255,0.08)' },
  pen_test: { label: 'Pen Test',      color: '#ffb340', bg: 'rgba(255,179,64,0.08)' },
}

function getScanModeBadge(mode) {
  return SCAN_MODE_META[mode] || { label: 'Fast Scan', color: '#00ff88', bg: 'rgba(0,255,136,0.08)' }
}

const sevColors = ['#ff4560', '#ffb340', '#4af4ff', 'rgba(240,237,232,0.35)']
const sevLabels = ['Critical', 'High', 'Medium', 'Low']

function getBarColor(score) {
  if (score >= 9) return '#ff4560'
  if (score >= 7) return '#ffb340'
  if (score >= 4) return '#4af4ff'
  return '#00ff88'
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
        <p key={i} style={{ color: p.color || p.payload.fill || p.fill }}>{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

const markdownComponents = {
  h1: ({ children }) => <h1 style={{ fontFamily: "'Syne',sans-serif", fontWeight: 500, fontSize: '28px', color: '#f0ede8', marginTop: '32px', marginBottom: '16px' }}>{children}</h1>,
  h2: ({ children }) => <h2 style={{ fontFamily: "'Syne',sans-serif", fontWeight: 500, fontSize: '22px', color: '#f0ede8', marginTop: '28px', marginBottom: '12px' }}>{children}</h2>,
  h3: ({ children }) => <h3 style={{ fontFamily: "'Syne',sans-serif", fontWeight: 500, fontSize: '18px', color: '#f0ede8', marginTop: '20px', marginBottom: '10px' }}>{children}</h3>,
  p: ({ children }) => <p style={{ fontFamily: "'Instrument Sans',sans-serif", fontSize: '14px', color: 'rgba(240,237,232,0.75)', lineHeight: 1.75, marginBottom: '16px' }}>{children}</p>,
  code: ({ children }) => <code style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '12px', background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: '2px', color: '#00ff88' }}>{children}</code>,
  pre: ({ children }) => <pre style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.08)', padding: '20px', overflowX: 'auto', marginBottom: '20px' }}>{children}</pre>,
  ul: ({ children }) => <ul style={{ paddingLeft: '24px', marginBottom: '16px', listStyle: 'disc' }}>{children}</ul>,
  ol: ({ children }) => <ol style={{ paddingLeft: '24px', marginBottom: '16px', listStyle: 'decimal' }}>{children}</ol>,
  li: ({ children }) => <li style={{ fontFamily: "'Instrument Sans',sans-serif", fontSize: '14px', color: 'rgba(240,237,232,0.7)', marginBottom: '6px', lineHeight: 1.65 }}>{children}</li>,
  blockquote: ({ children }) => <blockquote style={{ borderLeft: '2px solid #00ff88', paddingLeft: '16px', color: 'rgba(240,237,232,0.5)', margin: '20px 0', fontStyle: 'italic' }}>{children}</blockquote>,
  strong: ({ children }) => <strong style={{ color: '#f0ede8', fontWeight: 500 }}>{children}</strong>,
}

export default function ScanResultClient({
  id, target_redacted, scan_timestamp, ports, cve_findings, ai_summary, cve_count, highest_cvss, scan_mode
}) {
  const router = useRouter()
  const [activeTab, setActiveTab] = useState('report')
  const scanIdShort = id.substring(0, 8)
  const risk = getRiskBadge(highest_cvss)
  const modeMeta = getScanModeBadge(scan_mode)

  const sevData = (() => {
    const buckets = { Critical: 0, High: 0, Medium: 0, Low: 0 }
    const safeCves = Array.isArray(cve_findings) ? cve_findings : []
    safeCves.forEach((cve) => {
      const score = parseCvss(cve.cvss)
      if (score >= 9) buckets.Critical++
      else if (score >= 7) buckets.High++
      else if (score >= 4) buckets.Medium++
      else buckets.Low++
    })
    return Object.entries(buckets)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({ name, value }))
  })()

  const sortedCves = [...(Array.isArray(cve_findings) ? cve_findings : [])].sort((a, b) => parseCvss(b.cvss) - parseCvss(a.cvss))
  const topCves = sortedCves.slice(0, 5).map((cve) => ({
    id: (cve.id || cve.cve_id || 'N/A').substring(0, 16),
    cvss: parseCvss(cve.cvss),
  }))

  function downloadJSON() {
    const blob = new Blob([JSON.stringify({ ports, cve_findings }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `netsec-scan-${scanIdShort}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  function downloadReport() {
    const blob = new Blob([ai_summary || ''], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `netsec-report-${scanIdShort}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  const tabBtn = (tab, label) => ({
    background: 'none',
    border: 'none',
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '10px',
    letterSpacing: '0.15em',
    textTransform: 'uppercase',
    color: activeTab === tab ? '#f0ede8' : 'rgba(240,237,232,0.35)',
    padding: '0 0 10px',
    cursor: 'pointer',
    borderBottom: activeTab === tab ? '1px solid #00ff88' : '1px solid transparent',
    marginRight: '32px',
    transition: 'color 0.2s, border-color 0.2s',
  })

  return (
    <div>
      <style>{`
        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(16px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes tabFade {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        .page-enter { animation: fadeUp 0.5s ease forwards; }
        .tab-content { animation: tabFade 0.15s ease forwards; }
      `}</style>

      <div className="page-enter">
        {/* Breadcrumb */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          color: 'rgba(240,237,232,0.35)',
          letterSpacing: '0.08em',
          marginBottom: '24px',
        }}>
          <Link href="/dashboard" style={{ color: 'rgba(240,237,232,0.35)', textDecoration: 'none', transition: 'color 0.2s' }}
            onMouseEnter={(e) => e.currentTarget.style.color = '#f0ede8'}
            onMouseLeave={(e) => e.currentTarget.style.color = 'rgba(240,237,232,0.35)'}
          >
            Dashboard
          </Link>
          <span>/</span>
          <Link href="/dashboard/history" style={{ color: 'rgba(240,237,232,0.35)', textDecoration: 'none', transition: 'color 0.2s' }}
            onMouseEnter={(e) => e.currentTarget.style.color = '#f0ede8'}
            onMouseLeave={(e) => e.currentTarget.style.color = 'rgba(240,237,232,0.35)'}
          >
            History
          </Link>
          <span>/</span>
          <span style={{ color: 'rgba(240,237,232,0.6)' }}>Scan</span>
        </div>

        {/* Header row */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px' }}>
          <div>
            <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'rgba(240,237,232,0.4)', marginBottom: '4px' }}>
              SCAN #{scanIdShort}
            </p>
            <h1 style={{ fontFamily: "'Syne', sans-serif", fontWeight: 500, fontSize: '28px', color: '#f0ede8', lineHeight: 1.1 }}>
              {target_redacted || 'Unknown Target'}
            </h1>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginBottom: '8px' }}>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '11px',
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                color: modeMeta.color,
                background: modeMeta.bg,
                border: `1px solid ${modeMeta.color}`,
                padding: '8px 16px',
                display: 'inline-block',
              }}>
                {modeMeta.label}
              </span>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '11px',
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                color: risk.color,
                background: risk.bg,
                border: `1px solid ${risk.color}`,
                padding: '8px 20px',
                display: 'inline-block',
              }}>
                {risk.label} Risk
              </span>
            </div>
            <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: 'rgba(240,237,232,0.4)', letterSpacing: '0.05em' }}>
              {formatDate(scan_timestamp)}
            </p>
          </div>
        </div>

        {/* Divider */}
        <div style={{ height: '1px', background: 'rgba(255,255,255,0.07)', marginBottom: '28px' }} />

        {/* Tabs */}
        <div style={{ display: 'flex', marginBottom: '28px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          {[['report', 'AI Report'], ['cve', 'CVE Findings'], ['raw', 'Raw Data']].map(([tab, label]) => (
            <button key={tab} style={tabBtn(tab)} onClick={() => setActiveTab(tab)}>
              {label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div key={activeTab} className="tab-content">

          {/* Tab 1: AI Report */}
          {activeTab === 'report' && (
            <div style={{
              background: 'rgba(0,0,0,0.3)',
              border: '1px solid rgba(255,255,255,0.06)',
              padding: '36px',
              maxHeight: '700px',
              overflowY: 'auto',
            }}>
              {ai_summary ? (
                <ReactMarkdown components={markdownComponents}>{ai_summary}</ReactMarkdown>
              ) : (
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'rgba(240,237,232,0.3)' }}>
                  No AI report generated for this scan.
                </p>
              )}
            </div>
          )}

          {/* Tab 2: CVE Findings */}
          {activeTab === 'cve' && (
            <div>
              {/* Ports Grid */}
              <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.15em', color: '#00ff88', marginBottom: '16px' }}>
                Detected Ports ({ports.length})
              </p>
              {ports.length === 0 ? (
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'rgba(240,237,232,0.3)', textAlign: 'center', padding: '40px' }}>
                  No open ports detected.
                </p>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '8px', marginBottom: '36px' }}>
                  {ports.map((port, i) => (
                    <div key={i} style={{
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid rgba(255,255,255,0.07)',
                      padding: '20px 16px',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px', marginBottom: '6px' }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, fontSize: '24px', color: '#00ff88', lineHeight: 1 }}>
                          {port.portid || port.port || port.port_number || '?'}
                        </span>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '9px', textTransform: 'uppercase', color: 'rgba(240,237,232,0.4)', letterSpacing: '0.05em' }}>
                          {port.protocol || port.proto || 'tcp'}
                        </span>
                      </div>
                      <p style={{ fontFamily: "'Instrument Sans', sans-serif", fontSize: '13px', color: 'rgba(240,237,232,0.7)', marginBottom: '3px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {port.service || port.service_name || port.name || 'unknown'}
                      </p>
                      {(port.product || port.product_name) && (
                        <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', color: 'rgba(240,237,232,0.35)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {(port.product || port.product_name)} {(port.version || port.version_string || port.ver)}
                        </p>
                      )}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginTop: '8px' }}>
                        <div style={{
                          width: '6px', height: '6px', borderRadius: '50%',
                          background: (port.port_state || port.state || 'open') === 'open' ? '#00ff88' : '#ffb340',
                          boxShadow: (port.port_state || port.state || 'open') === 'open' ? '0 0 6px #00ff88' : '0 0 6px #ffb340',
                        }} />
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '9px', textTransform: 'uppercase', color: 'rgba(240,237,232,0.4)' }}>
                          {port.port_state || port.state || 'open'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Charts */}
              {sevData.length === 0 && cve_findings.length === 0 ? (
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'rgba(240,237,232,0.3)', textAlign: 'center', padding: '40px' }}>
                  No CVE data available.
                </p>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2px', marginBottom: '32px' }}>
                  {/* Donut */}
                  <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', padding: '24px' }}>
                    <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.15em', color: '#00ff88', marginBottom: '16px' }}>
                      Severity Breakdown
                    </p>
                    <ResponsiveContainer width="100%" height={220}>
                      <PieChart>
                        <Pie
                          data={sevData}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={90}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {sevData.map((_, i) => (
                            <Cell key={i} fill={sevColors[i % sevColors.length]} />
                          ))}
                        </Pie>
                        <Tooltip content={<CustomTooltip />} />
                        <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle">
                          <tspan x="50%" dy="-8" style={{ fontFamily: "'Syne', sans-serif", fontWeight: 600, fontSize: '24px', fill: '#f0ede8' }}>
                            {cve_findings.length}
                          </tspan>
                          <tspan x="50%" dy="22" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', fill: 'rgba(240,237,232,0.4)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                            CVEs
                          </tspan>
                        </text>
                      </PieChart>
                    </ResponsiveContainer>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', marginTop: '12px' }}>
                      {sevData.map((d, i) => (
                        <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: sevColors[i % sevColors.length] }} />
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', color: 'rgba(240,237,232,0.4)' }}>
                            {d.name} {d.value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Top CVEs Bar */}
                  <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', padding: '24px' }}>
                    <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.15em', color: '#00ff88', marginBottom: '16px' }}>
                      Top CVEs by Score
                    </p>
                    <ResponsiveContainer width="100%" height={220}>
                      <BarChart data={topCves} layout="vertical" margin={{ top: 0, right: 20, left: 0, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                        <XAxis type="number" domain={[0, 10]} tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, fill: 'rgba(240,237,232,0.35)' }} axisLine={false} tickLine={false} />
                        <YAxis type="category" dataKey="id" tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, fill: '#00ff88' }} axisLine={false} tickLine={false} width={80} />
                        <Tooltip content={<CustomTooltip />} />
                        <Bar dataKey="cvss" radius={[0, 2, 2, 0]}>
                          {topCves.map((entry, i) => (
                            <Cell key={i} fill={getBarColor(entry.cvss)} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {/* CVE Table */}
              <div style={{ marginTop: '8px' }}>
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.15em', color: 'rgba(240,237,232,0.35)', marginBottom: '12px' }}>
                  All CVE Findings ({cve_findings.length})
                </p>
                {cve_findings.length === 0 ? (
                  <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'rgba(240,237,232,0.3)', padding: '20px 0', textAlign: 'center' }}>
                    No CVEs matched for detected services. Service versions may not have been identified.
                  </p>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr>
                          {['CVE ID', 'CVSS', 'Summary', 'Service'].map((h) => (
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
                            }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {sortedCves.map((cve, i) => {
                          const score = parseCvss(cve.cvss)
                          const scoreColor = score >= 9 ? '#ff4560' : score >= 7 ? '#ffb340' : score >= 4 ? '#4af4ff' : '#00ff88'
                          const cveId = cve.id || cve.cve_id || 'N/A'
                          const cveUrl = cveId.startsWith('CVE-') ? `https://cve.circl.lu/cve/${cveId}` : null
                          return (
                            <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                              <td style={{ padding: '12px 16px' }}>
                                {cveUrl ? (
                                  <a href={cveUrl} target="_blank" rel="noopener noreferrer" style={{
                                    fontFamily: "'JetBrains Mono', monospace",
                                    fontSize: '11px',
                                    color: '#00ff88',
                                    textDecoration: 'none',
                                  }}>
                                    {cveId} ↗
                                  </a>
                                ) : (
                                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: '#00ff88' }}>{cveId}</span>
                                )}
                              </td>
                              <td style={{ padding: '12px 16px' }}>
                                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: scoreColor }}>{score.toFixed(1)}</span>
                              </td>
                              <td style={{ padding: '12px 16px', maxWidth: '400px' }}>
                                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: 'rgba(240,237,232,0.6)' }}>
                                  {cve.summary || cve.description || '—'}
                                </span>
                              </td>
                              <td style={{ padding: '12px 16px' }}>
                                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', color: 'rgba(240,237,232,0.4)' }}>
                                  {cve.port ? `${cve.port}/${cve.protocol || 'tcp'} ` : ''}{cve.service || '—'}
                                </span>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tab 3: Raw Data */}
          {activeTab === 'raw' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2px' }}>
              <div>
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.15em', color: '#00ff88', marginBottom: '12px' }}>
                  Ports Data
                </p>
                <pre style={{
                  background: 'rgba(0,0,0,0.4)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  padding: '20px',
                  maxHeight: '500px',
                  overflow: 'auto',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '11px',
                  color: 'rgba(240,237,232,0.6)',
                  lineHeight: 1.6,
                  margin: 0,
                }}>
                  {JSON.stringify(ports, null, 2)}
                </pre>
              </div>
              <div>
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.15em', color: '#00ff88', marginBottom: '12px' }}>
                  CVE Data
                </p>
                <pre style={{
                  background: 'rgba(0,0,0,0.4)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  padding: '20px',
                  maxHeight: '500px',
                  overflow: 'auto',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '11px',
                  color: 'rgba(240,237,232,0.6)',
                  lineHeight: 1.6,
                  margin: 0,
                }}>
                  {JSON.stringify(cve_findings, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Export Buttons */}
        <div style={{ display: 'flex', gap: '12px', marginTop: '32px' }}>
          <button
            onClick={downloadJSON}
            style={{
              flex: 1,
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '10px',
              textTransform: 'uppercase',
              letterSpacing: '0.12em',
              color: 'rgba(240,237,232,0.5)',
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.08)',
              padding: '12px 20px',
              cursor: 'pointer',
              transition: 'all 0.2s',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#00ff88'; e.currentTarget.style.color = '#00ff88' }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.color = 'rgba(240,237,232,0.5)' }}
          >
            Download JSON
          </button>
          <button
            onClick={downloadReport}
            style={{
              flex: 1,
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '10px',
              textTransform: 'uppercase',
              letterSpacing: '0.12em',
              color: 'rgba(240,237,232,0.5)',
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.08)',
              padding: '12px 20px',
              cursor: 'pointer',
              transition: 'all 0.2s',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#00ff88'; e.currentTarget.style.color = '#00ff88' }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.color = 'rgba(240,237,232,0.5)' }}
          >
            Download Report
          </button>
          <button
            onClick={() => router.push('/dashboard/history')}
            style={{
              flex: 1,
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '10px',
              textTransform: 'uppercase',
              letterSpacing: '0.12em',
              color: 'rgba(240,237,232,0.5)',
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.08)',
              padding: '12px 20px',
              cursor: 'pointer',
              transition: 'all 0.2s',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)'; e.currentTarget.style.color = '#f0ede8' }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.color = 'rgba(240,237,232,0.5)' }}
          >
            Back to History
          </button>
        </div>
      </div>
    </div>
  )
}
